//! Storage node process: identity on the volume, DRPC, pieces in S3.
//!
//! This crate serves `Upload`, `Download`, `Exists`, `Retain`, `RetainBig`, and
//! `RestoreTrash` over TLS, Noise, and QUIC, deletes expired pieces and old
//! trash, settles closed bandwidth-order hours, checks in with each trusted
//! satellite, dials graceful exit for a pending satellite, polls held amounts
//! and pricing, and serves the Vue dashboard JSON on `0.0.0.0:14002`.

#![deny(clippy::undocumented_unsafe_blocks)]

#[allow(clippy::all, dead_code, unused_imports)]
mod contact {
    include!(concat!(env!("OUT_DIR"), "/contact.rs"));
}
#[allow(clippy::all, dead_code, unused_imports)]
mod node {
    include!(concat!(env!("OUT_DIR"), "/node.rs"));
}
#[allow(clippy::all, dead_code, unused_imports)]
mod gracefulexit {
    include!(concat!(env!("OUT_DIR"), "/gracefulexit.rs"));
}
#[allow(clippy::all, dead_code, unused_imports)]
mod heldamount {
    include!(concat!(env!("OUT_DIR"), "/heldamount.rs"));
}
#[allow(clippy::all, dead_code, unused_imports)]
mod nodestats {
    include!(concat!(env!("OUT_DIR"), "/nodestats.rs"));
}

mod bloom;
mod checkin;
mod config;
mod dashboard;
mod exit;
mod identity;
mod noise_key;
mod orders;
mod payout;
mod server;

pub use config::Config;
pub use exit::{format_exit_row, format_exit_status};
pub use identity::{IDENTITY_PEM, load_or_create};
pub use server::{
    Node, PIECESTORE_EXISTS, PIECESTORE_RESTORE_TRASH, PIECESTORE_RETAIN, PIECESTORE_RETAIN_BIG,
    TrustedSatellite,
};

use std::path::Path;
use std::sync::Arc;

use storj_rpc::{NodeId, NodeUrl};

/// What the binary should do. No arguments serves the node.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    /// Serve DRPC, the piece chore, settlement, check-in, payout polling, and
    /// graceful exit.
    Run,
    /// Record a pending exit for one trusted satellite id.
    ExitSatellite(String),
    /// Print the stored exit rows.
    ExitStatus,
}

/// `storagenode`, `storagenode exit-satellite <id>`, or `storagenode exit-status`.
pub fn command<I, S>(args: I) -> Result<Command, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args = args.into_iter();
    match args.next().as_ref().map(|arg| arg.as_ref()) {
        None => Ok(Command::Run),
        Some("exit-satellite") => {
            let Some(id) = args.next() else {
                return Err("exit-satellite requires a satellite id".into());
            };
            if args.next().is_some() {
                return Err("exit-satellite takes one satellite id".into());
            }
            let id = id.as_ref().trim();
            if id.is_empty() {
                return Err("exit-satellite requires a satellite id".into());
            }
            Ok(Command::ExitSatellite(id.to_owned()))
        }
        Some("exit-status") => {
            if args.next().is_some() {
                return Err("exit-status takes no arguments".into());
            }
            Ok(Command::ExitStatus)
        }
        Some(other) => Err(format!("unknown command {other}")),
    }
}

/// Failure while starting or serving the node.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Operator or S3 settings were rejected.
    #[error(transparent)]
    Config(#[from] config::Error),
    /// The volume identity could not be loaded or written.
    #[error(transparent)]
    Identity(#[from] identity::Error),
    /// The volume Noise key could not be loaded or written.
    #[error(transparent)]
    Noise(#[from] noise_key::Error),
    /// A trusted satellite has no leaf whose CA matches its node id.
    #[error("{0}")]
    Satellite(String),
    /// The node rejected a satellite certificate or its TLS config.
    #[error(transparent)]
    Node(#[from] server::BuildError),
    /// The piece store or the bucket check failed.
    #[error(transparent)]
    Store(#[from] s3store::Error),
    /// The listen socket failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Loads the identity, opens the piece store, and checks the bucket.
///
/// [`s3store::Store::startup`] calls `HeadBucket`. A failure here is returned
/// to the caller. The binary exits. This function does not bind a port and
/// does not dial a satellite.
pub async fn start(config: &Config) -> Result<Arc<Node>, Error> {
    let identity = load_or_create(&config.s3.volume)?;
    let noise = noise_key::Key::load_or_create(&config.s3.volume)?;
    // A node URL is an id and an address, not a public key. Refuse to build
    // a node that would listen with an empty leaf.
    let trusted = load_satellites(&config.s3.volume, &config.satellites)?;
    let store = s3store::Store::new(config.s3.clone())?;
    let node = Node::with_noise(identity, store, trusted, noise_key::DEFAULT_PROTOCOL, noise)?;
    node.startup().await?;
    Ok(Arc::new(node))
}

/// `{volume}/satellites/{node-id}.pem` is the leaf, then the CA.
///
/// The CA must hash to the id in `STORJ_SATELLITES`. The leaf is what
/// [`storj_uplink::verify_order_limit`] checks.
fn load_satellites(volume: &Path, urls: &[NodeUrl]) -> Result<Vec<TrustedSatellite>, Error> {
    let mut trusted = Vec::with_capacity(urls.len());
    for url in urls {
        let path = volume.join("satellites").join(format!("{}.pem", url.id));
        let pem = match std::fs::read_to_string(&path) {
            Ok(pem) => pem,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::Satellite(format!(
                    "missing certificate for {} at {}",
                    url.id,
                    path.display()
                )));
            }
            Err(err) => return Err(err.into()),
        };
        let certs = identity::certificate_ders(&pem)
            .map_err(|err| Error::Satellite(format!("satellite {} certificate: {err}", url.id)))?;
        if certs.len() < 2 {
            return Err(Error::Satellite(format!(
                "satellite {} certificate chain needs a leaf and a CA",
                url.id
            )));
        }
        trusted.push(TrustedSatellite {
            id: url.id,
            address: url.address.clone(),
            leaf_der: certs[0].clone(),
            ca_der: certs[1].clone(),
        });
    }
    Ok(trusted)
}

/// Starts the node and serves DRPC until the process is killed.
pub async fn run(config: Config) -> Result<(), Error> {
    let node = start(&config).await?;
    let dashboard = Arc::new(dashboard::Dashboard::new(Arc::clone(&node), &config));
    let (dashboard_listener, dashboard_addr) = dashboard::listen().await?;
    let listener = Node::listen(config.listen).await?;
    let addr = listener.local_addr()?;
    let quic = node.quic_endpoint(addr)?;
    eprintln!("storagenode: node {} listening on {addr}", node.node_id());
    eprintln!("storagenode: dashboard http://{dashboard_addr}");
    tokio::spawn(async move {
        if let Err(err) = dashboard.serve(dashboard_listener).await {
            eprintln!("storagenode: dashboard stopped: {err}");
        }
    });
    let quic_node = Arc::clone(&node);
    tokio::spawn(async move {
        let _ = quic_node.serve_quic(quic).await;
    });
    let settling = Arc::clone(&node);
    tokio::spawn(async move {
        settling.serve_orders().await;
    });
    let collecting = Arc::clone(&node);
    tokio::spawn(async move {
        collecting.serve_chore().await;
    });
    let checking = Arc::clone(&node);
    let operator = checkin::Operator::from_config(&config);
    tokio::spawn(async move {
        checkin::serve(checking, operator).await;
    });
    let exiting = Arc::clone(&node);
    tokio::spawn(async move {
        exit::serve(exiting).await;
    });
    let pricing = Arc::clone(&node);
    tokio::spawn(async move {
        payout::serve(pricing).await;
    });
    node.serve(listener).await?;
    Ok(())
}

/// Records a pending exit for a trusted satellite and the bytes live for it.
///
/// The satellite must be in the configured set and its leaf must be signed by
/// the CA that hashes to that id. This does not dial the satellite and does
/// not delete pieces.
pub fn request_exit(config: &Config, satellite_id: &str) -> Result<s3store::ExitRow, Error> {
    let id = NodeId::from_string(satellite_id.trim())
        .map_err(|_| Error::Satellite(format!("satellite id {satellite_id:?} is not a node id")))?;
    if id.is_zero() {
        return Err(Error::Satellite(
            "satellite id is not a trusted satellite".into(),
        ));
    }
    let trusted = load_satellites(&config.s3.volume, &config.satellites)?;
    let Some(satellite) = trusted.iter().find(|sat| sat.id == id) else {
        return Err(Error::Satellite(format!(
            "satellite {id} is not a trusted satellite"
        )));
    };
    server::accept_satellite(satellite)?;
    let store = s3store::Store::new(config.s3.clone())?;
    Ok(store.begin_exit(&id.to_string())?)
}

/// Prints every stored exit row. Completion is the stored receipt, not a file.
pub fn exit_status(config: &Config) -> Result<String, Error> {
    let store = s3store::Store::new(config.s3.clone())?;
    Ok(exit::format_exit_status(&store.exit_rows()?))
}

#[cfg(test)]
mod command_tests {
    use super::*;

    #[test]
    fn commands_are_run_exit_satellite_and_exit_status() {
        assert_eq!(command(std::iter::empty::<&str>()).unwrap(), Command::Run);
        assert_eq!(
            command(["exit-satellite", "  abc  "]).unwrap(),
            Command::ExitSatellite("abc".into())
        );
        assert!(command(["exit-satellite"]).is_err());
        assert!(command(["exit-satellite", "a", "b"]).is_err());
        assert_eq!(command(["exit-status"]).unwrap(), Command::ExitStatus);
        assert!(command(["exit-status", "x"]).is_err());
        let err = command(["dashboard"]).unwrap_err();
        assert!(err.contains("unknown command"), "{err}");
    }
}
