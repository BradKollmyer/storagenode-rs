//! Storage node process: identity on the volume, DRPC over TLS, pieces in S3.
//!
//! This crate serves `Upload`, `Download`, `Exists`, `Retain`, and `RetainBig`.
//! Noise, QUIC, settlement, and check-in are not in this binary yet.

#![deny(clippy::undocumented_unsafe_blocks)]

mod bloom;
mod config;
mod identity;
mod server;

pub use config::Config;
pub use identity::{IDENTITY_PEM, load_or_create};
pub use server::{
    Node, PIECESTORE_EXISTS, PIECESTORE_RETAIN, PIECESTORE_RETAIN_BIG, TrustedSatellite,
};

use std::path::Path;
use std::sync::Arc;

use storj_rpc::NodeUrl;

/// Failure while starting or serving the node.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Operator or S3 settings were rejected.
    #[error(transparent)]
    Config(#[from] config::Error),
    /// The volume identity could not be loaded or written.
    #[error(transparent)]
    Identity(#[from] identity::Error),
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
    // A node URL is an id and an address, not a public key. Refuse to build
    // a node that would listen with an empty leaf.
    let trusted = load_satellites(&config.s3.volume, &config.satellites)?;
    let store = s3store::Store::new(config.s3.clone())?;
    let node = Node::new(identity, store, trusted)?;
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
            leaf_der: certs[0].clone(),
            ca_der: certs[1].clone(),
        });
    }
    Ok(trusted)
}

/// Starts the node and serves DRPC until the process is killed.
pub async fn run(config: Config) -> Result<(), Error> {
    let node = start(&config).await?;
    let listener = Node::listen(config.listen).await?;
    let addr = listener.local_addr()?;
    eprintln!("storagenode: node {} listening on {addr}", node.node_id());
    node.serve(listener).await?;
    Ok(())
}
