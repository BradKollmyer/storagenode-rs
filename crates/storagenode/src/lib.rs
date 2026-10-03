//! Storage node process: identity on the volume, DRPC over TLS, pieces in S3.
//!
//! This crate serves `Upload`, `Download`, and `Exists`. Noise, QUIC, retain,
//! settlement, and check-in are not in this binary yet.

#![deny(clippy::undocumented_unsafe_blocks)]

mod config;
mod identity;
mod server;

pub use config::Config;
pub use identity::{IDENTITY_PEM, load_or_create};
pub use server::{Node, PIECESTORE_EXISTS, TrustedSatellite};

use std::sync::Arc;

/// Failure while starting or serving the node.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Operator or S3 settings were rejected.
    #[error(transparent)]
    Config(#[from] config::Error),
    /// The volume identity could not be loaded or written.
    #[error(transparent)]
    Identity(#[from] identity::Error),
    /// The piece store or the bucket check failed.
    #[error(transparent)]
    Store(#[from] s3store::Error),
    /// The node certificate could not build a TLS server config.
    #[error(transparent)]
    Tls(#[from] storj_rpc::IdentityError),
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
    let store = s3store::Store::new(config.s3.clone())?;
    let trusted = config
        .satellites
        .iter()
        .map(|url| TrustedSatellite {
            id: url.id,
            // The node URL has the satellite id, not its leaf certificate.
            // Check-in learns the certificate later. Until then a signature
            // from this id cannot be verified.
            leaf_der: Vec::new(),
        })
        .collect();
    let node = Node::new(identity, store, trusted)?;
    node.startup().await?;
    Ok(Arc::new(node))
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
