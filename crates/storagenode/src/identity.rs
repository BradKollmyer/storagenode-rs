//! Volume identity. Generated once at difficulty 0 and reloaded after that.
//!
//! `Identity` has no PEM encoder. The file is leaf certificate, CA, then one
//! PKCS#8 `PRIVATE KEY`, which is what [`storj_rpc::Identity::from_pem`] reads.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use std::fs;
use std::io;
use std::path::Path;
use storj_rpc::Identity;

/// File name of the PEM identity inside the volume directory.
pub const IDENTITY_PEM: &str = "identity.pem";

/// Identity on disk could not be read, written, or parsed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The volume or the PEM file could not be accessed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// The PEM was not a Storj identity.
    #[error(transparent)]
    Identity(#[from] storj_rpc::IdentityError),
}

/// Loads `{volume}/identity.pem`, or generates a difficulty-0 identity and writes it.
///
/// The private key is mode `0600` on Unix. The PEM is written to a temporary
/// file, synced, and published with a hard link so a reader never sees an
/// empty `identity.pem`. The directory is synced after the link. A second
/// start that loses the race reads the file the winner published.
pub fn load_or_create(volume: &Path) -> Result<Identity, Error> {
    fs::create_dir_all(volume)?;
    let path = volume.join(IDENTITY_PEM);
    if let Some(identity) = read_identity(&path)? {
        return Ok(identity);
    }
    let identity = Identity::generate()?;
    let pem = encode_pem(&identity);
    match crate::secret::publish(volume, &path, pem.as_bytes()) {
        Ok(()) => Ok(identity),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => read_identity(&path)?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "identity.pem disappeared after a racing create",
                )
            })
            .map_err(Error::from),
        Err(err) => Err(err.into()),
    }
}

/// Loads `{volume}/identity.pem`. `Ok(None)` when there is none. Never
/// creates one.
pub(crate) fn load(volume: &Path) -> Result<Option<Identity>, Error> {
    read_identity(&volume.join(IDENTITY_PEM))
}

/// Leaf, CA, then any parents. No private key. Satellite trust files use this shape.
#[cfg(test)]
pub(crate) fn certificate_chain_pem(identity: &Identity) -> String {
    let mut pem = String::new();
    for cert in identity.cert_chain() {
        pem.push_str(&pem_block("CERTIFICATE", cert.as_ref()));
    }
    pem
}

/// DER of every `CERTIFICATE` block, in file order.
pub(crate) fn certificate_ders(pem: &str) -> Result<Vec<Vec<u8>>, storj_rpc::IdentityError> {
    let mut out = Vec::new();
    let mut rest = pem;
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let end = after.find(END).ok_or_else(|| {
            storj_rpc::IdentityError::Certificate("certificate block is truncated".into())
        })?;
        let encoded: String = after[..end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let der = BASE64.decode(encoded).map_err(|err| {
            storj_rpc::IdentityError::Certificate(format!("certificate is not base64: {err}"))
        })?;
        out.push(der);
        rest = &after[end + END.len()..];
    }
    Ok(out)
}

fn encode_pem(identity: &Identity) -> String {
    let mut pem = String::new();
    for cert in identity.cert_chain() {
        pem.push_str(&pem_block("CERTIFICATE", cert.as_ref()));
    }
    pem.push_str(&pem_block(
        "PRIVATE KEY",
        identity.private_key().secret_der(),
    ));
    pem
}

fn pem_block(tag: &str, der: &[u8]) -> String {
    let encoded = BASE64.encode(der);
    let mut out = format!("-----BEGIN {tag}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {tag}-----\n"));
    out
}

fn read_identity(path: &Path) -> Result<Option<Identity>, Error> {
    match fs::read_to_string(path) {
        Ok(pem) => Ok(Some(Identity::from_pem(&pem)?)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn persists_leaf_first_pkcs8_and_reloads_the_same_id() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("sn-id-{nanos}-{}", std::process::id()));
        let first = load_or_create(&dir).expect("generate");
        let pem = fs::read_to_string(dir.join(IDENTITY_PEM)).expect("pem");
        let cert = pem.find("BEGIN CERTIFICATE").expect("cert");
        let key = pem.find("BEGIN PRIVATE KEY").expect("key");
        assert!(cert < key, "leaf certificates come before the key");
        assert!(pem.matches("BEGIN CERTIFICATE").count() >= 2, "leaf and CA");
        assert!(!pem.contains("EC PRIVATE KEY"));

        let second = load_or_create(&dir).expect("reload");
        assert_eq!(first.node_id(), second.node_id());
        let message = b"storagenode";
        let signature = second.hash_and_sign(message).expect("sign");
        first.hash_and_verify(message, &signature).expect("verify");
        let _ = fs::remove_dir_all(&dir);
    }
}
