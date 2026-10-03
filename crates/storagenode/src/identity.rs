//! Volume identity. Generated once at difficulty 0 and reloaded after that.
//!
//! `Identity` has no PEM encoder. The file is leaf certificate, CA, then one
//! PKCS#8 `PRIVATE KEY`, which is what [`storj_rpc::Identity::from_pem`] reads.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
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
/// The private key is mode `0600` on Unix. A crash between generate and the
/// next start must not mint a second id, so the file is synced before return.
/// Two racing starts: the loser reads the file the winner created.
pub fn load_or_create(volume: &Path) -> Result<Identity, Error> {
    fs::create_dir_all(volume)?;
    let path = volume.join(IDENTITY_PEM);
    if path.is_file() {
        let pem = fs::read_to_string(&path)?;
        return Ok(Identity::from_pem(&pem)?);
    }
    let identity = Identity::generate()?;
    let pem = encode_pem(&identity);
    match write_secret(&path, pem.as_bytes()) {
        Ok(()) => Ok(identity),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            let pem = fs::read_to_string(&path)?;
            Ok(Identity::from_pem(&pem)?)
        }
        Err(err) => Err(err.into()),
    }
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

fn write_secret(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(bytes)?;
    // The id cannot be regenerated. Do not return until the PEM is durable.
    file.sync_all()?;
    Ok(())
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
