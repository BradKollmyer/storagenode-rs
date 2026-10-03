//! X25519 key for the Noise IK responder.
//!
//! One 32-byte private key lives on the volume as `noise.key`. The public key
//! is derived on load. The process accepts a single protocol; Go's default is
//! [`DEFAULT_PROTOCOL`] (`NOISE_IK_25519_CHACHAPOLY_BLAKE2B`).

use std::fs;
use std::io;
use std::path::Path;

use snow::params::DHChoice;
use snow::resolvers::{CryptoResolver, DefaultResolver};
use storj_proto::noise::NoiseProtocol;

/// File name of the raw private key inside the volume directory.
pub const FILE_NAME: &str = "noise.key";

/// `NOISE_IK_25519_CHACHAPOLY_BLAKE2B`. Go's `noise.DefaultProto`.
pub const DEFAULT_PROTOCOL: i32 = NoiseProtocol::NoiseIk25519ChachapolyBlake2b as i32;

/// `NOISE_IK_25519_AESGCM_BLAKE2B`.
pub const AES_PROTOCOL: i32 = NoiseProtocol::NoiseIk25519AesgcmBlake2b as i32;

/// Noise key material could not be generated, read, or written.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The volume or the key file could not be accessed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// The key was the wrong length, or X25519 was unavailable.
    #[error("{0}")]
    Crypto(String),
}

/// Responder static key. The private half is what `NoiseStream::accept` takes.
pub struct Key {
    private: [u8; 32],
    public: [u8; 32],
}

impl Key {
    /// Generates a new X25519 key. Does not touch the disk.
    pub fn generate() -> Result<Self, Error> {
        let pair = snow::Builder::new(noise_params()?)
            .generate_keypair()
            .map_err(|err| Error::Crypto(err.to_string()))?;
        let key = Self::from_private(&pair.private)?;
        // Snow's own public half must match the derivation used on reload.
        if key.public.as_slice() != pair.public.as_slice() {
            return Err(Error::Crypto(
                "derived X25519 public key does not match snow".into(),
            ));
        }
        Ok(key)
    }

    /// Loads `{volume}/noise.key`, or generates one and publishes it.
    ///
    /// The file is mode `0600` on Unix. A second start that loses the create
    /// race reads the key the winner linked, instead of replacing it.
    pub fn load_or_create(volume: &Path) -> Result<Self, Error> {
        fs::create_dir_all(volume)?;
        let path = volume.join(FILE_NAME);
        match read_key(&path) {
            Ok(key) => Ok(key),
            Err(Error::Io(err)) if err.kind() == io::ErrorKind::NotFound => {
                let key = Self::generate()?;
                match crate::secret::publish(volume, &path, key.private()) {
                    Ok(()) => Ok(key),
                    Err(err) if err.kind() == io::ErrorKind::AlreadyExists => read_key(&path),
                    Err(err) => Err(err.into()),
                }
            }
            Err(err) => Err(err),
        }
    }

    /// Raw scalar passed to `NoiseStream::accept`.
    pub fn private(&self) -> &[u8; 32] {
        &self.private
    }

    /// Advertised responder key passed to `NoiseStream::connect`.
    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }

    fn from_private(bytes: &[u8]) -> Result<Self, Error> {
        let private: [u8; 32] = bytes.try_into().map_err(|_| {
            Error::Crypto(format!(
                "noise private key is {} bytes, expected 32",
                bytes.len()
            ))
        })?;
        let public = public_from_private(&private)?;
        Ok(Self { private, public })
    }
}

fn noise_params() -> Result<snow::params::NoiseParams, Error> {
    "Noise_IK_25519_ChaChaPoly_BLAKE2b"
        .parse()
        .map_err(|err: snow::Error| Error::Crypto(err.to_string()))
}

fn public_from_private(private: &[u8; 32]) -> Result<[u8; 32], Error> {
    let mut dh = DefaultResolver
        .resolve_dh(&DHChoice::Curve25519)
        .ok_or_else(|| Error::Crypto("missing X25519".into()))?;
    dh.set(private);
    let bytes = dh.pubkey();
    bytes.try_into().map_err(|_| {
        Error::Crypto(format!(
            "X25519 public key is {} bytes, expected 32",
            bytes.len()
        ))
    })
}

fn read_key(path: &Path) -> Result<Key, Error> {
    let bytes = fs::read(path)?;
    Key::from_private(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn persists_32_bytes_and_reloads_the_same_public_key() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("sn-noise-{nanos}-{}", std::process::id()));
        let first = Key::load_or_create(&dir).expect("generate");
        let bytes = fs::read(dir.join(FILE_NAME)).expect("key file");
        assert_eq!(bytes.as_slice(), first.private().as_slice());
        assert_ne!(first.public(), &[0; 32]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.join(FILE_NAME))
                .expect("meta")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let second = Key::load_or_create(&dir).expect("reload");
        assert_eq!(first.public(), second.public());
        assert_eq!(first.private(), second.private());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_a_truncated_key_instead_of_replacing_it() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("sn-noise-bad-{nanos}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(FILE_NAME), [1u8; 31]).unwrap();
        match Key::load_or_create(&dir) {
            Err(err) => assert!(err.to_string().contains("31"), "{err}"),
            Ok(_) => panic!("truncated key was accepted"),
        }
        assert_eq!(fs::read(dir.join(FILE_NAME)).unwrap().len(), 31);
        let _ = fs::remove_dir_all(&dir);
    }
}
