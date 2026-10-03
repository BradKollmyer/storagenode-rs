//! Create-once secret files on the volume: the identity and the Noise key.

use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Writes `bytes` to a temp file in `volume`, syncs it, then links `path`.
///
/// `rename` would replace a secret the other start already published.
/// `hard_link` fails with [`io::ErrorKind::AlreadyExists`] instead, and the
/// loser reads `path` only after that link exists. The directory entry is
/// synced before return so a crash cannot drop it and mint a new secret.
///
/// The temp file holds the secret. It is removed on every way out, including
/// a failed write or sync.
pub(crate) fn publish(volume: &Path, path: &Path, bytes: &[u8]) -> io::Result<()> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|dur| dur.as_nanos())
        .unwrap_or(0);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("secret");
    let tmp = volume.join(format!(".{name}.{}.{nanos}.tmp", std::process::id()));
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&tmp)?;
    let published = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        // Link, don't rename over a file the other start already published.
        // Sync the directory before dropping the temp name: that name is the
        // other directory entry for the same inode.
        fs::hard_link(&tmp, path)?;
        fs::File::open(volume)?.sync_all()
    })();
    drop(file);
    let _ = fs::remove_file(&tmp);
    published
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_links_once_and_leaves_no_temp_file() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let volume =
            std::env::temp_dir().join(format!("storagenode-secret-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&volume).unwrap();
        let path = volume.join("secret.key");

        publish(&volume, &path, b"first").unwrap();
        let err = publish(&volume, &path, b"second").expect_err("already published");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).unwrap(), b"first");

        // A failed publish must not leave the secret in a temp file either.
        let missing = volume.join("no-such-dir").join("secret.key");
        publish(&volume, &missing, b"third").expect_err("link target directory is missing");
        let names: Vec<_> = fs::read_dir(&volume)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["secret.key"]);
        let _ = fs::remove_dir_all(&volume);
    }
}
