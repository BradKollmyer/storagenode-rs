//! SQLite cache of piece metadata (`pieces.db` on the volume).
//!
//! The bucket is the source of the bytes, the hash, and the order limit.
//! Trash lives only here. A missing or unfinished database is rebuilt from
//! object metadata; every rebuilt row is live. `user_version` stays 0 until
//! that listing finishes, so a restart does not treat a partial file as done.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};

use crate::{Error, Result};

/// How long a trashed piece keeps its object before the chore deletes it.
pub const TRASH_KEEP: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// File name of the index inside the volume directory.
pub const PIECES_DB: &str = "pieces.db";

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS pieces (
    satellite TEXT NOT NULL,
    piece_id TEXT NOT NULL,
    size INTEGER NOT NULL,
    piece_hash BLOB NOT NULL,
    hash_algorithm TEXT NOT NULL,
    order_limit BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    trashed_at INTEGER,
    state TEXT NOT NULL CHECK (state IN ('writing', 'live', 'trash')),
    PRIMARY KEY (satellite, piece_id)
);
CREATE INDEX IF NOT EXISTS pieces_expires ON pieces (expires_at);
CREATE INDEX IF NOT EXISTS pieces_trash ON pieces (trashed_at);
";

/// `PRAGMA user_version` written only after a full prefix listing finishes.
const REBUILD_VERSION: i64 = 1;

/// `sha256` or `blake3`. Both hashes are 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256.
    Sha256,
    /// BLAKE3.
    Blake3,
}

impl HashAlgorithm {
    /// Metadata value stored on the object.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Blake3 => "blake3",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "sha256" => Some(Self::Sha256),
            "blake3" => Some(Self::Blake3),
            _ => None,
        }
    }
}

/// Index state. Trash is a flag on the row, not a second object key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PieceState {
    /// Inserted before the object is committed. Not served.
    Writing,
    /// Readable piece.
    Live,
    /// Hidden from `exists` until restore, or until the chore deletes it.
    Trash,
}

impl PieceState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Writing => "writing",
            Self::Live => "live",
            Self::Trash => "trash",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "writing" => Ok(Self::Writing),
            "live" => Ok(Self::Live),
            "trash" => Ok(Self::Trash),
            _ => Err(Error::Index(format!("unknown piece state {value}"))),
        }
    }
}

/// Fields stored on the object and copied into the index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PieceMeta {
    /// Piece hash, 32 bytes (SHA-256 or BLAKE3).
    pub hash: [u8; 32],
    /// Hash algorithm used for [`Self::hash`].
    pub algorithm: HashAlgorithm,
    /// When the piece was created.
    pub created: SystemTime,
    /// When the piece expires. Absent when the order limit has no expiry.
    pub expires: Option<SystemTime>,
    /// Encoded order limit (the bytes that are base64 on the object).
    pub order_limit: Vec<u8>,
}

/// One index row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PieceInfo {
    /// Satellite that owns the piece.
    pub satellite_id: String,
    /// Piece id.
    pub piece_id: String,
    /// Object size in bytes.
    pub size: u64,
    /// Piece hash.
    pub hash: [u8; 32],
    /// Hash algorithm.
    pub algorithm: HashAlgorithm,
    /// Encoded order limit.
    pub order_limit: Vec<u8>,
    /// Creation time, truncated to milliseconds.
    pub created: SystemTime,
    /// Expiry, truncated to milliseconds.
    pub expires: Option<SystemTime>,
    /// When the piece was trashed. Set only while [`Self::state`] is trash.
    pub trashed_at: Option<SystemTime>,
    /// `writing`, `live`, or `trash`.
    pub state: PieceState,
}

impl PieceInfo {
    pub(crate) fn from_meta(
        satellite_id: &str,
        piece_id: &str,
        size: u64,
        meta: &PieceMeta,
        state: PieceState,
    ) -> Self {
        Self {
            satellite_id: satellite_id.to_owned(),
            piece_id: piece_id.to_owned(),
            size,
            hash: meta.hash,
            algorithm: meta.algorithm,
            order_limit: meta.order_limit.clone(),
            created: meta.created,
            expires: meta.expires,
            trashed_at: None,
            state,
        }
    }
}

/// Configured allocation and index totals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Space {
    /// Configured allocation in bytes.
    pub allocated: u64,
    /// Sum of live piece sizes.
    pub used: u64,
    /// Sum of trashed piece sizes. Not subtracted from [`Self::free`].
    pub trash: u64,
    /// `allocated - used`, or 0 when used is larger.
    pub free: u64,
}

#[derive(Clone)]
pub(crate) struct Index {
    conn: Arc<Mutex<Connection>>,
}

impl Index {
    /// Opens `pieces.db`, creating it and the schema if needed.
    ///
    /// Creating the file is not a finished rebuild. [`Self::rebuild_done`]
    /// stays false until [`Self::mark_rebuild_done`].
    pub(crate) fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|err| Error::Index(format!("create {}: {err}", parent.display())))?;
            }
        }
        let conn = Connection::open(path).map_err(db_err)?;
        // WAL is crash durability for this file. This process takes `conn`
        // for every call, so a reader does not overlap the writer.
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(db_err)?;
        // A foreign lock should fail the call, not park a worker for seconds.
        conn.busy_timeout(Duration::from_millis(250))
            .map_err(db_err)?;
        conn.execute_batch(SCHEMA).map_err(db_err)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// True after a prefix listing has been fully applied.
    ///
    /// `user_version` is 0 on a new file and on a file whose rebuild was
    /// interrupted. File existence is not this bit.
    pub(crate) fn rebuild_done(&self) -> Result<bool> {
        let version = self
            .with(|conn| conn.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0)))?;
        Ok(version >= REBUILD_VERSION)
    }

    /// Records that the listing finished. Not set from the schema itself.
    pub(crate) fn mark_rebuild_done(&self) -> Result<()> {
        // `user_version` does not accept a bound parameter.
        self.with(|conn| conn.pragma_update(None, "user_version", REBUILD_VERSION))
    }

    pub(crate) fn upsert(&self, info: &PieceInfo) -> Result<()> {
        let size = i64::try_from(info.size)
            .map_err(|_| Error::Index("piece size exceeds sqlite integer".into()))?;
        let created = system_to_millis(info.created)?;
        let expires = option_millis(info.expires)?;
        let trashed = option_millis(info.trashed_at)?;
        self.with(|conn| {
            conn.execute(
                "INSERT INTO pieces (
                    satellite, piece_id, size, piece_hash, hash_algorithm, order_limit,
                    created_at, expires_at, trashed_at, state
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                ON CONFLICT(satellite, piece_id) DO UPDATE SET
                    size = excluded.size,
                    piece_hash = excluded.piece_hash,
                    hash_algorithm = excluded.hash_algorithm,
                    order_limit = excluded.order_limit,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at,
                    trashed_at = excluded.trashed_at,
                    state = excluded.state",
                params![
                    info.satellite_id,
                    info.piece_id,
                    size,
                    info.hash.as_slice(),
                    info.algorithm.as_str(),
                    info.order_limit,
                    created,
                    expires,
                    trashed,
                    info.state.as_str(),
                ],
            )
            .map(|_| ())
        })
    }

    pub(crate) fn mark_live(&self, satellite_id: &str, piece_id: &str) -> Result<()> {
        let changed = self.with(|conn| {
            conn.execute(
                "UPDATE pieces SET state = 'live', trashed_at = NULL
                 WHERE satellite = ?1 AND piece_id = ?2 AND state = 'writing'",
                params![satellite_id, piece_id],
            )
        })?;
        if changed == 0 {
            return Err(Error::Index("piece is not in the writing state".into()));
        }
        Ok(())
    }

    pub(crate) fn delete(&self, satellite_id: &str, piece_id: &str) -> Result<()> {
        self.with(|conn| {
            conn.execute(
                "DELETE FROM pieces WHERE satellite = ?1 AND piece_id = ?2",
                params![satellite_id, piece_id],
            )
            .map(|_| ())
        })
    }

    pub(crate) fn get(&self, satellite_id: &str, piece_id: &str) -> Result<Option<PieceInfo>> {
        let raw = self.with(|conn| {
            let mut stmt = conn.prepare(
                "SELECT size, piece_hash, hash_algorithm, order_limit,
                        created_at, expires_at, trashed_at, state
                 FROM pieces WHERE satellite = ?1 AND piece_id = ?2",
            )?;
            stmt.query_row(params![satellite_id, piece_id], |row| {
                Ok(RawRow {
                    size: row.get(0)?,
                    hash: row.get(1)?,
                    algorithm: row.get(2)?,
                    order_limit: row.get(3)?,
                    created_at: row.get(4)?,
                    expires_at: row.get(5)?,
                    trashed_at: row.get(6)?,
                    state: row.get(7)?,
                })
            })
            .optional()
        })?;
        match raw {
            None => Ok(None),
            Some(raw) => raw.into_info(satellite_id, piece_id).map(Some),
        }
    }

    pub(crate) fn exists_live(&self, satellite_id: &str, piece_id: &str) -> Result<bool> {
        self.with(|conn| {
            conn.query_row(
                "SELECT 1 FROM pieces
                 WHERE satellite = ?1 AND piece_id = ?2 AND state = 'live'",
                params![satellite_id, piece_id],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
        })
    }

    /// Marks a live row trash. Already-trash is false and does not move `trashed_at`.
    pub(crate) fn trash(&self, satellite_id: &str, piece_id: &str, at: SystemTime) -> Result<bool> {
        let at = system_to_millis(at)?;
        let changed = self.with(|conn| {
            conn.execute(
                "UPDATE pieces SET state = 'trash', trashed_at = ?3
                 WHERE satellite = ?1 AND piece_id = ?2 AND state = 'live'",
                params![satellite_id, piece_id, at],
            )
        })?;
        Ok(changed > 0)
    }

    pub(crate) fn restore_trash(&self, satellite_id: &str) -> Result<u64> {
        let changed = self.with(|conn| {
            conn.execute(
                "UPDATE pieces SET state = 'live', trashed_at = NULL
                 WHERE satellite = ?1 AND state = 'trash'",
                params![satellite_id],
            )
        })?;
        u64::try_from(changed).map_err(|_| Error::Index("restore count overflow".into()))
    }

    /// `(live, trash)`. `writing` is omitted, so an in-flight overwrite drops
    /// the previous size from `live` until that row is live again.
    pub(crate) fn sums(&self) -> Result<(u64, u64)> {
        let (used, trash) = self.with(|conn| {
            conn.query_row(
                "SELECT
                    COALESCE(SUM(CASE WHEN state = 'live' THEN size ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN state = 'trash' THEN size ELSE 0 END), 0)
                 FROM pieces",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
        })?;
        let used =
            u64::try_from(used).map_err(|_| Error::Index("negative live size sum".into()))?;
        let trash =
            u64::try_from(trash).map_err(|_| Error::Index("negative trash size sum".into()))?;
        Ok((used, trash))
    }

    pub(crate) fn expired(&self, now: SystemTime) -> Result<Vec<(String, String)>> {
        let now = system_to_millis(now)?;
        self.keys(
            "SELECT satellite, piece_id FROM pieces
             WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            now,
        )
    }

    pub(crate) fn is_expired(
        &self,
        satellite_id: &str,
        piece_id: &str,
        now: SystemTime,
    ) -> Result<bool> {
        let now = system_to_millis(now)?;
        self.with(|conn| {
            conn.query_row(
                "SELECT 1 FROM pieces
                 WHERE satellite = ?1 AND piece_id = ?2
                   AND expires_at IS NOT NULL AND expires_at <= ?3",
                params![satellite_id, piece_id, now],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
        })
    }

    pub(crate) fn trash_due(&self, now: SystemTime) -> Result<Vec<(String, String)>> {
        let Some(cutoff) = trash_cutoff(now) else {
            return Ok(Vec::new());
        };
        self.keys(
            "SELECT satellite, piece_id FROM pieces
             WHERE state = 'trash' AND trashed_at IS NOT NULL AND trashed_at <= ?1",
            cutoff,
        )
    }

    pub(crate) fn is_trash_due(
        &self,
        satellite_id: &str,
        piece_id: &str,
        now: SystemTime,
    ) -> Result<bool> {
        let Some(cutoff) = trash_cutoff(now) else {
            return Ok(false);
        };
        self.with(|conn| {
            conn.query_row(
                "SELECT 1 FROM pieces
                 WHERE satellite = ?1 AND piece_id = ?2
                   AND state = 'trash' AND trashed_at IS NOT NULL AND trashed_at <= ?3",
                params![satellite_id, piece_id, cutoff],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
        })
    }

    fn keys(&self, sql: &str, millis: i64) -> Result<Vec<(String, String)>> {
        self.with(|conn| {
            let mut stmt = conn.prepare(sql)?;
            let rows = stmt.query_map(params![millis], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            Ok(out)
        })
    }

    fn with<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| Error::Index("lock poisoned".into()))?;
        f(&conn).map_err(db_err)
    }
}

struct RawRow {
    size: i64,
    hash: Vec<u8>,
    algorithm: String,
    order_limit: Vec<u8>,
    created_at: i64,
    expires_at: Option<i64>,
    trashed_at: Option<i64>,
    state: String,
}

impl RawRow {
    fn into_info(self, satellite_id: &str, piece_id: &str) -> Result<PieceInfo> {
        let size =
            u64::try_from(self.size).map_err(|_| Error::Index("negative piece size".into()))?;
        let hash: [u8; 32] = self
            .hash
            .try_into()
            .map_err(|_| Error::Index("piece hash is not 32 bytes".into()))?;
        let algorithm = HashAlgorithm::parse(&self.algorithm)
            .ok_or_else(|| Error::Index(format!("unknown hash algorithm {}", self.algorithm)))?;
        Ok(PieceInfo {
            satellite_id: satellite_id.to_owned(),
            piece_id: piece_id.to_owned(),
            size,
            hash,
            algorithm,
            order_limit: self.order_limit,
            created: millis_to_system(self.created_at)?,
            expires: self.expires_at.map(millis_to_system).transpose()?,
            trashed_at: self.trashed_at.map(millis_to_system).transpose()?,
            state: PieceState::parse(&self.state)?,
        })
    }
}

fn db_err(err: rusqlite::Error) -> Error {
    Error::Index(err.to_string())
}

pub(crate) fn system_to_millis(time: SystemTime) -> Result<i64> {
    let dur = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Metadata("timestamp is before the unix epoch".into()))?;
    let millis = dur.as_millis();
    i64::try_from(millis).map_err(|_| Error::Metadata("timestamp overflow".into()))
}

fn option_millis(time: Option<SystemTime>) -> Result<Option<i64>> {
    time.map(system_to_millis).transpose()
}

fn millis_to_system(millis: i64) -> Result<SystemTime> {
    let millis = u64::try_from(millis).map_err(|_| Error::Index("negative timestamp".into()))?;
    UNIX_EPOCH
        .checked_add(Duration::from_millis(millis))
        .ok_or_else(|| Error::Index("timestamp overflow".into()))
}

fn trash_cutoff(now: SystemTime) -> Option<i64> {
    let cutoff = now.checked_sub(TRASH_KEEP).unwrap_or(UNIX_EPOCH);
    system_to_millis(cutoff).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> (tempfile_dir::Dir, std::path::PathBuf) {
        let dir = tempfile_dir::Dir::new();
        let path = dir.path().join(PIECES_DB);
        (dir, path)
    }

    fn meta(expires: Option<SystemTime>) -> PieceMeta {
        PieceMeta {
            hash: [0x11; 32],
            algorithm: HashAlgorithm::Sha256,
            created: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            expires,
            order_limit: b"limit".to_vec(),
        }
    }

    #[test]
    fn wal_round_trip_trash_and_expiry() {
        let (_dir, path) = temp_db();
        let index = Index::open(&path).unwrap();
        assert!(!index.rebuild_done().unwrap());
        let mode: String = index
            .with(|conn| conn.query_row("PRAGMA journal_mode", [], |row| row.get(0)))
            .unwrap();
        assert_eq!(mode.to_ascii_lowercase(), "wal");

        let created = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let info = PieceInfo::from_meta("sat", "piece", 10, &meta(None), PieceState::Writing);
        index.upsert(&info).unwrap();
        assert!(!index.exists_live("sat", "piece").unwrap());
        index.mark_live("sat", "piece").unwrap();
        assert!(index.exists_live("sat", "piece").unwrap());
        let got = index.get("sat", "piece").unwrap().unwrap();
        assert_eq!(got.state, PieceState::Live);
        assert_eq!(got.created, created);
        assert_eq!(got.hash, [0x11; 32]);
        assert_eq!(got.order_limit, b"limit");
        assert_eq!(index.sums().unwrap(), (10, 0));

        let trashed = created + Duration::from_secs(50);
        assert!(index.trash("sat", "piece", trashed).unwrap());
        assert!(
            !index
                .trash("sat", "piece", trashed + Duration::from_secs(5))
                .unwrap()
        );
        let got = index.get("sat", "piece").unwrap().unwrap();
        assert_eq!(got.state, PieceState::Trash);
        assert_eq!(got.trashed_at, Some(trashed));
        assert_eq!(index.sums().unwrap(), (0, 10));
        assert!(!index.exists_live("sat", "piece").unwrap());

        assert_eq!(index.restore_trash("other").unwrap(), 0);
        assert_eq!(index.restore_trash("sat").unwrap(), 1);
        assert!(index.exists_live("sat", "piece").unwrap());

        let expires = created + Duration::from_secs(10);
        let expiring =
            PieceInfo::from_meta("sat", "old", 4, &meta(Some(expires)), PieceState::Live);
        index.upsert(&expiring).unwrap();
        assert!(
            index
                .expired(expires - Duration::from_secs(1))
                .unwrap()
                .is_empty()
        );
        let due = index.expired(expires).unwrap();
        assert_eq!(due, vec![("sat".to_owned(), "old".to_owned())]);
        assert!(index.is_expired("sat", "old", expires).unwrap());
        assert!(!index.is_expired("sat", "piece", expires).unwrap());

        assert!(!index.rebuild_done().unwrap());
        index.mark_rebuild_done().unwrap();
        assert!(index.rebuild_done().unwrap());
        drop(index);
        let index = Index::open(&path).unwrap();
        assert!(index.rebuild_done().unwrap());
        assert!(index.is_expired("sat", "old", expires).unwrap());
    }

    /// Tiny temp dir that deletes itself. Avoids a dev-dependency for one test.
    mod tempfile_dir {
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};

        static SEQ: AtomicU64 = AtomicU64::new(0);

        pub struct Dir(PathBuf);

        impl Dir {
            pub fn new() -> Self {
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos();
                let seq = SEQ.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "s3store-index-{}-{nanos}-{seq}",
                    std::process::id()
                ));
                std::fs::create_dir_all(&path).expect("temp");
                Self(path)
            }

            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }
}
