//! SQLite cache of piece metadata (`pieces.db` on the volume).
//!
//! The bucket is the source of the bytes, the hash, and the order limit.
//! Trash lives only here. A missing or unfinished database is rebuilt from
//! object metadata; every rebuilt row is live. `user_version` stays 0 until
//! that listing finishes, so a restart does not treat a partial file as done.
//! Bandwidth orders, the daily transfer counter, and the last check-in
//! summary live in the same file. A second database would not survive the
//! volume the pieces already use.

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
    hash_signature BLOB NOT NULL,
    hash_ts_seconds INTEGER,
    hash_ts_nanos INTEGER,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    trashed_at INTEGER,
    state TEXT NOT NULL CHECK (state IN ('writing', 'live', 'trash')),
    PRIMARY KEY (satellite, piece_id)
);
CREATE INDEX IF NOT EXISTS pieces_expires ON pieces (expires_at);
CREATE INDEX IF NOT EXISTS pieces_trash ON pieces (trashed_at);

CREATE TABLE IF NOT EXISTS orders (
    satellite TEXT NOT NULL,
    serial BLOB NOT NULL,
    window_start INTEGER NOT NULL,
    limit_blob BLOB NOT NULL,
    order_blob BLOB NOT NULL,
    amount INTEGER NOT NULL,
    status INTEGER,
    archived_at INTEGER,
    PRIMARY KEY (satellite, serial)
);
CREATE INDEX IF NOT EXISTS orders_window ON orders (satellite, window_start, status);

CREATE TABLE IF NOT EXISTS graceful_exits (
    satellite TEXT PRIMARY KEY,
    live_bytes INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'failed', 'completed')),
    reason TEXT,
    message BLOB,
    pieces_deleted INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS bandwidth_daily (
    satellite TEXT NOT NULL,
    day INTEGER NOT NULL,
    put INTEGER NOT NULL DEFAULT 0,
    get INTEGER NOT NULL DEFAULT 0,
    get_audit INTEGER NOT NULL DEFAULT 0,
    get_repair INTEGER NOT NULL DEFAULT 0,
    put_repair INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (satellite, day)
);

CREATE TABLE IF NOT EXISTS checkins (
    satellite TEXT PRIMARY KEY,
    checked_in_at INTEGER NOT NULL,
    quic_ok INTEGER NOT NULL
);
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
    /// Uplink `PieceHash` signature. Repair reads this back unchanged.
    pub hash_signature: Vec<u8>,
    /// Original protobuf timestamp (`seconds`, `nanos`), not [`Self::created`].
    ///
    /// `None` when the uplink hash omitted the field. Milliseconds in
    /// `created` are not this value.
    pub hash_timestamp: Option<(i64, i32)>,
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
    /// Uplink `PieceHash` signature.
    pub hash_signature: Vec<u8>,
    /// Original protobuf timestamp (`seconds`, `nanos`).
    pub hash_timestamp: Option<(i64, i32)>,
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
            hash_signature: meta.hash_signature.clone(),
            hash_timestamp: meta.hash_timestamp,
            created: meta.created,
            expires: meta.expires,
            trashed_at: None,
            state,
        }
    }
}

/// Pending, failed, or completed graceful exit for one satellite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    /// `exit-satellite` recorded the row. The chore may dial.
    Pending,
    /// The satellite sent `ExitFailed`. Pieces stay. Do not dial again.
    Failed,
    /// The satellite sent `ExitCompleted`. The receipt is [`ExitRow::message`].
    Completed,
}

impl ExitStatus {
    /// Value stored in `graceful_exits.status` and printed by `exit-status`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Failed => "failed",
            Self::Completed => "completed",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "failed" => Ok(Self::Failed),
            "completed" => Ok(Self::Completed),
            _ => Err(Error::Index(format!("unknown exit status {value}"))),
        }
    }
}

/// One graceful-exit row. `live_bytes` is the live sum at request time.
///
/// [`Self::message`] is the encoded `ExitFailed` or `ExitCompleted`. It stays
/// after a later object delete fails. [`Self::pieces_deleted`] is set only
/// once that delete finishes, so a restart can retry it without dialing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitRow {
    /// Satellite id, the same string as `pieces.satellite`.
    pub satellite_id: String,
    /// Live piece bytes when the exit was requested. Trash is not included.
    pub live_bytes: u64,
    /// Pending, failed, or completed.
    pub status: ExitStatus,
    /// `ExitFailed.Reason` name. Empty unless [`Self::status`] is failed.
    pub reason: String,
    /// Encoded failure or the completion receipt. Empty while pending.
    pub message: Vec<u8>,
    /// The satellite prefix and its rows were deleted after the receipt.
    pub pieces_deleted: bool,
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

/// One finished transfer, split the way the dashboard rollup is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BandwidthKind {
    /// Uplink upload.
    Put,
    /// Uplink download.
    Get,
    /// Audit download.
    GetAudit,
    /// Repair download.
    GetRepair,
    /// Repair upload.
    PutRepair,
}

/// Bandwidth for one satellite on one UTC day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BandwidthDay {
    /// UTC midnight, unix milliseconds.
    pub day_millis: i64,
    /// PUT bytes.
    pub put: u64,
    /// GET bytes.
    pub get: u64,
    /// GET_AUDIT bytes.
    pub get_audit: u64,
    /// GET_REPAIR bytes.
    pub get_repair: u64,
    /// PUT_REPAIR bytes.
    pub put_repair: u64,
}

impl BandwidthDay {
    /// Every action, including audit and repair.
    pub fn total(self) -> u64 {
        self.put
            .saturating_add(self.get)
            .saturating_add(self.get_audit)
            .saturating_add(self.get_repair)
            .saturating_add(self.put_repair)
    }

    /// GET, GET_AUDIT, and GET_REPAIR.
    pub fn egress(self) -> u64 {
        self.get
            .saturating_add(self.get_audit)
            .saturating_add(self.get_repair)
    }

    /// PUT and PUT_REPAIR.
    pub fn ingress(self) -> u64 {
        self.put.saturating_add(self.put_repair)
    }
}

/// Last successful check-in for one satellite.
///
/// Disqualified, suspended, and vetted times are not stored. The check-in
/// response does not carry them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckInRow {
    /// Satellite id, the same string as `pieces.satellite`.
    pub satellite_id: String,
    /// When the check-in was accepted.
    pub checked_in_at: SystemTime,
    /// `CheckInResponse.ping_node_success_quic`.
    pub quic_ok: bool,
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
        // A database created before the hash signature columns still opens.
        // New files already have the columns from SCHEMA.
        migrate(&conn).map_err(db_err)?;
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
                    hash_signature, hash_ts_seconds, hash_ts_nanos,
                    created_at, expires_at, trashed_at, state
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                ON CONFLICT(satellite, piece_id) DO UPDATE SET
                    size = excluded.size,
                    piece_hash = excluded.piece_hash,
                    hash_algorithm = excluded.hash_algorithm,
                    order_limit = excluded.order_limit,
                    hash_signature = excluded.hash_signature,
                    hash_ts_seconds = excluded.hash_ts_seconds,
                    hash_ts_nanos = excluded.hash_ts_nanos,
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
                    info.hash_signature,
                    info.hash_timestamp.map(|stamp| stamp.0),
                    info.hash_timestamp.map(|stamp| stamp.1),
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
                        hash_signature, hash_ts_seconds, hash_ts_nanos,
                        created_at, expires_at, trashed_at, state
                 FROM pieces WHERE satellite = ?1 AND piece_id = ?2",
            )?;
            stmt.query_row(params![satellite_id, piece_id], |row| {
                Ok(RawRow {
                    size: row.get(0)?,
                    hash: row.get(1)?,
                    algorithm: row.get(2)?,
                    order_limit: row.get(3)?,
                    hash_signature: row.get(4)?,
                    hash_ts_seconds: row.get(5)?,
                    hash_ts_nanos: row.get(6)?,
                    created_at: row.get(7)?,
                    expires_at: row.get(8)?,
                    trashed_at: row.get(9)?,
                    state: row.get(10)?,
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

    /// Live piece ids for one satellite created strictly before `before`.
    ///
    /// `writing` and `trash` are omitted. A row whose `created_at` equals the
    /// cutoff stays: the filter was built at that instant and does not list it.
    pub(crate) fn live_before(
        &self,
        satellite_id: &str,
        before: SystemTime,
    ) -> Result<Vec<String>> {
        let before = system_to_millis(before)?;
        self.with(|conn| {
            let mut stmt = conn.prepare(
                "SELECT piece_id FROM pieces
                 WHERE satellite = ?1 AND state = 'live' AND created_at < ?2",
            )?;
            let rows =
                stmt.query_map(params![satellite_id, before], |row| row.get::<_, String>(0))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            Ok(out)
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
        with_conn(&self.conn, f)
    }

    pub(crate) fn orders(&self) -> OrderRows {
        OrderRows {
            conn: Arc::clone(&self.conn),
        }
    }

    /// Records a pending exit and the live bytes for `satellite_id` right now.
    ///
    /// A second request is an error so a stored failure or receipt is not
    /// replaced. Failed precondition deletes the row; that satellite can be
    /// requested again.
    pub(crate) fn begin_exit(&self, satellite_id: &str) -> Result<ExitRow> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| Error::Index("lock poisoned".into()))?;
        let exists: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM graceful_exits WHERE satellite = ?1",
                params![satellite_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_err)?;
        if exists.is_some() {
            return Err(Error::Index(format!(
                "graceful exit for {satellite_id} is already recorded"
            )));
        }
        let live: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(size), 0) FROM pieces
                 WHERE satellite = ?1 AND state = 'live'",
                params![satellite_id],
                |row| row.get(0),
            )
            .map_err(db_err)?;
        let live_bytes =
            u64::try_from(live).map_err(|_| Error::Index("negative live size sum".into()))?;
        conn.execute(
            "INSERT INTO graceful_exits (
                satellite, live_bytes, status, reason, message, pieces_deleted
             ) VALUES (?1, ?2, 'pending', NULL, NULL, 0)",
            params![satellite_id, live],
        )
        .map_err(db_err)?;
        Ok(ExitRow {
            satellite_id: satellite_id.to_owned(),
            live_bytes,
            status: ExitStatus::Pending,
            reason: String::new(),
            message: Vec::new(),
            pieces_deleted: false,
        })
    }

    pub(crate) fn exit_row(&self, satellite_id: &str) -> Result<Option<ExitRow>> {
        let raw = self.with(|conn| {
            conn.query_row(
                "SELECT satellite, live_bytes, status, reason, message, pieces_deleted
                 FROM graceful_exits WHERE satellite = ?1",
                params![satellite_id],
                RawExit::read,
            )
            .optional()
        })?;
        raw.map(RawExit::into_row).transpose()
    }

    pub(crate) fn exit_rows(&self) -> Result<Vec<ExitRow>> {
        let raw = self.with(|conn| {
            let mut stmt = conn.prepare(
                "SELECT satellite, live_bytes, status, reason, message, pieces_deleted
                 FROM graceful_exits ORDER BY satellite",
            )?;
            let rows = stmt.query_map([], RawExit::read)?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            Ok(out)
        })?;
        raw.into_iter().map(RawExit::into_row).collect()
    }

    /// Drops a pending row. A stored failure or receipt is left in place.
    pub(crate) fn cancel_exit(&self, satellite_id: &str) -> Result<()> {
        self.with(|conn| {
            conn.execute(
                "DELETE FROM graceful_exits WHERE satellite = ?1 AND status = 'pending'",
                params![satellite_id],
            )
            .map(|_| ())
        })
    }

    /// Stores the reason name and the encoded `ExitFailed`. Does not delete pieces.
    pub(crate) fn fail_exit(&self, satellite_id: &str, reason: &str, message: &[u8]) -> Result<()> {
        let changed = self.with(|conn| {
            conn.execute(
                "UPDATE graceful_exits
                 SET status = 'failed', reason = ?2, message = ?3
                 WHERE satellite = ?1 AND status = 'pending'",
                params![satellite_id, reason, message],
            )
        })?;
        if changed == 0 {
            return Err(Error::Index(format!(
                "no pending graceful exit for {satellite_id}"
            )));
        }
        Ok(())
    }

    /// Stores the receipt. A row that is already completed keeps its receipt.
    pub(crate) fn complete_exit(&self, satellite_id: &str, receipt: &[u8]) -> Result<()> {
        match self.exit_row(satellite_id)? {
            Some(row) if row.status == ExitStatus::Completed => Ok(()),
            Some(row) if row.status == ExitStatus::Pending => {
                let changed = self.with(|conn| {
                    conn.execute(
                        "UPDATE graceful_exits
                         SET status = 'completed', reason = NULL, message = ?2, pieces_deleted = 0
                         WHERE satellite = ?1 AND status = 'pending'",
                        params![satellite_id, receipt],
                    )
                })?;
                if changed == 0 {
                    return Err(Error::Index(format!(
                        "no pending graceful exit for {satellite_id}"
                    )));
                }
                Ok(())
            }
            _ => Err(Error::Index(format!(
                "no pending graceful exit for {satellite_id}"
            ))),
        }
    }

    /// The delete finished. The receipt column is not touched.
    pub(crate) fn mark_exit_deleted(&self, satellite_id: &str) -> Result<()> {
        let changed = self.with(|conn| {
            conn.execute(
                "UPDATE graceful_exits SET pieces_deleted = 1
                 WHERE satellite = ?1 AND status = 'completed'",
                params![satellite_id],
            )
        })?;
        if changed == 0 {
            return Err(Error::Index(format!(
                "no completed graceful exit for {satellite_id}"
            )));
        }
        Ok(())
    }

    /// Every piece id for one satellite, including `writing` and `trash`.
    pub(crate) fn piece_ids(&self, satellite_id: &str) -> Result<Vec<String>> {
        self.with(|conn| {
            let mut stmt = conn.prepare("SELECT piece_id FROM pieces WHERE satellite = ?1")?;
            let rows = stmt.query_map(params![satellite_id], |row| row.get::<_, String>(0))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            Ok(out)
        })
    }

    /// Adds `bytes` to the UTC day of `at`. Zero bytes are not stored.
    pub(crate) fn add_bandwidth(
        &self,
        satellite_id: &str,
        kind: BandwidthKind,
        bytes: u64,
        at: SystemTime,
    ) -> Result<()> {
        if bytes == 0 {
            return Ok(());
        }
        let bytes = i64::try_from(bytes)
            .map_err(|_| Error::Index("bandwidth byte count overflows".into()))?;
        let day = day_millis(at)?;
        let (put, get, get_audit, get_repair, put_repair) = match kind {
            BandwidthKind::Put => (bytes, 0, 0, 0, 0),
            BandwidthKind::Get => (0, bytes, 0, 0, 0),
            BandwidthKind::GetAudit => (0, 0, bytes, 0, 0),
            BandwidthKind::GetRepair => (0, 0, 0, bytes, 0),
            BandwidthKind::PutRepair => (0, 0, 0, 0, bytes),
        };
        self.with(|conn| {
            conn.execute(
                "INSERT INTO bandwidth_daily (
                    satellite, day, put, get, get_audit, get_repair, put_repair
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(satellite, day) DO UPDATE SET
                    put = put + excluded.put,
                    get = get + excluded.get,
                    get_audit = get_audit + excluded.get_audit,
                    get_repair = get_repair + excluded.get_repair,
                    put_repair = put_repair + excluded.put_repair",
                params![
                    satellite_id,
                    day,
                    put,
                    get,
                    get_audit,
                    get_repair,
                    put_repair
                ],
            )
        })?;
        Ok(())
    }

    /// Rows for the UTC month containing `now`, oldest day first.
    ///
    /// `satellite_id` `None` sums every satellite into one row per day.
    pub(crate) fn bandwidth_days(
        &self,
        satellite_id: Option<&str>,
        now: SystemTime,
    ) -> Result<Vec<BandwidthDay>> {
        let (start, end) = month_window(now)?;
        self.with(|conn| {
            let mut stmt = conn.prepare(
                "SELECT day,
                        COALESCE(SUM(put), 0),
                        COALESCE(SUM(get), 0),
                        COALESCE(SUM(get_audit), 0),
                        COALESCE(SUM(get_repair), 0),
                        COALESCE(SUM(put_repair), 0)
                 FROM bandwidth_daily
                 WHERE day >= ?1 AND day < ?2 AND (?3 IS NULL OR satellite = ?3)
                 GROUP BY day
                 ORDER BY day",
            )?;
            let rows = stmt.query_map(params![start, end, satellite_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            Ok(out)
        })?
        .into_iter()
        .map(|(day, put, get, audit, repair, put_repair)| {
            Ok(BandwidthDay {
                day_millis: day,
                put: nonneg(put, "put bandwidth")?,
                get: nonneg(get, "get bandwidth")?,
                get_audit: nonneg(audit, "audit bandwidth")?,
                get_repair: nonneg(repair, "repair get bandwidth")?,
                put_repair: nonneg(put_repair, "repair put bandwidth")?,
            })
        })
        .collect()
    }

    /// Live piece bytes. `None` is every satellite. `writing` and trash are omitted.
    pub(crate) fn live_bytes(&self, satellite_id: Option<&str>) -> Result<u64> {
        let total = self.with(|conn| {
            conn.query_row(
                "SELECT COALESCE(SUM(size), 0) FROM pieces
                 WHERE state = 'live' AND (?1 IS NULL OR satellite = ?1)",
                params![satellite_id],
                |row| row.get::<_, i64>(0),
            )
        })?;
        nonneg(total, "live size sum")
    }

    /// Replaces the stored summary for `row.satellite_id`.
    pub(crate) fn record_check_in(&self, row: &CheckInRow) -> Result<()> {
        let at = system_to_millis(row.checked_in_at)?;
        self.with(|conn| {
            conn.execute(
                "INSERT INTO checkins (satellite, checked_in_at, quic_ok)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(satellite) DO UPDATE SET
                    checked_in_at = excluded.checked_in_at,
                    quic_ok = excluded.quic_ok",
                params![row.satellite_id, at, i64::from(row.quic_ok)],
            )
        })?;
        Ok(())
    }

    /// Every stored check-in, ordered by satellite id.
    pub(crate) fn check_ins(&self) -> Result<Vec<CheckInRow>> {
        let rows = self.with(|conn| {
            let mut stmt = conn.prepare(
                "SELECT satellite, checked_in_at, quic_ok
                 FROM checkins
                 ORDER BY satellite",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(CheckInStored {
                    satellite_id: row.get(0)?,
                    checked_in_at: row.get(1)?,
                    quic_ok: row.get(2)?,
                })
            })?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            Ok(out)
        })?;
        rows.into_iter().map(CheckInStored::into_row).collect()
    }
}

fn with_conn<T>(
    conn: &Mutex<Connection>,
    f: impl FnOnce(&Connection) -> rusqlite::Result<T>,
) -> Result<T> {
    let conn = conn
        .lock()
        .map_err(|_| Error::Index("lock poisoned".into()))?;
    f(&conn).map_err(db_err)
}

/// One bandwidth order kept for settlement. `status` is unset until the
/// satellite accepts or rejects the window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredOrder {
    /// Satellite id, the same text as a piece row.
    pub satellite: String,
    /// Uplink serial number.
    pub serial: Vec<u8>,
    /// UTC hour of `OrderCreation`, as unix seconds.
    pub window_start: i64,
    /// Encoded order limit.
    pub limit: Vec<u8>,
    /// Encoded uplink order.
    pub order: Vec<u8>,
    /// Signed amount. Only a larger amount replaces an unsent row.
    pub amount: i64,
}

/// `status` of one serial. Absent when the row was never saved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredOrderStatus {
    /// `None` while unsent. `Some(0)` accepted, `Some(1)` rejected.
    pub status: Option<i32>,
    /// Signed amount stored for the serial.
    pub amount: i64,
}

/// Orders table in `pieces.db`. Cheap to clone: it shares the index connection.
#[derive(Clone)]
pub struct OrderRows {
    conn: Arc<Mutex<Connection>>,
}

impl OrderRows {
    /// Inserts the order, or replaces an unsent row when `amount` is larger.
    ///
    /// An archived serial is left alone. Resubmitting it would be a second
    /// window for a serial the satellite already answered.
    pub fn save(&self, order: &StoredOrder) -> Result<()> {
        self.with(|conn| {
            conn.execute(
                "INSERT INTO orders (
                    satellite, serial, window_start, limit_blob, order_blob, amount
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(satellite, serial) DO UPDATE SET
                    window_start = excluded.window_start,
                    limit_blob = excluded.limit_blob,
                    order_blob = excluded.order_blob,
                    amount = excluded.amount
                 WHERE orders.status IS NULL AND excluded.amount > orders.amount",
                params![
                    order.satellite,
                    order.serial,
                    order.window_start,
                    order.limit,
                    order.order,
                    order.amount,
                ],
            )?;
            Ok(())
        })
    }

    /// Unsent orders for one satellite hour, oldest serial first.
    pub fn window(&self, satellite: &str, window_start: i64) -> Result<Vec<StoredOrder>> {
        self.with(|conn| {
            let mut stmt = conn.prepare(
                "SELECT serial, limit_blob, order_blob, amount
                 FROM orders
                 WHERE status IS NULL AND satellite = ?1 AND window_start = ?2
                 ORDER BY serial",
            )?;
            let rows = stmt.query_map(params![satellite, window_start], |row| {
                Ok(StoredOrder {
                    satellite: satellite.to_owned(),
                    serial: row.get(0)?,
                    window_start,
                    limit: row.get(1)?,
                    order: row.get(2)?,
                    amount: row.get(3)?,
                })
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        })
    }

    /// One closed-hour candidate per satellite. The caller drops hours that
    /// are still inside the grace period.
    pub fn unsent_windows(&self) -> Result<Vec<(String, i64)>> {
        self.with(|conn| {
            let mut stmt = conn.prepare(
                "SELECT DISTINCT satellite, window_start
                 FROM orders
                 WHERE status IS NULL
                 ORDER BY window_start, satellite",
            )?;
            let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        })
    }

    /// Marks one unsent serial. A serial that is already archived is unchanged.
    pub fn archive(
        &self,
        satellite: &str,
        serial: &[u8],
        status: i32,
        at: SystemTime,
    ) -> Result<()> {
        let at = system_to_millis(at)?;
        self.with(|conn| {
            conn.execute(
                "UPDATE orders
                 SET status = ?1, archived_at = ?2
                 WHERE satellite = ?3 AND serial = ?4 AND status IS NULL",
                params![status, at, satellite, serial],
            )?;
            Ok(())
        })
    }

    /// Drops archived rows strictly older than `before`.
    pub fn delete_archived_before(&self, before: SystemTime) -> Result<u64> {
        let before = system_to_millis(before)?;
        self.with(|conn| {
            let n = conn.execute(
                "DELETE FROM orders
                 WHERE status IS NOT NULL AND archived_at IS NOT NULL AND archived_at < ?1",
                params![before],
            )?;
            Ok(u64::try_from(n).unwrap_or(0))
        })
    }

    /// `Ok(None)` when this serial has no row.
    pub fn status(&self, satellite: &str, serial: &[u8]) -> Result<Option<StoredOrderStatus>> {
        self.with(|conn| {
            conn.query_row(
                "SELECT status, amount FROM orders WHERE satellite = ?1 AND serial = ?2",
                params![satellite, serial],
                |row| {
                    Ok(StoredOrderStatus {
                        status: row.get(0)?,
                        amount: row.get(1)?,
                    })
                },
            )
            .optional()
        })
    }

    fn with<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> Result<T> {
        with_conn(&self.conn, f)
    }
}

struct RawExit {
    satellite: String,
    live_bytes: i64,
    status: String,
    reason: Option<String>,
    message: Option<Vec<u8>>,
    pieces_deleted: i64,
}

impl RawExit {
    fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            satellite: row.get(0)?,
            live_bytes: row.get(1)?,
            status: row.get(2)?,
            reason: row.get(3)?,
            message: row.get(4)?,
            pieces_deleted: row.get(5)?,
        })
    }

    fn into_row(self) -> Result<ExitRow> {
        let live_bytes = u64::try_from(self.live_bytes)
            .map_err(|_| Error::Index("negative exit size".into()))?;
        Ok(ExitRow {
            satellite_id: self.satellite,
            live_bytes,
            status: ExitStatus::parse(&self.status)?,
            reason: self.reason.unwrap_or_default(),
            message: self.message.unwrap_or_default(),
            pieces_deleted: self.pieces_deleted != 0,
        })
    }
}

struct RawRow {
    size: i64,
    hash: Vec<u8>,
    algorithm: String,
    order_limit: Vec<u8>,
    hash_signature: Vec<u8>,
    hash_ts_seconds: Option<i64>,
    hash_ts_nanos: Option<i32>,
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
        let hash_timestamp = match (self.hash_ts_seconds, self.hash_ts_nanos) {
            (None, None) => None,
            (Some(seconds), Some(nanos)) => Some((seconds, nanos)),
            _ => {
                return Err(Error::Index(
                    "piece hash timestamp is missing seconds or nanos".into(),
                ));
            }
        };
        Ok(PieceInfo {
            satellite_id: satellite_id.to_owned(),
            piece_id: piece_id.to_owned(),
            size,
            hash,
            algorithm,
            order_limit: self.order_limit,
            hash_signature: self.hash_signature,
            hash_timestamp,
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

fn nonneg(value: i64, what: &str) -> Result<u64> {
    u64::try_from(value).map_err(|_| Error::Index(format!("negative {what}")))
}

struct CheckInStored {
    satellite_id: String,
    checked_in_at: i64,
    quic_ok: i64,
}

impl CheckInStored {
    fn into_row(self) -> Result<CheckInRow> {
        Ok(CheckInRow {
            satellite_id: self.satellite_id,
            checked_in_at: millis_to_system(self.checked_in_at)?,
            quic_ok: self.quic_ok != 0,
        })
    }
}

/// UTC midnight of `at`, as unix milliseconds.
fn day_millis(at: SystemTime) -> Result<i64> {
    let millis = system_to_millis(at)?;
    Ok(millis.div_euclid(86_400_000) * 86_400_000)
}

/// `[start, end)` unix milliseconds of the UTC month that contains `now`.
fn month_window(now: SystemTime) -> Result<(i64, i64)> {
    let millis = system_to_millis(now)?;
    let secs = millis.div_euclid(1_000);
    let dt = time::OffsetDateTime::from_unix_timestamp(secs)
        .map_err(|err| Error::Index(err.to_string()))?;
    let start_date = dt
        .date()
        .replace_day(1)
        .map_err(|err| Error::Index(err.to_string()))?;
    let next = start_date
        .checked_add(time::Duration::days(31))
        .ok_or_else(|| Error::Index("month overflow".into()))?
        .replace_day(1)
        .map_err(|err| Error::Index(err.to_string()))?;
    let start = start_date
        .midnight()
        .assume_utc()
        .unix_timestamp()
        .checked_mul(1_000)
        .ok_or_else(|| Error::Index("month overflow".into()))?;
    let end = next
        .midnight()
        .assume_utc()
        .unix_timestamp()
        .checked_mul(1_000)
        .ok_or_else(|| Error::Index("month overflow".into()))?;
    Ok((start, end))
}

/// Adds piece columns that predate this schema, and drops check-in reputation
/// columns this process does not store.
fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(pieces)")?;
    let names = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !names.iter().any(|name| name == "hash_signature") {
        conn.execute(
            "ALTER TABLE pieces ADD COLUMN hash_signature BLOB NOT NULL DEFAULT X''",
            [],
        )?;
    }
    if !names.iter().any(|name| name == "hash_ts_seconds") {
        conn.execute("ALTER TABLE pieces ADD COLUMN hash_ts_seconds INTEGER", [])?;
    }
    if !names.iter().any(|name| name == "hash_ts_nanos") {
        conn.execute("ALTER TABLE pieces ADD COLUMN hash_ts_nanos INTEGER", [])?;
    }
    drop_checkin_reputation(conn)?;
    Ok(())
}

/// Older files stored these as NULL. Drop them so they are not leftover state.
fn drop_checkin_reputation(conn: &Connection) -> rusqlite::Result<()> {
    let names = {
        let mut stmt = conn.prepare("PRAGMA table_info(checkins)")?;
        stmt.query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    if names.iter().any(|name| name == "disqualified_at") {
        conn.execute("ALTER TABLE checkins DROP COLUMN disqualified_at", [])?;
    }
    if names.iter().any(|name| name == "suspended_at") {
        conn.execute("ALTER TABLE checkins DROP COLUMN suspended_at", [])?;
    }
    if names.iter().any(|name| name == "vetted_at") {
        conn.execute("ALTER TABLE checkins DROP COLUMN vetted_at", [])?;
    }
    Ok(())
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
            hash_signature: b"sig".to_vec(),
            hash_timestamp: Some((1_700_000_000, 123_456_789)),
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
        assert!(index.live_before("sat", created).unwrap().is_empty());
        assert_eq!(
            index
                .live_before("sat", created + Duration::from_secs(1))
                .unwrap(),
            vec!["piece".to_owned()]
        );
        assert!(
            index
                .live_before("other", created + Duration::from_secs(1))
                .unwrap()
                .is_empty()
        );
        let got = index.get("sat", "piece").unwrap().unwrap();
        assert_eq!(got.state, PieceState::Live);
        assert_eq!(got.created, created);
        assert_eq!(got.hash, [0x11; 32]);
        assert_eq!(got.order_limit, b"limit");
        assert_eq!(got.hash_signature, b"sig");
        assert_eq!(got.hash_timestamp, Some((1_700_000_000, 123_456_789)));
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

    #[test]
    fn orders_keep_the_largest_amount_and_expire_after_seven_days() {
        let (_dir, path) = temp_db();
        let index = Index::open(&path).unwrap();
        let orders = index.orders();
        let window = 1_700_000_000;
        let mut row = StoredOrder {
            satellite: "sat".into(),
            serial: vec![1, 2, 3],
            window_start: window,
            limit: b"limit-a".to_vec(),
            order: b"order-a".to_vec(),
            amount: 10,
        };
        orders.save(&row).unwrap();
        row.amount = 4;
        row.order = b"order-smaller".to_vec();
        orders.save(&row).unwrap();
        let got = orders.status("sat", &[1, 2, 3]).unwrap().unwrap();
        assert_eq!(got.status, None);
        assert_eq!(got.amount, 10);
        row.amount = 25;
        row.order = b"order-b".to_vec();
        row.limit = b"limit-b".to_vec();
        orders.save(&row).unwrap();
        let got = orders.status("sat", &[1, 2, 3]).unwrap().unwrap();
        assert_eq!(got.amount, 25);
        assert_eq!(
            orders.window("sat", window).unwrap(),
            vec![StoredOrder {
                satellite: "sat".into(),
                serial: vec![1, 2, 3],
                window_start: window,
                limit: b"limit-b".to_vec(),
                order: b"order-b".to_vec(),
                amount: 25,
            }]
        );

        let archived_at = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        orders.archive("sat", &[1, 2, 3], 0, archived_at).unwrap();
        row.amount = 90;
        orders.save(&row).unwrap();
        let got = orders.status("sat", &[1, 2, 3]).unwrap().unwrap();
        assert_eq!(got.status, Some(0));
        assert_eq!(got.amount, 25);
        assert!(orders.window("sat", window).unwrap().is_empty());

        // The sender passes `now - 7 days`. Equal to the archive time stays.
        let week = Duration::from_secs(7 * 24 * 60 * 60);
        let now = archived_at + week;
        let cutoff = now.checked_sub(week).expect("cutoff");
        assert_eq!(orders.delete_archived_before(cutoff).unwrap(), 0);
        let later = now + Duration::from_secs(1);
        let cutoff = later.checked_sub(week).expect("cutoff");
        assert_eq!(orders.delete_archived_before(cutoff).unwrap(), 1);
        assert!(orders.status("sat", &[1, 2, 3]).unwrap().is_none());
    }

    #[test]
    fn bandwidth_counter_survives_reopen_and_ignores_zero() {
        let (_dir, path) = temp_db();
        let at = UNIX_EPOCH + Duration::from_secs(1_791_039_845);
        let index = Index::open(&path).unwrap();
        index
            .add_bandwidth("sat", BandwidthKind::Put, 0, at)
            .unwrap();
        assert!(index.bandwidth_days(None, at).unwrap().is_empty());
        index
            .add_bandwidth("sat", BandwidthKind::Put, 10, at)
            .unwrap();
        index
            .add_bandwidth("sat", BandwidthKind::Get, 4, at)
            .unwrap();
        index
            .add_bandwidth("other", BandwidthKind::GetAudit, 1, at)
            .unwrap();
        drop(index);

        let index = Index::open(&path).unwrap();
        let all = index.bandwidth_days(None, at).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].day_millis, 1_790_985_600_000);
        assert_eq!(all[0].put, 10);
        assert_eq!(all[0].get, 4);
        assert_eq!(all[0].get_audit, 1);
        assert_eq!(all[0].total(), 15);
        let one = index.bandwidth_days(Some("sat"), at).unwrap();
        assert_eq!(one[0].total(), 14);
        assert_eq!(one[0].egress(), 4);
        assert_eq!(one[0].ingress(), 10);
        let (start, end) = month_window(at).unwrap();
        assert_eq!(start, 1_790_812_800_000);
        assert_eq!(end, 1_793_491_200_000);
        assert!(
            index
                .bandwidth_days(Some("missing"), at)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn check_in_summary_survives_reopen() {
        let (_dir, path) = temp_db();
        let index = Index::open(&path).unwrap();
        let at = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        index
            .record_check_in(&CheckInRow {
                satellite_id: "sat".into(),
                checked_in_at: at,
                quic_ok: false,
            })
            .unwrap();
        let rows = index.check_ins().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].satellite_id, "sat");
        assert_eq!(rows[0].checked_in_at, at);
        assert!(!rows[0].quic_ok);

        let later = at + Duration::from_secs(5);
        index
            .record_check_in(&CheckInRow {
                satellite_id: "sat".into(),
                checked_in_at: later,
                quic_ok: true,
            })
            .unwrap();
        drop(index);
        let index = Index::open(&path).unwrap();
        let rows = index.check_ins().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].checked_in_at, later);
        assert!(rows[0].quic_ok);
    }

    #[test]
    fn open_drops_unused_checkin_columns() {
        let (_dir, path) = temp_db();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE checkins (
                satellite TEXT PRIMARY KEY,
                checked_in_at INTEGER NOT NULL,
                quic_ok INTEGER NOT NULL,
                disqualified_at INTEGER,
                suspended_at INTEGER,
                vetted_at INTEGER
            );",
        )
        .unwrap();
        drop(conn);
        let _index = Index::open(&path).unwrap();
        let conn = Connection::open(&path).unwrap();
        let mut stmt = conn.prepare("PRAGMA table_info(checkins)").unwrap();
        let names = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(names.iter().any(|name| name == "checked_in_at"));
        assert!(names.iter().any(|name| name == "quic_ok"));
        assert!(!names.iter().any(|name| name == "disqualified_at"));
        assert!(!names.iter().any(|name| name == "suspended_at"));
        assert!(!names.iter().any(|name| name == "vetted_at"));
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
