//! S3 piece store.
//!
//! One object per piece. The key is `{prefix}/{satellite-id}/{piece-id}`
//! (prefix defaults to `pieces`). The body is the raw piece bytes, with no
//! hashstore footer. User metadata is stored and returned without the
//! `x-amz-meta-` prefix. Piece metadata keys (the SDK adds `x-amz-meta-`):
//! - `piece-hash` — hex
//! - `hash-algorithm` — `sha256` or `blake3`
//! - `created` — RFC3339
//! - `expires` — RFC3339, or absent
//! - `order-limit` — standard base64 of the encoded order limit
//!
//! [`Store::put_piece`] commits that metadata in order: insert `writing`,
//! `PutObject` or complete multipart, then mark `live`. [`Store::put`] writes
//! an object and does not touch the index.
//!
//! Bodies of at most [`PART_SIZE`] bytes use one `PutObject`. Larger bodies
//! use multipart upload, [`PART_SIZE`] per part, last part shorter.

#![deny(clippy::undocumented_unsafe_blocks)]

mod index;

pub use index::{HashAlgorithm, PIECES_DB, PieceInfo, PieceMeta, PieceState, Space, TRASH_KEEP};

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_sdk_s3::config::{
    BehaviorVersion, Credentials, Region, RequestChecksumCalculation, ResponseChecksumValidation,
};
use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

/// Single `PutObject` limit. Larger bodies are multipart with parts of this size.
pub const PART_SIZE: usize = 5 * 1024 * 1024;

const DEFAULT_REGION: &str = "us-east-1";
const DEFAULT_PREFIX: &str = "pieces";

/// Connection settings for one bucket.
///
/// `Debug` redacts `secret_access_key`. The secret is not otherwise logged.
#[derive(Clone)]
pub struct Config {
    /// S3 API endpoint, including scheme (`http://127.0.0.1:9000`, or an AWS URL).
    pub endpoint: String,
    /// Bucket that holds piece objects.
    pub bucket: String,
    /// Static access key id.
    pub access_key_id: String,
    /// Static secret. Not included in [`Debug`] output.
    pub secret_access_key: String,
    /// AWS region. Empty becomes `us-east-1`.
    pub region: String,
    /// Key prefix. Empty becomes `pieces`. Trimmed of leading and trailing `/`.
    pub prefix: String,
    /// `None` uses path-style unless the endpoint host is `amazonaws.com`.
    pub path_style: Option<bool>,
    /// Directory that holds [`PIECES_DB`]. Created if absent.
    pub volume: PathBuf,
    /// Allocation in bytes. Free space is this minus the sum of live sizes.
    pub allocated_bytes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            bucket: String::new(),
            access_key_id: String::new(),
            secret_access_key: String::new(),
            region: DEFAULT_REGION.to_owned(),
            prefix: DEFAULT_PREFIX.to_owned(),
            path_style: None,
            volume: PathBuf::new(),
            allocated_bytes: 0,
        }
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field("region", &self.region)
            .field("prefix", &self.prefix)
            .field("path_style", &self.path_style)
            .field("volume", &self.volume)
            .field("allocated_bytes", &self.allocated_bytes)
            .finish()
    }
}

/// Client for piece objects in one bucket.
pub struct Store {
    client: aws_sdk_s3::Client,
    bucket: String,
    prefix: String,
    index: index::Index,
    allocated_bytes: u64,
    /// File was absent at open. [`Store::startup`] lists the bucket once.
    needs_rebuild: AtomicBool,
    /// Held across a piece commit and across each chore delete, so GC cannot
    /// remove an object a commit just replaced. One lock for the bucket;
    /// split per piece if a GC pass blocks uploads.
    commit: Arc<tokio::sync::Mutex<()>>,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store")
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("allocated_bytes", &self.allocated_bytes)
            .finish_non_exhaustive()
    }
}

/// Bytes from [`Store::download`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Download {
    /// Object bytes for the requested range.
    pub bytes: Vec<u8>,
    /// The row was trash and the object is still in the bucket.
    ///
    /// The download does not clear the flag. [`Store::restore_trash`] does.
    pub restored_from_trash: bool,
}

/// Failure from the piece store. Display text does not include the secret.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    /// Endpoint, bucket, or credentials were rejected before any request.
    #[error("{0}")]
    Config(&'static str),
    /// `endpoint` is not an absolute `http` or `https` URL.
    #[error("s3 endpoint must be an absolute http(s) URL")]
    Endpoint,
    /// Satellite id, piece id, prefix, or metadata key cannot form a safe object key.
    #[error("{0}")]
    InvalidKey(String),
    /// `start` is greater than `end` in a half-open range.
    #[error("invalid range {start}..{end}")]
    Range {
        /// Start of the half-open range.
        start: u64,
        /// End of the half-open range, exclusive.
        end: u64,
    },
    /// The piece object is not in the bucket.
    #[error("object not found")]
    NotFound,
    /// The S3 API returned an error, or the bucket could not be reached.
    #[error("{0}")]
    S3(String),
    /// Piece hash, algorithm, time, or order limit cannot be stored.
    #[error("piece metadata: {0}")]
    Metadata(String),
    /// `pieces.db` could not be opened or updated.
    #[error("piece index: {0}")]
    Index(String),
}

/// Piece-store result.
pub type Result<T> = std::result::Result<T, Error>;

impl Store {
    /// Builds a client and opens `pieces.db`.
    ///
    /// Does not contact the bucket. [`Store::startup`] does, and rebuilds the
    /// index when the database file was missing.
    pub fn new(config: Config) -> Result<Self> {
        if config.endpoint.is_empty() {
            return Err(Error::Config("endpoint is required"));
        }
        if config.bucket.is_empty() {
            return Err(Error::Config("bucket is required"));
        }
        if config.access_key_id.is_empty() {
            return Err(Error::Config("access key is required"));
        }
        if config.secret_access_key.is_empty() {
            return Err(Error::Config("secret is required"));
        }
        if config.volume.as_os_str().is_empty() {
            return Err(Error::Config("volume is required"));
        }

        let path_style = path_style_for(&config.endpoint, config.path_style)?;
        let region = if config.region.is_empty() {
            DEFAULT_REGION
        } else {
            config.region.as_str()
        };
        let prefix = if config.prefix.is_empty() {
            DEFAULT_PREFIX.to_owned()
        } else {
            config.prefix
        };

        // Static keys only. Do not fall through to the environment credential chain.
        let credentials = Credentials::new(
            config.access_key_id,
            config.secret_access_key,
            None,
            None,
            "s3store",
        );
        let sdk = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(region.to_owned()))
            .endpoint_url(config.endpoint)
            .credentials_provider(credentials)
            .force_path_style(path_style)
            .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
            .response_checksum_validation(ResponseChecksumValidation::WhenRequired)
            .build();

        let (index, missing) = index::Index::open(&config.volume.join(PIECES_DB))?;
        Ok(Self {
            client: aws_sdk_s3::Client::from_conf(sdk),
            bucket: config.bucket,
            prefix,
            index,
            allocated_bytes: config.allocated_bytes,
            needs_rebuild: AtomicBool::new(missing),
            commit: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    /// Returns an error when the bucket is missing or the endpoint cannot be reached.
    ///
    /// This is not a piece lookup. A 404 here stays [`Error::S3`] even when the
    /// SDK reports `NotFound` (aws-sdk synthesizes that for an empty 404 body).
    pub async fn head_bucket(&self) -> Result<()> {
        self.client
            .head_bucket()
            .bucket(&self.bucket)
            .send()
            .await
            .map(|_| ())
            .map_err(|err| Error::S3(err.to_string()))
    }

    /// Checks the bucket, then rebuilds the index if `pieces.db` was missing.
    ///
    /// Rebuild lists the prefix and inserts a live row for every object whose
    /// user metadata has the piece fields. Trash is not on the object, so
    /// every rebuilt row is live.
    pub async fn startup(&self) -> Result<()> {
        self.head_bucket().await?;
        if self.needs_rebuild.swap(false, Ordering::AcqRel)
            && let Err(err) = self.rebuild().await
        {
            self.needs_rebuild.store(true, Ordering::Release);
            return Err(err);
        }
        Ok(())
    }

    /// Writes a piece: insert `writing`, put the object, then mark `live`.
    pub async fn put_piece(
        &self,
        satellite_id: &str,
        piece_id: &str,
        body: &[u8],
        meta: PieceMeta,
    ) -> Result<()> {
        let mut upload = self.upload_piece(satellite_id, piece_id, meta)?;
        upload.write(body).await?;
        upload.finish().await
    }

    /// Starts a piece upload. [`Upload::finish`] runs the writing/live commit.
    ///
    /// [`Upload::cancel`] before finish aborts a multipart upload and does not
    /// delete an object already stored at this key.
    pub fn upload_piece(
        &self,
        satellite_id: &str,
        piece_id: &str,
        meta: PieceMeta,
    ) -> Result<Upload> {
        let map = metadata_map(&meta)?;
        let mut upload = self.upload(satellite_id, piece_id, Some(map))?;
        upload.piece = Some(PieceAttempt {
            satellite_id: satellite_id.to_owned(),
            piece_id: piece_id.to_owned(),
            meta,
            previous: None,
            reserved: false,
            committed: false,
        });
        Ok(upload)
    }

    /// Reads a live or trashed piece.
    ///
    /// A `writing` row and a missing row are [`Error::NotFound`], even when
    /// the key is in the bucket. Trash still returns the bytes and sets
    /// [`Download::restored_from_trash`].
    pub async fn download(
        &self,
        satellite_id: &str,
        piece_id: &str,
        range: Option<std::ops::Range<u64>>,
    ) -> Result<Download> {
        check_piece(satellite_id, piece_id)?;
        let info = self
            .index
            .get(satellite_id, piece_id)?
            .ok_or(Error::NotFound)?;
        let restored = match info.state {
            PieceState::Live => false,
            PieceState::Trash => true,
            PieceState::Writing => return Err(Error::NotFound),
        };
        match self.get(satellite_id, piece_id, range).await {
            Ok(bytes) => Ok(Download {
                bytes,
                restored_from_trash: restored,
            }),
            Err(Error::NotFound) => {
                if self.index.get(satellite_id, piece_id)?.as_ref() == Some(&info) {
                    self.index.delete(satellite_id, piece_id)?;
                }
                Err(Error::NotFound)
            }
            Err(err) => Err(err),
        }
    }

    /// True only for a `live` row.
    pub fn exists(&self, satellite_id: &str, piece_id: &str) -> Result<bool> {
        check_piece(satellite_id, piece_id)?;
        self.index.exists_live(satellite_id, piece_id)
    }

    /// The index row, including `writing` and `trash`. `Ok(None)` when absent.
    pub fn info(&self, satellite_id: &str, piece_id: &str) -> Result<Option<PieceInfo>> {
        check_piece(satellite_id, piece_id)?;
        self.index.get(satellite_id, piece_id)
    }

    /// Flags a live piece as trash. Does not move the object.
    ///
    /// Already-trash succeeds and leaves the original `trashed_at` in place.
    pub async fn trash(&self, satellite_id: &str, piece_id: &str, at: SystemTime) -> Result<()> {
        check_piece(satellite_id, piece_id)?;
        let _guard = self.commit.lock().await;
        if self.index.trash(satellite_id, piece_id, at)? {
            return Ok(());
        }
        match self.index.get(satellite_id, piece_id)? {
            Some(info) if info.state == PieceState::Trash => Ok(()),
            _ => Err(Error::NotFound),
        }
    }

    /// Clears trash for one satellite. Rows whose objects were already
    /// deleted by the chore are gone, so they are not restored.
    pub async fn restore_trash(&self, satellite_id: &str) -> Result<u64> {
        check_id("satellite id", satellite_id)?;
        let _guard = self.commit.lock().await;
        self.index.restore_trash(satellite_id)
    }

    /// Allocation, live bytes, trash bytes, and free space (`allocated - live`).
    pub fn space(&self) -> Result<Space> {
        let (used, trash) = self.index.sums()?;
        Ok(Space {
            allocated: self.allocated_bytes,
            used,
            trash,
            free: self.allocated_bytes.saturating_sub(used),
        })
    }

    /// Deletes expired pieces, then trash whose `trashed_at` is at least
    /// [`TRASH_KEEP`] before `now`. Each delete removes the object and the row.
    pub async fn run_chore(&self, now: SystemTime) -> Result<()> {
        for (satellite_id, piece_id) in self.index.expired(now)? {
            let _guard = self.commit.lock().await;
            if self.index.is_expired(&satellite_id, &piece_id, now)? {
                self.delete_stored(&satellite_id, &piece_id).await?;
            }
        }
        for (satellite_id, piece_id) in self.index.trash_due(now)? {
            let _guard = self.commit.lock().await;
            if self.index.is_trash_due(&satellite_id, &piece_id, now)? {
                self.delete_stored(&satellite_id, &piece_id).await?;
            }
        }
        Ok(())
    }

    /// Starts an upload.
    ///
    /// The key is replaced only when [`Upload::finish`] commits. [`Upload::cancel`]
    /// and drop abort an in-progress multipart upload and leave any object already
    /// stored at this key in place.
    pub fn upload(
        &self,
        satellite_id: &str,
        piece_id: &str,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<Upload> {
        let key = object_key(&self.prefix, satellite_id, piece_id)?;
        Ok(Upload {
            client: self.client.clone(),
            bucket: self.bucket.clone(),
            key,
            metadata,
            buf: Vec::new(),
            upload_id: None,
            parts: Vec::new(),
            next_part: 1,
            failed: None,
            index: self.index.clone(),
            commit: Arc::clone(&self.commit),
            piece: None,
        })
    }

    /// Writes `body` and commits it, overwriting an existing object at the same key.
    pub async fn put(
        &self,
        satellite_id: &str,
        piece_id: &str,
        body: &[u8],
        metadata: Option<HashMap<String, String>>,
    ) -> Result<()> {
        let mut upload = self.upload(satellite_id, piece_id, metadata)?;
        upload.write(body).await?;
        upload.finish().await
    }

    /// Reads the object. `range` is half-open `[start, end)`. `None` reads the whole body.
    pub async fn get(
        &self,
        satellite_id: &str,
        piece_id: &str,
        range: Option<std::ops::Range<u64>>,
    ) -> Result<Vec<u8>> {
        let key = object_key(&self.prefix, satellite_id, piece_id)?;
        if let Some(range) = &range {
            if range.start > range.end {
                return Err(Error::Range {
                    start: range.start,
                    end: range.end,
                });
            }
            if range.start == range.end {
                // S3 has no empty byte range. One GetObject byte classifies a
                // missing key as NoSuchKey, same as a full get. HeadObject does
                // not: s3s-fs reports a missing key as NoSuchBucket.
                self.probe_object(&key, range.start).await?;
                return Ok(Vec::new());
            }
        }
        let mut req = self.client.get_object().bucket(&self.bucket).key(&key);
        if let Some(range) = range {
            let end_inclusive = range.end - 1;
            req = req.range(format!("bytes={}-{}", range.start, end_inclusive));
        }
        let out = req.send().await.map_err(map_s3)?;
        let bytes = out
            .body
            .collect()
            .await
            .map_err(|err| Error::S3(err.to_string()))?
            .into_bytes();
        // `Bytes` -> `Vec` reuses the allocation when this handle is unique.
        Ok(Vec::from(bytes))
    }

    /// One-byte `GetObject` at `at`.
    ///
    /// `Ok` means the object exists (`InvalidRange` is an empty object, or `at`
    /// is past the end). [`Error::NotFound`] is `NoSuchKey` / `NotFound` only.
    /// `NoSuchBucket` stays [`Error::S3`] so a missing bucket is not a missing piece.
    async fn probe_object(&self, key: &str, at: u64) -> Result<Option<HashMap<String, String>>> {
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .range(format!("bytes={at}-{at}"))
            .send()
            .await
        {
            Ok(out) => {
                let meta = normalize_metadata(out.metadata());
                out.body
                    .collect()
                    .await
                    .map_err(|err| Error::S3(err.to_string()))?;
                Ok(meta)
            }
            Err(err) if is_missing_code(err.code()) => Err(Error::NotFound),
            Err(err) if err.code() == Some("InvalidRange") => Ok(None),
            Err(err) => Err(map_s3(err)),
        }
    }

    /// User metadata for an existing object, without the `x-amz-meta-` prefix.
    ///
    /// `Ok(None)` means the object exists and has no user metadata.
    /// A missing object is [`Error::NotFound`].
    pub async fn head(
        &self,
        satellite_id: &str,
        piece_id: &str,
    ) -> Result<Option<HashMap<String, String>>> {
        let key = object_key(&self.prefix, satellite_id, piece_id)?;
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(out) => Ok(normalize_metadata(out.metadata())),
            Err(err) if is_missing_code(err.code()) => Err(Error::NotFound),
            // s3s-fs 0.12 HeadObject returns NoSuchBucket for a missing key.
            // GetObject returns NoSuchKey. A bucket that is actually missing
            // stays NoSuchBucket on GetObject, and head_bucket still reports it.
            Err(err) if err.code() == Some("NoSuchBucket") => self.probe_object(&key, 0).await,
            Err(err) => Err(map_s3(err)),
        }
    }

    /// Deletes the object and the index row. Already-absent keys succeed.
    pub async fn delete(&self, satellite_id: &str, piece_id: &str) -> Result<()> {
        let _guard = self.commit.lock().await;
        self.delete_stored(satellite_id, piece_id).await
    }

    async fn delete_stored(&self, satellite_id: &str, piece_id: &str) -> Result<()> {
        let key = object_key(&self.prefix, satellite_id, piece_id)?;
        delete_object(&self.client, &self.bucket, &key).await?;
        self.index.delete(satellite_id, piece_id)
    }

    async fn rebuild(&self) -> Result<u64> {
        let prefix = list_prefix(&self.prefix);
        let mut count = 0u64;
        let mut start_after: Option<String> = None;
        loop {
            let page = self.list_page(&prefix, start_after.as_deref()).await?;
            if page.keys.is_empty() {
                break;
            }
            for key in &page.keys {
                let Some((satellite_id, piece_id)) = split_object_key(&self.prefix, key) else {
                    continue;
                };
                let Some((size, meta)) = self.head_listed(key).await? else {
                    continue;
                };
                let Some(info) = piece_from_metadata(&satellite_id, &piece_id, size, &meta) else {
                    continue;
                };
                self.index.upsert(&info)?;
                count += 1;
            }
            if !page.truncated {
                break;
            }
            // s3s-fs pages with start_after and is_truncated. It does not
            // return a continuation token.
            let Some(last) = page.keys.last() else {
                break;
            };
            if start_after.as_deref() == Some(last.as_str()) {
                break;
            }
            start_after = Some(last.clone());
        }
        Ok(count)
    }

    async fn list_page(&self, prefix: &str, start_after: Option<&str>) -> Result<ListPage> {
        let mut req = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .max_keys(1000);
        if !prefix.is_empty() {
            req = req.prefix(prefix);
        }
        if let Some(start_after) = start_after {
            req = req.start_after(start_after);
        }
        let out = req.send().await.map_err(map_s3)?;
        let keys = out
            .contents()
            .iter()
            .filter_map(|obj| obj.key().map(str::to_owned))
            .collect();
        Ok(ListPage {
            keys,
            truncated: out.is_truncated().unwrap_or(false),
        })
    }

    async fn head_listed(&self, key: &str) -> Result<Option<(u64, HashMap<String, String>)>> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(out) => {
                let size = out.content_length().unwrap_or(0);
                let size = u64::try_from(size).unwrap_or(0);
                let meta = normalize_metadata(out.metadata()).unwrap_or_default();
                Ok(Some((size, meta)))
            }
            Err(err) if is_missing_code(err.code()) || err.code() == Some("NoSuchBucket") => {
                Ok(None)
            }
            Err(err) => Err(map_s3(err)),
        }
    }
}

/// An upload that has not been committed.
///
/// [`Upload::finish`] writes the object. [`Upload::cancel`] and drop abort an
/// in-progress multipart upload. They do not delete an object already stored
/// at this key.
#[must_use = "call finish or cancel"]
pub struct Upload {
    client: aws_sdk_s3::Client,
    bucket: String,
    key: String,
    metadata: Option<HashMap<String, String>>,
    buf: Vec<u8>,
    upload_id: Option<String>,
    parts: Vec<CompletedPart>,
    next_part: i32,
    // A failed part must not be completed later as a short or empty object.
    failed: Option<Error>,
    index: index::Index,
    commit: Arc<tokio::sync::Mutex<()>>,
    piece: Option<PieceAttempt>,
}

struct PieceAttempt {
    satellite_id: String,
    piece_id: String,
    meta: PieceMeta,
    previous: Option<PieceInfo>,
    reserved: bool,
    committed: bool,
}

struct ListPage {
    keys: Vec<String>,
    truncated: bool,
}

impl Upload {
    /// Appends bytes. A full part is uploaded only once the body grows past it,
    /// so a body of exactly [`PART_SIZE`] stays a single `PutObject`.
    pub async fn write(&mut self, mut data: &[u8]) -> Result<()> {
        if let Some(err) = &self.failed {
            return Err(err.clone());
        }
        while !data.is_empty() {
            if self.buf.len() == PART_SIZE {
                self.upload_full_part().await?;
            }
            let room = PART_SIZE - self.buf.len();
            let n = room.min(data.len());
            self.buf.extend_from_slice(&data[..n]);
            data = &data[n..];
        }
        Ok(())
    }

    /// Commits the object, overwriting any previous body at this key.
    ///
    /// A piece upload inserts `writing` first. The row stays `writing` when
    /// this returns after the put and before `live` is recorded, including
    /// when the process dies in that window. The object is then not served.
    pub async fn finish(mut self) -> Result<()> {
        let commit = Arc::clone(&self.commit);
        let _guard = commit.lock().await;
        self.reserve_piece()?;
        if let Err(err) = self.finish_inner().await {
            // Put did not return success. Restore the previous row so a failed
            // overwrite does not hide that piece. A crash skips this and leaves
            // `writing`, which is not served.
            self.rollback_piece()?;
            return Err(err);
        }
        // Complete already published the object. Do not abort it on drop.
        self.upload_id = None;
        if let Some(piece) = &mut self.piece {
            piece.committed = true;
        }
        self.mark_piece_live()?;
        Ok(())
    }

    /// Aborts an in-progress multipart upload.
    ///
    /// An object already stored at this key stays. This upload has not put,
    /// so cancel does not delete that key or a live row.
    pub async fn cancel(mut self) -> Result<()> {
        self.abort_multipart().await?;
        self.upload_id = None;
        self.rollback_piece()?;
        Ok(())
    }

    async fn finish_inner(&mut self) -> Result<()> {
        if let Some(err) = &self.failed {
            return Err(err.clone());
        }
        if self.upload_id.is_none() {
            self.put_single().await?;
            return Ok(());
        }
        if !self.buf.is_empty() {
            self.upload_full_part().await?;
        }
        let upload_id = self
            .upload_id
            .clone()
            .ok_or(Error::S3("multipart upload id missing".into()))?;
        let upload = CompletedMultipartUpload::builder()
            .set_parts(Some(std::mem::take(&mut self.parts)))
            .build();
        self.client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(&self.key)
            .upload_id(upload_id)
            .multipart_upload(upload)
            .send()
            .await
            .map_err(map_s3)?;
        Ok(())
    }

    async fn put_single(&mut self) -> Result<()> {
        let pairs = metadata_pairs(self.metadata.as_ref())?;
        let body = ByteStream::from(std::mem::take(&mut self.buf));
        let mut req = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&self.key)
            .body(body);
        for (key, value) in pairs {
            req = req.metadata(key, value);
        }
        req.send().await.map_err(map_s3)?;
        Ok(())
    }

    async fn upload_full_part(&mut self) -> Result<()> {
        if let Some(err) = &self.failed {
            return Err(err.clone());
        }
        if let Err(err) = self.ensure_multipart().await {
            self.failed = Some(err.clone());
            return Err(err);
        }
        let part_number = self.next_part;
        let body = ByteStream::from(self.buf.clone());
        let upload_id = match self.upload_id.clone() {
            Some(upload_id) => upload_id,
            None => {
                let err = Error::S3("multipart upload id missing".into());
                self.failed = Some(err.clone());
                return Err(err);
            }
        };
        let out = match self
            .client
            .upload_part()
            .bucket(&self.bucket)
            .key(&self.key)
            .upload_id(upload_id)
            .part_number(part_number)
            .body(body)
            .send()
            .await
        {
            Ok(out) => out,
            Err(err) => {
                let err = map_s3(err);
                self.failed = Some(err.clone());
                return Err(err);
            }
        };
        // CompleteMultipartUpload on AWS rejects a part that has no ETag.
        let Some(etag) = out.e_tag() else {
            let err = Error::S3("upload part response is missing an etag".into());
            self.failed = Some(err.clone());
            return Err(err);
        };
        self.parts.push(
            CompletedPart::builder()
                .part_number(part_number)
                .e_tag(etag)
                .build(),
        );
        self.next_part += 1;
        self.buf.clear();
        Ok(())
    }

    async fn ensure_multipart(&mut self) -> Result<()> {
        if self.upload_id.is_some() {
            return Ok(());
        }
        let pairs = metadata_pairs(self.metadata.as_ref())?;
        let mut req = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(&self.key);
        for (key, value) in pairs {
            req = req.metadata(key, value);
        }
        let out = req.send().await.map_err(map_s3)?;
        self.upload_id = Some(
            out.upload_id
                .ok_or(Error::S3("multipart upload id missing".into()))?,
        );
        Ok(())
    }

    async fn abort_multipart(&mut self) -> Result<()> {
        let Some(upload_id) = self.upload_id.clone() else {
            return Ok(());
        };
        match self
            .client
            .abort_multipart_upload()
            .bucket(&self.bucket)
            .key(&self.key)
            .upload_id(upload_id)
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(err) if is_missing_code(err.code()) || err.code() == Some("NoSuchUpload") => Ok(()),
            Err(err) => Err(Error::S3(err.to_string())),
        }
    }

    fn reserve_piece(&mut self) -> Result<()> {
        let Some(piece) = &self.piece else {
            return Ok(());
        };
        if piece.reserved {
            return Ok(());
        }
        let satellite_id = piece.satellite_id.clone();
        let piece_id = piece.piece_id.clone();
        let meta = piece.meta.clone();
        let size = self.buffered_len();
        let previous = self.index.get(&satellite_id, &piece_id)?;
        let row = PieceInfo::from_meta(&satellite_id, &piece_id, size, &meta, PieceState::Writing);
        self.index.upsert(&row)?;
        let Some(piece) = self.piece.as_mut() else {
            return Ok(());
        };
        piece.previous = previous;
        piece.reserved = true;
        Ok(())
    }

    fn rollback_piece(&mut self) -> Result<()> {
        let Some(piece) = self.piece.as_mut() else {
            return Ok(());
        };
        if !piece.reserved || piece.committed {
            return Ok(());
        }
        let previous = piece.previous.clone();
        let satellite_id = piece.satellite_id.clone();
        let piece_id = piece.piece_id.clone();
        piece.reserved = false;
        if let Some(previous) = previous {
            self.index.upsert(&previous)
        } else {
            self.index.delete(&satellite_id, &piece_id)
        }
    }

    fn mark_piece_live(&mut self) -> Result<()> {
        let Some(piece) = self.piece.as_mut() else {
            return Ok(());
        };
        if !piece.reserved {
            return Ok(());
        }
        self.index.mark_live(&piece.satellite_id, &piece.piece_id)?;
        piece.reserved = false;
        piece.previous = None;
        Ok(())
    }

    fn buffered_len(&self) -> u64 {
        let parts = u64::from(self.next_part.saturating_sub(1).cast_unsigned());
        let part_len = u64::try_from(PART_SIZE).unwrap_or(u64::MAX);
        parts
            .saturating_mul(part_len)
            .saturating_add(u64::try_from(self.buf.len()).unwrap_or(u64::MAX))
    }
}

impl Drop for Upload {
    fn drop(&mut self) {
        if self
            .piece
            .as_ref()
            .is_some_and(|piece| piece.reserved && !piece.committed)
        {
            let _ = self.rollback_piece();
        }
        // Only abort this upload id. DeleteObject from Drop can run after a
        // later put of the same key and remove that committed object.
        let Some(upload_id) = self.upload_id.clone() else {
            return;
        };
        let client = self.client.clone();
        let bucket = self.bucket.clone();
        let key = self.key.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = client
                    .abort_multipart_upload()
                    .bucket(&bucket)
                    .key(&key)
                    .upload_id(upload_id)
                    .send()
                    .await;
            });
        }
    }
}

fn check_piece(satellite_id: &str, piece_id: &str) -> Result<()> {
    check_id("satellite id", satellite_id)?;
    check_id("piece id", piece_id)?;
    Ok(())
}

fn metadata_map(meta: &PieceMeta) -> Result<HashMap<String, String>> {
    if meta.order_limit.is_empty() {
        return Err(Error::Metadata("order limit is empty".into()));
    }
    let mut map = HashMap::new();
    map.insert("piece-hash".to_owned(), encode_hex(&meta.hash));
    map.insert(
        "hash-algorithm".to_owned(),
        meta.algorithm.as_str().to_owned(),
    );
    map.insert("created".to_owned(), format_rfc3339(meta.created)?);
    if let Some(expires) = meta.expires {
        map.insert("expires".to_owned(), format_rfc3339(expires)?);
    }
    map.insert("order-limit".to_owned(), BASE64.encode(&meta.order_limit));
    let len = map
        .iter()
        .map(|(key, value)| "x-amz-meta-".len() + key.len() + value.len())
        .sum::<usize>();
    if len > 2048 {
        return Err(Error::Metadata("user metadata exceeds 2048 bytes".into()));
    }
    Ok(map)
}

fn piece_from_metadata(
    satellite_id: &str,
    piece_id: &str,
    size: u64,
    meta: &HashMap<String, String>,
) -> Option<PieceInfo> {
    let hash = decode_hex(meta.get("piece-hash")?)?;
    let hash: [u8; 32] = hash.try_into().ok()?;
    let algorithm = HashAlgorithm::parse(meta.get("hash-algorithm")?)?;
    let created = parse_rfc3339(meta.get("created")?).ok()?;
    let expires = match meta.get("expires") {
        None => None,
        Some(value) if value.is_empty() => None,
        Some(value) => Some(parse_rfc3339(value).ok()?),
    };
    let order_limit = BASE64.decode(meta.get("order-limit")?).ok()?;
    if order_limit.is_empty() {
        return None;
    }
    Some(PieceInfo {
        satellite_id: satellite_id.to_owned(),
        piece_id: piece_id.to_owned(),
        size,
        hash,
        algorithm,
        order_limit,
        created,
        expires,
        trashed_at: None,
        state: PieceState::Live,
    })
}

fn format_rfc3339(time: SystemTime) -> Result<String> {
    let dt = system_to_offset(time)?;
    dt.format(&time::format_description::well_known::Rfc3339)
        .map_err(|err| Error::Metadata(err.to_string()))
}

fn parse_rfc3339(value: &str) -> Result<SystemTime> {
    let dt = time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map_err(|err| Error::Metadata(err.to_string()))?;
    let nanos = dt.unix_timestamp_nanos();
    if nanos < 0 {
        return Err(Error::Metadata("timestamp is before the unix epoch".into()));
    }
    let nanos = u64::try_from(nanos).map_err(|_| Error::Metadata("timestamp overflow".into()))?;
    let secs = nanos / 1_000_000_000;
    let sub = u32::try_from(nanos % 1_000_000_000)
        .map_err(|_| Error::Metadata("timestamp overflow".into()))?;
    UNIX_EPOCH
        .checked_add(std::time::Duration::new(secs, sub))
        .ok_or_else(|| Error::Metadata("timestamp overflow".into()))
}

fn system_to_offset(time: SystemTime) -> Result<time::OffsetDateTime> {
    let dur = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Metadata("timestamp is before the unix epoch".into()))?;
    let nanos =
        i128::try_from(dur.as_nanos()).map_err(|_| Error::Metadata("timestamp overflow".into()))?;
    time::OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|err| Error::Metadata(err.to_string()))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = from_hex(bytes[i])?;
        let lo = from_hex(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn list_prefix(prefix: &str) -> String {
    let prefix = prefix.trim_matches('/');
    if prefix.is_empty() {
        String::new()
    } else {
        format!("{prefix}/")
    }
}

fn split_object_key(prefix: &str, key: &str) -> Option<(String, String)> {
    let prefix = prefix.trim_matches('/');
    let rest = if prefix.is_empty() {
        key
    } else {
        key.strip_prefix(prefix)?.strip_prefix('/')?
    };
    if rest.is_empty() || rest.ends_with('/') {
        return None;
    }
    let (satellite_id, piece_id) = rest.split_once('/')?;
    if piece_id.contains('/') || satellite_id.starts_with('.') || piece_id.starts_with('.') {
        return None;
    }
    if check_id("satellite id", satellite_id).is_err() || check_id("piece id", piece_id).is_err() {
        return None;
    }
    Some((satellite_id.to_owned(), piece_id.to_owned()))
}

fn metadata_pairs(metadata: Option<&HashMap<String, String>>) -> Result<Vec<(String, String)>> {
    let Some(metadata) = metadata else {
        return Ok(Vec::new());
    };
    let mut pairs = Vec::with_capacity(metadata.len());
    for (key, value) in metadata {
        let key = normalize_meta_key(key);
        if key.is_empty() {
            return Err(Error::InvalidKey("metadata key is empty".into()));
        }
        pairs.push((key, value.clone()));
    }
    Ok(pairs)
}

fn normalize_metadata(meta: Option<&HashMap<String, String>>) -> Option<HashMap<String, String>> {
    let meta = meta?;
    if meta.is_empty() {
        return None;
    }
    let map = meta
        .iter()
        .map(|(key, value)| (normalize_meta_key(key), value.clone()))
        .collect();
    Some(map)
}

fn normalize_meta_key(key: &str) -> String {
    let key = key.trim();
    let stripped = strip_meta_prefix(key);
    stripped.to_ascii_lowercase()
}

fn strip_meta_prefix(key: &str) -> &str {
    const PREFIX: &[u8] = b"x-amz-meta-";
    if key.len() >= PREFIX.len() && key.as_bytes()[..PREFIX.len()].eq_ignore_ascii_case(PREFIX) {
        &key[PREFIX.len()..]
    } else {
        key
    }
}

/// S3 `DeleteObject` is success when the key is already gone. `s3s-fs` returns `NoSuchKey`.
async fn delete_object(client: &aws_sdk_s3::Client, bucket: &str, key: &str) -> Result<()> {
    match client.delete_object().bucket(bucket).key(key).send().await {
        Ok(_) => Ok(()),
        Err(err) if is_missing_code(err.code()) => Ok(()),
        Err(err) => Err(Error::S3(err.to_string())),
    }
}

fn map_s3<E, R>(err: SdkError<E, R>) -> Error
where
    E: ProvideErrorMetadata,
    R: fmt::Debug,
{
    if is_missing_code(err.code()) {
        Error::NotFound
    } else {
        Error::S3(err.to_string())
    }
}

fn is_missing_code(code: Option<&str>) -> bool {
    matches!(code, Some("NoSuchKey" | "NotFound"))
}

fn path_style_for(endpoint: &str, path_style: Option<bool>) -> Result<bool> {
    if let Some(path_style) = path_style {
        return Ok(path_style);
    }
    let host = endpoint_host(endpoint)?;
    Ok(!host_is_amazonaws(&host))
}

fn host_is_amazonaws(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "amazonaws.com" || host.ends_with(".amazonaws.com")
}

fn endpoint_host(endpoint: &str) -> Result<String> {
    let rest = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))
        .ok_or(Error::Endpoint)?;
    if rest.is_empty() {
        return Err(Error::Endpoint);
    }
    let authority = rest.split('/').next().unwrap_or(rest);
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']').ok_or(Error::Endpoint)?;
        &rest[..end]
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    if host.is_empty() {
        return Err(Error::Endpoint);
    }
    Ok(host.to_owned())
}

fn object_key(prefix: &str, satellite_id: &str, piece_id: &str) -> Result<String> {
    check_id("satellite id", satellite_id)?;
    check_id("piece id", piece_id)?;
    let prefix = prefix.trim_matches('/');
    if prefix.is_empty() {
        return Ok(format!("{satellite_id}/{piece_id}"));
    }
    for segment in prefix.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(Error::InvalidKey("prefix is not a safe path".into()));
        }
    }
    Ok(format!("{prefix}/{satellite_id}/{piece_id}"))
}

fn check_id(what: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
    {
        return Err(Error::InvalidKey(format!(
            "{what} must be a single path segment"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_style_unless_the_host_is_amazonaws() {
        assert!(path_style_for("http://127.0.0.1:9000", None).unwrap());
        assert!(path_style_for("https://rgw.example.com", None).unwrap());
        assert!(path_style_for("http://[::1]:9000", None).unwrap());
        assert!(!path_style_for("https://s3.us-east-1.amazonaws.com", None).unwrap());
        assert!(!path_style_for("https://s3.amazonaws.com/bucket", None).unwrap());
        assert!(path_style_for("https://s3.amazonaws.com", Some(true)).unwrap());
        assert!(!path_style_for("http://127.0.0.1:9000", Some(false)).unwrap());
        assert!(path_style_for("https://s3.amazonaws.com.cn", None).unwrap());
        assert!(path_style_for("not a url", None).is_err());
    }

    #[test]
    fn key_is_prefix_satellite_and_piece() {
        assert_eq!(
            object_key("pieces", "sat", "piece").unwrap(),
            "pieces/sat/piece"
        );
        assert_eq!(
            object_key("/pieces/", "sat", "abc").unwrap(),
            "pieces/sat/abc"
        );
        assert_eq!(object_key("", "sat", "abc").unwrap(), "sat/abc");
        assert!(object_key("pieces", "sa/t", "piece").is_err());
        assert!(object_key("pieces", "sat", "..").is_err());
        assert!(object_key("a/../b", "sat", "piece").is_err());
    }

    #[test]
    fn debug_redacts_the_secret() {
        let config = Config {
            endpoint: "http://127.0.0.1:9000".to_owned(),
            bucket: "pieces".to_owned(),
            access_key_id: "AKIDEXAMPLE".to_owned(),
            secret_access_key: "super-secret-value".to_owned(),
            ..Config::default()
        };
        let text = format!("{config:?}");
        assert!(!text.contains("super-secret-value"), "{text}");
        assert!(text.contains("AKIDEXAMPLE"), "{text}");
        assert!(text.contains("<redacted>"), "{text}");
    }

    #[test]
    fn metadata_keys_drop_the_amz_prefix() {
        assert_eq!(normalize_meta_key("X-Amz-Meta-Piece-Hash"), "piece-hash");
        assert_eq!(normalize_meta_key("note"), "note");
    }

    #[test]
    fn piece_metadata_round_trip() {
        let created = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let expires = created + std::time::Duration::from_millis(1500);
        let meta = PieceMeta {
            hash: [0xab; 32],
            algorithm: HashAlgorithm::Blake3,
            created,
            expires: Some(expires),
            order_limit: b"order-limit-bytes".to_vec(),
        };
        let map = metadata_map(&meta).unwrap();
        let hash = "ab".repeat(32);
        assert_eq!(
            map.get("piece-hash").map(String::as_str),
            Some(hash.as_str())
        );
        assert_eq!(
            map.get("hash-algorithm").map(String::as_str),
            Some("blake3")
        );
        assert_eq!(
            map.get("order-limit").map(String::as_str),
            Some("b3JkZXItbGltaXQtYnl0ZXM=")
        );
        let info = piece_from_metadata("sat", "piece", 4, &map).unwrap();
        assert_eq!(info.hash, meta.hash);
        assert_eq!(info.algorithm, HashAlgorithm::Blake3);
        assert_eq!(info.order_limit, meta.order_limit);
        assert_eq!(
            index::system_to_millis(info.created).unwrap(),
            index::system_to_millis(created).unwrap()
        );
        assert_eq!(
            index::system_to_millis(info.expires.unwrap()).unwrap(),
            index::system_to_millis(expires).unwrap()
        );
        assert_eq!(info.state, PieceState::Live);

        let mut bare = HashMap::new();
        bare.insert("note".to_owned(), "x".to_owned());
        assert!(piece_from_metadata("sat", "piece", 1, &bare).is_none());
    }

    #[test]
    fn split_key_is_prefix_satellite_and_piece() {
        assert_eq!(
            split_object_key("pieces", "pieces/sat/abc").unwrap(),
            ("sat".to_owned(), "abc".to_owned())
        );
        assert!(split_object_key("pieces", "pieces/sat").is_none());
        assert!(split_object_key("pieces", "other/sat/abc").is_none());
        assert!(split_object_key("pieces", "pieces/sat/a/b").is_none());
    }

    #[test]
    fn empty_order_limit_is_rejected() {
        let meta = PieceMeta {
            hash: [1; 32],
            algorithm: HashAlgorithm::Sha256,
            created: UNIX_EPOCH + std::time::Duration::from_secs(10),
            expires: None,
            order_limit: Vec::new(),
        };
        assert!(matches!(metadata_map(&meta), Err(Error::Metadata(_))));
    }
}
