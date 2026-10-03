//! S3 piece store.
//!
//! One object per piece. The key is `{prefix}/{satellite-id}/{piece-id}`
//! (prefix defaults to `pieces`). The body is the raw piece bytes, with no
//! hashstore footer. User metadata is stored and returned without the
//! `x-amz-meta-` prefix. This crate does not define piece-hash keys.
//!
//! Bodies of at most [`PART_SIZE`] bytes use one `PutObject`. Larger bodies
//! use multipart upload, [`PART_SIZE`] per part, last part shorter.

#![deny(clippy::undocumented_unsafe_blocks)]

use std::collections::HashMap;
use std::fmt;

use aws_sdk_s3::config::{
    BehaviorVersion, Credentials, Region, RequestChecksumCalculation, ResponseChecksumValidation,
};
use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};

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
            .finish()
    }
}

/// Client for piece objects in one bucket.
pub struct Store {
    client: aws_sdk_s3::Client,
    bucket: String,
    prefix: String,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store")
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
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
}

/// Piece-store result.
pub type Result<T> = std::result::Result<T, Error>;

impl Store {
    /// Builds a client. Does not contact the bucket; call [`Store::head_bucket`] for that.
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

        Ok(Self {
            client: aws_sdk_s3::Client::from_conf(sdk),
            bucket: config.bucket,
            prefix,
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

    /// Deletes the object. Already-absent keys succeed.
    pub async fn delete(&self, satellite_id: &str, piece_id: &str) -> Result<()> {
        let key = object_key(&self.prefix, satellite_id, piece_id)?;
        delete_object(&self.client, &self.bucket, &key).await
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
    pub async fn finish(mut self) -> Result<()> {
        let result = self.finish_inner().await;
        if result.is_ok() {
            // Complete already published the object. Do not abort it on drop.
            self.upload_id = None;
        }
        result
    }

    /// Aborts an in-progress multipart upload.
    ///
    /// An object already stored at this key stays. This upload has not committed,
    /// so cancel does not delete the key.
    pub async fn cancel(mut self) -> Result<()> {
        self.abort_multipart().await?;
        self.upload_id = None;
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
}

impl Drop for Upload {
    fn drop(&mut self) {
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
}
