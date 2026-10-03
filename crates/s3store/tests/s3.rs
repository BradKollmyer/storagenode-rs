//! Piece puts against an in-process `s3s` server. No real S3 endpoint.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use s3s::auth::SimpleAuth;
use s3s::service::S3ServiceBuilder;
use s3s_fs::FileSystem;
use s3store::{Config, Error, PART_SIZE, Store};

const ACCESS_KEY: &str = "test-access-key";
const SECRET: &str = "test-secret-key";
const BUCKET: &str = "pieces";

struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("s3store-{}-{nanos}-{seq}", process::id()));
        std::fs::create_dir_all(&path).expect("temp root");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct TestS3 {
    store: Store,
    root: TempRoot,
    endpoint: String,
}

impl TestS3 {
    async fn start() -> Self {
        let root = TempRoot::new();
        // s3s-fs CreateBucket is create_dir on the bucket path.
        std::fs::create_dir(root.path().join(BUCKET)).expect("bucket dir");
        let addr = spawn_server(root.path());
        let endpoint = format!("http://{addr}");
        let store = Store::new(Config {
            endpoint: endpoint.clone(),
            bucket: BUCKET.to_owned(),
            access_key_id: ACCESS_KEY.to_owned(),
            secret_access_key: SECRET.to_owned(),
            ..Config::default()
        })
        .expect("store");
        store.head_bucket().await.expect("bucket is reachable");
        Self {
            store,
            root,
            endpoint,
        }
    }
}

fn spawn_server(root: &Path) -> SocketAddr {
    let fs = FileSystem::new(root).expect("s3s filesystem");
    let mut builder = S3ServiceBuilder::new(fs);
    builder.set_auth(SimpleAuth::from_single(ACCESS_KEY, SECRET));
    let service = builder.build();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let addr = listener.local_addr().expect("local addr");
    let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");

    tokio::spawn(async move {
        let http = ConnBuilder::new(TokioExecutor::new());
        loop {
            let (socket, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(err) => {
                    eprintln!("s3s accept: {err}");
                    break;
                }
            };
            let conn = http
                .serve_connection(TokioIo::new(socket), service.clone())
                .into_owned();
            tokio::spawn(async move {
                let _ = conn.await;
            });
        }
    });
    addr
}

/// s3s-fs records `CreateMultipartUpload` as `.upload-{id}.json` and each
/// `UploadPart` as `.upload_id-{id}.part-{n}` in the filesystem root.
fn multipart_files(root: &Path) -> Vec<(String, u64)> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(root).expect("root") {
        let entry = entry.expect("entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(".upload-")
            || name.starts_with(".upload_id-")
            || name.contains(".upload-")
        {
            let len = entry.metadata().expect("meta").len();
            found.push((name, len));
        }
    }
    found.sort();
    found
}

fn part_files(root: &Path) -> Vec<(String, u64)> {
    multipart_files(root)
        .into_iter()
        .filter(|(name, _)| name.starts_with(".upload_id-") && name.contains(".part-"))
        .collect()
}

fn note(value: &str) -> HashMap<String, String> {
    let mut meta = HashMap::new();
    meta.insert("note".to_owned(), value.to_owned());
    meta
}

#[tokio::test]
async fn put_range_head_overwrite_and_delete() {
    let s3 = TestS3::start().await;
    let store = &s3.store;
    let body = b"abcdefghijklmnopqrstuvwxyz";

    store
        .put("sat-a", "piece-1", body, Some(note("alpha")))
        .await
        .expect("put");

    let got = store
        .get("sat-a", "piece-1", Some(0..4))
        .await
        .expect("range");
    assert_eq!(got, b"abcd");

    let empty = store
        .get("sat-a", "piece-1", Some(4..4))
        .await
        .expect("empty range");
    assert!(empty.is_empty());

    let tail = store
        .get("sat-a", "piece-1", Some(20..26))
        .await
        .expect("tail");
    assert_eq!(tail, b"uvwxyz");

    let all = store.get("sat-a", "piece-1", None).await.expect("full");
    assert_eq!(all, body);

    let meta = store.head("sat-a", "piece-1").await.expect("head");
    assert_eq!(
        meta.expect("metadata").get("note").map(String::as_str),
        Some("alpha")
    );

    store
        .put("sat-a", "piece-1", b"overwritten", Some(note("beta")))
        .await
        .expect("overwrite");
    let got = store.get("sat-a", "piece-1", None).await.expect("get");
    assert_eq!(got, b"overwritten");
    let meta = store.head("sat-a", "piece-1").await.expect("head");
    assert_eq!(
        meta.expect("metadata").get("note").map(String::as_str),
        Some("beta")
    );

    // A second piece does not replace the first.
    store
        .put("sat-a", "piece-2", b"other", None)
        .await
        .expect("other piece");
    assert_eq!(
        store.get("sat-a", "piece-1", None).await.expect("kept"),
        b"overwritten"
    );
    assert!(
        store
            .head("sat-a", "piece-2")
            .await
            .expect("no meta")
            .is_none()
    );

    store.delete("sat-a", "piece-1").await.expect("delete");
    let err = store
        .get("sat-a", "piece-1", None)
        .await
        .expect_err("deleted");
    assert!(matches!(err, Error::NotFound), "{err}");
    store
        .delete("sat-a", "piece-1")
        .await
        .expect("delete again");
}

#[tokio::test]
async fn multipart_put_and_range() {
    let s3 = TestS3::start().await;
    let store = &s3.store;
    let mut body = vec![0_u8; PART_SIZE + 7];
    for (i, byte) in body.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }

    let mut upload = store
        .upload("sat-b", "big", Some(note("big")))
        .expect("upload");
    upload.write(&body[..PART_SIZE]).await.expect("first part");
    upload.write(&body[PART_SIZE..]).await.expect("tail");
    upload.finish().await.expect("finish");

    let head = store.get("sat-b", "big", Some(0..3)).await.expect("head");
    assert_eq!(head, &body[..3]);
    let tail_at = (PART_SIZE as u64) - 1;
    let tail = store
        .get("sat-b", "big", Some(tail_at..body.len() as u64))
        .await
        .expect("tail");
    assert_eq!(tail, &body[PART_SIZE - 1..]);

    let meta = store.head("sat-b", "big").await.expect("head");
    assert_eq!(
        meta.expect("metadata").get("note").map(String::as_str),
        Some("big")
    );
}

#[tokio::test]
async fn cancel_discards_in_progress_uploads() {
    let s3 = TestS3::start().await;
    let store = &s3.store;

    let mut small = store.upload("sat-c", "small", None).expect("upload");
    small.write(b"not-committed").await.expect("write");
    small.cancel().await.expect("cancel");
    let err = store
        .get("sat-c", "small", None)
        .await
        .expect_err("small cancel");
    assert!(matches!(err, Error::NotFound), "{err}");

    let mut big = store.upload("sat-c", "big", None).expect("upload");
    let chunk = vec![7_u8; PART_SIZE];
    big.write(&chunk).await.expect("full part");
    big.write(b"more").await.expect("past one part");
    big.cancel().await.expect("cancel multipart");
    let err = store
        .get("sat-c", "big", None)
        .await
        .expect_err("multipart cancel");
    assert!(matches!(err, Error::NotFound), "{err}");

    store
        .put("sat-c", "big", b"after-cancel", None)
        .await
        .expect("put after cancel");
    assert_eq!(
        store.get("sat-c", "big", None).await.expect("get"),
        b"after-cancel"
    );

    // Cancel of an uncommitted overwrite leaves the previous object.
    store
        .put("sat-c", "kept", b"original", Some(note("keep")))
        .await
        .expect("original");
    let mut overwrite = store
        .upload("sat-c", "kept", Some(note("next")))
        .expect("upload");
    overwrite.write(b"not-committed").await.expect("write");
    overwrite.cancel().await.expect("cancel overwrite");
    assert_eq!(
        store.get("sat-c", "kept", None).await.expect("kept"),
        b"original"
    );
    let meta = store.head("sat-c", "kept").await.expect("head");
    assert_eq!(
        meta.expect("meta").get("note").map(String::as_str),
        Some("keep")
    );

    let mut big_overwrite = store.upload("sat-c", "kept", None).expect("upload");
    big_overwrite
        .write(&vec![9_u8; PART_SIZE])
        .await
        .expect("part");
    big_overwrite.write(b"x").await.expect("tail");
    big_overwrite
        .cancel()
        .await
        .expect("cancel multipart overwrite");
    assert_eq!(
        store
            .get("sat-c", "kept", None)
            .await
            .expect("still original"),
        b"original"
    );
}

#[tokio::test]
async fn part_size_boundary_is_one_put_or_two_parts() {
    let s3 = TestS3::start().await;
    let store = &s3.store;
    let root = s3.root.path();

    let mut exact = vec![0_u8; PART_SIZE];
    for (i, byte) in exact.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    let mut upload = store.upload("sat-bound", "exact", None).expect("upload");
    upload.write(&exact).await.expect("write exact");
    assert!(
        multipart_files(root).is_empty(),
        "exactly PART_SIZE must not call CreateMultipartUpload: {:?}",
        multipart_files(root)
    );
    upload.finish().await.expect("finish exact");
    assert!(
        multipart_files(root).is_empty(),
        "PutObject leaves no multipart files: {:?}",
        multipart_files(root)
    );
    assert_eq!(
        store
            .get("sat-bound", "exact", Some(0..1))
            .await
            .expect("first"),
        &exact[..1]
    );
    let end = PART_SIZE as u64;
    assert_eq!(
        store
            .get("sat-bound", "exact", Some(end - 1..end))
            .await
            .expect("last"),
        &exact[PART_SIZE - 1..]
    );

    let mut plus = exact;
    plus.push(0x5a);
    let mut upload = store.upload("sat-bound", "plus", None).expect("upload");
    upload.write(&plus).await.expect("write plus");
    let parts = part_files(root);
    assert_eq!(
        parts.len(),
        1,
        "first part is uploaded before finish; the extra byte is the second part: {parts:?}"
    );
    assert!(parts[0].0.contains(".part-1"), "{parts:?}");
    assert_eq!(parts[0].1, PART_SIZE as u64, "{parts:?}");
    assert!(
        multipart_files(root)
            .iter()
            .any(|(name, _)| name.starts_with(".upload-")),
        "CreateMultipartUpload wrote an upload id: {:?}",
        multipart_files(root)
    );
    upload.finish().await.expect("finish plus");
    assert!(
        part_files(root).is_empty(),
        "complete removes part files: {:?}",
        part_files(root)
    );
    let tail_at = (PART_SIZE as u64) - 1;
    let tail = store
        .get("sat-bound", "plus", Some(tail_at..tail_at + 2))
        .await
        .expect("tail");
    assert_eq!(tail, &plus[PART_SIZE - 1..]);
}

#[tokio::test]
async fn missing_key_head_and_empty_range_are_not_found() {
    let s3 = TestS3::start().await;
    let store = &s3.store;

    let err = store.head("sat-z", "missing").await.expect_err("head");
    assert!(matches!(err, Error::NotFound), "{err}");
    let err = store
        .get("sat-z", "missing", Some(0..0))
        .await
        .expect_err("empty range");
    assert!(matches!(err, Error::NotFound), "{err}");
    let err = store.get("sat-z", "missing", None).await.expect_err("full");
    assert!(matches!(err, Error::NotFound), "{err}");

    store
        .put("sat-z", "empty", b"", Some(note("empty")))
        .await
        .expect("empty put");
    assert!(
        store
            .get("sat-z", "empty", Some(0..0))
            .await
            .expect("empty range")
            .is_empty()
    );
    let meta = store.head("sat-z", "empty").await.expect("head empty");
    assert_eq!(
        meta.expect("meta").get("note").map(String::as_str),
        Some("empty")
    );

    let missing_bucket = Store::new(Config {
        endpoint: s3.endpoint.clone(),
        bucket: "no-such-bucket".to_owned(),
        access_key_id: ACCESS_KEY.to_owned(),
        secret_access_key: SECRET.to_owned(),
        ..Config::default()
    })
    .expect("store");
    let err = missing_bucket
        .head_bucket()
        .await
        .expect_err("missing bucket");
    assert!(!matches!(err, Error::NotFound), "{err}");
}

#[tokio::test]
async fn drop_aborts_multipart_without_deleting_a_later_put() {
    let s3 = TestS3::start().await;
    let store = &s3.store;
    {
        let mut upload = store.upload("sat-d", "race", None).expect("upload");
        let chunk = vec![3_u8; PART_SIZE];
        upload.write(&chunk).await.expect("part");
        upload.write(b"x").await.expect("tail");
    }
    store
        .put("sat-d", "race", b"committed", None)
        .await
        .expect("put");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        store.get("sat-d", "race", None).await.expect("get"),
        b"committed"
    );
}

#[tokio::test]
async fn head_bucket_errors_when_unreachable() {
    let store = Store::new(Config {
        endpoint: "http://127.0.0.1:1".to_owned(),
        bucket: BUCKET.to_owned(),
        access_key_id: ACCESS_KEY.to_owned(),
        secret_access_key: SECRET.to_owned(),
        ..Config::default()
    })
    .expect("store");
    let err = store.head_bucket().await.expect_err("unreachable");
    let text = err.to_string();
    assert!(!text.contains(SECRET), "{text}");
    assert!(!matches!(err, Error::NotFound), "{err}");
}
