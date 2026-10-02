//! Piece puts against an in-process `s3s` server. No real S3 endpoint.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

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
        let path = std::env::temp_dir().join(format!("s3store-{}-{nanos}", process::id()));
        std::fs::create_dir_all(&path).expect("temp root");
        Self(path)
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct TestS3 {
    store: Store,
    _root: TempRoot,
}

impl TestS3 {
    async fn start() -> Self {
        let root = TempRoot::new();
        let addr = spawn_server(&root.0);
        let endpoint = format!("http://{addr}");
        create_bucket(&endpoint).await;
        let store = Store::new(Config {
            endpoint,
            bucket: BUCKET.to_owned(),
            access_key_id: ACCESS_KEY.to_owned(),
            secret_access_key: SECRET.to_owned(),
            ..Config::default()
        })
        .expect("store");
        store.head_bucket().await.expect("bucket is reachable");
        Self { store, _root: root }
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

fn admin_client(endpoint: &str) -> aws_sdk_s3::Client {
    let config = aws_sdk_s3::Config::builder()
        .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .endpoint_url(endpoint)
        .force_path_style(true)
        .credentials_provider(aws_sdk_s3::config::Credentials::new(
            ACCESS_KEY,
            SECRET,
            None,
            None,
            "s3store-test",
        ))
        .request_checksum_calculation(aws_sdk_s3::config::RequestChecksumCalculation::WhenRequired)
        .response_checksum_validation(aws_sdk_s3::config::ResponseChecksumValidation::WhenRequired)
        .build();
    aws_sdk_s3::Client::from_conf(config)
}

async fn create_bucket(endpoint: &str) {
    admin_client(endpoint)
        .create_bucket()
        .bucket(BUCKET)
        .send()
        .await
        .expect("create bucket");
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
