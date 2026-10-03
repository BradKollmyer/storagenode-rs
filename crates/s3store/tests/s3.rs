//! Piece puts against an in-process `s3s` server. No real S3 endpoint.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use s3s::auth::SimpleAuth;
use s3s::service::S3ServiceBuilder;
use s3s_fs::FileSystem;
use s3store::{
    Config, Error, HashAlgorithm, PART_SIZE, PIECES_DB, PieceMeta, PieceState, Store, TRASH_KEEP,
};

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
    config: Config,
}

impl TestS3 {
    async fn start() -> Self {
        let root = TempRoot::new();
        // s3s-fs CreateBucket is create_dir on the bucket path.
        std::fs::create_dir(root.path().join(BUCKET)).expect("bucket dir");
        let addr = spawn_server(root.path());
        let endpoint = format!("http://{addr}");
        let config = Config {
            endpoint: endpoint.clone(),
            bucket: BUCKET.to_owned(),
            access_key_id: ACCESS_KEY.to_owned(),
            secret_access_key: SECRET.to_owned(),
            volume: root.path().join("volume"),
            allocated_bytes: 1 << 40,
            ..Config::default()
        };
        let store = Store::new(config.clone()).expect("store");
        store.startup().await.expect("startup");
        Self {
            store,
            root,
            endpoint,
            config,
        }
    }

    /// Drops the open database, deletes it, and opens a new one on the same volume.
    fn reopen_without_db(&mut self) {
        let scratch = self.root.path().join(format!(
            "scratch-{}",
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&scratch).expect("scratch");
        let mut scratch_config = self.config.clone();
        scratch_config.volume = scratch;
        // Drop the connection before unlinking pieces.db.
        self.store = Store::new(scratch_config).expect("scratch store");
        for name in [PIECES_DB, "pieces.db-wal", "pieces.db-shm"] {
            let path = self.config.volume.join(name);
            if path.exists() {
                std::fs::remove_file(&path).expect("remove db");
            }
        }
        self.store = Store::new(self.config.clone()).expect("reopen");
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

    let volume = TempRoot::new();
    let missing_bucket = Store::new(Config {
        endpoint: s3.endpoint.clone(),
        bucket: "no-such-bucket".to_owned(),
        access_key_id: ACCESS_KEY.to_owned(),
        secret_access_key: SECRET.to_owned(),
        volume: volume.path().join("volume"),
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
    let volume = TempRoot::new();
    let store = Store::new(Config {
        endpoint: "http://127.0.0.1:1".to_owned(),
        bucket: BUCKET.to_owned(),
        access_key_id: ACCESS_KEY.to_owned(),
        secret_access_key: SECRET.to_owned(),
        volume: volume.path().join("volume"),
        ..Config::default()
    })
    .expect("store");
    let err = store.head_bucket().await.expect_err("unreachable");
    let text = err.to_string();
    assert!(!text.contains(SECRET), "{text}");
    assert!(!matches!(err, Error::NotFound), "{err}");
}

fn piece_meta(expires: Option<SystemTime>, hash_byte: u8) -> PieceMeta {
    PieceMeta {
        hash: [hash_byte; 32],
        algorithm: HashAlgorithm::Blake3,
        created: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        expires,
        order_limit: b"order-limit-bytes".to_vec(),
    }
}

#[tokio::test]
async fn trash_restore_and_chore() {
    let s3 = TestS3::start().await;
    let store = &s3.store;
    let body = b"trashed-bytes";
    store
        .put_piece("sat-a", "piece-1", body, piece_meta(None, 0x11))
        .await
        .expect("put");
    store
        .put_piece("sat-b", "piece-1", b"other", piece_meta(None, 0x22))
        .await
        .expect("other sat");
    assert!(store.exists("sat-a", "piece-1").expect("exists"));

    let trashed_at = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    store
        .trash("sat-a", "piece-1", trashed_at)
        .await
        .expect("trash");
    assert!(!store.exists("sat-a", "piece-1").expect("exists"));
    assert!(store.exists("sat-b", "piece-1").expect("other"));
    // Trash is a flag. The object stays at the same key.
    assert_eq!(
        store.get("sat-a", "piece-1", None).await.expect("object"),
        body
    );

    let download = store
        .download("sat-a", "piece-1", None)
        .await
        .expect("download trash");
    assert!(download.restored_from_trash);
    assert_eq!(download.bytes, body);
    assert!(!store.exists("sat-a", "piece-1").expect("still trash"));

    // A second trash does not move the 7-day clock.
    store
        .trash("sat-a", "piece-1", trashed_at + Duration::from_secs(10))
        .await
        .expect("trash again");
    let info = store.info("sat-a", "piece-1").expect("info").expect("row");
    assert_eq!(info.state, PieceState::Trash);
    assert_eq!(info.trashed_at, Some(trashed_at));

    assert_eq!(store.restore_trash("sat-b").await.expect("other"), 0);
    assert!(!store.exists("sat-a", "piece-1").expect("untouched"));
    assert_eq!(store.restore_trash("sat-a").await.expect("restore"), 1);
    assert!(store.exists("sat-a", "piece-1").expect("live"));
    let download = store
        .download("sat-a", "piece-1", Some(0..4))
        .await
        .expect("download");
    assert!(!download.restored_from_trash);
    assert_eq!(download.bytes, b"tras");

    store
        .trash("sat-a", "piece-1", trashed_at)
        .await
        .expect("trash");
    store
        .run_chore(trashed_at + TRASH_KEEP - Duration::from_secs(1))
        .await
        .expect("too soon");
    assert!(
        store
            .download("sat-a", "piece-1", None)
            .await
            .expect("kept")
            .restored_from_trash
    );
    store
        .run_chore(trashed_at + TRASH_KEEP)
        .await
        .expect("empty trash");
    let err = store
        .download("sat-a", "piece-1", None)
        .await
        .expect_err("deleted");
    assert!(matches!(err, Error::NotFound), "{err}");
    let err = store
        .get("sat-a", "piece-1", None)
        .await
        .expect_err("object gone");
    assert!(matches!(err, Error::NotFound), "{err}");
    assert!(store.info("sat-a", "piece-1").expect("info").is_none());
    assert!(store.exists("sat-b", "piece-1").expect("other sat"));

    // No index row: the object is not served.
    store
        .put("sat-a", "orphan", b"hidden", None)
        .await
        .expect("raw put");
    let err = store
        .download("sat-a", "orphan", None)
        .await
        .expect_err("unreferenced");
    assert!(matches!(err, Error::NotFound), "{err}");
    assert_eq!(
        store.get("sat-a", "orphan", None).await.expect("bytes"),
        b"hidden"
    );

    let mut upload = store
        .upload_piece("sat-b", "piece-1", piece_meta(None, 0x33))
        .expect("upload");
    upload.write(b"nope").await.expect("write");
    upload.cancel().await.expect("cancel");
    assert!(store.exists("sat-b", "piece-1").expect("still live"));
    assert_eq!(
        store.get("sat-b", "piece-1", None).await.expect("kept"),
        b"other"
    );
}

#[tokio::test]
async fn chore_deletes_expired_pieces() {
    let s3 = TestS3::start().await;
    let store = &s3.store;
    let created = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let expires = created + Duration::from_secs(100);
    store
        .put_piece("sat-e", "old", b"gone", piece_meta(Some(expires), 0x44))
        .await
        .expect("old");
    store
        .put_piece(
            "sat-e",
            "keep",
            b"stay",
            piece_meta(Some(expires + Duration::from_secs(50)), 0x45),
        )
        .await
        .expect("keep");
    store
        .put_piece("sat-e", "forever", b"ever", piece_meta(None, 0x46))
        .await
        .expect("forever");

    store
        .run_chore(expires - Duration::from_secs(1))
        .await
        .expect("before expiry");
    assert!(store.exists("sat-e", "old").expect("not yet"));

    store.run_chore(expires).await.expect("expire");
    assert!(store.info("sat-e", "old").expect("info").is_none());
    assert!(matches!(
        store.get("sat-e", "old", None).await,
        Err(Error::NotFound)
    ));
    assert!(store.exists("sat-e", "keep").expect("keep"));
    assert!(store.exists("sat-e", "forever").expect("forever"));

    store
        .run_chore(expires + Duration::from_secs(50))
        .await
        .expect("later");
    assert!(store.info("sat-e", "keep").expect("info").is_none());
    assert!(store.exists("sat-e", "forever").expect("no expiry"));
    assert_eq!(
        store.get("sat-e", "forever", None).await.expect("bytes"),
        b"ever"
    );
}

#[tokio::test]
async fn free_space_is_allocation_minus_live_sizes() {
    let s3 = TestS3::start().await;
    let mut config = s3.config.clone();
    config.allocated_bytes = 1000;
    config.volume = s3.root.path().join("space-volume");
    let store = Store::new(config).expect("store");
    store.startup().await.expect("startup");
    let space = store.space().expect("space");
    assert_eq!(
        (space.allocated, space.used, space.trash, space.free),
        (1000, 0, 0, 1000)
    );

    store
        .put_piece("sat-s", "a", &[1; 400], piece_meta(None, 0x01))
        .await
        .expect("a");
    store
        .put_piece("sat-s", "b", &[2; 100], piece_meta(None, 0x02))
        .await
        .expect("b");
    let space = store.space().expect("space");
    assert_eq!((space.used, space.trash, space.free), (500, 0, 500));

    store
        .put_piece("sat-s", "a", &[3; 50], piece_meta(None, 0x03))
        .await
        .expect("overwrite");
    let space = store.space().expect("space");
    assert_eq!((space.used, space.free), (150, 850));

    store
        .trash(
            "sat-s",
            "b",
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        )
        .await
        .expect("trash");
    let space = store.space().expect("space");
    assert_eq!((space.used, space.trash, space.free), (50, 100, 950));

    store
        .put_piece("sat-s", "big", &[9; 2000], piece_meta(None, 0x04))
        .await
        .expect("over");
    assert_eq!(store.space().expect("space").free, 0);
}

#[tokio::test]
async fn rebuild_from_object_metadata() {
    let mut s3 = TestS3::start().await;
    let created = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let expires = created + Duration::from_secs(3600);
    let body = b"rebuild-me";
    s3.store
        .put_piece("sat-r", "piece", body, piece_meta(Some(expires), 0xab))
        .await
        .expect("put");

    let mut big = vec![0_u8; PART_SIZE + 3];
    big[0] = 1;
    big[PART_SIZE] = 2;
    s3.store
        .put_piece("sat-r", "big", &big, piece_meta(None, 0xcd))
        .await
        .expect("multipart");

    // Trash is not stored on the object.
    s3.store
        .trash("sat-r", "piece", created)
        .await
        .expect("trash");
    s3.store
        .put("sat-r", "plain", b"xyz", Some(note("nope")))
        .await
        .expect("plain");

    let head = s3
        .store
        .head("sat-r", "piece")
        .await
        .expect("head")
        .expect("meta");
    assert_eq!(
        head.get("piece-hash").map(String::as_str),
        Some("ab".repeat(32).as_str())
    );
    assert_eq!(
        head.get("hash-algorithm").map(String::as_str),
        Some("blake3")
    );
    let created_meta = head.get("created").expect("created");
    assert!(
        created_meta.starts_with("2023-11-14T22:13:20"),
        "{created_meta}"
    );
    assert!(head.contains_key("expires"));
    assert_eq!(
        head.get("order-limit").map(String::as_str),
        Some("b3JkZXItbGltaXQtYnl0ZXM=")
    );

    s3.reopen_without_db();
    s3.store.startup().await.expect("rebuild");

    let info = s3.store.info("sat-r", "piece").expect("info").expect("row");
    assert_eq!(info.state, PieceState::Live);
    assert_eq!(info.hash, [0xab; 32]);
    assert_eq!(info.algorithm, HashAlgorithm::Blake3);
    assert_eq!(info.order_limit, b"order-limit-bytes");
    assert_eq!(info.size, u64::try_from(body.len()).unwrap());
    assert_eq!(info.created, created);
    assert_eq!(info.expires, Some(expires));
    assert!(info.trashed_at.is_none());
    assert!(s3.store.exists("sat-r", "piece").expect("exists"));
    let download = s3
        .store
        .download("sat-r", "piece", None)
        .await
        .expect("download");
    assert!(!download.restored_from_trash);
    assert_eq!(download.bytes, body);

    let big_info = s3.store.info("sat-r", "big").expect("info").expect("row");
    assert_eq!(big_info.size, u64::try_from(big.len()).unwrap());
    assert_eq!(big_info.hash, [0xcd; 32]);
    assert!(big_info.expires.is_none());
    assert_eq!(
        s3.store
            .get("sat-r", "big", Some(0..1))
            .await
            .expect("head byte"),
        [1]
    );

    assert!(s3.store.info("sat-r", "plain").expect("info").is_none());
    assert!(!s3.store.exists("sat-r", "plain").expect("plain"));

    // The database file exists now, so startup must not rebuild trash away.
    s3.store
        .trash("sat-r", "piece", created)
        .await
        .expect("trash");
    s3.store.startup().await.expect("startup");
    assert_eq!(
        s3.store
            .info("sat-r", "piece")
            .expect("info")
            .expect("row")
            .state,
        PieceState::Trash
    );
}
