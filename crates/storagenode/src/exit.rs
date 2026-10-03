//! Graceful exit. The satellite moves the data. This node only receives.
//!
//! `exit-satellite` stores a pending row. The chore dials `Process` for each
//! pending satellite and only calls Recv. `NotReady` waits for the next tick.
//! `ExitCompleted` stores the receipt, then deletes that satellite's pieces.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use prost::Message;
use s3store::{ExitRow, ExitStatus, Store};
use storj_rpc::transport::{self, TransportMode};
use storj_rpc::{Conn, Error as RpcError, NodeId};

use crate::gracefulexit::SatelliteMessage;
use crate::gracefulexit::satellite_message::Message as SatelliteMessageKind;
use crate::server::Node;

/// `/gracefulexit.SatelliteGracefulExit/Process`.
pub(crate) const PROCESS: &str = "/gracefulexit.SatelliteGracefulExit/Process";

/// `/gracefulexit.SatelliteGracefulExit/GracefulExitFeasibility`.
///
/// The Go console dials this. This process has no dashboard, so the worker
/// does not.
#[allow(dead_code)]
pub(crate) const FEASIBILITY: &str = "/gracefulexit.SatelliteGracefulExit/GracefulExitFeasibility";

/// Go `gracefulexit.Config.ChoreInterval` release default.
const INTERVAL: Duration = Duration::from_secs(60);

/// One dial. A failure leaves the row pending for the next tick.
const DIAL_TIMEOUT: Duration = Duration::from_secs(60);

/// drpc `FailedPrecondition`. The satellite refused the exit.
const RPC_FAILED_PRECONDITION: u64 = 9;

const TRANSFER_UNSUPPORTED: &str = "satellite has requested piece transfer, but piece-transfer-based graceful exit is no longer supported";
const DELETE_UNSUPPORTED: &str = "satellite has requested piece deletion, but piece-transfer-based graceful exit is no longer supported";

/// One pass per pending satellite. A satellite that already has a worker is skipped.
pub(crate) async fn serve(node: Arc<Node>) {
    let running = Arc::new(Mutex::new(HashSet::<String>::new()));
    loop {
        if let Err(err) = delete_finished(&node).await {
            eprintln!("storagenode: graceful exit delete: {err}");
        }
        match node.piece_store().pending_exits() {
            Ok(rows) => {
                for row in rows {
                    launch(&node, &running, row.satellite_id);
                }
            }
            Err(err) => eprintln!("storagenode: graceful exit list: {err}"),
        }
        tokio::time::sleep(INTERVAL).await;
    }
}

fn launch(node: &Arc<Node>, running: &Arc<Mutex<HashSet<String>>>, satellite_id: String) {
    {
        let mut guard = running.lock().unwrap_or_else(|err| err.into_inner());
        if !guard.insert(satellite_id.clone()) {
            return;
        }
    }
    let node = Arc::clone(node);
    let running = Arc::clone(running);
    tokio::spawn(async move {
        if let Err(err) = process_satellite(&node, &satellite_id).await {
            eprintln!("storagenode: graceful exit {satellite_id}: {err}");
        }
        running
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .remove(&satellite_id);
    });
}

async fn delete_finished(node: &Node) -> Result<(), String> {
    let rows = node
        .piece_store()
        .exits_to_delete()
        .map_err(|err| err.to_string())?;
    for row in rows {
        if let Err(err) = delete_pieces(node.piece_store(), &row.satellite_id).await {
            eprintln!(
                "storagenode: graceful exit {} delete: {err}",
                row.satellite_id
            );
        }
    }
    Ok(())
}

/// Deletes pieces for a stored receipt, then marks that delete finished.
///
/// The receipt is already committed. A delete error leaves it in place.
pub(crate) async fn delete_pieces(store: &Store, satellite_id: &str) -> Result<(), String> {
    store
        .delete_satellite(satellite_id)
        .await
        .map_err(|err| err.to_string())?;
    store
        .mark_exit_deleted(satellite_id)
        .map_err(|err| err.to_string())?;
    Ok(())
}

/// Dials `Process` while the row is pending. Tests call this directly.
pub(crate) async fn process_satellite(node: &Node, satellite_id: &str) -> Result<(), String> {
    match node
        .piece_store()
        .exit_row(satellite_id)
        .map_err(|err| err.to_string())?
    {
        Some(row) if row.status == ExitStatus::Pending => {}
        _ => return Ok(()),
    }
    let id: NodeId = satellite_id
        .parse()
        .map_err(|_| format!("satellite id {satellite_id} is not a node id"))?;
    let Some(address) = node.satellite_address(id) else {
        return Err(format!("satellite {id} is not trusted"));
    };
    if address.is_empty() {
        return Err(format!("satellite {id} has no dial address"));
    }
    let transport = transport::dial(
        node.identity(),
        id,
        &address,
        TransportMode::Tcp,
        DIAL_TIMEOUT,
        None,
    )
    .await
    .map_err(|err| err.to_string())?;
    let mut conn = Conn::new(transport);
    let mut stream = conn
        .open_stream(PROCESS)
        .await
        .map_err(|err| err.to_string())?;
    let result = recv_exit(node, satellite_id, &mut conn, &stream).await;
    let _ = conn.close_send(&mut stream).await;
    result
}

async fn recv_exit(
    node: &Node,
    satellite_id: &str,
    conn: &mut Conn<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>,
    stream: &storj_rpc::RpcStream,
) -> Result<(), String> {
    loop {
        let bytes = match conn.recv_msg_opt(stream).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(()),
            Err(RpcError::Remote { code, message }) if code == RPC_FAILED_PRECONDITION => {
                node.piece_store()
                    .cancel_exit(satellite_id)
                    .map_err(|err| err.to_string())?;
                return Err(format!("graceful exit refused: {message}"));
            }
            Err(err) => return Err(err.to_string()),
        };
        let message = SatelliteMessage::decode(bytes.as_slice()).map_err(|err| err.to_string())?;
        match message.message {
            Some(SatelliteMessageKind::NotReady(_)) => return Ok(()),
            Some(SatelliteMessageKind::TransferPiece(_)) => {
                return Err(TRANSFER_UNSUPPORTED.into());
            }
            Some(SatelliteMessageKind::DeletePiece(_)) => return Err(DELETE_UNSUPPORTED.into()),
            Some(SatelliteMessageKind::ExitFailed(failed)) => {
                let reason = reason_name(failed.reason);
                let encoded = failed.encode_to_vec();
                node.piece_store()
                    .fail_exit(satellite_id, &reason, &encoded)
                    .map_err(|err| err.to_string())?;
                return Ok(());
            }
            Some(SatelliteMessageKind::ExitCompleted(completed)) => {
                let encoded = completed.encode_to_vec();
                node.piece_store()
                    .complete_exit(satellite_id, &encoded)
                    .map_err(|err| err.to_string())?;
                // The receipt is committed. A delete error must not clear it.
                delete_pieces(node.piece_store(), satellite_id).await?;
                return Ok(());
            }
            None => {
                eprintln!("storagenode: unknown graceful exit message from {satellite_id}");
            }
        }
    }
}

fn reason_name(reason: i32) -> String {
    crate::gracefulexit::exit_failed::Reason::try_from(reason)
        .map(|reason| reason.as_str_name().to_owned())
        .unwrap_or_else(|_| reason.to_string())
}

/// One `exit-status` line: satellite, live bytes, status, reason or receipt.
pub fn format_exit_row(row: &ExitRow) -> String {
    format!(
        "{}\t{}\t{}\t{}",
        row.satellite_id,
        row.live_bytes,
        row.status.as_str(),
        exit_detail(row)
    )
}

/// Header plus one line per row. An empty table is still the header.
pub fn format_exit_status(rows: &[ExitRow]) -> String {
    let mut out = String::from("satellite\tlive_bytes\tstatus\tdetail\n");
    for row in rows {
        out.push_str(&format_exit_row(row));
        out.push('\n');
    }
    out
}

fn exit_detail(row: &ExitRow) -> String {
    match row.status {
        ExitStatus::Pending => String::new(),
        ExitStatus::Failed => {
            let encoded = hex(&row.message);
            if row.reason.is_empty() {
                encoded
            } else {
                format!("{} {encoded}", row.reason)
            }
        }
        ExitStatus::Completed => hex(&row.message),
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::process;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as ConnBuilder;
    use s3s::auth::SimpleAuth;
    use s3s::service::S3ServiceBuilder;
    use s3s_fs::FileSystem;
    use s3store::{HashAlgorithm, PieceMeta, Store};
    use storj_rpc::frame::{Kind, Packet};
    use storj_rpc::{Identity, marshal_error, server_config};
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    use crate::config::Config;
    use crate::gracefulexit::{ExitCompleted, ExitFailed};
    use crate::identity::certificate_chain_pem;
    use crate::noise_key;
    use crate::server::TrustedSatellite;

    const ACCESS_KEY: &str = "test-access-key";
    const SECRET: &str = "test-secret-key";
    const BUCKET: &str = "pieces";

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("storagenode-exit-{nanos}-{seq}-{}", process::id()));
            std::fs::create_dir_all(&path).expect("temp");
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

    struct Bucket {
        store: Store,
        root: TempRoot,
        endpoint: String,
    }

    impl Bucket {
        async fn start() -> Self {
            let root = TempRoot::new();
            std::fs::create_dir(root.path().join(BUCKET)).expect("bucket");
            let addr = spawn_s3(root.path());
            let endpoint = format!("http://{addr}");
            let store = Store::new(s3store::Config {
                endpoint: endpoint.clone(),
                bucket: BUCKET.to_owned(),
                access_key_id: ACCESS_KEY.to_owned(),
                secret_access_key: SECRET.to_owned(),
                volume: root.path().join("volume"),
                allocated_bytes: 1 << 40,
                ..s3store::Config::default()
            })
            .expect("store");
            store.startup().await.expect("startup");
            Self {
                store,
                root,
                endpoint,
            }
        }

        fn reopen(&self) -> Store {
            open_again(&self.endpoint, &self.root.path().join("volume"))
        }
    }

    fn open_again(endpoint: &str, volume: &Path) -> Store {
        Store::new(s3store::Config {
            endpoint: endpoint.to_owned(),
            bucket: BUCKET.to_owned(),
            access_key_id: ACCESS_KEY.to_owned(),
            secret_access_key: SECRET.to_owned(),
            volume: volume.to_path_buf(),
            allocated_bytes: 1 << 40,
            ..s3store::Config::default()
        })
        .expect("reopen")
    }

    fn spawn_s3(root: &Path) -> SocketAddr {
        let fs = FileSystem::new(root).expect("fs");
        let mut builder = S3ServiceBuilder::new(fs);
        builder.set_auth(SimpleAuth::from_single(ACCESS_KEY, SECRET));
        let service = builder.build();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("addr");
        let listener = TcpListener::from_std(listener).expect("tokio");
        tokio::spawn(async move {
            let http = ConnBuilder::new(TokioExecutor::new());
            loop {
                let (socket, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(_) => break,
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

    fn meta() -> PieceMeta {
        PieceMeta {
            hash: [0x11; 32],
            algorithm: HashAlgorithm::Sha256,
            created: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            expires: None,
            order_limit: b"limit".to_vec(),
            hash_signature: b"sig".to_vec(),
            hash_timestamp: Some((1_700_000_000, 0)),
        }
    }

    async fn put(store: &Store, satellite: &str, piece: &str, body: &[u8]) {
        store
            .put_piece(satellite, piece, body, meta())
            .await
            .expect("put");
    }

    fn node_for(store: Store, satellites: &[(&Identity, &str)]) -> Node {
        let identity = Identity::generate().expect("node");
        let trusted = satellites
            .iter()
            .map(|(sat, address)| TrustedSatellite {
                id: sat.node_id(),
                address: (*address).to_owned(),
                leaf_der: sat.leaf_der().as_ref().to_vec(),
                ca_der: sat.ca_der().as_ref().to_vec(),
            })
            .collect();
        Node::with_noise(
            identity,
            store,
            trusted,
            noise_key::DEFAULT_PROTOCOL,
            noise_key::Key::generate().expect("noise"),
        )
        .expect("node")
    }

    enum Step {
        Message(Vec<u8>),
        FailedPrecondition,
    }

    fn spawn_satellite(
        identity: Identity,
        steps: Vec<Step>,
        seen: Arc<Mutex<Option<String>>>,
    ) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let address = format!("127.0.0.1:{}", listener.local_addr().expect("addr").port());
        let listener = TcpListener::from_std(listener).expect("tokio");
        tokio::spawn(async move {
            let acceptor =
                tokio_rustls::TlsAcceptor::from(Arc::new(server_config(&identity).expect("tls")));
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let _ = sock.set_nodelay(true);
            if let Err(err) = serve_exit(acceptor, sock, steps, &seen).await {
                eprintln!("test exit satellite: {err}");
            }
        });
        address
    }

    async fn serve_exit(
        acceptor: tokio_rustls::TlsAcceptor,
        mut sock: TcpStream,
        steps: Vec<Step>,
        seen: &Mutex<Option<String>>,
    ) -> Result<(), String> {
        let mut prefix = [0u8; 8];
        sock.read_exact(&mut prefix)
            .await
            .map_err(|err| err.to_string())?;
        if prefix.as_slice() != storj_rpc::DRPC_TLS_MUX_PREFIX {
            return Err("missing drpc prefix".into());
        }
        let tls = acceptor.accept(sock).await.map_err(|err| err.to_string())?;
        let mut conn = Conn::new(tls);
        let invoke = conn.read_packet().await.map_err(|err| err.to_string())?;
        if invoke.kind != Kind::INVOKE {
            return Err("expected invoke".into());
        }
        let path = String::from_utf8(invoke.data).unwrap_or_default();
        *seen.lock().expect("seen") = Some(path);
        let mut message_id = 1u64;
        for step in steps {
            let (kind, data) = match step {
                Step::Message(data) => (Kind::MESSAGE, data),
                Step::FailedPrecondition => (
                    Kind::ERROR,
                    marshal_error(RPC_FAILED_PRECONDITION, "exit refused"),
                ),
            };
            conn.write_packet(&Packet {
                stream_id: invoke.stream_id,
                message_id,
                kind,
                control: false,
                data,
            })
            .await
            .map_err(|err| err.to_string())?;
            message_id += 1;
            if kind == Kind::ERROR {
                break;
            }
        }
        conn.write_packet(&Packet {
            stream_id: invoke.stream_id,
            message_id,
            kind: Kind::CLOSE,
            control: false,
            data: Vec::new(),
        })
        .await
        .map_err(|err| err.to_string())?;
        let _ = tokio::time::timeout(Duration::from_secs(2), conn.read_packet()).await;
        Ok(())
    }

    fn wrap(message: SatelliteMessageKind) -> Vec<u8> {
        SatelliteMessage {
            message: Some(message),
        }
        .encode_to_vec()
    }

    async fn dial(node: &Node, satellite_id: &str) -> Result<(), String> {
        tokio::time::timeout(
            Duration::from_secs(5),
            process_satellite(node, satellite_id),
        )
        .await
        .map_err(|_| "exit worker timed out".to_owned())?
    }

    #[test]
    fn feasibility_path_is_the_satellite_rpc() {
        assert_eq!(
            FEASIBILITY,
            "/gracefulexit.SatelliteGracefulExit/GracefulExitFeasibility"
        );
        assert_eq!(PROCESS, "/gracefulexit.SatelliteGracefulExit/Process");
    }

    #[tokio::test]
    async fn exit_completed_deletes_only_that_satellite() {
        let bucket = Bucket::start().await;
        let satellite = Identity::generate().unwrap();
        let other = Identity::generate().unwrap();
        let sat = satellite.node_id().to_string();
        let other_id = other.node_id().to_string();
        put(&bucket.store, &sat, "live", b"abcd").await;
        put(&bucket.store, &sat, "trashed", b"xyz").await;
        bucket
            .store
            .trash(&sat, "trashed", SystemTime::now())
            .await
            .unwrap();
        put(&bucket.store, &other_id, "kept", b"hello").await;

        let completed = ExitCompleted {
            exit_complete_signature: b"signed-receipt".to_vec(),
            satellite_id: satellite.node_id().as_bytes().to_vec(),
            node_id: Vec::new(),
            completed: None,
        };
        let seen = Arc::new(Mutex::new(None));
        let address = spawn_satellite(
            satellite.clone(),
            vec![
                Step::Message(SatelliteMessage { message: None }.encode_to_vec()),
                Step::Message(wrap(SatelliteMessageKind::ExitCompleted(completed.clone()))),
            ],
            Arc::clone(&seen),
        );
        let endpoint = bucket.endpoint.clone();
        let volume = bucket.root.path().join("volume");
        let node = node_for(bucket.store, &[(&satellite, &address), (&other, "")]);
        node.piece_store().begin_exit(&sat).unwrap();
        assert_eq!(
            node.piece_store()
                .exit_row(&sat)
                .unwrap()
                .unwrap()
                .live_bytes,
            4
        );

        dial(&node, &sat).await.unwrap();

        assert_eq!(seen.lock().unwrap().as_deref(), Some(PROCESS));
        assert!(node.piece_store().info(&sat, "live").unwrap().is_none());
        assert!(node.piece_store().info(&sat, "trashed").unwrap().is_none());
        assert!(matches!(
            node.piece_store().get(&sat, "live", None).await,
            Err(s3store::Error::NotFound)
        ));
        assert!(matches!(
            node.piece_store().get(&sat, "trashed", None).await,
            Err(s3store::Error::NotFound)
        ));
        let kept = node
            .piece_store()
            .download(&other_id, "kept", None)
            .await
            .unwrap();
        assert_eq!(kept.bytes, b"hello");

        let row = node.piece_store().exit_row(&sat).unwrap().unwrap();
        assert_eq!(row.status, ExitStatus::Completed);
        assert_eq!(row.message, completed.encode_to_vec());
        assert!(row.pieces_deleted);
        assert!(node.piece_store().pending_exits().unwrap().is_empty());
        process_satellite(&node, &sat).await.unwrap();

        let again = open_again(&endpoint, &volume);
        let stored = again.exit_row(&sat).unwrap().unwrap();
        assert_eq!(stored.status, ExitStatus::Completed);
        assert_eq!(stored.message, completed.encode_to_vec());
        assert_eq!(stored.live_bytes, 4);
        assert!(again.info(&other_id, "kept").unwrap().is_some());
    }

    #[tokio::test]
    async fn transfer_piece_is_unsupported() {
        let err = unsupported_message(SatelliteMessageKind::TransferPiece(
            crate::gracefulexit::TransferPiece::default(),
        ))
        .await;
        assert_eq!(
            err,
            "satellite has requested piece transfer, but piece-transfer-based graceful exit is no longer supported"
        );
    }

    #[tokio::test]
    async fn delete_piece_is_unsupported() {
        let err = unsupported_message(SatelliteMessageKind::DeletePiece(
            crate::gracefulexit::DeletePiece::default(),
        ))
        .await;
        assert_eq!(
            err,
            "satellite has requested piece deletion, but piece-transfer-based graceful exit is no longer supported"
        );
    }

    async fn unsupported_message(message: SatelliteMessageKind) -> String {
        let bucket = Bucket::start().await;
        let satellite = Identity::generate().unwrap();
        let sat = satellite.node_id().to_string();
        put(&bucket.store, &sat, "live", b"abcd").await;
        let address = spawn_satellite(
            satellite.clone(),
            vec![Step::Message(wrap(message))],
            Arc::new(Mutex::new(None)),
        );
        let node = node_for(bucket.store, &[(&satellite, &address)]);
        node.piece_store().begin_exit(&sat).unwrap();
        let err = dial(&node, &sat).await.expect_err("unsupported");
        let got = node
            .piece_store()
            .download(&sat, "live", None)
            .await
            .unwrap();
        assert_eq!(got.bytes, b"abcd");
        assert_eq!(
            node.piece_store().exit_row(&sat).unwrap().unwrap().status,
            ExitStatus::Pending
        );
        err
    }

    #[tokio::test]
    async fn not_ready_stays_pending_and_download_still_works() {
        let bucket = Bucket::start().await;
        let satellite = Identity::generate().unwrap();
        let sat = satellite.node_id().to_string();
        put(&bucket.store, &sat, "live", b"abcd").await;
        let address = spawn_satellite(
            satellite.clone(),
            vec![Step::Message(wrap(SatelliteMessageKind::NotReady(
                crate::gracefulexit::NotReady {},
            )))],
            Arc::new(Mutex::new(None)),
        );
        let node = node_for(bucket.store, &[(&satellite, &address)]);
        node.piece_store().begin_exit(&sat).unwrap();
        let err = node
            .piece_store()
            .delete_satellite(&sat)
            .await
            .expect_err("pending");
        assert!(err.to_string().contains("receipt"), "{err}");
        dial(&node, &sat).await.unwrap();
        let row = node.piece_store().exit_row(&sat).unwrap().unwrap();
        assert_eq!(row.status, ExitStatus::Pending);
        assert!(row.message.is_empty());
        let got = node
            .piece_store()
            .download(&sat, "live", None)
            .await
            .unwrap();
        assert_eq!(got.bytes, b"abcd");
    }

    #[tokio::test]
    async fn failed_precondition_removes_the_row() {
        let bucket = Bucket::start().await;
        let satellite = Identity::generate().unwrap();
        let sat = satellite.node_id().to_string();
        put(&bucket.store, &sat, "live", b"abcd").await;
        let address = spawn_satellite(
            satellite.clone(),
            vec![Step::FailedPrecondition],
            Arc::new(Mutex::new(None)),
        );
        let node = node_for(bucket.store, &[(&satellite, &address)]);
        node.piece_store().begin_exit(&sat).unwrap();
        let err = dial(&node, &sat).await.expect_err("refused");
        assert!(err.contains("refused"), "{err}");
        assert!(node.piece_store().exit_row(&sat).unwrap().is_none());
        let got = node
            .piece_store()
            .download(&sat, "live", None)
            .await
            .unwrap();
        assert_eq!(got.bytes, b"abcd");
        process_satellite(&node, &sat).await.unwrap();
    }

    #[tokio::test]
    async fn exit_failed_stores_the_reason_and_keeps_pieces() {
        let bucket = Bucket::start().await;
        let satellite = Identity::generate().unwrap();
        let sat = satellite.node_id().to_string();
        put(&bucket.store, &sat, "live", b"abcd").await;
        let failed = ExitFailed {
            exit_failure_signature: b"failed-sig".to_vec(),
            reason: crate::gracefulexit::exit_failed::Reason::InactiveTimeframeExceeded as i32,
            satellite_id: satellite.node_id().as_bytes().to_vec(),
            node_id: Vec::new(),
            failed: None,
        };
        let address = spawn_satellite(
            satellite.clone(),
            vec![Step::Message(wrap(SatelliteMessageKind::ExitFailed(
                failed.clone(),
            )))],
            Arc::new(Mutex::new(None)),
        );
        let endpoint = bucket.endpoint.clone();
        let volume = bucket.root.path().join("volume");
        let node = node_for(bucket.store, &[(&satellite, &address)]);
        let row = node.piece_store().begin_exit(&sat).unwrap();
        assert_eq!(row.live_bytes, 4);
        dial(&node, &sat).await.unwrap();
        let stored = node.piece_store().exit_row(&sat).unwrap().unwrap();
        assert_eq!(stored.status, ExitStatus::Failed);
        assert_eq!(stored.reason, "INACTIVE_TIMEFRAME_EXCEEDED");
        assert_eq!(stored.message, failed.encode_to_vec());
        assert!(!stored.pieces_deleted);
        assert_eq!(stored.live_bytes, 4);
        let text = format_exit_status(std::slice::from_ref(&stored));
        assert!(text.contains(&sat), "{text}");
        assert!(text.contains("\t4\tfailed\t"), "{text}");
        assert!(text.contains("INACTIVE_TIMEFRAME_EXCEEDED"), "{text}");
        assert!(text.contains(&hex(&failed.encode_to_vec())), "{text}");
        let got = node
            .piece_store()
            .download(&sat, "live", None)
            .await
            .unwrap();
        assert_eq!(got.bytes, b"abcd");
        process_satellite(&node, &sat).await.unwrap();

        let again = open_again(&endpoint, &volume);
        let stored = again.exit_row(&sat).unwrap().unwrap();
        assert_eq!(stored.reason, "INACTIVE_TIMEFRAME_EXCEEDED");
        assert_eq!(stored.message, failed.encode_to_vec());
        assert!(again.info(&sat, "live").unwrap().is_some());
    }

    #[tokio::test]
    async fn receipt_stays_when_pieces_are_not_deleted_yet() {
        let bucket = Bucket::start().await;
        let satellite = Identity::generate().unwrap();
        let sat = satellite.node_id().to_string();
        put(&bucket.store, &sat, "live", b"abcd").await;
        let node = node_for(bucket.store, &[(&satellite, "")]);
        node.piece_store().begin_exit(&sat).unwrap();
        let receipt = b"receipt-bytes";
        node.piece_store().complete_exit(&sat, receipt).unwrap();
        let row = node.piece_store().exit_row(&sat).unwrap().unwrap();
        assert_eq!(row.message, receipt);
        assert!(!row.pieces_deleted);
        let got = node
            .piece_store()
            .download(&sat, "live", None)
            .await
            .unwrap();
        assert_eq!(got.bytes, b"abcd");
        delete_pieces(node.piece_store(), &sat).await.unwrap();
        assert!(node.piece_store().info(&sat, "live").unwrap().is_none());
        let row = node.piece_store().exit_row(&sat).unwrap().unwrap();
        assert_eq!(row.message, receipt);
        assert!(row.pieces_deleted);
    }

    #[tokio::test]
    async fn exit_satellite_records_the_row_and_status_prints_it() {
        let bucket = Bucket::start().await;
        let satellite = Identity::generate().unwrap();
        let stranger = Identity::generate().unwrap();
        let sat = satellite.node_id().to_string();
        put(&bucket.store, &sat, "one", b"abcd").await;
        put(&bucket.store, &sat, "two", b"abcdef").await;
        let volume = bucket.root.path().join("volume");
        std::fs::create_dir_all(volume.join("satellites")).unwrap();
        std::fs::write(
            volume.join("satellites").join(format!("{sat}.pem")),
            certificate_chain_pem(&satellite),
        )
        .unwrap();
        let config = exit_config(&bucket, &sat);
        let row = crate::request_exit(&config, &sat).unwrap();
        assert_eq!(row.live_bytes, 10);
        assert_eq!(row.status, ExitStatus::Pending);
        let text = crate::exit_status(&config).unwrap();
        assert!(
            text.starts_with("satellite\tlive_bytes\tstatus\tdetail\n"),
            "{text}"
        );
        assert!(text.contains(&format!("{sat}\t10\tpending\t")), "{text}");
        let again = bucket.reopen();
        let stored = again.exit_row(&sat).unwrap().unwrap();
        assert_eq!(stored.live_bytes, 10);
        assert_eq!(stored.status, ExitStatus::Pending);

        let err = crate::request_exit(&config, &stranger.node_id().to_string()).unwrap_err();
        assert!(err.to_string().contains("not a trusted satellite"), "{err}");
        let err = crate::request_exit(&config, "not-a-node-id").unwrap_err();
        assert!(err.to_string().contains("not a node id"), "{err}");

        let ca = satellite.ca_der();
        let bad = format!("{}{}", pem_cert(ca.as_ref()), pem_cert(ca.as_ref()));
        std::fs::write(volume.join("satellites").join(format!("{sat}.pem")), bad).unwrap();
        // begin_exit rejects an existing row before the certificate is checked.
        again.cancel_exit(&sat).unwrap();
        let err = crate::request_exit(&config, &sat).unwrap_err();
        assert!(
            err.to_string().contains("leaf") || err.to_string().contains("CA"),
            "{err}"
        );
    }

    fn exit_config(bucket: &Bucket, satellite_id: &str) -> Config {
        Config::from_fn(|key| {
            let value = match key {
                "STORJ_S3_ENDPOINT" => bucket.endpoint.as_str(),
                "STORJ_S3_BUCKET" => BUCKET,
                "STORJ_S3_ACCESS_KEY_ID" => ACCESS_KEY,
                "STORJ_S3_SECRET_ACCESS_KEY" => SECRET,
                "STORJ_OPERATOR_EMAIL" => "op@example.com",
                "STORJ_OPERATOR_WALLET" => "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "STORJ_CONTACT_EXTERNAL_ADDRESS" => "127.0.0.1:28967",
                "STORJ_SATELLITES" => return Some(format!("{satellite_id}@127.0.0.1:7777")),
                "STORJ_VOLUME" => {
                    return Some(bucket.root.path().join("volume").display().to_string());
                }
                _ => return None,
            };
            Some(value.to_owned())
        })
        .expect("config")
    }

    fn pem_cert(der: &[u8]) -> String {
        let encoded = BASE64.encode(der);
        let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in encoded.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(line).unwrap());
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
        out
    }
}
