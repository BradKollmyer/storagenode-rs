//! Check-in with each trusted satellite.
//!
//! The loop dials `/contact.Node/CheckIn` over storj-rpc TCP/TLS. `features`
//! stays 0: this node does not advertise TCP fast open or hashstore.
//! `CheckInResponse.hashstore_settings` is not applied.
//!
//! The noise attestation matches `storj.io/common/rpc/noise.GenerateKeyAttestation`:
//! `Identity::hash_and_sign` of `noise-key-attestation-v1:` || uint64be(unix nanos)
//! || X25519 public key. `noise_proto` is the protocol this process accepts
//! (1, unless a test built the node with protocol 2).

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use prost::Message;
use storj_proto::noise::NoiseKeyAttestation;
use storj_rpc::transport::{self, TransportMode};
use storj_rpc::{Conn, Identity, NodeId};

use crate::config::Config;
use crate::server::Node;

/// `/contact.Node/CheckIn`, from the pin's `contact_drpc.pb.go`.
pub(crate) const CHECK_IN: &str = "/contact.Node/CheckIn";

/// Go `contact.Config.Interval` release default.
const INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Go `contact.Config.CheckInTimeout` release default.
const TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Go `monitor.Config.NotifyLowDiskCooldown`. The least time between two
/// check-ins when the second is asked for by a nearly full node.
const LOW_SPACE_COOLDOWN: Duration = Duration::from_secs(10 * 60);

/// The Go storage node release this node reports to satellites, in the form
/// Go sends it (`SemVer.VString`).
///
/// A satellite with a minimum version selects only nodes at or above it, and
/// that minimum is a Go release number. This is the release of the Go tree
/// this node's wire behaviour was checked against. Raise it after checking
/// against a newer release, not to get past a satellite's minimum: the number
/// tells the satellite which behaviour to expect.
pub(crate) const GO_COMPATIBLE_VERSION: &str = "v1.164.1";

/// Go `initialBackOff`.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// Operator fields sent on every check-in. The wallet was already checked at startup.
#[derive(Clone, Debug)]
pub(crate) struct Operator {
    /// `STORJ_OPERATOR_EMAIL`.
    pub email: String,
    /// `STORJ_OPERATOR_WALLET`.
    pub wallet: String,
    /// `STORJ_OPERATOR_WALLET_FEATURES`, split on commas.
    pub wallet_features: Vec<String>,
    /// `STORJ_CONTACT_EXTERNAL_ADDRESS`.
    pub address: String,
}

impl Operator {
    pub(crate) fn from_config(config: &Config) -> Self {
        Self {
            email: config.operator_email.clone(),
            wallet: config.operator_wallet.clone(),
            wallet_features: config.wallet_features.clone(),
            address: config.contact_external_address.clone(),
        }
    }
}

/// One check-in pass. A dial or RPC failure is returned and does not panic.
///
/// Every trusted satellite is attempted. An empty address is not dialed.
/// The running process uses [`serve`], which retries; tests call this directly.
#[cfg(test)]
pub(crate) async fn check_in(
    node: &Node,
    operator: &Operator,
    timeout: Duration,
) -> Result<(), String> {
    let mut errors = Vec::new();
    for (id, address) in node.contact_targets() {
        if let Err(err) = attempt(node, operator, id, &address, timeout).await {
            errors.push(format!("{id}: {err}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// Independent loop per trusted satellite. One slow satellite does not hold the others.
pub(crate) async fn serve(node: Arc<Node>, operator: Operator) {
    for (id, address) in node.contact_targets() {
        let node = Arc::clone(&node);
        let operator = operator.clone();
        tokio::spawn(async move {
            loop {
                retry(&node, &operator, id, &address).await;
                next_check_in(&node, Instant::now(), INTERVAL, LOW_SPACE_COOLDOWN).await;
            }
        });
    }
}

/// Waits out `interval` after the check-in at `last`. Returns sooner when an
/// upload finds the node low on space, but not within `cooldown` of `last`.
///
/// The satellite learns the free space only at check-in. Without this a full
/// node stays selected, and refuses uploads, for up to the whole interval.
pub(crate) async fn next_check_in(
    node: &Node,
    last: Instant,
    interval: Duration,
    cooldown: Duration,
) {
    tokio::select! {
        () = tokio::time::sleep(interval) => {}
        () = node.low_space() => {
            let wait = cooldown.saturating_sub(last.elapsed());
            tokio::time::sleep(wait).await;
        }
    }
}

async fn retry(node: &Node, operator: &Operator, id: NodeId, address: &str) {
    if address.is_empty() {
        eprintln!("storagenode: check-in {id} has no dial address");
        return;
    }
    let mut backoff = INITIAL_BACKOFF;
    loop {
        match attempt(node, operator, id, address, TIMEOUT).await {
            Ok(()) => {
                eprintln!("storagenode: checked in with {id}");
                return;
            }
            Err(err) => eprintln!("storagenode: check-in {id} failed: {err}"),
        }
        if backoff >= INTERVAL {
            return;
        }
        tokio::time::sleep(backoff).await;
        backoff = backoff.saturating_mul(2);
    }
}

async fn attempt(
    node: &Node,
    operator: &Operator,
    id: NodeId,
    address: &str,
    timeout: Duration,
) -> Result<(), String> {
    if address.is_empty() {
        return Err("satellite has no dial address".into());
    }
    // Uploads and cleanup can change capacity during retry backoff. Sample
    // it for each request, rather than retaining the first attempt's value.
    let free_disk = node
        .free_disk()
        .map_err(|err| format!("disk space: {err}"))?;
    let request = check_in_request(node, operator, free_disk)?;
    let rpc = async {
        let transport = transport::dial(
            node.identity(),
            id,
            address,
            TransportMode::Tcp,
            timeout,
            None,
        )
        .await
        .map_err(|err| err.to_string())?;
        // TLS pinned this connection to the satellite's id, so this is its
        // current leaf. Order limits are verified with it from now on.
        node.observe_satellite_leaf(id, &transport.peer_cert);
        let mut conn = Conn::new(transport);
        let bytes = conn
            .invoke(CHECK_IN, &request)
            .await
            .map_err(|err| err.to_string())?;
        let response = crate::contact::CheckInResponse::decode(bytes.as_slice())
            .map_err(|err| err.to_string())?;
        // hashstore_settings is intentionally unread. This node has no hashstore.
        if !response.ping_node_success {
            if response.ping_error_message.is_empty() {
                return Err("check-in rejected".into());
            }
            return Err(response.ping_error_message);
        }
        if !response.ping_error_message.is_empty() {
            eprintln!(
                "storagenode: check-in {id} online but satellite reported {}",
                response.ping_error_message
            );
        }
        let row = s3store::CheckInRow {
            satellite_id: id.to_string(),
            checked_in_at: SystemTime::now(),
            quic_ok: response.ping_node_success_quic,
        };
        node.piece_store()
            .record_check_in(&row)
            .map_err(|err| format!("save check-in: {err}"))?;
        Ok(())
    };
    match tokio::time::timeout(timeout, rpc).await {
        Ok(result) => result,
        Err(_) => Err("check-in timed out".into()),
    }
}

fn check_in_request(node: &Node, operator: &Operator, free_disk: i64) -> Result<Vec<u8>, String> {
    let attestation = attest(
        node.identity(),
        node.noise_public_key(),
        node.noise_protocol(),
        node.noise_certchain(),
    )?;
    let message = crate::contact::CheckInRequest {
        address: operator.address.clone(),
        version: Some(node_version()),
        capacity: Some(capacity(free_disk)),
        operator: Some(crate::node::NodeOperator {
            email: operator.email.clone(),
            wallet: operator.wallet.clone(),
            wallet_features: operator.wallet_features.clone(),
        }),
        noise_key_attestation: Some(attestation),
        debounce_limit: 0,
        // TCP fast-open and hashstore bits stay unset.
        features: 0,
        signed_tags: None,
    };
    Ok(message.encode_to_vec())
}

/// The version a satellite stores for this node.
///
/// A satellite that sets a minimum version selects only nodes that report
/// `release` and a version at or above it. The version is
/// [`GO_COMPATIBLE_VERSION`], not this crate's own number, which no satellite
/// minimum is expressed in. `release` is true for a release build, as the Go
/// release binaries report. The commit and its time are this repository's,
/// from the build script.
fn node_version() -> crate::node::NodeVersion {
    let commit_unix: i64 = env!("STORAGENODE_COMMIT_UNIX").parse().unwrap_or(0);
    crate::node::NodeVersion {
        version: GO_COMPATIBLE_VERSION.to_owned(),
        commit_hash: env!("STORAGENODE_COMMIT").to_owned(),
        timestamp: (commit_unix > 0).then_some(prost_types::Timestamp {
            seconds: commit_unix,
            nanos: 0,
        }),
        release: !cfg!(debug_assertions),
    }
}

#[allow(deprecated)]
fn capacity(free_disk: i64) -> crate::node::NodeCapacity {
    crate::node::NodeCapacity {
        free_bandwidth: 0,
        free_disk,
    }
}

/// Sign `b"noise-key-attestation-v1:" || uint64be(max(unix_nanos, 0)) || public_key`.
fn attest(
    identity: &Identity,
    public_key: &[u8],
    protocol: i32,
    certchain: &[u8],
) -> Result<NoiseKeyAttestation, String> {
    let nanos = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX),
        Err(_) => 0,
    };
    let mut message = Vec::with_capacity(24 + 8 + public_key.len());
    message.extend_from_slice(b"noise-key-attestation-v1:");
    message.extend_from_slice(&nanos.to_be_bytes());
    message.extend_from_slice(public_key);
    let signature = identity
        .hash_and_sign(&message)
        .map_err(|err| err.to_string())?;
    let seconds = i64::try_from(nanos / 1_000_000_000).unwrap_or(i64::MAX);
    let subsec = i32::try_from(nanos % 1_000_000_000).unwrap_or(0);
    Ok(NoiseKeyAttestation {
        node_certchain: certchain.to_vec(),
        noise_proto: protocol,
        noise_public_key: public_key.to_vec(),
        timestamp: Some(prost_types::Timestamp {
            seconds,
            nanos: subsec,
        }),
        signature,
        deprecated_node_id: identity.node_id().as_bytes().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as ConnBuilder;
    use prost::Message;
    use s3s::auth::SimpleAuth;
    use s3s::service::S3ServiceBuilder;
    use s3s_fs::FileSystem;
    use storj_rpc::frame::{Kind, Packet};
    use storj_rpc::{Conn, Identity, server_config};
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::noise_key;
    use crate::server::TrustedSatellite;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "storagenode-checkin-{nanos}-{seq}-{}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("temp");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct Fixture {
        node: Node,
        identity: Identity,
        _root: TempDir,
    }

    fn fixture(satellite: &Identity, address: &str) -> Fixture {
        fixture_at_endpoint(satellite, address, "http://127.0.0.1:1")
    }

    fn fixture_at_endpoint(satellite: &Identity, address: &str, endpoint: &str) -> Fixture {
        let root = TempDir::new();
        let store = s3store::Store::new(s3store::Config {
            endpoint: endpoint.into(),
            bucket: "pieces".into(),
            access_key_id: "ak".into(),
            secret_access_key: "sk".into(),
            volume: root.0.join("volume"),
            allocated_bytes: 5_000,
            ..s3store::Config::default()
        })
        .expect("store");
        let identity = Identity::generate().expect("identity");
        let noise = noise_key::Key::generate().expect("noise");
        let node = Node::with_noise(
            identity.clone(),
            store,
            vec![TrustedSatellite {
                id: satellite.node_id(),
                address: address.to_owned(),
                leaf_der: satellite.leaf_der().as_ref().to_vec(),
                ca_der: satellite.ca_der().as_ref().to_vec(),
            }],
            noise_key::DEFAULT_PROTOCOL,
            noise,
        )
        .expect("node");
        Fixture {
            node,
            identity,
            _root: root,
        }
    }

    fn operator() -> Operator {
        Operator {
            email: "op@example.com".into(),
            wallet: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            wallet_features: vec!["beta".into()],
            address: "203.0.113.9:28967".into(),
        }
    }

    struct Seen {
        path: String,
        request: crate::contact::CheckInRequest,
    }

    fn spawn_satellite(identity: Identity, seen: Arc<Mutex<Option<Seen>>>, accept: bool) -> String {
        spawn_satellite_controlled(identity, seen, Arc::new(AtomicBool::new(accept)))
    }

    fn spawn_satellite_controlled(
        identity: Identity,
        seen: Arc<Mutex<Option<Seen>>>,
        accept: Arc<AtomicBool>,
    ) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let address = format!("127.0.0.1:{}", listener.local_addr().expect("addr").port());
        let listener = TcpListener::from_std(listener).expect("tokio");
        tokio::spawn(async move {
            let acceptor =
                tokio_rustls::TlsAcceptor::from(Arc::new(server_config(&identity).expect("tls")));
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let seen = Arc::clone(&seen);
                let accept = accept.load(Ordering::Relaxed);
                tokio::spawn(async move {
                    if let Err(err) = serve_check_in(acceptor, sock, &seen, accept).await {
                        eprintln!("test satellite: {err}");
                    }
                });
            }
        });
        address
    }

    async fn serve_check_in(
        acceptor: tokio_rustls::TlsAcceptor,
        mut sock: TcpStream,
        seen: &Mutex<Option<Seen>>,
        accept: bool,
    ) -> Result<(), String> {
        let _ = sock.set_nodelay(true);
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
        let mut body = None;
        loop {
            let pkt = conn.read_packet().await.map_err(|err| err.to_string())?;
            if pkt.stream_id != invoke.stream_id {
                continue;
            }
            match pkt.kind {
                Kind::MESSAGE => body = Some(pkt.data),
                Kind::CLOSE_SEND | Kind::CLOSE => break,
                Kind::ERROR => return Err("client error".into()),
                _ => {}
            }
        }
        let request =
            crate::contact::CheckInRequest::decode(body.ok_or("missing check-in body")?.as_slice())
                .map_err(|err| err.to_string())?;
        *seen.lock().expect("seen") = Some(Seen { path, request });
        let response = crate::contact::CheckInResponse {
            ping_node_success: accept,
            ping_error_message: if accept {
                String::new()
            } else {
                "not accepting".into()
            },
            ping_node_success_quic: false,
            node_tag_success: false,
            node_tag_error_message: String::new(),
            hashstore_settings: Some(crate::contact::HashstoreSettings {
                active_migrate: true,
                passive_migrate: true,
                write_to_new: true,
                read_new_first: true,
                ttl_to_new: true,
            }),
        };
        conn.write_packet(&Packet {
            stream_id: invoke.stream_id,
            message_id: 1,
            kind: Kind::MESSAGE,
            control: false,
            data: response.encode_to_vec(),
        })
        .await
        .map_err(|err| err.to_string())?;
        conn.write_packet(&Packet {
            stream_id: invoke.stream_id,
            message_id: 2,
            kind: Kind::CLOSE,
            control: false,
            data: Vec::new(),
        })
        .await
        .map_err(|err| err.to_string())?;
        let _ = tokio::time::timeout(Duration::from_secs(2), conn.read_packet()).await;
        Ok(())
    }

    #[tokio::test]
    #[allow(deprecated)]
    async fn check_in_sends_operator_capacity_and_noise_attestation() {
        let satellite = Identity::generate().unwrap();
        let seen = Arc::new(Mutex::new(None));
        let address = spawn_satellite(satellite.clone(), Arc::clone(&seen), true);
        let fixture = fixture(&satellite, &address);
        // The node starts with a leaf the satellite no longer uses. The
        // check-in dial sees the current one.
        let stale = Identity::generate().unwrap();
        fixture
            .node
            .observe_satellite_leaf(satellite.node_id(), stale.leaf_der().as_ref());
        check_in(&fixture.node, &operator(), Duration::from_secs(5))
            .await
            .expect("check-in");
        let seen = seen.lock().expect("seen").take().expect("request");
        assert_eq!(seen.path, CHECK_IN);
        assert_eq!(
            fixture.node.satellite_leaf(satellite.node_id()).unwrap(),
            satellite.leaf_der().as_ref()
        );
        let req = seen.request;
        assert_eq!(req.address, "203.0.113.9:28967");
        assert_eq!(req.features, 0);
        assert_eq!(req.debounce_limit, 0);
        assert!(req.signed_tags.is_none());
        let version = req.version.expect("version");
        assert_eq!(version.version, GO_COMPATIBLE_VERSION);
        // The satellite parses `v<major>.<minor>.<patch>` and compares numbers.
        let numbers: Vec<u64> = version
            .version
            .strip_prefix('v')
            .expect("Go sends the v prefix")
            .split('.')
            .map(|part| part.parse().expect("a number"))
            .collect();
        assert_eq!(numbers.len(), 3);
        assert_eq!(numbers[0], 1, "a Go storage node release is v1.x.y");
        // Tests are a debug build. A release build reports `release`.
        assert_eq!(version.release, !cfg!(debug_assertions));
        assert_eq!(version.commit_hash, env!("STORAGENODE_COMMIT"));
        assert_eq!(version.commit_hash.is_empty(), version.timestamp.is_none());
        let operator = req.operator.expect("operator");
        assert_eq!(operator.email, "op@example.com");
        assert_eq!(
            operator.wallet,
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(operator.wallet_features, ["beta"]);
        let capacity = req.capacity.expect("capacity");
        assert_eq!(capacity.free_disk, 5_000);
        assert_eq!(capacity.free_bandwidth, 0);
        let att = req.noise_key_attestation.expect("attestation");
        assert_eq!(att.noise_proto, noise_key::DEFAULT_PROTOCOL);
        assert_eq!(att.noise_proto, 1);
        assert_eq!(att.noise_public_key, fixture.node.noise_public_key());
        assert_eq!(
            att.deprecated_node_id,
            fixture.identity.node_id().as_bytes()
        );
        let mut chain = Vec::new();
        for cert in fixture.identity.cert_chain() {
            chain.extend_from_slice(cert.as_ref());
        }
        assert_eq!(att.node_certchain, chain);
        let ts = att.timestamp.expect("timestamp");
        assert!(ts.seconds >= 0);
        let nanos =
            u64::try_from(ts.seconds).unwrap() * 1_000_000_000 + u64::try_from(ts.nanos).unwrap();
        let mut payload = b"noise-key-attestation-v1:".to_vec();
        payload.extend_from_slice(&nanos.to_be_bytes());
        payload.extend_from_slice(&att.noise_public_key);
        storj_rpc::hash_and_verify(
            fixture.identity.leaf_der().as_ref(),
            &payload,
            &att.signature,
        )
        .expect("attestation signature");
        let saved = fixture.node.piece_store().check_ins().expect("check-ins");
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].satellite_id, satellite.node_id().to_string());
        assert!(!saved[0].quic_ok);
    }

    #[tokio::test]
    async fn rejected_check_in_is_an_error_and_hashstore_settings_are_ignored() {
        let satellite = Identity::generate().unwrap();
        let seen = Arc::new(Mutex::new(None));
        let address = spawn_satellite(satellite.clone(), Arc::clone(&seen), false);
        let fixture = fixture(&satellite, &address);
        let err = check_in(&fixture.node, &operator(), Duration::from_secs(5))
            .await
            .expect_err("rejected");
        assert!(err.contains("not accepting"), "{err}");
        assert!(seen.lock().expect("seen").is_some());
        assert!(
            fixture
                .node
                .piece_store()
                .check_ins()
                .expect("check-ins")
                .is_empty()
        );
    }

    fn spawn_bucket(root: &Path) -> String {
        std::fs::create_dir(root.join("pieces")).unwrap();
        let fs = FileSystem::new(root).unwrap();
        let mut builder = S3ServiceBuilder::new(fs);
        builder.set_auth(SimpleAuth::from_single("ak", "sk"));
        let service = builder.build();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let listener = TcpListener::from_std(listener).unwrap();
        tokio::spawn(async move {
            let http = ConnBuilder::new(TokioExecutor::new());
            while let Ok((socket, _)) = listener.accept().await {
                let connection = http
                    .serve_connection(TokioIo::new(socket), service.clone())
                    .into_owned();
                tokio::spawn(async move {
                    let _ = connection.await;
                });
            }
        });
        format!("http://{address}")
    }

    #[tokio::test]
    async fn check_in_retry_refreshes_capacity_after_a_piece_commits() {
        let satellite = Identity::generate().unwrap();
        let seen = Arc::new(Mutex::new(None));
        let accept = Arc::new(AtomicBool::new(false));
        let address =
            spawn_satellite_controlled(satellite.clone(), Arc::clone(&seen), Arc::clone(&accept));
        let bucket_root = TempDir::new();
        let endpoint = spawn_bucket(&bucket_root.0);
        let fixture = fixture_at_endpoint(&satellite, &address, &endpoint);
        let op = operator();
        let change_capacity = async {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if seen.lock().unwrap().is_some() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("first check-in received");
            assert_eq!(
                seen.lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .request
                    .capacity
                    .as_ref()
                    .unwrap()
                    .free_disk,
                5_000
            );
            fixture
                .node
                .piece_store()
                .put_piece(
                    &satellite.node_id().to_string(),
                    "new-piece",
                    &vec![1; 1_000],
                    s3store::PieceMeta {
                        hash: [1; 32],
                        algorithm: s3store::HashAlgorithm::Sha256,
                        created: SystemTime::now(),
                        expires: None,
                        order_limit: vec![1],
                        hash_signature: vec![1],
                        hash_timestamp: None,
                    },
                )
                .await
                .unwrap();
            accept.store(true, Ordering::Relaxed);
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                retry(&fixture.node, &op, satellite.node_id(), &address),
                change_capacity,
            );
        })
        .await
        .expect("retry accepted");
        let final_request = seen.lock().unwrap().take().unwrap().request;
        assert_eq!(final_request.capacity.unwrap().free_disk, 4_000);
        assert_eq!(fixture.node.piece_store().check_ins().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn closed_local_port_is_not_a_successful_check_in() {
        let satellite = Identity::generate().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = format!("127.0.0.1:{}", listener.local_addr().expect("addr").port());
        drop(listener);
        let fixture = fixture(&satellite, &address);
        let err = check_in(&fixture.node, &operator(), Duration::from_secs(2))
            .await
            .expect_err("dial");
        assert!(!err.is_empty(), "{err}");
    }
}
