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
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    let free = node.free_disk().map_err(|err| err.to_string())?;
    let mut errors = Vec::new();
    for (id, address) in node.contact_targets() {
        if let Err(err) = attempt(node, operator, id, &address, free, timeout).await {
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
                match node.free_disk() {
                    Ok(free) => retry(&node, &operator, id, &address, free).await,
                    Err(err) => eprintln!("storagenode: check-in {id} disk space: {err}"),
                }
                tokio::time::sleep(INTERVAL).await;
            }
        });
    }
}

async fn retry(node: &Node, operator: &Operator, id: NodeId, address: &str, free_disk: i64) {
    if address.is_empty() {
        eprintln!("storagenode: check-in {id} has no dial address");
        return;
    }
    let mut backoff = INITIAL_BACKOFF;
    loop {
        match attempt(node, operator, id, address, free_disk, TIMEOUT).await {
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
    free_disk: i64,
    timeout: Duration,
) -> Result<(), String> {
    if address.is_empty() {
        return Err("satellite has no dial address".into());
    }
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
        version: Some(crate::node::NodeVersion {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            commit_hash: String::new(),
            timestamp: None,
            release: false,
        }),
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
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use prost::Message;
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
        let root = TempDir::new();
        let store = s3store::Store::new(s3store::Config {
            endpoint: "http://127.0.0.1:1".into(),
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
        check_in(&fixture.node, &operator(), Duration::from_secs(5))
            .await
            .expect("check-in");
        let seen = seen.lock().expect("seen").take().expect("request");
        assert_eq!(seen.path, CHECK_IN);
        let req = seen.request;
        assert_eq!(req.address, "203.0.113.9:28967");
        assert_eq!(req.features, 0);
        assert_eq!(req.debounce_limit, 0);
        assert!(req.signed_tags.is_none());
        let version = req.version.expect("version");
        assert_eq!(version.version, env!("CARGO_PKG_VERSION"));
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
