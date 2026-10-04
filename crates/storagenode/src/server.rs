//! DRPC over TLS, Noise, and QUIC. One RPC per connection.
//!
//! TCP is read for 8 bytes. [`storj_rpc::DRPC_TLS_MUX_PREFIX`] starts TLS
//! with the node id pinned. [`storj_rpc::noise::HEADER`] is consumed, then
//! [`storj_rpc::noise::NoiseStream::accept`] runs with this process's one
//! protocol. Any other prefix is closed. UDP is QUIC with ALPN `storj` and
//! has no mux header. The server reads with [`Conn::read_packet`]. `invoke`
//! and `open_stream` are client calls and are not used here.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use prost::Message;
use s3store::{BandwidthKind, HashAlgorithm, PieceBody, PieceMeta, PieceState, Store, Upload};
use storj_proto::orders::{Order, OrderLimit, PieceAction, PieceHash};
use storj_proto::piecestore::{
    ExistsRequest, ExistsResponse, PieceDownloadRequest, PieceDownloadResponse, PieceUploadRequest,
    PieceUploadResponse, RestoreTrashRequest, RestoreTrashResponse, RetainRequest, RetainResponse,
    StorageMethod, piece_download_response, piece_upload_request,
};
use storj_proto::rpc::{PIECESTORE_DOWNLOAD, PIECESTORE_UPLOAD};
use storj_rpc::frame::{Kind, Packet};
use storj_rpc::{Conn, DRPC_TLS_MUX_PREFIX, Identity, NodeId, marshal_error};
use storj_uplink::{
    PieceHashAlgo, PiecePublicKey, encode_order_limit, sign_piece_hash_node, verify_order,
    verify_order_limit, verify_piece_hash_uplink,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

use crate::noise_key::{self, Key};

use crate::orders::{self, Orders};
use crate::wire;

/// DRPC path for `piecestore.Piecestore/Exists`.
///
/// `storj-proto` exports upload and download only.
pub const PIECESTORE_EXISTS: &str = "/piecestore.Piecestore/Exists";

/// DRPC path for `piecestore.Piecestore/Retain`.
pub const PIECESTORE_RETAIN: &str = "/piecestore.Piecestore/Retain";

/// DRPC path for `piecestore.Piecestore/RetainBig`.
pub const PIECESTORE_RETAIN_BIG: &str = "/piecestore.Piecestore/RetainBig";

/// DRPC path for `piecestore.Piecestore/RestoreTrash`.
pub const PIECESTORE_RESTORE_TRASH: &str = "/piecestore.Piecestore/RestoreTrash";

/// DRPC path for `contact.Contact/PingNode`.
///
/// The satellite dials the node back and calls this inside every check-in,
/// over TCP and then over QUIC. A node that does not answer is recorded as
/// down and is never selected.
pub const CONTACT_PING_NODE: &str = "/contact.Contact/PingNode";

/// Unix seconds of Go's zero `time.Time` (year 1). Unset on the wire.
const GO_ZERO_TIME_UNIX: i64 = -62_135_596_800;

/// Budget for the 8-byte prefix, the TLS, Noise, or QUIC handshake, and the
/// invoke packet. A connection that has not named an RPC by then is closed.
/// After the invoke, [`Conn`] bounds each read and write on its own.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Go `retain.Config.MaxTimeSkew`. Retain keeps a piece stored within this
/// long before the filter's creation date, in the filter or not. The filter
/// is built from a database snapshot, and the two clocks are not the same.
const RETAIN_MAX_TIME_SKEW: Duration = Duration::from_secs(72 * 60 * 60);

/// Go `collector.Config.Interval`. Expired pieces and old trash are deleted
/// this often.
const CHORE_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Rows retain trashes per sqlite transaction. Other RPCs run in between.
const RETAIN_BATCH: usize = 1000;

/// Piece ids read per query while walking a satellite for retain. A
/// well-filled node holds too many for one list.
const RETAIN_PAGE: usize = 10_000;

/// Go `piecestore.Config.ReportCapacityThreshold`. An upload that finds less
/// free space than this asks for a check-in now, so the satellite stops
/// selecting a node that is about to refuse uploads.
const REPORT_CAPACITY_THRESHOLD: u64 = 5_000_000_000;

/// How long an upload trusts the last free-space read. The read sums the
/// index, so it is not repeated per upload; finished uploads are subtracted
/// from the cached figure in between.
const SPACE_REFRESH: Duration = Duration::from_secs(60);

/// Go `piecestore.Config.ExpirationGracePeriod`. A limit's piece or order
/// expiration counts as passed only once it is this far behind this node's
/// clock, which may run ahead of the satellite's.
const EXPIRATION_GRACE: Duration = Duration::from_secs(48 * 60 * 60);

/// How long a refused RPC waits for the peer to hang up before this side does.
const ERROR_LINGER: Duration = Duration::from_secs(5);

/// How long a finished RPC waits for the client's close packet. The Go
/// client writes it right after reading the response. Without this bound a
/// peer that says nothing more holds the connection for the whole per-read
/// deadline.
const CLOSE_LINGER: Duration = Duration::from_secs(10);

/// Pause after a failed `accept`, so a full descriptor table is not a busy loop.
const ACCEPT_RETRY: Duration = Duration::from_millis(250);

// 1 is OK in `rpcstatus`. Canceled is 2.
const RPC_CANCELED: u64 = 2;
const RPC_INVALID_ARGUMENT: u64 = 3;
const RPC_NOT_FOUND: u64 = 5;
const RPC_PERMISSION_DENIED: u64 = 7;
const RPC_ABORTED: u64 = 10;
const RPC_UNIMPLEMENTED: u64 = 12;
const RPC_INTERNAL: u64 = 13;
const RPC_UNAUTHENTICATED: u64 = 16;

/// A satellite whose order limits this node will accept.
///
/// `leaf_der` is the certificate that signed the limit. `ca_der` is the CA
/// whose hash is `id`. A node URL does not carry either certificate.
#[derive(Clone, Debug)]
pub struct TrustedSatellite {
    /// Satellite node id. Must equal the node id of [`Self::ca_der`].
    pub id: NodeId,
    /// `host:port` dialed for settlement. Empty when this process does not settle.
    pub address: String,
    /// Leaf certificate DER passed to `verify_order_limit`.
    pub leaf_der: Vec<u8>,
    /// CA certificate DER.
    pub ca_der: Vec<u8>,
}

/// `Node::new` could not build the TLS acceptor or accept a satellite chain.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// The storage node identity could not build a server config.
    #[error(transparent)]
    Tls(#[from] storj_rpc::IdentityError),
    /// The leaf was empty, was the CA, or the CA hashed to a different id.
    #[error("{0}")]
    Satellite(String),
    /// The Noise key could not be generated.
    #[error(transparent)]
    Noise(#[from] noise_key::Error),
    /// The process was asked to accept a protocol other than 1 or 2.
    #[error("unsupported noise protocol {0}")]
    NoiseProtocol(i32),
}

struct KnownSatellite {
    /// The certificate that signs this satellite's order limits. It starts
    /// as the leaf in `satellites/{id}.pem` and follows the satellite when
    /// it rotates: see [`Node::observe_satellite_leaf`].
    leaf: RwLock<Vec<u8>>,
    address: String,
}

/// Piecestore server bound to one identity, one Noise key, and one bucket.
pub struct Node {
    identity: Identity,
    store: Store,
    /// Satellite id to the leaf that verifies order limits, and its dial address.
    satellites: HashMap<NodeId, KnownSatellite>,
    /// Replay window for this process. Settlement orders are in `pieces.db`.
    serials: Mutex<Serials>,
    /// Committed free allocation and space reserved by unfinished uploads.
    free_space: Mutex<FreeSpace>,
    /// Bumped when an upload finds the node low on space. Each check-in loop
    /// keeps its own receiver, so a bump during a dial is still there later.
    low_space: tokio::sync::watch::Sender<u64>,
    orders: Orders,
    acceptor: tokio_rustls::TlsAcceptor,
    /// One X25519 key. Check-in attests the public half.
    noise: Key,
    /// The only Noise IK protocol this process will complete.
    noise_protocol: i32,
    /// Leaf then CA, concatenated DER. Sent on Noise uploads, which have no TLS cert.
    noise_certchain: Vec<u8>,
}

#[derive(Default)]
struct FreeSpace {
    cached: Option<(Instant, u64)>,
    reserved: u64,
    uploads: usize,
}

/// Holds the entire order limit until publication succeeds or the RPC fails.
/// Drop also releases it when the upload future is cancelled.
struct SpaceReservation<'a> {
    node: &'a Node,
    bytes: u64,
}

impl SpaceReservation<'_> {
    /// Charge the committed bytes and release any unused part of the limit
    /// before writing the reply, which can fail after the piece is live.
    fn commit(self, bytes: u64) {
        let mut space = self
            .node
            .free_space
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        if let Some((_, free)) = space.cached.as_mut() {
            *free = free.saturating_sub(bytes);
        }
    }
}

impl Drop for SpaceReservation<'_> {
    fn drop(&mut self) {
        let mut space = self
            .node
            .free_space
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        space.reserved -= self.bytes;
        space.uploads -= 1;
    }
}

impl Node {
    /// Builds a TLS acceptor and an ephemeral Noise key for protocol 1.
    ///
    /// Does not contact the bucket or bind a port. The binary uses
    /// [`Self::with_noise`] so the volume key survives a restart.
    pub fn new(
        identity: Identity,
        store: Store,
        trusted: Vec<TrustedSatellite>,
    ) -> Result<Self, BuildError> {
        let noise = Key::generate()?;
        Self::with_noise(identity, store, trusted, noise_key::DEFAULT_PROTOCOL, noise)
    }

    /// `protocol` is the one Noise IK cipher this process accepts.
    ///
    /// `1` is `NOISE_IK_25519_CHACHAPOLY_BLAKE2B`. `2` is
    /// `NOISE_IK_25519_AESGCM_BLAKE2B`. A handshake for the other cipher fails.
    pub fn with_noise(
        identity: Identity,
        store: Store,
        trusted: Vec<TrustedSatellite>,
        protocol: i32,
        noise: Key,
    ) -> Result<Self, BuildError> {
        if protocol != noise_key::DEFAULT_PROTOCOL && protocol != noise_key::AES_PROTOCOL {
            return Err(BuildError::NoiseProtocol(protocol));
        }
        let config: rustls::ServerConfig = storj_rpc::server_config(&identity)?;
        let mut satellites = HashMap::with_capacity(trusted.len());
        for satellite in trusted {
            let leaf = verified_leaf(&satellite)?;
            satellites.insert(
                satellite.id,
                KnownSatellite {
                    leaf: RwLock::new(leaf),
                    address: satellite.address,
                },
            );
        }
        let noise_certchain = cert_chain_der(&identity);
        Ok(Self {
            identity,
            store,
            satellites,
            serials: Mutex::new(Serials::default()),
            free_space: Mutex::new(FreeSpace::default()),
            low_space: tokio::sync::watch::Sender::new(0),
            orders: Orders::new(),
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
            noise,
            noise_protocol: protocol,
            noise_certchain,
        })
    }

    /// Protocol passed to `NoiseStream::accept`. Not a byte after the header.
    pub fn noise_protocol(&self) -> i32 {
        self.noise_protocol
    }

    /// X25519 public key a client passes to `NoiseStream::connect`.
    pub fn noise_public_key(&self) -> &[u8; 32] {
        self.noise.public()
    }

    /// Leaf private key and certificate chain. Check-in signs with this.
    pub(crate) fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Piece bucket and `pieces.db`, including graceful-exit rows.
    pub(crate) fn piece_store(&self) -> &Store {
        &self.store
    }

    /// Dial address for a satellite that passed [`accept_satellite`].
    pub(crate) fn satellite_address(&self, id: NodeId) -> Option<String> {
        self.satellites.get(&id).map(|sat| sat.address.clone())
    }

    /// Leaf then CA. `NoiseKeyAttestation.node_certchain` is these bytes.
    pub(crate) fn noise_certchain(&self) -> &[u8] {
        &self.noise_certchain
    }

    /// Trusted satellite id and the address check-in dials.
    ///
    /// Only satellites that passed the leaf-signed-by-CA check are present.
    pub(crate) fn contact_targets(&self) -> Vec<(NodeId, String)> {
        self.satellites
            .iter()
            .map(|(id, sat)| (*id, sat.address.clone()))
            .collect()
    }

    /// Takes the leaf a satellite presented on a connection this node dialed.
    ///
    /// The dial is pinned to the satellite's node id, so TLS has already
    /// checked that the leaf is signed by the CA that hashes to `id`. When
    /// it differs from the leaf this node holds, the satellite has rotated
    /// its certificate, and its order limits are signed by the new one. The
    /// Go node gets the same result by resolving the identity over a dial.
    /// Without this every upload, download, and audit from that satellite is
    /// refused until the operator replaces the PEM file.
    pub(crate) fn observe_satellite_leaf(&self, id: NodeId, leaf: &[u8]) {
        let Some(known) = self.satellites.get(&id) else {
            return;
        };
        if leaf.is_empty() {
            return;
        }
        let mut held = known.leaf.write().unwrap_or_else(|err| err.into_inner());
        if held.as_slice() != leaf {
            eprintln!(
                "storagenode: satellite {id} presented a new certificate; its order limits are now verified with it"
            );
            *held = leaf.to_vec();
        }
    }

    #[cfg(test)]
    pub(crate) fn satellite_leaf(&self, id: NodeId) -> Option<Vec<u8>> {
        let known = self.satellites.get(&id)?;
        Some(
            known
                .leaf
                .read()
                .unwrap_or_else(|err| err.into_inner())
                .clone(),
        )
    }

    /// This loop's view of the low-space generation. The current value counts
    /// as already seen, so only a reservation after this call wakes the loop.
    pub(crate) fn subscribe_low_space(&self) -> tokio::sync::watch::Receiver<u64> {
        self.low_space.subscribe()
    }

    /// Free disk reported at check-in: allocation minus the sum of live sizes.
    pub(crate) fn free_disk(&self) -> Result<i64, s3store::Error> {
        let free = self.store.space()?.free;
        Ok(i64::try_from(free).unwrap_or(i64::MAX))
    }

    /// This node's id.
    pub fn node_id(&self) -> NodeId {
        self.identity.node_id()
    }

    /// `HeadBucket`, then the index rebuild when `pieces.db` is unfinished.
    ///
    /// A bucket error is returned. The process exits on it. This does not dial
    /// a satellite.
    pub async fn startup(&self) -> s3store::Result<()> {
        self.store.startup().await
    }

    /// Binds `addr` (`0.0.0.0:28967` in the binary). Does not accept yet.
    pub async fn listen(addr: SocketAddr) -> io::Result<TcpListener> {
        TcpListener::bind(addr).await
    }

    /// Accepts until the task is dropped. Each connection is one RPC.
    ///
    /// An accept error is logged and retried. EMFILE and ECONNABORTED come
    /// from one connection or from load, and returning here exits the node.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> io::Result<()> {
        self.serve_accepted(|| listener.accept(), ACCEPT_RETRY)
            .await
    }

    /// The loop behind [`Self::serve`]. `accept` is the listener's, except in
    /// the test that makes it fail.
    async fn serve_accepted<F, Fut>(
        self: Arc<Self>,
        mut accept: F,
        retry: Duration,
    ) -> io::Result<()>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = io::Result<(TcpStream, SocketAddr)>>,
    {
        loop {
            let sock = match accept().await {
                Ok((sock, _)) => sock,
                Err(err) => {
                    eprintln!("storagenode: accept: {err}");
                    tokio::time::sleep(retry).await;
                    continue;
                }
            };
            let node = Arc::clone(&self);
            tokio::spawn(async move {
                let _ = node.handle(sock, HANDSHAKE_TIMEOUT).await;
            });
        }
    }

    /// QUIC endpoint on `addr` (the same port as TCP). ALPN is `storj`.
    ///
    /// Idle timeout is 15 minutes and the keepalive is 15 seconds, matching
    /// the storj-rpc QUIC client. A quiet connection is not dropped first.
    pub fn quic_endpoint(&self, addr: SocketAddr) -> io::Result<quinn::Endpoint> {
        quinn::Endpoint::server(quic_server_config(&self.identity)?, addr)
    }

    /// Accepts until the endpoint closes. Each connection is one bi-stream RPC.
    pub async fn serve_quic(self: Arc<Self>, endpoint: quinn::Endpoint) -> io::Result<()> {
        while let Some(incoming) = endpoint.accept().await {
            let node = Arc::clone(&self);
            tokio::spawn(async move {
                let _ = node.handle_quic(incoming, HANDSHAKE_TIMEOUT).await;
            });
        }
        Ok(())
    }

    /// `handshake` is the budget up to and including the invoke packet. A
    /// peer that connects and sends nothing must not hold a descriptor.
    async fn handle(&self, mut sock: TcpStream, handshake: Duration) -> io::Result<()> {
        let _ = sock.set_nodelay(true);
        let deadline = tokio::time::Instant::now() + handshake;
        let mut prefix = [0u8; 8];
        before(deadline, sock.read_exact(&mut prefix)).await?;
        if prefix.as_slice() == DRPC_TLS_MUX_PREFIX {
            let tls = before(deadline, self.acceptor.accept(sock)).await?;
            let peer = peer_node_id(&tls);
            self.serve_conn(tls, peer, Vec::new(), deadline).await?;
            return Ok(());
        }
        if prefix.as_slice() == storj_rpc::noise::HEADER.as_slice() {
            // The header does not carry the protocol number. One process, one cipher.
            let io = before(
                deadline,
                storj_rpc::noise::NoiseStream::accept(
                    sock,
                    self.noise_protocol,
                    self.noise.private(),
                ),
            )
            .await?;
            self.serve_conn(io, None, self.noise_certchain.clone(), deadline)
                .await?;
            return Ok(());
        }
        Ok(())
    }

    async fn handle_quic(&self, incoming: quinn::Incoming, handshake: Duration) -> io::Result<()> {
        let deadline = tokio::time::Instant::now() + handshake;
        let connection = before(deadline, async {
            incoming
                .await
                .map_err(|err| io::Error::other(err.to_string()))
        })
        .await?;
        let peer = quic_peer_node_id(&connection);
        let (send, recv) = before(deadline, async {
            connection
                .accept_bi()
                .await
                .map_err(|err| io::Error::other(err.to_string()))
        })
        .await?;
        let mut io = self
            .serve_conn(BiStream { send, recv }, peer, Vec::new(), deadline)
            .await?;
        // RecvStream::drop sends STOP_SENDING unless the peer finished the
        // stream. The uplink still writes its DRPC close after the response,
        // then closes the connection instead of finishing the stream. Bound
        // both waits: keepalive traffic must not retain a finished RPC.
        let _ = tokio::time::timeout(CLOSE_LINGER, async {
            let mut buf = [0u8; 1024];
            loop {
                match io.recv.read(&mut buf).await {
                    Ok(Some(0)) | Ok(None) | Err(_) => break,
                    Ok(Some(_)) => {}
                }
            }
            connection.closed().await;
        })
        .await;
        connection.close(0u32.into(), b"rpc finished");
        drop(io);
        Ok(())
    }

    async fn serve_conn<T>(
        &self,
        io: T,
        peer: Option<NodeId>,
        node_certchain: Vec<u8>,
        deadline: tokio::time::Instant,
    ) -> io::Result<T>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let mut conn = Conn::new(io);
        // A Go client whose context carries metadata (a sampled trace) writes
        // INVOKE_METADATA on the stream before INVOKE. Nothing here reads it.
        let invoke = loop {
            let pkt = before(deadline, async { conn.read_packet().await.map_err(io_err) }).await?;
            match pkt.kind {
                Kind::INVOKE => break pkt,
                Kind::INVOKE_METADATA => {}
                _ => return Ok(conn.into_inner()),
            }
        };
        let path = String::from_utf8(invoke.data).unwrap_or_default();
        let mut out = Out {
            conn,
            stream_id: invoke.stream_id,
            // The reader starts at message 1 and rejects 0.
            next_id: 1,
            node_certchain,
        };
        match self.dispatch(&mut out, peer, &path).await {
            Ok(()) => {
                // The client writes Close only after reading the response.
                // Dropping the socket first turns that write into EPIPE and
                // fails an RPC that already succeeded. A client that never
                // writes it gives up the connection after the linger budget.
                let _ = tokio::time::timeout(CLOSE_LINGER, out.conn.read_packet()).await;
                Ok(out.conn.into_inner())
            }
            Err(Fail::Proto { code, message }) => {
                let _ = out.fail(code, &message).await;
                out.linger(ERROR_LINGER).await;
                Ok(out.conn.into_inner())
            }
            Err(Fail::Transport(err)) => Err(io_err(err)),
        }
    }

    async fn dispatch<T>(
        &self,
        out: &mut Out<T>,
        peer: Option<NodeId>,
        path: &str,
    ) -> Result<(), Fail>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        match path {
            PIECESTORE_UPLOAD => self.upload(out).await,
            PIECESTORE_DOWNLOAD => self.download(out).await,
            PIECESTORE_EXISTS => self.exists(out, peer).await,
            PIECESTORE_RETAIN => self.retain(out, peer).await,
            PIECESTORE_RETAIN_BIG => self.retain_big(out, peer).await,
            PIECESTORE_RESTORE_TRASH => self.restore_trash(out, peer).await,
            CONTACT_PING_NODE => self.ping_node(out, peer).await,
            // `DeletePieces` lands here too. The Go node also answers it
            // with Unimplemented; deleted data is collected by retain.
            _ => Err(Fail::proto(RPC_UNIMPLEMENTED, "unknown rpc")),
        }
    }

    async fn upload<T>(&self, out: &mut Out<T>) -> Result<(), Fail>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let mut usage = Usage::default();
        let result = self.upload_stream(out, &mut usage).await;
        self.note_usage(&usage);
        result
    }

    async fn upload_stream<T>(&self, out: &mut Out<T>, usage: &mut Usage) -> Result<(), Fail>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let mut limit: Option<OrderLimit> = None;
        // The limit as stored: its known fields, then any this build lacks.
        let mut limit_bytes = Vec::new();
        let mut algo = PieceHashAlgo::Sha256;
        let mut hasher = PieceHashAlgo::Sha256.hasher();
        let mut space = None;
        let mut staging: Option<(Upload, String)> = None;
        let mut staged: i64 = 0;
        let mut authorized: i64 = 0;
        // Dropped on every return, including a failed upload, so the hour is
        // not stuck open and the largest order is still recorded.
        let mut tracked = None;

        loop {
            let Some(bytes) = out.recv().await? else {
                // Go: Canceled when the stream ends at the first receive,
                // Aborted once the upload has started.
                return Err(if limit.is_none() {
                    Fail::proto(RPC_CANCELED, "upload closed before the order limit")
                } else {
                    Fail::proto(RPC_ABORTED, "upload closed before the piece hash")
                });
            };
            let req = PieceUploadRequest::decode(bytes.as_slice())
                .map_err(|err| Fail::proto(RPC_INVALID_ARGUMENT, err.to_string()))?;
            if let Some(next) = req.limit {
                if limit.is_some() {
                    return Err(Fail::proto(RPC_INVALID_ARGUMENT, "duplicate order limit"));
                }
                algo = hash_algo(req.hash_algorithm)?;
                // The first message carries the algorithm. Later messages leave
                // the field at the protobuf zero (SHA-256) even for BLAKE3.
                hasher = algo.hasher();
                let unknown = limit_unknown(&bytes);
                self.check_limit(&next, true, &unknown)?;
                space = Some(self.reserve_space(&next)?);
                limit_bytes = encode_limit(&next, &unknown);
                tracked = Some(self.track_order(&next, limit_bytes.clone())?);
                usage.satellite = parse_node_id(&next.satellite_id)?.to_string();
                usage.action = next.action;
                limit = Some(next);
            } else if limit.is_none() {
                return Err(Fail::proto(
                    RPC_INVALID_ARGUMENT,
                    "expected order limit as the first message",
                ));
            }
            let Some(limit_ref) = limit.as_ref() else {
                return Err(Fail::proto(
                    RPC_INVALID_ARGUMENT,
                    "expected order limit as the first message",
                ));
            };
            if let Some(order) = req.order.as_ref() {
                authorized = check_order(limit_ref, order, authorized)?;
                if let Some(tracked) = tracked.as_mut() {
                    tracked.note(order);
                }
                usage.ordered |= order.amount > 0;
            }
            if let Some(chunk) = req.chunk.as_ref() {
                let next_len = check_chunk(staged, limit_ref.limit, authorized, chunk)?;
                if staging.is_none() {
                    let id = next_stage_id();
                    let upload = self.store.stage(&id).map_err(store_err)?;
                    staging = Some((upload, id));
                }
                let (spill, _) = staging.as_mut().expect("staging was opened for this chunk");
                // Hash and spill each chunk. The uplink hash arrives later, so
                // this is not the piece key yet. Up to one part stays in
                // memory and reaches S3 once, on the piece key.
                hasher.update(&chunk.data);
                spill.write(&chunk.data).await.map_err(store_err)?;
                staged = next_len;
                usage.bytes = u64::try_from(staged).unwrap_or(0);
            }
            if let Some(done) = req.done {
                let Some(limit) = limit.take() else {
                    return Err(Fail::proto(RPC_INVALID_ARGUMENT, "expected order limit"));
                };
                let digest = hasher.finalize();
                return self
                    .commit_upload(
                        out,
                        (&limit, limit_bytes),
                        algo,
                        (
                            staging,
                            staged,
                            space.take().expect("accepted limit reserved space"),
                        ),
                        &digest,
                        &done,
                    )
                    .await;
            }
        }
    }

    async fn commit_upload<T>(
        &self,
        out: &mut Out<T>,
        limit: (&OrderLimit, Vec<u8>),
        algo: PieceHashAlgo,
        spill: (Option<(Upload, String)>, i64, SpaceReservation<'_>),
        digest: &[u8],
        done: &PieceHash,
    ) -> Result<(), Fail>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let (limit, limit_bytes) = limit;
        // The Go endpoint wraps a failed piece-hash check, and a changed hash
        // algorithm, as Internal. The size check below stays InvalidArgument.
        if done.piece_id != limit.piece_id {
            return Err(Fail::proto(RPC_INTERNAL, "piece id changed"));
        }
        if done.hash_algorithm != algo.to_i32() {
            return Err(Fail::proto(RPC_INTERNAL, "hash algorithm mismatch"));
        }
        let (staging, staged, space) = spill;
        if done.piece_size != staged {
            return Err(Fail::proto(RPC_INVALID_ARGUMENT, "piece size mismatch"));
        }
        if done.hash.as_slice() != digest {
            return Err(Fail::proto(RPC_INTERNAL, "piece hash mismatch"));
        }
        let public = PiecePublicKey::from_bytes(&limit.uplink_public_key)
            .map_err(|_| Fail::proto(RPC_INTERNAL, "invalid uplink public key"))?;
        verify_piece_hash_uplink(done, &public)
            .map_err(|_| Fail::proto(RPC_INTERNAL, "invalid piece hash signature"))?;
        if digest.len() != 32 {
            return Err(Fail::proto(RPC_INTERNAL, "piece hash is not 32 bytes"));
        }
        if done.signature.is_empty() {
            return Err(Fail::proto(RPC_INTERNAL, "invalid piece hash signature"));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(digest);

        let satellite_id = parse_node_id(&limit.satellite_id)?;
        let sat = satellite_id.to_string();
        let piece = encode_hex(&limit.piece_id);
        // Metadata, including the hash, is fixed when the piece object is
        // created. The spill has no piece metadata. Publish the piece key
        // only after the uplink hash verifies.
        let meta = PieceMeta {
            hash,
            algorithm: store_algo(algo),
            // This node's clock, not the uplink's `done.timestamp`. Retain
            // compares it with the satellite's filter date, and an uplink
            // must not be able to date a piece out of, or into, that check.
            created: SystemTime::now(),
            expires: limit
                .piece_expiration
                .as_ref()
                .and_then(timestamp_to_system),
            order_limit: limit_bytes,
            hash_signature: done.signature.clone(),
            hash_timestamp: done
                .timestamp
                .as_ref()
                .map(|stamp| (stamp.seconds, stamp.nanos)),
        };
        if staged == 0 {
            let upload = self
                .store
                .upload_piece(&sat, &piece, meta)
                .map_err(store_err)?;
            upload.finish().await.map_err(store_err)?;
        } else {
            let Some((staging, stage_id)) = staging else {
                return Err(Fail::proto(RPC_INTERNAL, "missing staged piece"));
            };
            self.store
                .publish_staged(staging, &stage_id, &sat, &piece, meta)
                .await
                .map_err(store_err)?;
        }
        let piece_size = staged;
        space.commit(u64::try_from(piece_size).unwrap_or(0));

        let mut sn_hash = PieceHash {
            piece_id: limit.piece_id.clone(),
            hash: digest.to_vec(),
            piece_size,
            timestamp: Some(system_to_timestamp(SystemTime::now())),
            signature: Vec::new(),
            hash_algorithm: algo.to_i32(),
        };
        sign_piece_hash_node(&mut sn_hash, &self.identity)
            .map_err(|err| Fail::proto(RPC_INTERNAL, err.to_string()))?;
        let response = PieceUploadResponse {
            done: Some(sn_hash),
            // TLS and QUIC take the leaf from the connection. Noise cannot.
            node_certchain: out.node_certchain.clone(),
        };
        out.message(&response.encode_to_vec()).await?;
        out.close().await?;
        Ok(())
    }

    async fn download<T>(&self, out: &mut Out<T>) -> Result<(), Fail>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let mut usage = Usage::default();
        let result = self.download_stream(out, &mut usage).await;
        self.note_usage(&usage);
        result
    }

    async fn download_stream<T>(&self, out: &mut Out<T>, usage: &mut Usage) -> Result<(), Fail>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let mut limit: Option<OrderLimit> = None;
        let mut chunk = None;
        let mut authorized: i64 = 0;
        let mut advisory: i32 = 0;
        // The guard holds the hour shut for this RPC. The order is noted only
        // after the piece is readable, so a missing piece is not settled.
        let mut tracked = None;
        // Orders are cumulative and checked to be nondecreasing. Only the
        // latest one can matter for settlement, even when the peer repeats
        // an order indefinitely before sending its range.
        let mut early_order = None;
        loop {
            let Some(bytes) = out.recv().await? else {
                return Err(Fail::proto(
                    RPC_INVALID_ARGUMENT,
                    "missing download request",
                ));
            };
            let req = PieceDownloadRequest::decode(bytes.as_slice())
                .map_err(|err| Fail::proto(RPC_INVALID_ARGUMENT, err.to_string()))?;
            if req.maximum_chunk_size != 0 {
                advisory = req.maximum_chunk_size;
            }
            if let Some(next) = req.limit {
                if limit.is_some() {
                    return Err(Fail::proto(RPC_INVALID_ARGUMENT, "duplicate order limit"));
                }
                let unknown = limit_unknown(&bytes);
                self.check_limit(&next, false, &unknown)?;
                tracked = Some(self.track_order(&next, encode_limit(&next, &unknown))?);
                limit = Some(next);
            }
            if let Some(order) = req.order {
                let Some(limit_ref) = limit.as_ref() else {
                    return Err(Fail::proto(RPC_INVALID_ARGUMENT, "order before limit"));
                };
                authorized = check_order(limit_ref, &order, authorized).map_err(as_internal)?;
                early_order = Some(order);
            }
            if let Some(next) = req.chunk {
                chunk = Some(next);
            }
            if limit.is_some() && chunk.is_some() {
                break;
            }
        }
        let limit =
            limit.ok_or_else(|| Fail::proto(RPC_INVALID_ARGUMENT, "missing order limit"))?;
        let chunk = chunk.ok_or_else(|| Fail::proto(RPC_INVALID_ARGUMENT, "missing chunk"))?;
        if chunk.chunk_size > limit.limit {
            return Err(Fail::proto(
                RPC_INVALID_ARGUMENT,
                "requested more than the order limit allows",
            ));
        }
        let offset = u64::try_from(chunk.offset)
            .map_err(|_| Fail::proto(RPC_INVALID_ARGUMENT, "negative offset"))?;
        let size = u64::try_from(chunk.chunk_size)
            .map_err(|_| Fail::proto(RPC_INVALID_ARGUMENT, "negative size"))?;
        let end = offset
            .checked_add(size)
            .ok_or_else(|| Fail::proto(RPC_INVALID_ARGUMENT, "range overflow"))?;

        let satellite_id = parse_node_id(&limit.satellite_id)?;
        let piece = encode_hex(&limit.piece_id);
        let sat = satellite_id.to_string();
        let info = self
            .store
            .info(&sat, &piece)
            .map_err(store_err)?
            .ok_or_else(|| Fail::proto(RPC_NOT_FOUND, "piece not found"))?;
        if !matches!(info.state, PieceState::Live | PieceState::Trash) {
            return Err(Fail::proto(RPC_NOT_FOUND, "piece not found"));
        }
        if end > info.size {
            return Err(Fail::proto(
                RPC_INVALID_ARGUMENT,
                "requested more data than available",
            ));
        }
        let mut body = if size == 0 {
            None
        } else {
            Some(
                self.store
                    .open_download(&sat, &piece, Some(offset..end))
                    .await
                    .map_err(store_err)?,
            )
        };
        // A trashed piece that is still wanted goes back to live, as in the
        // Go node. Telling the peer it was restored and leaving the row trash
        // would let the chore delete it a week after it was trashed. Only an
        // opened object is restored: a zero-length read proves nothing.
        let restored = info.state == PieceState::Trash
            && body.is_some()
            && self
                .store
                .restore_piece(&sat, &piece)
                .await
                .map_err(store_err)?;
        // A later failure can still save the largest order. Nothing before
        // this point transferred a byte, so those orders are discarded.
        if let (Some(tracked), Some(order)) = (tracked.as_mut(), early_order.as_ref()) {
            tracked.note(order);
        }
        usage.satellite = sat.clone();
        usage.action = limit.action;
        usage.ordered_up_to(authorized);
        let mut pending = Vec::new();

        // GET and GET_AUDIT do not send the hash. GET_REPAIR does, before bytes.
        if limit.action == PieceAction::GetRepair as i32 {
            let stored_limit = OrderLimit::decode(info.order_limit.as_slice())
                .map_err(|err| Fail::proto(RPC_INTERNAL, err.to_string()))?;
            // The repairer verifies the satellite's signature on this limit.
            // A stored field this build does not know is part of what was
            // signed, so such a limit goes out as the stored bytes.
            let keeps_unknown = wire::unknown_fields(&info.order_limit, wire::ORDER_LIMIT_FIELDS)
                .is_some_and(|unknown| !unknown.is_empty());
            let header = PieceDownloadResponse {
                hash: Some(PieceHash {
                    piece_id: limit.piece_id.clone(),
                    hash: info.hash.to_vec(),
                    piece_size: i64::try_from(info.size).unwrap_or(i64::MAX),
                    timestamp: info
                        .hash_timestamp
                        .map(|(seconds, nanos)| prost_types::Timestamp { seconds, nanos }),
                    signature: info.hash_signature.clone(),
                    hash_algorithm: algo_i32(info.algorithm),
                }),
                limit: (!keeps_unknown).then_some(stored_limit),
                restored_from_trash: restored,
                chunk: None,
            };
            let mut header = header.encode_to_vec();
            if keeps_unknown {
                wire::put_embedded(&mut header, 3, &info.order_limit);
            }
            out.message(&header).await?;
        } else if restored {
            let header = PieceDownloadResponse {
                restored_from_trash: true,
                ..PieceDownloadResponse::default()
            };
            out.message(&header.encode_to_vec()).await?;
        }

        // The uplink sends the next order only after it has read part of what
        // was already authorized. Do not send past that, or both sides wait.
        let chunk_size = chunk_limit(advisory);
        let mut sent: u64 = 0;
        let mut file_off = offset;
        // The uplink closed its side of the stream. No further order can come.
        let mut orders_closed = false;
        while sent < size {
            // The uplink signs its next order before it needs it. Take every
            // order that has already arrived, as the Go node's receive loop
            // does. A download cancelled after this point then settles the
            // largest order the uplink sent, not the one being worked off.
            while !orders_closed {
                match out.recv_ready().await? {
                    Some(Some(more)) => {
                        authorized = later_order(&limit, &more, authorized, &mut tracked)?;
                        usage.ordered_up_to(authorized);
                    }
                    Some(None) => orders_closed = true,
                    None => break,
                }
            }
            let sent_i =
                i64::try_from(sent).map_err(|_| Fail::proto(RPC_INTERNAL, "offset overflow"))?;
            if sent_i >= authorized {
                let more = if orders_closed {
                    None
                } else {
                    out.recv().await?
                };
                let Some(more) = more else {
                    return Err(Fail::proto(
                        RPC_INVALID_ARGUMENT,
                        "order closed before the requested bytes were authorized",
                    ));
                };
                authorized = later_order(&limit, &more, authorized, &mut tracked)?;
                usage.ordered_up_to(authorized);
                continue;
            }
            let room = u64::try_from(authorized - sent_i)
                .map_err(|_| Fail::proto(RPC_INTERNAL, "offset overflow"))?;
            let n = room.min(size - sent).min(chunk_size as u64);
            let reader = body
                .as_mut()
                .ok_or_else(|| Fail::proto(RPC_INTERNAL, "missing piece body"))?;
            let data = read_piece(reader, &mut pending, n).await?;
            let response = PieceDownloadResponse {
                chunk: Some(piece_download_response::Chunk {
                    offset: i64::try_from(file_off)
                        .map_err(|_| Fail::proto(RPC_INTERNAL, "offset overflow"))?,
                    data,
                }),
                ..PieceDownloadResponse::default()
            };
            out.message(&response.encode_to_vec()).await?;
            sent += n;
            file_off += n;
        }
        out.close().await?;
        Ok(())
    }

    async fn exists<T>(&self, out: &mut Out<T>, peer: Option<NodeId>) -> Result<(), Fail>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        // Exists is the satellite's call. The id is the TLS client, not a field.
        let Some(peer) = peer else {
            return Err(Fail::proto(RPC_UNAUTHENTICATED, "missing peer identity"));
        };
        if !self.satellites.contains_key(&peer) {
            return Err(Fail::proto(
                RPC_PERMISSION_DENIED,
                "exists called with untrusted id",
            ));
        }
        let Some(bytes) = out.recv().await? else {
            return Err(Fail::proto(RPC_INVALID_ARGUMENT, "missing exists request"));
        };
        let req = ExistsRequest::decode(bytes.as_slice())
            .map_err(|err| Fail::proto(RPC_INVALID_ARGUMENT, err.to_string()))?;
        let sat = peer.to_string();
        let mut missing = Vec::new();
        let mut storage_method = Vec::with_capacity(req.piece_ids.len());
        for (index, piece_id) in req.piece_ids.iter().enumerate() {
            if piece_id.len() != 32 {
                return Err(Fail::proto(
                    RPC_INVALID_ARGUMENT,
                    "piece id must be 32 bytes",
                ));
            }
            match self.store.exists(&sat, &encode_hex(piece_id)) {
                Ok(true) => storage_method.push(StorageMethod::Piecestore as i32),
                Ok(false) => {
                    storage_method.push(StorageMethod::Unspecified as i32);
                    let index = u32::try_from(index)
                        .map_err(|_| Fail::proto(RPC_INVALID_ARGUMENT, "too many piece ids"))?;
                    missing.push(index);
                }
                Err(err) => return Err(store_err(err)),
            }
        }
        let response = ExistsResponse {
            missing,
            storage_method,
        };
        out.message(&response.encode_to_vec()).await?;
        out.close().await?;
        Ok(())
    }

    async fn retain<T>(&self, out: &mut Out<T>, peer: Option<NodeId>) -> Result<(), Fail>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let peer = self.trusted_satellite(peer, "retain")?;
        let Some(bytes) = out.recv().await? else {
            return Err(Fail::proto(RPC_INVALID_ARGUMENT, "missing retain request"));
        };
        let req = RetainRequest::decode(bytes.as_slice())
            .map_err(|err| Fail::proto(RPC_INVALID_ARGUMENT, err.to_string()))?;
        self.apply_retain(peer, &req).await?;
        reply_retain(out).await
    }

    async fn retain_big<T>(&self, out: &mut Out<T>, peer: Option<NodeId>) -> Result<(), Fail>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let peer = self.trusted_satellite(peer, "retain")?;
        // Same assembly as `RetainRequestFromStream`: chunks concatenate, and
        // the message that carries the hash ends the stream.
        let mut creation_date = None;
        let mut filter = Vec::new();
        loop {
            let Some(bytes) = out.recv().await? else {
                return Err(Fail::proto(RPC_INTERNAL, "retain closed before the hash"));
            };
            let req = RetainRequest::decode(bytes.as_slice())
                .map_err(|err| Fail::proto(RPC_INVALID_ARGUMENT, err.to_string()))?;
            // The first date that is set, as `RetainRequestFromStream` takes it.
            if creation_date
                .as_ref()
                .and_then(timestamp_to_system)
                .is_none()
            {
                creation_date = req.creation_date;
            }
            filter.extend_from_slice(&req.filter);
            if req.hash.is_empty() {
                continue;
            }
            let req = RetainRequest {
                creation_date,
                filter,
                hash_algorithm: req.hash_algorithm,
                hash: req.hash,
            };
            self.apply_retain(peer, &req).await?;
            return reply_retain(out).await;
        }
    }

    /// Trashes this satellite's live rows created more than
    /// [`RETAIN_MAX_TIME_SKEW`] before `creation_date` when the filter does
    /// not contain them. The object stays; the 7-day chore deletes trash.
    async fn apply_retain(&self, peer: NodeId, req: &RetainRequest) -> Result<(), Fail> {
        check_retain_hash(req.hash_algorithm, &req.filter, &req.hash)?;
        let filter = crate::bloom::Filter::from_bytes(&req.filter)
            .map_err(|err| Fail::proto(RPC_INVALID_ARGUMENT, err.to_string()))?;
        // An unset date is not an error in Go: its cutoff falls before every
        // piece, nothing is trashed, and the satellite gets its reply. The
        // same holds for a cutoff at or before the epoch.
        let created_before = req
            .creation_date
            .as_ref()
            .and_then(timestamp_to_system)
            .and_then(|created| created.checked_sub(RETAIN_MAX_TIME_SKEW))
            .filter(|cutoff| *cutoff > UNIX_EPOCH);
        let Some(created_before) = created_before else {
            return Ok(());
        };
        let sat = peer.to_string();
        // Page the walk: the piece list of a well-filled node does not fit
        // one query's memory. One transaction per batch, not one commit per
        // piece. A row that is gone, or no longer live, between the list and
        // the flag is skipped.
        let now = SystemTime::now();
        let mut after: Option<String> = None;
        loop {
            let page = self
                .store
                .live_page_before(&sat, created_before, after.as_deref(), RETAIN_PAGE)
                .map_err(store_err)?;
            if page.is_empty() {
                return Ok(());
            }
            after = page.last().cloned();
            let full = page.len() == RETAIN_PAGE;
            let mut rejected = Vec::new();
            for piece_id in page {
                if !filter.contains(&decode_piece_id(&piece_id)?) {
                    rejected.push(piece_id);
                }
            }
            for batch in rejected.chunks(RETAIN_BATCH) {
                self.store
                    .trash_created_before(&sat, batch, created_before, now)
                    .map_err(store_err)?;
                tokio::task::yield_now().await;
            }
            if !full {
                return Ok(());
            }
        }
    }

    /// Puts every trashed piece of the calling satellite back to live.
    ///
    /// This is how a satellite undoes a bad bloom filter. Trash the chore
    /// already deleted is gone and is not restored.
    async fn restore_trash<T>(&self, out: &mut Out<T>, peer: Option<NodeId>) -> Result<(), Fail>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let peer = self.trusted_satellite(peer, "restore trash")?;
        let Some(bytes) = out.recv().await? else {
            return Err(Fail::proto(
                RPC_INVALID_ARGUMENT,
                "missing restore trash request",
            ));
        };
        RestoreTrashRequest::decode(bytes.as_slice())
            .map_err(|err| Fail::proto(RPC_INVALID_ARGUMENT, err.to_string()))?;
        self.store
            .restore_trash(&peer.to_string())
            .await
            .map_err(store_err)?;
        out.message(&RestoreTrashResponse {}.encode_to_vec())
            .await?;
        out.close().await?;
        Ok(())
    }

    /// The satellite's ping-back. An empty reply to a trusted satellite.
    async fn ping_node<T>(&self, out: &mut Out<T>, peer: Option<NodeId>) -> Result<(), Fail>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        // The Go endpoint answers Unauthenticated for an untrusted peer too.
        let Some(peer) = peer else {
            return Err(Fail::proto(RPC_UNAUTHENTICATED, "missing peer identity"));
        };
        if !self.satellites.contains_key(&peer) {
            return Err(Fail::proto(
                RPC_UNAUTHENTICATED,
                "ping called with untrusted id",
            ));
        }
        let Some(bytes) = out.recv().await? else {
            return Err(Fail::proto(RPC_INVALID_ARGUMENT, "missing ping request"));
        };
        crate::contact::ContactPingRequest::decode(bytes.as_slice())
            .map_err(|err| Fail::proto(RPC_INVALID_ARGUMENT, err.to_string()))?;
        out.message(&crate::contact::ContactPingResponse {}.encode_to_vec())
            .await?;
        out.close().await?;
        Ok(())
    }

    fn trusted_satellite(&self, peer: Option<NodeId>, rpc: &str) -> Result<NodeId, Fail> {
        // Same check as Exists: the TLS client is the satellite, not a field.
        let Some(peer) = peer else {
            return Err(Fail::proto(RPC_UNAUTHENTICATED, "missing peer identity"));
        };
        if !self.satellites.contains_key(&peer) {
            return Err(Fail::proto(
                RPC_PERMISSION_DENIED,
                format!("{rpc} called with untrusted id"),
            ));
        }
        Ok(peer)
    }

    /// `unknown` is [`limit_unknown`] of the message that carried `limit`.
    fn check_limit(&self, limit: &OrderLimit, upload: bool, unknown: &[u8]) -> Result<(), Fail> {
        let allowed = if upload {
            limit.action == PieceAction::Put as i32 || limit.action == PieceAction::PutRepair as i32
        } else {
            limit.action == PieceAction::Get as i32
                || limit.action == PieceAction::GetRepair as i32
                || limit.action == PieceAction::GetAudit as i32
        };
        if !allowed {
            return Err(Fail::proto(
                RPC_INVALID_ARGUMENT,
                if upload {
                    "expected put or put repair"
                } else {
                    "expected get, get repair, or get audit"
                },
            ));
        }
        if limit.limit < 0 {
            return Err(Fail::proto(RPC_INVALID_ARGUMENT, "order limit is negative"));
        }
        if limit.storage_node_id.as_slice() != self.identity.node_id().as_bytes().as_slice() {
            return Err(Fail::proto(
                RPC_INVALID_ARGUMENT,
                "order intended for another storage node",
            ));
        }
        if limit.piece_id.len() != 32 {
            return Err(Fail::proto(
                RPC_INVALID_ARGUMENT,
                "piece id must be 32 bytes",
            ));
        }
        let now = SystemTime::now();
        if expired(limit.piece_expiration.as_ref(), now) {
            return Err(Fail::proto(RPC_INVALID_ARGUMENT, "piece expired"));
        }
        if expired(limit.order_expiration.as_ref(), now) {
            return Err(Fail::proto(RPC_INVALID_ARGUMENT, "order expired"));
        }
        if !creation_ok(limit.order_creation.as_ref(), now) {
            return Err(Fail::proto(
                RPC_INVALID_ARGUMENT,
                "order creation is outside the one hour grace",
            ));
        }
        if limit.uplink_public_key.is_empty() {
            return Err(Fail::proto(
                RPC_INVALID_ARGUMENT,
                "missing uplink public key",
            ));
        }
        if limit.serial_number.is_empty() {
            return Err(Fail::proto(RPC_INVALID_ARGUMENT, "missing serial number"));
        }
        let satellite_id = parse_node_id(&limit.satellite_id)?;
        // Go refuses these three as InvalidArgument before it looks at trust
        // or at the signature.
        if satellite_id.is_zero() {
            return Err(Fail::proto(RPC_INVALID_ARGUMENT, "missing satellite id"));
        }
        if limit.satellite_signature.is_empty() {
            return Err(Fail::proto(
                RPC_INVALID_ARGUMENT,
                "missing satellite signature",
            ));
        }
        if limit.piece_id.iter().all(|byte| *byte == 0) {
            return Err(Fail::proto(RPC_INVALID_ARGUMENT, "missing piece id"));
        }
        let Some(known) = self.satellites.get(&satellite_id) else {
            return Err(Fail::proto(RPC_PERMISSION_DENIED, "untrusted satellite"));
        };
        let leaf = known
            .leaf
            .read()
            .unwrap_or_else(|err| err.into_inner())
            .clone();
        if leaf.is_empty() {
            return Err(Fail::proto(
                RPC_UNAUTHENTICATED,
                "satellite certificate is not known",
            ));
        }
        let signed = if unknown.is_empty() {
            verify_order_limit(limit, &leaf).is_ok()
        } else {
            // The satellite signed a field this build does not have. Go
            // verifies over the known fields followed by the unknown ones,
            // which is the satellite's own encoding as long as new fields
            // take higher numbers.
            let mut bytes = encode_order_limit(limit);
            bytes.extend_from_slice(unknown);
            storj_rpc::hash_and_verify(&leaf, &bytes, &limit.satellite_signature).is_ok()
        };
        if !signed {
            return Err(Fail::proto(
                RPC_UNAUTHENTICATED,
                "invalid order limit signature",
            ));
        }
        self.reserve_serial(
            satellite_id,
            &limit.serial_number,
            serial_deadline(limit, now),
        )
    }

    /// Reserve capacity under the same lock as the free-space check, so
    /// concurrent uploads cannot each claim the same bytes.
    fn reserve_space(&self, limit: &OrderLimit) -> Result<SpaceReservation<'_>, Fail> {
        let need = u64::try_from(limit.limit).unwrap_or(u64::MAX);
        let free = {
            let mut space = self
                .free_space
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            let committed_free = match space.cached {
                // Do not sample the index while an upload may have replaced
                // a live row with `writing`. That temporarily omits its old
                // size. Commits charge the cache until every upload releases.
                Some((read_at, free)) if read_at.elapsed() < SPACE_REFRESH || space.uploads > 0 => {
                    free
                }
                _ => {
                    let free = self.store.space().map_err(store_err)?.free;
                    space.cached = Some((Instant::now(), free));
                    free
                }
            };
            let free = committed_free.saturating_sub(space.reserved);
            if need <= free {
                space.reserved += need;
                space.uploads += 1;
            }
            free
        };
        if free.saturating_sub(need) < REPORT_CAPACITY_THRESHOLD {
            self.low_space
                .send_modify(|generation| *generation = generation.wrapping_add(1));
        }
        if need > free {
            return Err(Fail::proto(
                RPC_ABORTED,
                format!("not enough available disk space, have: {free}, need: {need}"),
            ));
        }
        Ok(SpaceReservation {
            node: self,
            bytes: need,
        })
    }

    fn reserve_serial(
        &self,
        satellite: NodeId,
        serial: &[u8],
        deadline: SystemTime,
    ) -> Result<(), Fail> {
        let mut used = self.serials.lock().unwrap_or_else(|err| err.into_inner());
        if !used.reserve(satellite, serial, deadline, SystemTime::now()) {
            return Err(Fail::proto(RPC_UNAUTHENTICATED, "duplicate serial number"));
        }
        Ok(())
    }

    /// Counts a transfer whose order was kept for settlement, finished or not.
    fn note_usage(&self, usage: &Usage) {
        if usage.ordered {
            self.note_bandwidth(&usage.satellite, usage.action, usage.bytes);
        }
    }

    /// Records a transfer. Zero bytes are ignored. A sqlite error is logged
    /// so the piece RPC still succeeds.
    fn note_bandwidth(&self, satellite: &str, action: i32, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let Some(kind) = bandwidth_kind(action) else {
            return;
        };
        if let Err(err) = self
            .store
            .add_bandwidth(satellite, kind, bytes, SystemTime::now())
        {
            eprintln!("storagenode: bandwidth counter: {err}");
        }
    }

    /// `encoded` is [`encode_limit`] of `limit`, saved with the order.
    fn track_order(
        &self,
        limit: &OrderLimit,
        encoded: Vec<u8>,
    ) -> Result<orders::OrderGuard, Fail> {
        let satellite = parse_node_id(&limit.satellite_id)?;
        let window = order_window(limit)?;
        Ok(self
            .orders
            .begin(self.store.orders(), satellite, window, encoded))
    }

    /// Settles closed order hours as of `now`. Tests pass a later clock so a
    /// just-finished hour is closed without waiting.
    pub(crate) async fn settle_orders(&self, now: SystemTime) {
        let db = self.store.orders();
        self.orders
            .settle(
                &self.identity,
                &db,
                |id| self.satellites.get(&id).map(|sat| sat.address.clone()),
                &|id, leaf| self.observe_satellite_leaf(id, leaf),
                now,
            )
            .await;
    }

    /// Once an hour, delete expired pieces and trash older than seven days.
    ///
    /// Without this, both stay in the bucket and expired rows stay in `used`.
    pub(crate) async fn serve_chore(self: Arc<Self>) {
        loop {
            if let Err(err) = self.store.run_chore(SystemTime::now()).await {
                eprintln!("storagenode: piece chore: {err}");
            }
            tokio::time::sleep(CHORE_INTERVAL).await;
        }
    }

    /// Once an hour, after a delay of up to 30 seconds, settle closed hours.
    pub(crate) async fn serve_orders(self: Arc<Self>) {
        loop {
            tokio::time::sleep(orders::jitter(self.node_id())).await;
            self.settle_orders(SystemTime::now()).await;
            tokio::time::sleep(orders::SEND_INTERVAL).await;
        }
    }
}

/// Order-limit serials this process has accepted, kept until the order expires.
///
/// `by_deadline` holds the same keys in expiry order. Every upload and
/// download reserves a serial under one lock, so dropping the expired ones
/// must cost their number, not a scan of every serial still valid.
///
/// Go's table is capped at 1 MiB and drops a random serial once surpassed.
/// Here the cap is a count of similar size, and the serial with the nearest
/// deadline goes first: it would have expired soonest, so the replay gap it
/// opens is the smallest.
struct Serials {
    used: HashSet<([u8; 32], Vec<u8>)>,
    by_deadline: BTreeSet<(SystemTime, [u8; 32], Vec<u8>)>,
    /// The most serials held at once. 16-byte serials plus 32-byte satellite
    /// ids and map overhead are about 100 bytes each, so this is ~1 MiB.
    max: usize,
}

/// Go `piecestore.Config.MaxUsedSerialsSize` (1 MiB), as a serial count.
const MAX_SERIALS: usize = 10_000;

impl Default for Serials {
    fn default() -> Self {
        Self {
            used: HashSet::new(),
            by_deadline: BTreeSet::new(),
            max: MAX_SERIALS,
        }
    }
}

impl Serials {
    /// False when this satellite's serial is already reserved and its
    /// deadline is still after `now`.
    fn reserve(
        &mut self,
        satellite: NodeId,
        serial: &[u8],
        deadline: SystemTime,
        now: SystemTime,
    ) -> bool {
        self.drop_expired(now);
        let key = (*satellite.as_bytes(), serial.to_vec());
        if self.used.contains(&key) {
            return false;
        }
        while self.used.len() >= self.max {
            // Full: forget the serial whose deadline is nearest.
            if !self.drop_first() {
                break;
            }
        }
        self.used.insert(key.clone());
        self.by_deadline.insert((deadline, key.0, key.1));
        true
    }

    fn drop_expired(&mut self, now: SystemTime) {
        while let Some(first) = self.by_deadline.first()
            && first.0 <= now
        {
            self.drop_first();
        }
    }

    /// Removes the entry with the nearest deadline. False when empty.
    fn drop_first(&mut self) -> bool {
        let Some((_, satellite, serial)) = self.by_deadline.pop_first() else {
            return false;
        };
        self.used.remove(&(satellite, serial));
        true
    }
}

fn peer_node_id(tls: &tokio_rustls::server::TlsStream<TcpStream>) -> Option<NodeId> {
    let certs = tls.get_ref().1.peer_certificates()?;
    let ca = certs.get(1)?;
    NodeId::from_certificate_der(ca.as_ref()).ok()
}

fn quic_peer_node_id(connection: &quinn::Connection) -> Option<NodeId> {
    let certs = connection
        .peer_identity()?
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .ok()?;
    let ca = certs.get(1)?;
    NodeId::from_certificate_der(ca.as_ref()).ok()
}

fn cert_chain_der(identity: &Identity) -> Vec<u8> {
    let mut chain = Vec::new();
    for cert in identity.cert_chain() {
        chain.extend_from_slice(cert.as_ref());
    }
    chain
}

/// QUIC bi-stream as one byte pipe. There is no TCP mux header on this socket.
struct BiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl AsyncRead for BiStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for BiStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_shutdown(cx)
    }
}

fn quic_server_config(identity: &Identity) -> io::Result<quinn::ServerConfig> {
    let mut tls =
        storj_rpc::server_config(identity).map_err(|err| io::Error::other(err.to_string()))?;
    tls.alpn_protocols = vec![b"storj".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|err| io::Error::other(err.to_string()))?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_secs(15 * 60)
            .try_into()
            .expect("15 minutes fits in a QUIC idle timeout"),
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    server.transport_config(Arc::new(transport));
    Ok(server)
}

/// `fut`, or `TimedOut` once `deadline` passes.
async fn before<T>(
    deadline: tokio::time::Instant,
    fut: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    match tokio::time::timeout_at(deadline, fut).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "handshake timed out",
        )),
    }
}

fn io_err(err: storj_rpc::Error) -> io::Error {
    io::Error::other(err.to_string())
}

struct Out<T> {
    conn: Conn<T>,
    stream_id: u64,
    next_id: u64,
    /// Empty on TLS and QUIC. Noise uploads copy this into `node_certchain`.
    node_certchain: Vec<u8>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Out<T> {
    async fn send(&mut self, kind: Kind, data: &[u8]) -> Result<(), storj_rpc::Error> {
        let message_id = self.next_id;
        self.next_id += 1;
        self.conn
            .write_packet(&Packet {
                stream_id: self.stream_id,
                message_id,
                kind,
                control: false,
                data: data.to_vec(),
            })
            .await
    }

    async fn message(&mut self, data: &[u8]) -> Result<(), Fail> {
        self.send(Kind::MESSAGE, data)
            .await
            .map_err(Fail::Transport)
    }

    async fn close(&mut self) -> Result<(), Fail> {
        self.send(Kind::CLOSE, &[]).await.map_err(Fail::Transport)
    }

    async fn fail(&mut self, code: u64, message: &str) -> Result<(), storj_rpc::Error> {
        self.send(Kind::ERROR, &marshal_error(code, message)).await
    }

    /// Reads and discards until the peer ends the stream, hangs up, or
    /// `budget` passes.
    ///
    /// Closing a socket that still has unread bytes sends a reset, and a
    /// reset can discard the error packet before the peer has read it. An
    /// uplink whose upload is refused has chunks in flight, and a satellite
    /// that audits must see NotFound, not a broken connection.
    async fn linger(&mut self, budget: Duration) {
        let _ = tokio::time::timeout(budget, async {
            loop {
                match self.conn.read_packet().await {
                    Ok(pkt) if matches!(pkt.kind, Kind::CLOSE | Kind::CANCEL | Kind::ERROR) => {
                        break;
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        })
        .await;
    }

    /// [`Self::recv`] for a packet that has already arrived. `Ok(None)` when
    /// the peer has sent nothing more yet.
    ///
    /// `recv` is polled once and dropped. `Conn::read_packet` keeps a partial
    /// frame in the connection, so nothing that was read is lost.
    async fn recv_ready(&mut self) -> Result<Option<Option<Vec<u8>>>, Fail> {
        let mut recv = std::pin::pin!(self.recv());
        std::future::poll_fn(|cx| match recv.as_mut().poll(cx) {
            Poll::Ready(result) => Poll::Ready(result.map(Some)),
            Poll::Pending => Poll::Ready(Ok(None)),
        })
        .await
    }

    async fn recv(&mut self) -> Result<Option<Vec<u8>>, Fail> {
        loop {
            let pkt = self.conn.read_packet().await?;
            if pkt.stream_id != self.stream_id {
                if pkt.stream_id < self.stream_id {
                    continue;
                }
                return Err(Fail::Transport(storj_rpc::Error::UnexpectedStream {
                    got: pkt.stream_id,
                    expected: self.stream_id,
                }));
            }
            match pkt.kind {
                Kind::MESSAGE => return Ok(Some(pkt.data)),
                Kind::CLOSE | Kind::CLOSE_SEND => return Ok(None),
                Kind::CANCEL => return Err(Fail::proto(RPC_CANCELED, "canceled")),
                Kind::ERROR => return Err(Fail::proto(RPC_CANCELED, "client error")),
                _ if pkt.control => continue,
                other => {
                    return Err(Fail::proto(
                        RPC_INVALID_ARGUMENT,
                        format!("unexpected packet {other}"),
                    ));
                }
            }
        }
    }
}

/// What one upload or download adds to the local bandwidth counters.
///
/// The Go node adds it when it saves the order, which it does on every way
/// out of the RPC. An upload counts the bytes it wrote. A download counts
/// its largest order, not the bytes it sent.
#[derive(Default)]
struct Usage {
    satellite: String,
    action: i32,
    bytes: u64,
    /// An order with a positive amount was kept. Without one nothing is
    /// settled and nothing is counted.
    ordered: bool,
}

impl Usage {
    fn ordered_up_to(&mut self, amount: i64) {
        if let Ok(bytes) = u64::try_from(amount)
            && bytes > 0
        {
            self.ordered = true;
            self.bytes = bytes;
        }
    }
}

enum Fail {
    Proto { code: u64, message: String },
    Transport(storj_rpc::Error),
}

impl Fail {
    fn proto(code: u64, message: impl Into<String>) -> Self {
        Self::Proto {
            code,
            message: message.into(),
        }
    }
}

impl From<storj_rpc::Error> for Fail {
    fn from(err: storj_rpc::Error) -> Self {
        Self::Transport(err)
    }
}

fn next_stage_id() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    format!("{:016x}", NEXT.fetch_add(1, Ordering::Relaxed))
}

fn bandwidth_kind(action: i32) -> Option<BandwidthKind> {
    match PieceAction::try_from(action) {
        Ok(PieceAction::Put) => Some(BandwidthKind::Put),
        Ok(PieceAction::Get) => Some(BandwidthKind::Get),
        Ok(PieceAction::GetAudit) => Some(BandwidthKind::GetAudit),
        Ok(PieceAction::GetRepair) => Some(BandwidthKind::GetRepair),
        Ok(PieceAction::PutRepair) => Some(BandwidthKind::PutRepair),
        _ => None,
    }
}

fn store_err(err: s3store::Error) -> Fail {
    match err {
        s3store::Error::NotFound => Fail::proto(RPC_NOT_FOUND, "piece not found"),
        s3store::Error::InvalidKey(message) => Fail::proto(RPC_INVALID_ARGUMENT, message),
        other => Fail::proto(RPC_INTERNAL, other.to_string()),
    }
}

fn hash_algo(value: i32) -> Result<PieceHashAlgo, Fail> {
    match value {
        0 => Ok(PieceHashAlgo::Sha256),
        1 => Ok(PieceHashAlgo::Blake3),
        _ => Err(Fail::proto(RPC_INVALID_ARGUMENT, "unknown hash algorithm")),
    }
}

fn store_algo(algo: PieceHashAlgo) -> HashAlgorithm {
    match algo {
        PieceHashAlgo::Sha256 => HashAlgorithm::Sha256,
        PieceHashAlgo::Blake3 => HashAlgorithm::Blake3,
    }
}

fn algo_i32(algo: HashAlgorithm) -> i32 {
    match algo {
        HashAlgorithm::Sha256 => PieceHashAlgo::Sha256.to_i32(),
        HashAlgorithm::Blake3 => PieceHashAlgo::Blake3.to_i32(),
    }
}

fn check_order(limit: &OrderLimit, order: &Order, previous: i64) -> Result<i64, Fail> {
    if order.serial_number != limit.serial_number {
        return Err(Fail::proto(
            RPC_INVALID_ARGUMENT,
            "order serial number mismatch",
        ));
    }
    if order.amount < previous {
        return Err(Fail::proto(RPC_INVALID_ARGUMENT, "order amount decreased"));
    }
    if order.amount > limit.limit {
        return Err(Fail::proto(RPC_INVALID_ARGUMENT, "order exceeds limit"));
    }
    let public = PiecePublicKey::from_bytes(&limit.uplink_public_key)
        .map_err(|_| Fail::proto(RPC_UNAUTHENTICATED, "invalid uplink public key"))?;
    verify_order(order, &public)
        .map_err(|_| Fail::proto(RPC_UNAUTHENTICATED, "invalid order signature"))?;
    Ok(order.amount)
}

/// The fields of a request's order limit that this build's `OrderLimit` does
/// not have, as they came off the wire. The limit is field 1 of both the
/// upload and the download request. Empty for every limit of today.
fn limit_unknown(request: &[u8]) -> Vec<u8> {
    wire::embedded(request, 1)
        .and_then(|limit| wire::unknown_fields(limit, wire::ORDER_LIMIT_FIELDS))
        .unwrap_or_default()
}

/// The limit as the Go node would marshal it again: the known fields, then
/// the unknown ones. This is what is stored, returned on repair, and settled.
fn encode_limit(limit: &OrderLimit, unknown: &[u8]) -> Vec<u8> {
    let mut bytes = limit.encode_to_vec();
    bytes.extend_from_slice(unknown);
    bytes
}

/// The Go download wraps whatever its send and receive loops return,
/// a refused order included, as Internal.
fn as_internal(fail: Fail) -> Fail {
    match fail {
        Fail::Proto { message, .. } => Fail::proto(RPC_INTERNAL, message),
        transport => transport,
    }
}

/// A download message after the first. Its order raises the authorized
/// amount and becomes the one to settle.
fn later_order(
    limit: &OrderLimit,
    message: &[u8],
    authorized: i64,
    tracked: &mut Option<orders::OrderGuard>,
) -> Result<i64, Fail> {
    let req = PieceDownloadRequest::decode(message)
        .map_err(|err| Fail::proto(RPC_INVALID_ARGUMENT, err.to_string()))?;
    let Some(order) = req.order else {
        return Err(Fail::proto(RPC_INTERNAL, "expected order as the message"));
    };
    let authorized = check_order(limit, &order, authorized).map_err(as_internal)?;
    if let Some(tracked) = tracked.as_mut() {
        tracked.note(&order);
    }
    Ok(authorized)
}

fn check_chunk(
    have: i64,
    limit_bytes: i64,
    authorized: i64,
    chunk: &piece_upload_request::Chunk,
) -> Result<i64, Fail> {
    if chunk.offset < 0 {
        return Err(Fail::proto(RPC_INVALID_ARGUMENT, "negative chunk offset"));
    }
    if chunk.offset != have {
        return Err(Fail::proto(RPC_INVALID_ARGUMENT, "chunk out of order"));
    }
    let add = i64::try_from(chunk.data.len())
        .map_err(|_| Fail::proto(RPC_INVALID_ARGUMENT, "chunk too large"))?;
    let new_len = have
        .checked_add(add)
        .ok_or_else(|| Fail::proto(RPC_INVALID_ARGUMENT, "piece too large"))?;
    if new_len > limit_bytes {
        return Err(Fail::proto(
            RPC_INVALID_ARGUMENT,
            "piece exceeds order limit",
        ));
    }
    if new_len > authorized {
        return Err(Fail::proto(
            RPC_INVALID_ARGUMENT,
            "not enough allocated for the chunk",
        ));
    }
    Ok(new_len)
}

/// Reads `n` bytes from the object stream. `pending` is only the unread tail
/// of the last store chunk, not the piece.
async fn read_piece(body: &mut PieceBody, pending: &mut Vec<u8>, n: u64) -> Result<Vec<u8>, Fail> {
    let n = usize::try_from(n).map_err(|_| Fail::proto(RPC_INTERNAL, "offset overflow"))?;
    while pending.len() < n {
        match body.next().await.map_err(store_err)? {
            Some(chunk) if !chunk.is_empty() => pending.extend_from_slice(&chunk),
            Some(_) => {}
            None => break,
        }
    }
    if pending.len() < n {
        return Err(Fail::proto(RPC_INTERNAL, "short piece read"));
    }
    Ok(pending.drain(..n).collect())
}

/// The same leaf-signed-by-CA check as check-in. `exit-satellite` calls this
/// before it records a row.
pub(crate) fn accept_satellite(satellite: &TrustedSatellite) -> Result<(), BuildError> {
    verified_leaf(satellite)?;
    Ok(())
}

/// The leaf `verify_order_limit` uses.
///
/// The CA must hash to the trusted id and must have signed the leaf.
/// A leaf whose id is the CA id is rejected even when that certificate is
/// self-signed.
fn verified_leaf(satellite: &TrustedSatellite) -> Result<Vec<u8>, BuildError> {
    if satellite.leaf_der.is_empty() || satellite.ca_der.is_empty() {
        return Err(BuildError::Satellite(format!(
            "satellite {} certificate is not known",
            satellite.id
        )));
    }
    let ca_id = NodeId::from_certificate_der(&satellite.ca_der)
        .map_err(|err| BuildError::Satellite(format!("satellite {} CA: {err}", satellite.id)))?;
    if ca_id != satellite.id {
        return Err(BuildError::Satellite(format!(
            "satellite {} CA does not hash to the trusted node id",
            satellite.id
        )));
    }
    let leaf_id = NodeId::from_certificate_der(&satellite.leaf_der)
        .map_err(|err| BuildError::Satellite(format!("satellite {} leaf: {err}", satellite.id)))?;
    if leaf_id == ca_id {
        return Err(BuildError::Satellite(format!(
            "satellite {} leaf is the CA, not the signing certificate",
            satellite.id
        )));
    }
    let mut chain = Vec::with_capacity(satellite.leaf_der.len() + satellite.ca_der.len());
    chain.extend_from_slice(&satellite.leaf_der);
    chain.extend_from_slice(&satellite.ca_der);
    let leaf = storj_rpc::identity::verified_leaf(&chain, satellite.id).map_err(|err| {
        BuildError::Satellite(format!(
            "satellite {} leaf is not signed by its CA: {err}",
            satellite.id
        ))
    })?;
    Ok(leaf.to_vec())
}

/// Go uses 1 MiB unless the uplink asked for a size strictly between 1 KiB and 1 MiB.
fn chunk_limit(advisory: i32) -> usize {
    const KIB: i32 = 1024;
    const MIB: i32 = 1024 * 1024;
    if advisory > KIB && advisory < MIB {
        usize::try_from(advisory).unwrap_or(MIB as usize)
    } else {
        MIB as usize
    }
}

fn parse_node_id(bytes: &[u8]) -> Result<NodeId, Fail> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Fail::proto(RPC_INVALID_ARGUMENT, "node id must be 32 bytes"))?;
    Ok(NodeId::from_bytes(arr))
}

/// Lowercase hex. Piece ids in the index and exit receipts on the console.
pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn decode_piece_id(hex_id: &str) -> Result<[u8; 32], Fail> {
    if hex_id.len() != 64 {
        return Err(Fail::proto(RPC_INTERNAL, "piece id is not 32 bytes"));
    }
    let bytes = hex_id.as_bytes();
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, Fail> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Fail::proto(RPC_INTERNAL, "piece id is not hex")),
    }
}

/// Empty hash is the legacy unary retain. A present hash is the filter bytes.
fn check_retain_hash(algo: i32, filter: &[u8], hash: &[u8]) -> Result<(), Fail> {
    if hash.is_empty() {
        return Ok(());
    }
    let mut hasher = PieceHashAlgo::from_i32(algo).hasher();
    hasher.update(filter);
    if hasher.finalize().as_slice() != hash {
        return Err(Fail::proto(RPC_INTERNAL, "hash mismatch"));
    }
    Ok(())
}

async fn reply_retain<T>(out: &mut Out<T>) -> Result<(), Fail>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    out.message(&RetainResponse {}.encode_to_vec()).await?;
    out.close().await?;
    Ok(())
}

fn timestamp_to_system(ts: &prost_types::Timestamp) -> Option<SystemTime> {
    if !(0..1_000_000_000).contains(&ts.nanos) {
        return None;
    }
    if ts.seconds == GO_ZERO_TIME_UNIX && ts.nanos == 0 {
        return None;
    }
    if ts.seconds < 0 {
        return None;
    }
    let secs = u64::try_from(ts.seconds).ok()?;
    let nanos = u32::try_from(ts.nanos).ok()?;
    UNIX_EPOCH.checked_add(Duration::new(secs, nanos))
}

fn system_to_timestamp(time: SystemTime) -> prost_types::Timestamp {
    let dur = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    prost_types::Timestamp {
        seconds: i64::try_from(dur.as_secs()).unwrap_or(i64::MAX),
        nanos: i32::try_from(dur.subsec_nanos()).unwrap_or(0),
    }
}

fn expired(ts: Option<&prost_types::Timestamp>, now: SystemTime) -> bool {
    let Some(ts) = ts else {
        return false;
    };
    if ts.seconds == GO_ZERO_TIME_UNIX && ts.nanos == 0 {
        return false;
    }
    match timestamp_to_system(ts) {
        // Go: `expiration.Before(now.Add(-ExpirationGracePeriod))`.
        Some(time) => now
            .checked_sub(EXPIRATION_GRACE)
            .is_some_and(|cutoff| time < cutoff),
        None => true,
    }
}

fn creation_ok(ts: Option<&prost_types::Timestamp>, now: SystemTime) -> bool {
    let Some(ts) = ts else {
        return false;
    };
    let Some(created) = timestamp_to_system(ts) else {
        return false;
    };
    let earliest = now
        .checked_sub(orders::ORDER_LIMIT_GRACE)
        .unwrap_or(UNIX_EPOCH);
    let Some(latest) = now.checked_add(orders::ORDER_LIMIT_GRACE) else {
        return created >= earliest;
    };
    created >= earliest && created <= latest
}

/// UTC hour containing `OrderCreation`, as unix seconds.
fn order_window(limit: &OrderLimit) -> Result<i64, Fail> {
    let created = limit
        .order_creation
        .as_ref()
        .and_then(timestamp_to_system)
        .ok_or_else(|| {
            Fail::proto(
                RPC_INVALID_ARGUMENT,
                "order creation is outside the one hour grace",
            )
        })?;
    let secs = created
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            Fail::proto(
                RPC_INVALID_ARGUMENT,
                "order creation is outside the one hour grace",
            )
        })?
        .as_secs();
    i64::try_from(secs / 3600 * 3600).map_err(|_| Fail::proto(RPC_INTERNAL, "order window"))
}

/// When the limit's serial can be forgotten: once [`creation_ok`] refuses
/// the limit for its age, which is [`orders::ORDER_LIMIT_GRACE`] after
/// `OrderCreation`.
///
/// `OrderExpiration` is a day out and would hold every serial that long. It
/// can also already be in the past for a limit that is still accepted, and a
/// serial dropped then could be replayed.
fn serial_deadline(limit: &OrderLimit, now: SystemTime) -> SystemTime {
    limit
        .order_creation
        .as_ref()
        .and_then(timestamp_to_system)
        .and_then(|created| created.checked_add(orders::ORDER_LIMIT_GRACE))
        // `reserve` drops a serial at its deadline; the limit is still
        // accepted at exactly that instant.
        .and_then(|until| until.checked_add(Duration::from_secs(1)))
        .unwrap_or(now)
}

#[cfg(test)]
mod tests {
    use super::{
        CLOSE_LINGER, CONTACT_PING_NODE, EXPIRATION_GRACE, GO_ZERO_TIME_UNIX, Node,
        PIECESTORE_EXISTS, PIECESTORE_RESTORE_TRASH, PIECESTORE_RETAIN, PIECESTORE_RETAIN_BIG,
        RETAIN_MAX_TIME_SKEW, Serials, TrustedSatellite, creation_ok, encode_hex, expired,
        serial_deadline, system_to_timestamp,
    };
    use std::future::Future;
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::process;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as ConnBuilder;
    use prost::Message;
    use s3s::auth::SimpleAuth;
    use s3s::service::S3ServiceBuilder;
    use s3s_fs::FileSystem;
    use s3store::{HashAlgorithm, PieceState, Store};
    use storj_proto::orders::{
        Order, OrderLimit, PieceAction, SettlementRequest, SettlementWithWindowResponse,
    };
    use storj_proto::piecestore::{
        ExistsRequest, ExistsResponse, PieceDownloadRequest, PieceDownloadResponse,
        PieceUploadRequest, RestoreTrashRequest, RestoreTrashResponse, RetainRequest,
        RetainResponse, StorageMethod, piece_download_request, piece_upload_request,
    };
    use storj_proto::rpc::{PIECESTORE_DOWNLOAD, PIECESTORE_UPLOAD};
    use storj_rpc::frame::{Kind, Packet};
    use storj_rpc::noise::NoiseStream;
    use storj_rpc::transport::{self, TransportKind, TransportMode};
    use storj_rpc::{Conn, Identity, client_config, server_config, write_tls_mux_prefix};
    use storj_uplink::{
        Client, PieceConfig, PieceHashAlgo, PiecePrivateKey, sign_order, sign_order_limit,
    };
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use crate::Config;
    use crate::bloom::Filter;

    static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);
    static SERIAL: AtomicU64 = AtomicU64::new(1);

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
            let path =
                std::env::temp_dir().join(format!("storagenode-{nanos}-{seq}-{}", process::id()));
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

    struct TestBucket {
        store: Store,
        root: TempRoot,
    }

    impl TestBucket {
        async fn start(allocated_bytes: u64) -> Self {
            let root = TempRoot::new();
            std::fs::create_dir(root.path().join(BUCKET)).expect("bucket dir");
            let addr = spawn_s3(root.path());
            let config = s3store::Config {
                endpoint: format!("http://{addr}"),
                bucket: BUCKET.to_owned(),
                access_key_id: ACCESS_KEY.to_owned(),
                secret_access_key: SECRET.to_owned(),
                volume: root.path().join("volume"),
                allocated_bytes,
                ..s3store::Config::default()
            };
            let store = Store::new(config).expect("store");
            Self { store, root }
        }
    }

    fn spawn_s3(root: &Path) -> SocketAddr {
        let fs = FileSystem::new(root).expect("s3s filesystem");
        let mut builder = S3ServiceBuilder::new(fs);
        builder.set_auth(SimpleAuth::from_single(ACCESS_KEY, SECRET));
        let service = builder.build();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("local addr");
        let listener = TcpListener::from_std(listener).expect("tokio listener");
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

    struct Harness {
        node: Arc<Node>,
        addr: SocketAddr,
        identity: Identity,
        _root: TempRoot,
    }

    impl Harness {
        async fn start(satellites: &[Identity]) -> Self {
            Self::start_with(satellites, &[]).await
        }

        async fn start_with(satellites: &[Identity], addresses: &[&str]) -> Self {
            Self::open(satellites, addresses, None).await
        }

        async fn open(
            satellites: &[Identity],
            addresses: &[&str],
            noise: Option<(i32, crate::noise_key::Key)>,
        ) -> Self {
            Self::open_allocated(satellites, addresses, noise, 1 << 40).await
        }

        async fn open_allocated(
            satellites: &[Identity],
            addresses: &[&str],
            noise: Option<(i32, crate::noise_key::Key)>,
            allocated_bytes: u64,
        ) -> Self {
            let bucket = TestBucket::start(allocated_bytes).await;
            let identity = Identity::generate().expect("node identity");
            let trusted = satellites
                .iter()
                .enumerate()
                .map(|(index, sat)| TrustedSatellite {
                    id: sat.node_id(),
                    address: addresses.get(index).copied().unwrap_or("").to_owned(),
                    leaf_der: sat.leaf_der().as_ref().to_vec(),
                    ca_der: sat.ca_der().as_ref().to_vec(),
                })
                .collect();
            let node = match noise {
                Some((protocol, key)) => {
                    Node::with_noise(identity.clone(), bucket.store, trusted, protocol, key)
                }
                None => Node::new(identity.clone(), bucket.store, trusted),
            }
            .expect("node");
            let node = Arc::new(node);
            node.startup().await.expect("startup");
            // QUIC takes the UDP port with the TCP port's number. Another
            // test's QUIC client may hold it; pick a new TCP port then.
            let (listener, addr, quic) = loop {
                let listener = Node::listen("127.0.0.1:0".parse().unwrap())
                    .await
                    .expect("listen");
                let addr = listener.local_addr().expect("addr");
                match node.quic_endpoint(addr) {
                    Ok(quic) => break (listener, addr, quic),
                    Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {}
                    Err(err) => panic!("quic: {err}"),
                }
            };
            let serving = Arc::clone(&node);
            tokio::spawn(async move {
                let _ = serving.serve(listener).await;
            });
            let serving = Arc::clone(&node);
            tokio::spawn(async move {
                let _ = serving.serve_quic(quic).await;
            });
            Self {
                node,
                addr,
                identity,
                _root: bucket.root,
            }
        }

        async fn connect(&self, peer: &Identity) -> tokio_rustls::client::TlsStream<TcpStream> {
            let mut tcp = TcpStream::connect(self.addr).await.expect("connect");
            tcp.set_nodelay(true).expect("nodelay");
            write_tls_mux_prefix(&mut tcp).await.expect("prefix");
            let config = client_config(peer, self.identity.node_id()).expect("client config");
            let name = rustls::pki_types::ServerName::try_from("localhost".to_owned())
                .expect("server name");
            tokio_rustls::TlsConnector::from(Arc::new(config))
                .connect(name, tcp)
                .await
                .expect("tls")
        }

        async fn client(
            &self,
            peer: &Identity,
            satellite: &Identity,
        ) -> Client<tokio_rustls::client::TlsStream<TcpStream>> {
            let tls = self.connect(peer).await;
            let peer_cert = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .expect("peer cert")
                .as_ref()
                .to_vec();
            Client::new(
                Conn::new(tls),
                satellite.leaf_der().as_ref().to_vec(),
                peer_cert,
            )
        }

        async fn conn(&self, peer: &Identity) -> Conn<tokio_rustls::client::TlsStream<TcpStream>> {
            Conn::new(self.connect(peer).await)
        }
    }

    fn fresh_serial() -> Vec<u8> {
        let n = SERIAL.fetch_add(1, Ordering::Relaxed);
        let mut serial = vec![0u8; 16];
        serial[..8].copy_from_slice(&n.to_be_bytes());
        serial
    }

    fn proto_now() -> prost_types::Timestamp {
        system_to_timestamp(SystemTime::now())
    }

    fn proto_shift(delta: Duration, future: bool) -> prost_types::Timestamp {
        let now = SystemTime::now();
        let time = if future {
            now.checked_add(delta).expect("future")
        } else {
            now.checked_sub(delta).expect("past")
        };
        system_to_timestamp(time)
    }

    fn signed_limit(
        satellite: &Identity,
        node: &Identity,
        piece_key: &PiecePrivateKey,
        piece_id: &[u8],
        action: PieceAction,
        limit: i64,
    ) -> OrderLimit {
        let later = proto_shift(Duration::from_secs(2 * 60 * 60), true);
        let mut order_limit = OrderLimit {
            serial_number: fresh_serial(),
            satellite_id: satellite.node_id().as_bytes().to_vec(),
            uplink_public_key: piece_key.public().to_bytes().to_vec(),
            storage_node_id: node.node_id().as_bytes().to_vec(),
            piece_id: piece_id.to_vec(),
            limit,
            action: action as i32,
            piece_expiration: Some(later),
            order_expiration: Some(later),
            order_creation: Some(proto_now()),
            ..OrderLimit::default()
        };
        sign_order_limit(&mut order_limit, satellite).expect("sign limit");
        order_limit
    }

    fn order_for(limit: &OrderLimit, key: &PiecePrivateKey, amount: i64) -> Order {
        let mut order = Order {
            serial_number: limit.serial_number.clone(),
            amount,
            uplink_signature: Vec::new(),
        };
        sign_order(&mut order, key).expect("sign order");
        order
    }

    #[test]
    fn serial_is_refused_until_its_deadline_and_then_forgotten() {
        let sat = Identity::generate().unwrap().node_id();
        let other = Identity::generate().unwrap().node_id();
        let t0 = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let soon = t0 + Duration::from_secs(10);
        let late = t0 + Duration::from_secs(100);
        let mut serials = Serials::default();
        assert!(serials.reserve(sat, b"a", soon, t0));
        assert!(serials.reserve(sat, b"b", late, t0));
        assert!(!serials.reserve(sat, b"a", late, t0), "replay");
        // The serial is per satellite.
        assert!(serials.reserve(other, b"a", late, t0));
        assert_eq!(serials.used.len(), 3);

        // At its deadline `a` is dropped. `b` and the other satellite stay.
        assert!(!serials.reserve(sat, b"b", late, soon), "still reserved");
        assert_eq!(serials.used.len(), 2);
        assert_eq!(serials.by_deadline.len(), 2);
        assert!(serials.reserve(sat, b"a", late, soon));

        let end = late + Duration::from_secs(1);
        assert!(serials.reserve(sat, b"c", end + Duration::from_secs(1), end));
        assert_eq!(serials.used.len(), 1);
        assert_eq!(serials.by_deadline.len(), 1);
    }

    #[test]
    fn a_full_window_evicts_the_serial_that_expires_soonest() {
        let sat = Identity::generate().unwrap().node_id();
        let t0 = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let at = |secs: u64| t0 + Duration::from_secs(secs);
        let mut serials = Serials {
            max: 2,
            ..Serials::default()
        };
        assert!(serials.reserve(sat, b"a", at(10), t0));
        assert!(serials.reserve(sat, b"c", at(100), t0));
        // At the cap a repeat of a held serial is still a replay, not a slot.
        assert!(!serials.reserve(sat, b"c", at(200), t0));
        // Full: `a`, the nearest deadline, is forgotten so `z` fits.
        assert!(serials.reserve(sat, b"z", at(50), t0));
        assert!(
            !serials.reserve(sat, b"z", at(60), t0),
            "replay of a held serial"
        );
        // Inserting `a` back evicts `z` (deadline 50), not `c` (100).
        assert!(serials.reserve(sat, b"a", at(70), t0), "`a` was evicted");
        let held: std::collections::HashSet<_> = serials.used.iter().cloned().collect();
        assert_eq!(
            held,
            [
                (*sat.as_bytes(), b"c".to_vec()),
                (*sat.as_bytes(), b"a".to_vec())
            ]
            .into_iter()
            .collect()
        );
        // Expired serials are dropped before any live eviction is needed:
        // at t101 `c` is gone, so the next two inserts evict `a` (t70) only.
        let now = at(101);
        assert!(serials.reserve(sat, b"d", at(200), now));
        assert!(serials.reserve(sat, b"e", at(300), now));
        assert!(!serials.reserve(sat, b"d", at(400), now), "replay");
    }

    #[test]
    fn serial_is_kept_for_as_long_as_its_limit_is_accepted() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let created = now - Duration::from_secs(10 * 60);
        let limit = OrderLimit {
            order_creation: Some(system_to_timestamp(created)),
            // Already past, as it may be inside the expiration grace.
            order_expiration: Some(system_to_timestamp(now - Duration::from_secs(60))),
            ..OrderLimit::default()
        };
        let deadline = serial_deadline(&limit, now);
        let last_accepted = created + crate::orders::ORDER_LIMIT_GRACE;
        assert!(creation_ok(limit.order_creation.as_ref(), last_accepted));
        assert!(deadline > last_accepted);
        assert!(!creation_ok(limit.order_creation.as_ref(), deadline));
    }

    #[test]
    fn order_creation_grace_is_one_hour_and_expiration_grace_is_two_days() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let at = |delta: Duration, future: bool| {
            let time = if future {
                now.checked_add(delta).unwrap()
            } else {
                now.checked_sub(delta).unwrap()
            };
            system_to_timestamp(time)
        };
        assert!(creation_ok(Some(&at(Duration::from_secs(60), false)), now));
        assert!(creation_ok(
            Some(&at(Duration::from_secs(60 * 60), true)),
            now
        ));
        assert!(!creation_ok(
            Some(&at(Duration::from_secs(60 * 60 + 1), false)),
            now
        ));
        assert!(!creation_ok(
            Some(&at(Duration::from_secs(60 * 60 + 1), true)),
            now
        ));
        assert!(!creation_ok(None, now));
        let zero = prost_types::Timestamp {
            seconds: GO_ZERO_TIME_UNIX,
            nanos: 0,
        };
        assert!(!creation_ok(Some(&zero), now));
        assert!(!expired(Some(&zero), now));
        assert!(!expired(None, now));
        assert!(!expired(Some(&at(Duration::from_secs(1), true)), now));
        // Past, but inside the grace: still accepted.
        assert!(!expired(Some(&at(Duration::from_secs(1), false)), now));
        assert!(!expired(Some(&at(EXPIRATION_GRACE, false)), now));
        assert!(expired(
            Some(&at(EXPIRATION_GRACE + Duration::from_secs(1), false)),
            now
        ));
        let bad = prost_types::Timestamp {
            seconds: 1_700_000_000,
            nanos: 1_000_000_000,
        };
        assert!(expired(Some(&bad), now));
    }

    #[tokio::test]
    async fn stage_with_a_real_node_id() {
        let satellite = Identity::generate().unwrap();
        let harness = Harness::start(std::slice::from_ref(&satellite)).await;
        let piece = "11".repeat(32);
        let stage_id = "ab".repeat(8);
        let mut upload = harness.node.store.stage(&stage_id).expect("stage");
        upload.write(b"hello-piece").await.expect("write");
        upload.finish().await.expect("finish");
        let meta = s3store::PieceMeta {
            hash: [0x11; 32],
            algorithm: HashAlgorithm::Sha256,
            created: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            expires: None,
            order_limit: vec![1, 2, 3, 255],
            hash_signature: vec![0x30, 0x44, 0xff, b'+', b'/'],
            hash_timestamp: Some((1_700_000_000, 123_456_789)),
        };
        let sat = satellite.node_id().to_string();
        harness
            .node
            .store
            .commit_staged_piece(&sat, &piece, &stage_id, meta.clone())
            .await
            .expect("commit");
        let info = harness.node.store.info(&sat, &piece).unwrap().expect("row");
        assert_eq!(info.size, b"hello-piece".len() as u64);
        assert_eq!(info.hash_signature, meta.hash_signature);
        assert_eq!(info.hash_timestamp, meta.hash_timestamp);
    }

    #[tokio::test]
    async fn upload_download_exists_over_tls() {
        let satellite = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let harness = Harness::start(std::slice::from_ref(&satellite)).await;
        let piece_key = PiecePrivateKey::generate();
        let piece_id = vec![0x11; 32];
        let body = b"abcdefghijklmnopqrstuvwxyz".to_vec();

        let put = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &piece_id,
            PieceAction::Put,
            body.len() as i64,
        );
        let mut client = harness
            .client(&uplink, &satellite)
            .await
            .with_hash_algo(PieceHashAlgo::Sha256);
        let uploaded = client
            .upload(&put, &piece_key, &body)
            .await
            .expect("upload");
        assert_eq!(uploaded.hash.len(), 32);
        assert_eq!(uploaded.piece_size, body.len() as i64);

        let info = harness
            .node
            .store
            .info(&satellite.node_id().to_string(), &encode_hex(&piece_id))
            .unwrap()
            .expect("row");
        assert_eq!(info.state, PieceState::Live);
        assert_eq!(info.hash.as_slice(), uploaded.hash.as_slice());
        assert_eq!(info.algorithm, HashAlgorithm::Sha256);
        let stored = OrderLimit::decode(info.order_limit.as_slice()).unwrap();
        assert_eq!(stored.serial_number, put.serial_number);
        assert_eq!(stored.satellite_signature, put.satellite_signature);

        let get = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &piece_id,
            PieceAction::Get,
            body.len() as i64,
        );
        let mut client = harness.client(&uplink, &satellite).await;
        let got = client
            .download(&get, &piece_key, 0, body.len() as i64)
            .await
            .expect("get");
        assert_eq!(got, body);

        let audit = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &piece_id,
            PieceAction::GetAudit,
            4,
        );
        let mut client = harness.client(&uplink, &satellite).await;
        let range = client
            .download(&audit, &piece_key, 3, 4)
            .await
            .expect("audit");
        assert_eq!(range, b"defg");

        // GET does not lead with the hash. GET_REPAIR does.
        let get_wire = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &piece_id,
            PieceAction::Get,
            body.len() as i64,
        );
        let first = first_download(
            &harness,
            &uplink,
            &piece_key,
            &get_wire,
            0,
            body.len() as i64,
        )
        .await;
        assert!(first.hash.is_none());
        assert!(first.limit.is_none());
        assert!(first.chunk.is_some());

        let repair = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &piece_id,
            PieceAction::GetRepair,
            body.len() as i64,
        );
        let (header, repair_bytes) =
            read_download(&harness, &uplink, &piece_key, &repair, 0, body.len() as i64).await;
        assert!(header.chunk.is_none());
        let hash = header.hash.expect("repair hash");
        assert_eq!(hash.hash, uploaded.hash);
        assert_eq!(hash.piece_size, body.len() as i64);
        assert_eq!(hash.hash_algorithm, PieceHashAlgo::Sha256.to_i32());
        assert_eq!(hash.timestamp, put.order_creation);
        assert!(!hash.signature.is_empty());
        storj_uplink::verify_piece_hash_uplink(&hash, &piece_key.public()).expect("uplink hash");
        assert_eq!(info.hash_signature, hash.signature);
        let (seconds, nanos) = info.hash_timestamp.expect("stored timestamp");
        assert_eq!(
            hash.timestamp,
            Some(prost_types::Timestamp { seconds, nanos })
        );
        let limit = header.limit.expect("repair limit");
        assert_eq!(limit.serial_number, put.serial_number);
        assert_eq!(limit.piece_id, piece_id);
        assert_eq!(repair_bytes, body);

        let mut conn = harness.conn(&satellite).await;
        let request = ExistsRequest {
            piece_ids: vec![piece_id.clone(), vec![0x22; 32]],
        };
        let response = ExistsResponse::decode(
            conn.invoke(PIECESTORE_EXISTS, &request.encode_to_vec())
                .await
                .expect("exists")
                .as_slice(),
        )
        .unwrap();
        assert_eq!(response.missing, vec![1]);
        assert_eq!(
            response.storage_method,
            vec![
                StorageMethod::Piecestore as i32,
                StorageMethod::Unspecified as i32
            ]
        );

        let mut conn = harness.conn(&uplink).await;
        let err = conn
            .invoke(PIECESTORE_EXISTS, &request.encode_to_vec())
            .await
            .expect_err("uplink is not a satellite");
        assert!(err.to_string().contains("untrusted"), "{err}");
    }

    #[tokio::test]
    async fn upload_download_over_noise_and_quic() {
        let satellite = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let harness = Harness::start(std::slice::from_ref(&satellite)).await;
        assert_eq!(
            harness.node.noise_protocol(),
            crate::noise_key::DEFAULT_PROTOCOL
        );
        assert_ne!(harness.node.noise_public_key(), &[0; 32]);

        let protocol = harness.node.noise_protocol();
        let public = *harness.node.noise_public_key();
        let addr = harness.addr;
        let sat_leaf = satellite.leaf_der().as_ref().to_vec();
        // Empty peer cert: the uplink must use node_certchain from the response.
        upload_and_download(&harness, &satellite, move || {
            let sat_leaf = sat_leaf.clone();
            async move {
                let tcp = TcpStream::connect(addr).await.expect("connect");
                tcp.set_nodelay(true).expect("nodelay");
                let io = NoiseStream::connect(tcp, protocol, &public)
                    .await
                    .expect("noise");
                Client::new(Conn::new(io), sat_leaf, Vec::new())
            }
        })
        .await;

        let node_id = harness.identity.node_id();
        let address = harness.addr.to_string();
        let sat_leaf = satellite.leaf_der().as_ref().to_vec();
        let uplink_id = uplink.clone();
        upload_and_download(&harness, &satellite, move || {
            let sat_leaf = sat_leaf.clone();
            let uplink_id = uplink_id.clone();
            let address = address.clone();
            async move {
                let io = transport::dial(
                    &uplink_id,
                    node_id,
                    &address,
                    TransportMode::Quic,
                    Duration::from_secs(10),
                    None,
                )
                .await
                .expect("quic");
                assert_eq!(io.kind, TransportKind::Quic);
                assert!(!io.peer_cert.is_empty(), "quic leaf");
                let peer = io.peer_cert.clone();
                Client::new(Conn::new(io), sat_leaf, peer)
            }
        })
        .await;
    }

    #[tokio::test]
    async fn noise_protocol_2_is_the_only_handshake() {
        let satellite = Identity::generate().unwrap();
        let key = crate::noise_key::Key::generate().expect("key");
        let public = *key.public();
        let harness = Harness::open(
            std::slice::from_ref(&satellite),
            &[],
            Some((crate::noise_key::AES_PROTOCOL, key)),
        )
        .await;
        assert_eq!(
            harness.node.noise_protocol(),
            crate::noise_key::AES_PROTOCOL
        );
        assert_eq!(harness.node.noise_public_key(), &public);

        let addr = harness.addr;
        let sat_leaf = satellite.leaf_der().as_ref().to_vec();
        upload_and_download(&harness, &satellite, move || {
            let sat_leaf = sat_leaf.clone();
            async move {
                let tcp = TcpStream::connect(addr).await.expect("connect");
                tcp.set_nodelay(true).expect("nodelay");
                let io = NoiseStream::connect(tcp, crate::noise_key::AES_PROTOCOL, &public)
                    .await
                    .expect("protocol 2");
                Client::new(Conn::new(io), sat_leaf, Vec::new())
            }
        })
        .await;

        let tcp = TcpStream::connect(harness.addr).await.expect("connect");
        tcp.set_nodelay(true).expect("nodelay");
        let mismatched = tokio::time::timeout(
            Duration::from_secs(5),
            NoiseStream::connect(tcp, crate::noise_key::DEFAULT_PROTOCOL, &public),
        )
        .await
        .expect("other cipher should not hang");
        assert!(
            mismatched.is_err(),
            "protocol 1 must not complete against protocol 2"
        );
    }

    async fn upload_and_download<T, F, Fut>(harness: &Harness, satellite: &Identity, mut connect: F)
    where
        T: AsyncRead + AsyncWrite + Unpin,
        F: FnMut() -> Fut,
        Fut: Future<Output = Client<T>>,
    {
        let piece_key = PiecePrivateKey::generate();
        let n = SERIAL.fetch_add(1, Ordering::Relaxed);
        let mut piece_id = vec![0u8; 32];
        piece_id[..8].copy_from_slice(&n.to_be_bytes());
        let body = b"abcdefghijklmnopqrstuvwxyz".to_vec();
        let put = signed_limit(
            satellite,
            &harness.identity,
            &piece_key,
            &piece_id,
            PieceAction::Put,
            body.len() as i64,
        );
        let mut client = connect().await;
        let uploaded = client
            .upload(&put, &piece_key, &body)
            .await
            .expect("upload");
        assert_eq!(uploaded.hash.len(), 32);
        assert_eq!(uploaded.piece_size, body.len() as i64);
        let info = harness
            .node
            .store
            .info(&satellite.node_id().to_string(), &encode_hex(&piece_id))
            .unwrap()
            .expect("row");
        assert_eq!(info.hash.as_slice(), uploaded.hash.as_slice());

        let get = signed_limit(
            satellite,
            &harness.identity,
            &piece_key,
            &piece_id,
            PieceAction::Get,
            body.len() as i64,
        );
        let mut client = connect().await;
        let got = client
            .download(&get, &piece_key, 0, body.len() as i64)
            .await
            .expect("download");
        assert_eq!(got, body);
    }

    #[tokio::test]
    async fn blake3_put_repair_round_trip() {
        let satellite = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let harness = Harness::start(std::slice::from_ref(&satellite)).await;
        let piece_key = PiecePrivateKey::generate();
        let piece_id = vec![0x33; 32];
        let body = b"blake3-piece".to_vec();
        let put = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &piece_id,
            PieceAction::PutRepair,
            body.len() as i64,
        );
        let mut client = harness
            .client(&uplink, &satellite)
            .await
            .with_hash_algo(PieceHashAlgo::Blake3);
        let uploaded = client
            .upload(&put, &piece_key, &body)
            .await
            .expect("upload");
        assert_eq!(uploaded.hash_algorithm, PieceHashAlgo::Blake3.to_i32());
        let info = harness
            .node
            .store
            .info(&satellite.node_id().to_string(), &encode_hex(&piece_id))
            .unwrap()
            .unwrap();
        assert_eq!(info.algorithm, HashAlgorithm::Blake3);
        assert_eq!(info.hash.as_slice(), uploaded.hash.as_slice());

        let get = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &piece_id,
            PieceAction::Get,
            body.len() as i64,
        );
        let mut client = harness.client(&uplink, &satellite).await;
        let got = client
            .download(&get, &piece_key, 0, body.len() as i64)
            .await
            .expect("download");
        assert_eq!(got, body);
    }

    #[tokio::test]
    async fn download_waits_for_growing_orders() {
        let satellite = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let harness = Harness::start(std::slice::from_ref(&satellite)).await;
        let piece_key = PiecePrivateKey::generate();
        let piece_id = vec![0x44; 32];
        let body: Vec<u8> = (0..1000).map(|i| i as u8).collect();
        let put = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &piece_id,
            PieceAction::Put,
            body.len() as i64,
        );
        let mut client = harness.client(&uplink, &satellite).await;
        client
            .upload(&put, &piece_key, &body)
            .await
            .expect("upload");

        let get = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &piece_id,
            PieceAction::Get,
            body.len() as i64,
        );
        let mut client = harness
            .client(&uplink, &satellite)
            .await
            .with_config(PieceConfig {
                upload_buffer_size: 64,
                initial_step: 64,
                maximum_step: 128,
                maximum_chunk_size: 32,
            });
        let got = tokio::time::timeout(
            Duration::from_secs(5),
            client.download(&get, &piece_key, 10, 900),
        )
        .await
        .expect("download did not deadlock")
        .expect("download");
        assert_eq!(got, body[10..910]);
    }

    #[tokio::test]
    async fn repeated_early_download_orders_keep_only_the_largest_for_settlement() {
        let satellite = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let harness = Harness::start(std::slice::from_ref(&satellite)).await;
        let key = PiecePrivateKey::generate();
        let piece = [0xbb; 32];
        let body = b"12345678";
        let put = signed_limit(
            &satellite,
            &harness.identity,
            &key,
            &piece,
            PieceAction::Put,
            8,
        );
        harness
            .client(&uplink, &satellite)
            .await
            .upload(&put, &key, body)
            .await
            .unwrap();
        let get = signed_limit(
            &satellite,
            &harness.identity,
            &key,
            &piece,
            PieceAction::Get,
            8,
        );
        let mut conn = harness.conn(&uplink).await;
        let mut stream = conn.open_stream(PIECESTORE_DOWNLOAD).await.unwrap();
        conn.send_msg(
            &mut stream,
            &PieceDownloadRequest {
                limit: Some(get.clone()),
                ..Default::default()
            }
            .encode_to_vec(),
        )
        .await
        .unwrap();
        // No range yet: duplicates and a larger cumulative order must not
        // accumulate a history, or lose the amount eventually settled.
        for amount in [1, 8] {
            let request = PieceDownloadRequest {
                order: Some(order_for(&get, &key, amount)),
                ..Default::default()
            }
            .encode_to_vec();
            for _ in 0..1024 {
                conn.send_msg(&mut stream, &request).await.unwrap();
            }
        }
        conn.send_msg(
            &mut stream,
            &PieceDownloadRequest {
                chunk: Some(piece_download_request::Chunk {
                    offset: 0,
                    chunk_size: 8,
                }),
                ..Default::default()
            }
            .encode_to_vec(),
        )
        .await
        .unwrap();
        let response =
            PieceDownloadResponse::decode(conn.recv_msg(&stream).await.unwrap().as_slice())
                .unwrap();
        assert_eq!(response.chunk.unwrap().data, body);
        conn.close_send(&mut stream).await.unwrap();
        wait_idle(&harness.node).await;
        let saved = harness
            .node
            .store
            .orders()
            .status(&satellite.node_id().to_string(), &get.serial_number)
            .unwrap()
            .expect("download order saved");
        assert_eq!(saved.amount, 8);
    }

    #[tokio::test]
    async fn cancelled_download_settles_an_order_that_arrived_early() {
        const MIB: usize = 1 << 20;
        let satellite = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let harness = Harness::start(std::slice::from_ref(&satellite)).await;
        let sat = satellite.node_id().to_string();
        let piece_key = PiecePrivateKey::generate();
        let piece_id = [0x61; 32];
        let body = vec![5u8; 16 * MIB];
        put_piece_at(
            &harness.node.store,
            &sat,
            &piece_id,
            SystemTime::now(),
            &body,
        )
        .await;
        let limit = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &piece_id,
            PieceAction::Get,
            body.len() as i64,
        );

        let mut conn = harness.conn(&uplink).await;
        let mut stream = conn.open_stream(PIECESTORE_DOWNLOAD).await.unwrap();
        let first = PieceDownloadRequest {
            limit: Some(limit.clone()),
            order: Some(order_for(&limit, &piece_key, 12 * MIB as i64)),
            chunk: Some(piece_download_request::Chunk {
                offset: 0,
                chunk_size: body.len() as i64,
            }),
            maximum_chunk_size: 0,
        };
        conn.send_msg(&mut stream, &first.encode_to_vec())
            .await
            .unwrap();
        // The next order goes out before any byte comes back, as the uplink
        // does. The node has 12 MiB to send before it needs this one.
        let next = PieceDownloadRequest {
            order: Some(order_for(&limit, &piece_key, body.len() as i64)),
            ..PieceDownloadRequest::default()
        };
        conn.send_msg(&mut stream, &next.encode_to_vec())
            .await
            .unwrap();
        // One chunk, then hang up: long-tail cancellation.
        let chunk = conn.recv_msg(&stream).await.unwrap();
        assert!(!chunk.is_empty());
        drop(conn);

        wait_idle(&harness.node).await;
        let saved = harness
            .node
            .store
            .orders()
            .status(&sat, &limit.serial_number)
            .unwrap()
            .expect("an order was saved");
        assert_eq!(saved.amount, body.len() as i64);
        // The egress counter follows the saved order, as in Go, although the
        // download did not finish.
        wait_bandwidth(&harness.node, body.len() as u64).await;
    }

    #[tokio::test]
    async fn refused_upload_still_delivers_its_error_past_unread_chunks() {
        let satellite = Identity::generate().unwrap();
        let stranger = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let harness = Harness::start(std::slice::from_ref(&satellite)).await;
        let piece_key = PiecePrivateKey::generate();
        // Signed by a satellite this node does not trust: refused at once.
        let limit = signed_limit(
            &stranger,
            &harness.identity,
            &piece_key,
            &[0x62; 32],
            PieceAction::Put,
            1 << 30,
        );
        let mut conn = harness.conn(&uplink).await;
        let first = PieceUploadRequest {
            limit: Some(limit.clone()),
            ..PieceUploadRequest::default()
        };
        let data = vec![7u8; 256 * 1024];
        let mut packets = vec![
            (Kind::INVOKE, PIECESTORE_UPLOAD.as_bytes().to_vec()),
            (Kind::MESSAGE, first.encode_to_vec()),
        ];
        // Chunks the node will never read as an upload. They are written
        // without looking at the socket, as a client busy sending does.
        for index in 0..16i64 {
            let chunk = PieceUploadRequest {
                chunk: Some(piece_upload_request::Chunk {
                    offset: index * data.len() as i64,
                    data: data.clone(),
                }),
                ..PieceUploadRequest::default()
            };
            packets.push((Kind::MESSAGE, chunk.encode_to_vec()));
        }
        for (message_id, (kind, data)) in (1u64..).zip(packets) {
            let packet = Packet {
                stream_id: 1,
                message_id,
                kind,
                control: false,
                data,
            };
            if conn.write_packet(&packet).await.is_err() {
                break;
            }
        }
        let reply = conn.read_packet().await.expect("the error packet");
        assert!(reply.kind == Kind::ERROR, "got {}", reply.kind);
        let text = String::from_utf8_lossy(&reply.data).into_owned();
        assert!(text.contains("untrusted satellite"), "{text}");
    }

    #[tokio::test]
    async fn rejects_bad_order_limits() {
        let satellite = Identity::generate().unwrap();
        let other = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let harness = Harness::start(std::slice::from_ref(&satellite)).await;
        let piece_key = PiecePrivateKey::generate();
        let piece_id = vec![0x55; 32];
        let body = b"piece".to_vec();

        let put = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &piece_id,
            PieceAction::Put,
            64,
        );
        let mut client = harness.client(&uplink, &satellite).await;
        client.upload(&put, &piece_key, &body).await.expect("first");
        // The server finishes the RPC and drops the connection.
        let mut client = harness.client(&uplink, &satellite).await;
        let err = client
            .upload(&put, &piece_key, &body)
            .await
            .expect_err("replay");
        assert!(err.to_string().contains("duplicate serial"), "{err}");

        let untrusted = signed_limit(
            &other,
            &harness.identity,
            &piece_key,
            &piece_id,
            PieceAction::Put,
            64,
        );
        // The client checks the signature against `other`, which signed it.
        let mut client = harness.client(&uplink, &other).await;
        let err = client
            .upload(&untrusted, &piece_key, &body)
            .await
            .expect_err("untrusted");
        assert!(err.to_string().contains("untrusted"), "{err}");

        let stranger = Identity::generate().unwrap();
        let wrong_node = signed_limit(
            &satellite,
            &stranger,
            &piece_key,
            &piece_id,
            PieceAction::Put,
            64,
        );
        let mut client = harness.client(&uplink, &satellite).await;
        let err = client
            .upload(&wrong_node, &piece_key, &body)
            .await
            .expect_err("wrong node");
        assert!(err.to_string().contains("another storage node"), "{err}");

        let mut too_old = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &piece_id,
            PieceAction::Put,
            64,
        );
        too_old.order_creation = Some(proto_shift(Duration::from_secs(2 * 60 * 60), false));
        sign_order_limit(&mut too_old, &satellite).unwrap();
        let mut client = harness.client(&uplink, &satellite).await;
        let err = client
            .upload(&too_old, &piece_key, &body)
            .await
            .expect_err("too old");
        assert!(err.to_string().contains("one hour"), "{err}");

        let mut future = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &piece_id,
            PieceAction::Put,
            64,
        );
        future.order_creation = Some(proto_shift(Duration::from_secs(2 * 60 * 60), true));
        sign_order_limit(&mut future, &satellite).unwrap();
        let mut client = harness.client(&uplink, &satellite).await;
        let err = client
            .upload(&future, &piece_key, &body)
            .await
            .expect_err("future");
        assert!(err.to_string().contains("one hour"), "{err}");

        let get_on_upload = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &piece_id,
            PieceAction::Get,
            64,
        );
        let mut conn = harness.conn(&uplink).await;
        let mut stream = conn.open_stream(PIECESTORE_UPLOAD).await.unwrap();
        let request = PieceUploadRequest {
            limit: Some(get_on_upload),
            hash_algorithm: 0,
            ..PieceUploadRequest::default()
        };
        conn.send_msg(&mut stream, &request.encode_to_vec())
            .await
            .unwrap();
        let err = conn.recv_msg(&stream).await.expect_err("bad action");
        assert!(err.to_string().contains("put"), "{err}");

        let missing = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &[0x66; 32],
            PieceAction::Get,
            8,
        );
        let mut client = harness.client(&uplink, &satellite).await;
        let err = client
            .download(&missing, &piece_key, 0, 1)
            .await
            .expect_err("missing");
        assert!(err.to_string().contains("not found"), "{err}");
    }

    #[tokio::test]
    async fn closes_a_non_drpc_prefix() {
        let satellite = Identity::generate().unwrap();
        let harness = Harness::start(std::slice::from_ref(&satellite)).await;
        let mut tcp = TcpStream::connect(harness.addr).await.unwrap();
        tcp.write_all(b"DRPC!X!1").await.unwrap();
        tcp.flush().await.unwrap();
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), tcp.read(&mut buf))
            .await
            .expect("connection should close")
            .unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn invoke_metadata_before_the_invoke_is_skipped() {
        let satellite = Identity::generate().unwrap();
        let harness = Harness::start(std::slice::from_ref(&satellite)).await;
        let mut conn = harness.conn(&satellite).await;
        let request = ExistsRequest {
            piece_ids: vec![vec![0x11; 32]],
        }
        .encode_to_vec();
        // The Go client's order: metadata, invoke, message, on one stream.
        let packets = [
            (Kind::INVOKE_METADATA, b"trace".to_vec()),
            (Kind::INVOKE, PIECESTORE_EXISTS.as_bytes().to_vec()),
            (Kind::MESSAGE, request),
            (Kind::CLOSE_SEND, Vec::new()),
        ];
        for (message_id, (kind, data)) in (1u64..).zip(packets) {
            conn.write_packet(&Packet {
                stream_id: 1,
                message_id,
                kind,
                control: false,
                data,
            })
            .await
            .unwrap();
        }
        let reply = conn.read_packet().await.unwrap();
        assert!(reply.kind == Kind::MESSAGE, "got {}", reply.kind);
        let response = ExistsResponse::decode(reply.data.as_slice()).unwrap();
        assert_eq!(response.missing, vec![0]);
    }

    #[tokio::test]
    async fn accept_errors_are_retried_and_the_next_connection_is_served() {
        let satellite = Identity::generate().unwrap();
        let harness = Harness::start(std::slice::from_ref(&satellite)).await;
        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let addr = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicU64::new(0));
        // EMFILE three times, as a full descriptor table returns, then the
        // real listener.
        let accept = {
            let listener = Arc::clone(&listener);
            let calls = Arc::clone(&calls);
            move || {
                let listener = Arc::clone(&listener);
                let call = calls.fetch_add(1, Ordering::Relaxed);
                async move {
                    if call < 3 {
                        return Err(std::io::Error::from_raw_os_error(24));
                    }
                    listener.accept().await
                }
            }
        };
        let node = Arc::clone(&harness.node);
        let serving =
            tokio::spawn(
                async move { node.serve_accepted(accept, Duration::from_millis(1)).await },
            );

        // The loop is still there to handle this connection: a prefix that
        // is not DRPC is read and the socket closed.
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        tcp.write_all(b"DRPC!X!1").await.unwrap();
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(5), tcp.read(&mut buf))
            .await
            .expect("the connection after the accept errors is served")
            .unwrap();
        assert_eq!(n, 0);
        assert!(calls.load(Ordering::Relaxed) >= 4);
        assert!(!serving.is_finished(), "an accept error must not end serve");
        serving.abort();
    }

    #[tokio::test]
    async fn silent_connection_is_closed_after_the_handshake_budget() {
        let satellite = Identity::generate().unwrap();
        let harness = Harness::start(std::slice::from_ref(&satellite)).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let budget = Duration::from_millis(50);

        // Nothing at all, then the TLS prefix with no ClientHello after it.
        for prefix in [None, Some(storj_rpc::DRPC_TLS_MUX_PREFIX)] {
            let mut client = TcpStream::connect(addr).await.unwrap();
            if let Some(prefix) = prefix {
                client.write_all(prefix).await.unwrap();
            }
            let (sock, _) = listener.accept().await.unwrap();
            let err =
                tokio::time::timeout(Duration::from_secs(5), harness.node.handle(sock, budget))
                    .await
                    .expect("the handler must not wait for the peer")
                    .expect_err("handshake budget");
            assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
            let mut buf = [0u8; 1];
            assert_eq!(client.read(&mut buf).await.unwrap(), 0);
        }
    }

    #[test]
    fn satellite_leaf_must_be_the_certificate_whose_ca_matches() {
        let sat = Identity::generate().unwrap();
        let other = Identity::generate().unwrap();
        let ok = TrustedSatellite {
            id: sat.node_id(),
            address: String::new(),
            leaf_der: sat.leaf_der().as_ref().to_vec(),
            ca_der: sat.ca_der().as_ref().to_vec(),
        };
        assert_eq!(super::verified_leaf(&ok).unwrap(), sat.leaf_der().as_ref());
        let empty = TrustedSatellite {
            id: sat.node_id(),
            address: String::new(),
            leaf_der: Vec::new(),
            ca_der: sat.ca_der().as_ref().to_vec(),
        };
        assert!(super::verified_leaf(&empty).is_err());
        let mismatch = TrustedSatellite {
            id: sat.node_id(),
            address: String::new(),
            leaf_der: sat.leaf_der().as_ref().to_vec(),
            ca_der: other.ca_der().as_ref().to_vec(),
        };
        let err = super::verified_leaf(&mismatch).unwrap_err();
        assert!(err.to_string().contains("does not hash"), "{err}");
        let ca_as_leaf = TrustedSatellite {
            id: sat.node_id(),
            address: String::new(),
            leaf_der: sat.ca_der().as_ref().to_vec(),
            ca_der: sat.ca_der().as_ref().to_vec(),
        };
        let err = super::verified_leaf(&ca_as_leaf).unwrap_err();
        assert!(err.to_string().contains("leaf is the CA"), "{err}");
        let unrelated = TrustedSatellite {
            id: sat.node_id(),
            address: String::new(),
            leaf_der: other.leaf_der().as_ref().to_vec(),
            ca_der: sat.ca_der().as_ref().to_vec(),
        };
        let err = super::verified_leaf(&unrelated).unwrap_err();
        assert!(err.to_string().contains("not signed by its CA"), "{err}");
    }

    #[tokio::test]
    async fn head_bucket_failure_is_returned() {
        let root = TempRoot::new();
        let config = Config {
            s3: s3store::Config {
                endpoint: "http://127.0.0.1:1".into(),
                bucket: "missing".into(),
                access_key_id: "ak".into(),
                secret_access_key: "sk".into(),
                volume: root.path().join("volume"),
                ..s3store::Config::default()
            },
            operator_email: "op@example.com".into(),
            operator_wallet: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            wallet_features: Vec::new(),
            contact_external_address: "127.0.0.1:28967".into(),
            satellites: Vec::new(),
            listen: "127.0.0.1:0".parse().unwrap(),
        };
        match tokio::time::timeout(Duration::from_secs(20), crate::start(&config)).await {
            Ok(Err(err)) => assert!(matches!(err, crate::Error::Store(_)), "{err}"),
            Ok(Ok(_)) => panic!("head bucket succeeded"),
            Err(_) => panic!("head bucket should fail without hanging"),
        }
    }

    #[tokio::test]
    async fn start_refuses_a_satellite_without_a_leaf() {
        let root = TempRoot::new();
        let satellite = Identity::generate().unwrap();
        let config = node_config(&root, satellite.node_id());
        match crate::start(&config).await {
            Err(err) => {
                assert!(matches!(err, crate::Error::Satellite(_)), "{err}");
                assert!(err.to_string().contains("missing certificate"), "{err}");
            }
            Ok(_) => panic!("start listened without a satellite leaf"),
        }
    }

    #[tokio::test]
    async fn start_accepts_a_leaf_whose_ca_matches_then_checks_the_bucket() {
        let root = TempRoot::new();
        let satellite = Identity::generate().unwrap();
        let dir = root.path().join("volume").join("satellites");
        std::fs::create_dir_all(&dir).unwrap();
        let pem = crate::identity::certificate_chain_pem(&satellite);
        std::fs::write(dir.join(format!("{}.pem", satellite.node_id())), pem).unwrap();
        let config = node_config(&root, satellite.node_id());
        match tokio::time::timeout(Duration::from_secs(20), crate::start(&config)).await {
            Ok(Err(err)) => assert!(matches!(err, crate::Error::Store(_)), "{err}"),
            Ok(Ok(_)) => panic!("head bucket succeeded"),
            Err(_) => panic!("head bucket should fail without hanging"),
        }
        let volume = root.path().join("volume");
        let bytes = std::fs::read(volume.join(crate::noise_key::FILE_NAME)).expect("noise key");
        assert_eq!(bytes.len(), 32);
        let loaded = crate::noise_key::Key::load_or_create(&volume).expect("reload");
        assert_eq!(loaded.private().as_slice(), bytes.as_slice());
    }

    fn node_config(root: &TempRoot, satellite: storj_rpc::NodeId) -> Config {
        Config {
            s3: s3store::Config {
                endpoint: "http://127.0.0.1:1".into(),
                bucket: "missing".into(),
                access_key_id: "ak".into(),
                secret_access_key: "sk".into(),
                volume: root.path().join("volume"),
                ..s3store::Config::default()
            },
            operator_email: "op@example.com".into(),
            operator_wallet: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            wallet_features: Vec::new(),
            contact_external_address: "127.0.0.1:28967".into(),
            satellites: vec![storj_rpc::NodeUrl {
                id: satellite,
                address: "127.0.0.1:7777".into(),
            }],
            listen: "127.0.0.1:0".parse().unwrap(),
        }
    }

    #[tokio::test]
    async fn retain_trashes_pieces_the_filter_rejects() {
        let satellite = Identity::generate().unwrap();
        let other = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let harness = Harness::start(std::slice::from_ref(&satellite)).await;
        let sat = satellite.node_id().to_string();
        let other_id = other.node_id().to_string();
        let cutoff = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        // The filter date minus the skew margin is the real boundary.
        let edge = cutoff - RETAIN_MAX_TIME_SKEW;
        let old = edge - Duration::from_secs(60);
        // seed 0, one hash, 8-byte table: 0x01 is in the set and 0x02 is not.
        let keep_id = [0x01; 32];
        let drop_id = [0x02; 32];
        let fresh_id = [0x33; 32];
        let other_piece = [0x44; 32];
        let boundary_id = [0x55; 32];
        let already_id = [0x66; 32];
        let later_id = [0x77; 32];
        let mut filter = Filter::new(0, 1, 8).unwrap();
        filter.add(&keep_id);
        assert!(filter.contains(&keep_id));
        assert!(!filter.contains(&drop_id));

        put_piece_at(&harness.node.store, &sat, &keep_id, old, b"keep").await;
        put_piece_at(&harness.node.store, &sat, &drop_id, old, b"drop-me").await;
        // Before the filter date, but inside the margin. Not in the filter.
        let fresh = cutoff - Duration::from_secs(60);
        put_piece_at(&harness.node.store, &sat, &fresh_id, fresh, b"fresh").await;
        put_piece_at(&harness.node.store, &sat, &boundary_id, edge, b"edge").await;
        put_piece_at(&harness.node.store, &other_id, &other_piece, old, b"other").await;
        put_piece_at(&harness.node.store, &sat, &already_id, old, b"gone").await;
        let trashed_at = old + Duration::from_secs(5);
        harness
            .node
            .store
            .trash(&sat, &encode_hex(&already_id), trashed_at)
            .await
            .unwrap();

        let mut stranger = harness.conn(&uplink).await;
        let denied = stranger
            .invoke(
                PIECESTORE_RETAIN,
                &retain_message(&filter, cutoff, PieceHashAlgo::Sha256, true).encode_to_vec(),
            )
            .await
            .expect_err("uplink is not a satellite");
        assert!(denied.to_string().contains("untrusted"), "{denied}");
        assert_eq!(piece_state(&harness, &sat, &drop_id), PieceState::Live);

        let mut bad = retain_message(&filter, cutoff, PieceHashAlgo::Sha256, true);
        bad.filter[0] = 9;
        let mut hasher = PieceHashAlgo::Sha256.hasher();
        hasher.update(&bad.filter);
        bad.hash = hasher.finalize();
        let err = invoke_retain(&harness, &satellite, &bad)
            .await
            .expect_err("bad version");
        assert!(err.to_string().contains("unsupported version"), "{err}");

        let mut mismatch = retain_message(&filter, cutoff, PieceHashAlgo::Sha256, true);
        mismatch.hash = vec![0; 32];
        let err = invoke_retain(&harness, &satellite, &mismatch)
            .await
            .expect_err("hash");
        assert!(err.to_string().contains("hash mismatch"), "{err}");
        assert_eq!(piece_state(&harness, &sat, &drop_id), PieceState::Live);

        let ok = retain_message(&filter, cutoff, PieceHashAlgo::Sha256, true);
        let response = RetainResponse::decode(
            invoke_retain(&harness, &satellite, &ok)
                .await
                .expect("retain")
                .as_slice(),
        )
        .unwrap();
        assert_eq!(response, RetainResponse {});
        assert_eq!(piece_state(&harness, &sat, &keep_id), PieceState::Live);
        assert_eq!(piece_state(&harness, &sat, &drop_id), PieceState::Trash);
        assert_eq!(piece_state(&harness, &sat, &fresh_id), PieceState::Live);
        assert_eq!(piece_state(&harness, &sat, &boundary_id), PieceState::Live);
        assert_eq!(
            piece_state(&harness, &other_id, &other_piece),
            PieceState::Live
        );
        let already = harness
            .node
            .store
            .info(&sat, &encode_hex(&already_id))
            .unwrap()
            .unwrap();
        assert_eq!(already.state, PieceState::Trash);
        assert_eq!(already.trashed_at, Some(trashed_at));
        let downloaded = harness
            .node
            .store
            .download(&sat, &encode_hex(&drop_id), None)
            .await
            .unwrap();
        assert_eq!(downloaded.bytes, b"drop-me");
        assert!(downloaded.restored_from_trash);
        assert!(
            !harness
                .node
                .store
                .exists(&sat, &encode_hex(&drop_id))
                .unwrap()
        );

        put_piece_at(&harness.node.store, &sat, &later_id, old, b"later").await;
        let err = retain_big(&harness, &satellite, &filter, cutoff, true)
            .await
            .expect_err("bad retain big hash");
        assert!(err.to_string().contains("hash mismatch"), "{err}");
        assert_eq!(piece_state(&harness, &sat, &later_id), PieceState::Live);

        let response = RetainResponse::decode(
            retain_big(&harness, &satellite, &filter, cutoff, false)
                .await
                .expect("retain big")
                .as_slice(),
        )
        .unwrap();
        assert_eq!(response, RetainResponse {});
        assert_eq!(piece_state(&harness, &sat, &later_id), PieceState::Trash);
        assert_eq!(piece_state(&harness, &sat, &keep_id), PieceState::Live);
        let later = harness
            .node
            .store
            .download(&sat, &encode_hex(&later_id), None)
            .await
            .unwrap();
        assert_eq!(later.bytes, b"later");
        assert!(later.restored_from_trash);
    }

    #[tokio::test]
    async fn upload_that_does_not_fit_in_the_allocation_is_refused() {
        let satellite = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let harness =
            Harness::open_allocated(std::slice::from_ref(&satellite), &[], None, 10).await;
        let piece_key = PiecePrivateKey::generate();
        let put = |piece_id: [u8; 32], limit: i64| {
            signed_limit(
                &satellite,
                &harness.identity,
                &piece_key,
                &piece_id,
                PieceAction::Put,
                limit,
            )
        };

        // 4 of 10 bytes. The stored piece comes off the cached free space.
        let mut client = harness.client(&uplink, &satellite).await;
        client
            .upload(&put([0x41; 32], 4), &piece_key, b"abcd")
            .await
            .expect("fits");

        let mut client = harness.client(&uplink, &satellite).await;
        let err = client
            .upload(&put([0x42; 32], 7), &piece_key, b"abcdefg")
            .await
            .expect_err("7 bytes do not fit in the 6 left");
        assert!(err.to_string().contains("not enough available"), "{err}");
        assert!(
            harness
                .node
                .store
                .info(&satellite.node_id().to_string(), &encode_hex(&[0x42; 32]))
                .unwrap()
                .is_none()
        );

        let mut client = harness.client(&uplink, &satellite).await;
        client
            .upload(&put([0x43; 32], 6), &piece_key, b"abcdef")
            .await
            .expect("exactly the space left");
    }

    #[tokio::test]
    async fn concurrent_upload_reserves_capacity_and_cancel_releases_it() {
        let satellite = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let harness =
            Harness::open_allocated(std::slice::from_ref(&satellite), &[], None, 10).await;
        let key = PiecePrivateKey::generate();
        let limit = |piece, bytes| {
            signed_limit(
                &satellite,
                &harness.identity,
                &key,
                &[piece; 32],
                PieceAction::Put,
                bytes,
            )
        };
        let pending = limit(0xa1, 8);
        let mut conn = harness.conn(&uplink).await;
        let mut stream = conn.open_stream(PIECESTORE_UPLOAD).await.unwrap();
        conn.send_msg(
            &mut stream,
            &PieceUploadRequest {
                limit: Some(pending.clone()),
                order: Some(order_for(&pending, &key, 8)),
                chunk: Some(piece_upload_request::Chunk {
                    offset: 0,
                    data: b"12345678".to_vec(),
                }),
                ..Default::default()
            }
            .encode_to_vec(),
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while harness.node.orders.in_flight() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let err = harness
            .client(&uplink, &satellite)
            .await
            .upload(&limit(0xa2, 8), &key, b"12345678")
            .await
            .expect_err("the pending upload owns eight of the ten bytes");
        assert!(err.to_string().contains("not enough available"), "{err}");
        conn.close_send(&mut stream).await.unwrap();
        conn.recv_msg(&stream)
            .await
            .expect_err("incomplete upload cancelled");
        wait_idle(&harness.node).await;
        assert_eq!(harness.node.free_space.lock().unwrap().reserved, 0);

        // A short successful upload releases the unused portion of its limit.
        harness
            .client(&uplink, &satellite)
            .await
            .upload(&limit(0xa3, 10), &key, b"1234")
            .await
            .unwrap();
        harness
            .client(&uplink, &satellite)
            .await
            .upload(&limit(0xa4, 6), &key, b"123456")
            .await
            .unwrap();
        let space = harness.node.store.space().unwrap();
        assert_eq!(space.used, space.allocated);
        assert_eq!(space.used, 10);
    }

    #[tokio::test]
    async fn failed_upload_releases_its_capacity_reservation() {
        let satellite = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let harness =
            Harness::open_allocated(std::slice::from_ref(&satellite), &[], None, 10).await;
        let key = PiecePrivateKey::generate();
        let put = signed_limit(
            &satellite,
            &harness.identity,
            &key,
            &[0xb1; 32],
            PieceAction::Put,
            10,
        );
        let mut conn = harness.conn(&uplink).await;
        let mut stream = conn.open_stream(PIECESTORE_UPLOAD).await.unwrap();
        conn.send_msg(
            &mut stream,
            &PieceUploadRequest {
                limit: Some(put.clone()),
                order: Some(order_for(&put, &key, 10)),
                chunk: Some(piece_upload_request::Chunk {
                    offset: 1,
                    data: vec![1],
                }),
                ..Default::default()
            }
            .encode_to_vec(),
        )
        .await
        .unwrap();
        let err = conn
            .recv_msg(&stream)
            .await
            .expect_err("invalid chunk offset");
        assert!(err.to_string().contains("chunk out of order"), "{err}");
        let put = signed_limit(
            &satellite,
            &harness.identity,
            &key,
            &[0xb2; 32],
            PieceAction::Put,
            10,
        );
        harness
            .client(&uplink, &satellite)
            .await
            .upload(&put, &key, b"1234567890")
            .await
            .unwrap();
        assert_eq!(harness.node.store.space().unwrap().used, 10);
    }

    #[tokio::test]
    async fn expired_capacity_cache_preserves_in_flight_reservations() {
        let harness = Harness::open_allocated(&[], &[], None, 10).await;
        let limit = |bytes| OrderLimit {
            limit: bytes,
            ..Default::default()
        };
        let held = harness
            .node
            .reserve_space(&limit(8))
            .unwrap_or_else(|_| panic!("fits"));
        {
            let mut space = harness.node.free_space.lock().unwrap();
            space.cached.as_mut().unwrap().0 = Instant::now() - super::SPACE_REFRESH;
        }
        assert!(
            harness.node.reserve_space(&limit(3)).is_err(),
            "an expired cache cannot forget reserved bytes"
        );
        drop(held);
        assert!(
            harness.node.reserve_space(&limit(10)).is_ok(),
            "dropping the guard returns capacity"
        );
    }

    #[tokio::test]
    async fn a_finished_rpc_does_not_wait_forever_for_the_client_close() {
        let satellite = Identity::generate().unwrap();
        let harness = Harness::start(std::slice::from_ref(&satellite)).await;
        let request = ExistsRequest {
            piece_ids: vec![vec![0x11; 32]],
        };
        // open_stream + send, not invoke: this client never writes its close.
        let mut conn = harness.conn(&satellite).await;
        let mut stream = conn.open_stream(PIECESTORE_EXISTS).await.unwrap();
        conn.send_msg(&mut stream, &request.encode_to_vec())
            .await
            .unwrap();
        let reply = conn.recv_msg(&stream).await.expect("reply");
        ExistsResponse::decode(reply.as_slice()).unwrap();

        // The response is here and the stream's close frame arrives next.
        // What must not arrive until the linger budget passes is the end of
        // the connection itself.
        let started = std::time::Instant::now();
        tokio::time::timeout(CLOSE_LINGER + Duration::from_secs(5), async {
            loop {
                match conn.read_packet().await {
                    Ok(pkt) if matches!(pkt.kind, Kind::CLOSE | Kind::CANCEL | Kind::ERROR) => {}
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        })
        .await
        .expect("the server lingers for the close, then hangs up");
        assert!(started.elapsed() >= CLOSE_LINGER, "hung up too early");
    }

    #[tokio::test]
    async fn finished_quic_rpc_closes_even_when_the_peer_keeps_the_connection() {
        let satellite = Identity::generate().unwrap();
        let harness = Harness::start(std::slice::from_ref(&satellite)).await;
        for finish_stream in [false, true] {
            let endpoint = harness
                .node
                .quic_endpoint("127.0.0.1:0".parse().unwrap())
                .unwrap();
            let addr = endpoint.local_addr().unwrap();
            let node = Arc::clone(&harness.node);
            let handler = tokio::spawn(async move {
                let incoming = endpoint.accept().await.unwrap();
                node.handle_quic(incoming, Duration::from_secs(5)).await
            });
            let transport = transport::dial(
                &satellite,
                harness.identity.node_id(),
                &addr.to_string(),
                TransportMode::Quic,
                Duration::from_secs(5),
                None,
            )
            .await
            .unwrap();
            let mut conn = Conn::new(transport);
            let mut stream = conn.open_stream(CONTACT_PING_NODE).await.unwrap();
            conn.send_msg(
                &mut stream,
                &crate::contact::ContactPingRequest {}.encode_to_vec(),
            )
            .await
            .unwrap();
            conn.recv_msg(&stream).await.unwrap();
            conn.close_send(&mut stream).await.unwrap();
            // Keep the QUIC connection alive. One peer leaves its byte
            // stream open; the other sends FIN but never closes the connection.
            let mut transport = conn.into_inner();
            if finish_stream {
                transport.shutdown().await.unwrap();
            }
            tokio::time::timeout(CLOSE_LINGER + Duration::from_secs(3), handler)
                .await
                .expect("finished QUIC handler released within cleanup budget")
                .unwrap()
                .unwrap();
            drop(transport);
        }
    }

    #[tokio::test]
    async fn satellite_ping_back_is_answered_over_tls_and_quic() {
        let satellite = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let harness = Harness::start(std::slice::from_ref(&satellite)).await;
        let request = crate::contact::ContactPingRequest {}.encode_to_vec();

        let mut conn = harness.conn(&satellite).await;
        let reply = conn
            .invoke(CONTACT_PING_NODE, &request)
            .await
            .expect("ping over tls");
        assert_eq!(
            crate::contact::ContactPingResponse::decode(reply.as_slice()).unwrap(),
            crate::contact::ContactPingResponse {}
        );

        // The satellite pings over QUIC next, on the UDP port of the same number.
        let quic = transport::dial(
            &satellite,
            harness.identity.node_id(),
            &harness.addr.to_string(),
            TransportMode::Quic,
            Duration::from_secs(10),
            None,
        )
        .await
        .expect("quic dial");
        let mut conn = Conn::new(quic);
        let reply = conn
            .invoke(CONTACT_PING_NODE, &request)
            .await
            .expect("ping over quic");
        assert!(reply.is_empty());

        let mut stranger = harness.conn(&uplink).await;
        let denied = stranger
            .invoke(CONTACT_PING_NODE, &request)
            .await
            .expect_err("only a trusted satellite may ping");
        assert!(denied.to_string().contains("untrusted"), "{denied}");
    }

    #[tokio::test]
    async fn retain_without_a_creation_date_trashes_nothing() {
        let satellite = Identity::generate().unwrap();
        let harness = Harness::start(std::slice::from_ref(&satellite)).await;
        let sat = satellite.node_id().to_string();
        let piece_id = [0x02; 32];
        let old = UNIX_EPOCH + Duration::from_secs(1_600_000_000);
        put_piece_at(&harness.node.store, &sat, &piece_id, old, b"old").await;
        // An empty filter contains nothing, so any cutoff would trash the piece.
        let filter = Filter::new(0, 1, 8).unwrap();
        let mut request = retain_message(&filter, old, PieceHashAlgo::Sha256, true);
        request.creation_date = None;
        let reply = invoke_retain(&harness, &satellite, &request)
            .await
            .expect("the Go node answers this too");
        assert_eq!(
            RetainResponse::decode(reply.as_slice()).unwrap(),
            RetainResponse {}
        );
        assert_eq!(piece_state(&harness, &sat, &piece_id), PieceState::Live);
    }

    #[tokio::test]
    async fn zero_piece_id_is_an_invalid_argument() {
        let satellite = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let harness = Harness::start(std::slice::from_ref(&satellite)).await;
        let piece_key = PiecePrivateKey::generate();
        let limit = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &[0u8; 32],
            PieceAction::Put,
            4,
        );
        let mut conn = harness.conn(&uplink).await;
        let first = PieceUploadRequest {
            limit: Some(limit),
            ..PieceUploadRequest::default()
        };
        let err = conn
            .invoke(PIECESTORE_UPLOAD, &first.encode_to_vec())
            .await
            .expect_err("zero piece id");
        match err {
            storj_rpc::Error::Remote { code, message } => {
                assert_eq!(code, 3, "{message}");
                assert!(message.contains("missing piece id"), "{message}");
            }
            other => panic!("expected a status, got {other}"),
        }
    }

    #[tokio::test]
    async fn low_space_brings_the_next_check_in_forward() {
        let satellite = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let piece_key = PiecePrivateKey::generate();
        let hour = Duration::from_secs(60 * 60);
        let cooldown = Duration::from_millis(300);
        // Plenty of space, then an allocation under the 5 GB threshold.
        for (allocated, woken) in [(1u64 << 40, false), (1 << 30, true)] {
            let harness =
                Harness::open_allocated(std::slice::from_ref(&satellite), &[], None, allocated)
                    .await;
            let mut low_space = harness.node.subscribe_low_space();
            let last = std::time::Instant::now();
            let waiting = tokio::spawn(async move {
                crate::checkin::next_check_in(&mut low_space, last, hour, cooldown).await;
            });
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(!waiting.is_finished());

            let put = signed_limit(
                &satellite,
                &harness.identity,
                &piece_key,
                &[0x71; 32],
                PieceAction::Put,
                4,
            );
            let mut client = harness.client(&uplink, &satellite).await;
            client
                .upload(&put, &piece_key, b"abcd")
                .await
                .expect("upload");

            if woken {
                tokio::time::timeout(Duration::from_secs(5), waiting)
                    .await
                    .expect("the upload asked for a check-in")
                    .unwrap();
                assert!(last.elapsed() >= cooldown, "the cooldown still applies");
            } else {
                tokio::time::sleep(cooldown + Duration::from_millis(200)).await;
                assert!(!waiting.is_finished(), "no early check-in with space left");
                waiting.abort();
            }
        }
    }

    #[tokio::test]
    async fn low_space_during_a_dial_stays_pending_for_every_satellite() {
        let satellite = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let piece_key = PiecePrivateKey::generate();
        let harness =
            Harness::open_allocated(std::slice::from_ref(&satellite), &[], None, 1 << 30).await;
        let mut first = harness.node.subscribe_low_space();
        let mut second = harness.node.subscribe_low_space();
        let put = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &[0x72; 32],
            PieceAction::Put,
            4,
        );
        let mut client = harness.client(&uplink, &satellite).await;
        client
            .upload(&put, &piece_key, b"abcd")
            .await
            .expect("upload");

        let hour = Duration::from_secs(60 * 60);
        let cooldown = Duration::from_millis(300);
        let last = std::time::Instant::now();
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                crate::checkin::next_check_in(&mut first, last, hour, cooldown),
                crate::checkin::next_check_in(&mut second, last, hour, cooldown),
            );
        })
        .await
        .expect("both satellites still have the low-space signal");
        assert!(last.elapsed() >= cooldown, "the cooldown still applies");
    }

    #[tokio::test]
    async fn order_limits_follow_a_rotated_satellite_leaf() {
        let satellite = Identity::generate().unwrap();
        // Stands in for the satellite's new leaf. In the node the TLS dial
        // has checked it against the satellite's CA before it gets here.
        let rotated = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let harness = Harness::start(std::slice::from_ref(&satellite)).await;
        let piece_key = PiecePrivateKey::generate();
        let limit_signed_by = |signer: &Identity, piece_id: [u8; 32]| {
            let mut limit = signed_limit(
                &satellite,
                &harness.identity,
                &piece_key,
                &piece_id,
                PieceAction::Put,
                4,
            );
            sign_order_limit(&mut limit, signer).expect("sign limit");
            limit
        };

        let mut client = harness.client(&uplink, &rotated).await;
        let err = client
            .upload(&limit_signed_by(&rotated, [0x81; 32]), &piece_key, b"abcd")
            .await
            .expect_err("signed by a leaf the node does not hold");
        assert!(
            err.to_string().contains("invalid order limit signature"),
            "{err}"
        );

        harness
            .node
            .observe_satellite_leaf(satellite.node_id(), rotated.leaf_der().as_ref());
        let mut client = harness.client(&uplink, &rotated).await;
        client
            .upload(&limit_signed_by(&rotated, [0x82; 32]), &piece_key, b"abcd")
            .await
            .expect("the new leaf signs limits now");

        let mut client = harness.client(&uplink, &satellite).await;
        let err = client
            .upload(
                &limit_signed_by(&satellite, [0x83; 32]),
                &piece_key,
                b"abcd",
            )
            .await
            .expect_err("the old leaf no longer signs limits");
        assert!(
            err.to_string().contains("invalid order limit signature"),
            "{err}"
        );

        // An id this node does not trust, and an empty leaf, change nothing.
        harness
            .node
            .observe_satellite_leaf(rotated.node_id(), rotated.leaf_der().as_ref());
        harness
            .node
            .observe_satellite_leaf(satellite.node_id(), &[]);
        assert_eq!(
            harness.node.satellite_leaf(satellite.node_id()).unwrap(),
            rotated.leaf_der().as_ref()
        );
        assert!(harness.node.satellite_leaf(rotated.node_id()).is_none());
    }

    #[tokio::test]
    async fn order_limit_field_this_build_lacks_is_verified_kept_and_returned() {
        let satellite = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let harness = Harness::start(std::slice::from_ref(&satellite)).await;
        let sat = satellite.node_id().to_string();
        let piece_key = PiecePrivateKey::generate();
        let piece_id = [0x91; 32];
        let body = b"repair me";
        let size = body.len() as i64;

        // Field 16: one a newer satellite added. It signs every field.
        let mut extra = Vec::new();
        crate::wire::put_embedded(&mut extra, 16, b"future");
        let limit_with_extra = |action: PieceAction| {
            let mut limit = signed_limit(
                &satellite,
                &harness.identity,
                &piece_key,
                &piece_id,
                action,
                size,
            );
            let mut signed = storj_uplink::encode_order_limit(&limit);
            signed.extend_from_slice(&extra);
            limit.satellite_signature = satellite.hash_and_sign(&signed).unwrap();
            let mut wire = limit.encode_to_vec();
            wire.extend_from_slice(&extra);
            (limit, wire)
        };
        let request_with = |limit: &OrderLimit, limit_wire: &[u8]| {
            let rest = PieceDownloadRequest {
                limit: None,
                order: Some(order_for(limit, &piece_key, size)),
                chunk: Some(piece_download_request::Chunk {
                    offset: 0,
                    chunk_size: size,
                }),
                maximum_chunk_size: 0,
            };
            let mut request = Vec::new();
            crate::wire::put_embedded(&mut request, 1, limit_wire);
            request.extend_from_slice(&rest.encode_to_vec());
            request
        };

        // The piece was uploaded under such a limit.
        let (_, stored) = limit_with_extra(PieceAction::Put);
        let meta = s3store::PieceMeta {
            hash: [0xab; 32],
            algorithm: HashAlgorithm::Sha256,
            created: SystemTime::now(),
            expires: None,
            order_limit: stored.clone(),
            hash_signature: b"sig".to_vec(),
            hash_timestamp: None,
        };
        harness
            .node
            .store
            .put_piece(&sat, &encode_hex(&piece_id), body, meta)
            .await
            .unwrap();

        // The field is on the wire but the signature does not cover it.
        let plain = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &piece_id,
            PieceAction::GetRepair,
            size,
        );
        let mut tampered = plain.encode_to_vec();
        tampered.extend_from_slice(&extra);
        let mut conn = harness.conn(&uplink).await;
        let err = conn
            .invoke(PIECESTORE_DOWNLOAD, &request_with(&plain, &tampered))
            .await
            .expect_err("the extra field is not signed");
        assert!(
            err.to_string().contains("invalid order limit signature"),
            "{err}"
        );

        let (get, get_wire) = limit_with_extra(PieceAction::GetRepair);
        let mut conn = harness.conn(&uplink).await;
        let mut stream = conn.open_stream(PIECESTORE_DOWNLOAD).await.unwrap();
        conn.send_msg(&mut stream, &request_with(&get, &get_wire))
            .await
            .unwrap();
        // The repairer gets the stored limit back with the field it signed.
        let header = conn.recv_msg(&stream).await.unwrap();
        assert_eq!(
            crate::wire::embedded(&header, 3).unwrap(),
            stored.as_slice()
        );
        let decoded = PieceDownloadResponse::decode(header.as_slice()).unwrap();
        assert!(decoded.hash.is_some());
        let chunk = PieceDownloadResponse::decode(conn.recv_msg(&stream).await.unwrap().as_slice())
            .unwrap();
        assert_eq!(chunk.chunk.unwrap().data, body);
        drop(conn);

        // The order is settled with the limit as the satellite signed it.
        wait_idle(&harness.node).await;
        let orders = harness.node.store.orders();
        let saved: Vec<_> = orders
            .unsent_windows()
            .unwrap()
            .into_iter()
            .flat_map(|(satellite, window)| orders.window(&satellite, window).unwrap())
            .filter(|order| order.serial == get.serial_number)
            .collect();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].limit, get_wire);
    }

    #[tokio::test]
    async fn restore_trash_puts_the_calling_satellites_trash_back() {
        let satellite = Identity::generate().unwrap();
        let other = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let harness = Harness::start(&[satellite.clone(), other.clone()]).await;
        let sat = satellite.node_id().to_string();
        let other_id = other.node_id().to_string();
        let created = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let mine = [0x21; 32];
        let theirs = [0x22; 32];
        let store = &harness.node.store;
        put_piece_at(store, &sat, &mine, created, b"mine").await;
        put_piece_at(store, &other_id, &theirs, created, b"theirs").await;
        let now = SystemTime::now();
        store.trash(&sat, &encode_hex(&mine), now).await.unwrap();
        store
            .trash(&other_id, &encode_hex(&theirs), now)
            .await
            .unwrap();
        let request = RestoreTrashRequest {}.encode_to_vec();

        let mut stranger = harness.conn(&uplink).await;
        let denied = stranger
            .invoke(PIECESTORE_RESTORE_TRASH, &request)
            .await
            .expect_err("uplink is not a satellite");
        assert!(denied.to_string().contains("untrusted"), "{denied}");
        assert_eq!(piece_state(&harness, &sat, &mine), PieceState::Trash);

        let mut conn = harness.conn(&satellite).await;
        let reply = conn
            .invoke(PIECESTORE_RESTORE_TRASH, &request)
            .await
            .expect("restore trash");
        assert_eq!(
            RestoreTrashResponse::decode(reply.as_slice()).unwrap(),
            RestoreTrashResponse {}
        );
        assert_eq!(piece_state(&harness, &sat, &mine), PieceState::Live);
        assert!(store.exists(&sat, &encode_hex(&mine)).unwrap());
        // Another satellite's trash is not this caller's to restore.
        assert_eq!(piece_state(&harness, &other_id, &theirs), PieceState::Trash);
    }

    #[tokio::test]
    async fn download_restores_a_trashed_piece() {
        let satellite = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let harness = Harness::start(std::slice::from_ref(&satellite)).await;
        let sat = satellite.node_id().to_string();
        let piece_id = [0x31; 32];
        let body = b"still wanted";
        let store = &harness.node.store;
        put_piece_at(store, &sat, &piece_id, SystemTime::now(), body).await;
        store
            .trash(&sat, &encode_hex(&piece_id), SystemTime::now())
            .await
            .unwrap();
        assert!(!store.exists(&sat, &encode_hex(&piece_id)).unwrap());

        let piece_key = PiecePrivateKey::generate();
        let limit = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &piece_id,
            PieceAction::Get,
            body.len() as i64,
        );
        let (first, got) =
            read_download(&harness, &uplink, &piece_key, &limit, 0, body.len() as i64).await;
        assert!(first.restored_from_trash);
        assert_eq!(got, body);

        let info = store.info(&sat, &encode_hex(&piece_id)).unwrap().unwrap();
        assert_eq!(info.state, PieceState::Live);
        assert_eq!(info.trashed_at, None);
        assert!(store.exists(&sat, &encode_hex(&piece_id)).unwrap());
    }

    async fn put_piece_at(
        store: &Store,
        satellite: &str,
        piece_id: &[u8; 32],
        created: SystemTime,
        body: &[u8],
    ) {
        let meta = s3store::PieceMeta {
            hash: [0xab; 32],
            algorithm: HashAlgorithm::Sha256,
            created,
            expires: None,
            order_limit: b"limit".to_vec(),
            hash_signature: b"sig".to_vec(),
            hash_timestamp: None,
        };
        store
            .put_piece(satellite, &encode_hex(piece_id), body, meta)
            .await
            .expect("put");
    }

    fn piece_state(harness: &Harness, satellite: &str, piece_id: &[u8; 32]) -> PieceState {
        harness
            .node
            .store
            .info(satellite, &encode_hex(piece_id))
            .unwrap()
            .expect("row")
            .state
    }

    async fn invoke_retain(
        harness: &Harness,
        peer: &Identity,
        request: &RetainRequest,
    ) -> Result<Vec<u8>, storj_rpc::Error> {
        // One RPC per connection. A failed retain closes the TLS session.
        let mut conn = harness.conn(peer).await;
        conn.invoke(PIECESTORE_RETAIN, &request.encode_to_vec())
            .await
    }

    fn retain_message(
        filter: &Filter,
        created_before: SystemTime,
        algo: PieceHashAlgo,
        with_hash: bool,
    ) -> RetainRequest {
        let bytes = filter.to_bytes();
        let hash = if with_hash {
            let mut hasher = algo.hasher();
            hasher.update(&bytes);
            hasher.finalize()
        } else {
            Vec::new()
        };
        RetainRequest {
            creation_date: Some(system_to_timestamp(created_before)),
            filter: bytes,
            hash_algorithm: algo.to_i32(),
            hash,
        }
    }

    async fn retain_big(
        harness: &Harness,
        peer: &Identity,
        filter: &Filter,
        created_before: SystemTime,
        bad_hash: bool,
    ) -> Result<Vec<u8>, storj_rpc::Error> {
        let bytes = filter.to_bytes();
        let mid = bytes.len() / 2;
        let mut hasher = PieceHashAlgo::Blake3.hasher();
        hasher.update(&bytes);
        let mut hash = hasher.finalize();
        if bad_hash {
            hash[0] ^= 0xff;
        }
        let mut conn = harness.conn(peer).await;
        let mut stream = conn.open_stream(PIECESTORE_RETAIN_BIG).await?;
        let first = RetainRequest {
            creation_date: Some(system_to_timestamp(created_before)),
            filter: bytes[..mid].to_vec(),
            hash_algorithm: 0,
            hash: Vec::new(),
        };
        conn.send_msg(&mut stream, &first.encode_to_vec()).await?;
        let second = RetainRequest {
            creation_date: None,
            filter: bytes[mid..].to_vec(),
            hash_algorithm: PieceHashAlgo::Blake3.to_i32(),
            hash,
        };
        conn.send_msg(&mut stream, &second.encode_to_vec()).await?;
        conn.close_send(&mut stream).await?;
        conn.recv_msg(&stream).await
    }

    async fn first_download(
        harness: &Harness,
        uplink: &Identity,
        piece_key: &PiecePrivateKey,
        limit: &OrderLimit,
        offset: i64,
        size: i64,
    ) -> PieceDownloadResponse {
        let (first, _) = read_download(harness, uplink, piece_key, limit, offset, size).await;
        first
    }

    async fn read_download(
        harness: &Harness,
        uplink: &Identity,
        piece_key: &PiecePrivateKey,
        limit: &OrderLimit,
        offset: i64,
        size: i64,
    ) -> (PieceDownloadResponse, Vec<u8>) {
        let mut conn = harness.conn(uplink).await;
        let mut stream = conn.open_stream(PIECESTORE_DOWNLOAD).await.unwrap();
        let request = PieceDownloadRequest {
            limit: Some(limit.clone()),
            order: Some(order_for(limit, piece_key, size)),
            chunk: Some(piece_download_request::Chunk {
                offset,
                chunk_size: size,
            }),
            maximum_chunk_size: 16 * 1024,
        };
        conn.send_msg(&mut stream, &request.encode_to_vec())
            .await
            .unwrap();
        let mut first = None;
        let mut got = Vec::new();
        while (got.len() as i64) < size {
            let Some(bytes) = conn.recv_msg_opt(&stream).await.unwrap() else {
                break;
            };
            let response = PieceDownloadResponse::decode(bytes.as_slice()).unwrap();
            if first.is_none() {
                first = Some(response.clone());
            }
            if let Some(chunk) = response.chunk {
                got.extend_from_slice(&chunk.data);
            }
        }
        (first.expect("a response"), got)
    }

    fn pin_creation(limit: &mut OrderLimit, satellite: &Identity, created: prost_types::Timestamp) {
        limit.order_creation = Some(created);
        sign_order_limit(limit, satellite).expect("sign limit");
    }

    async fn wait_in_flight(node: &Node) {
        for _ in 0..100 {
            if node.orders.in_flight() > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("upload did not open an order window");
    }

    /// The order row is saved when the handler drops its guard, which can be
    /// just after the client has already observed the response.
    async fn wait_idle(node: &Node) {
        for _ in 0..200 {
            if node.orders.in_flight() == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("order window stayed open");
    }

    /// `now` far enough past an order created during this test that its hour is closed.
    fn closed_now() -> SystemTime {
        SystemTime::now() + Duration::from_secs(2 * 60 * 60 + 2)
    }

    struct SettlementLog {
        windows: Mutex<Vec<Vec<SettlementRequest>>>,
    }

    impl SettlementLog {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                windows: Mutex::new(Vec::new()),
            })
        }

        fn windows(&self) -> Vec<Vec<SettlementRequest>> {
            self.windows.lock().expect("log").clone()
        }
    }

    fn spawn_settlement_satellite(identity: Identity, log: Arc<SettlementLog>) -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind satellite");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("satellite addr");
        let listener = TcpListener::from_std(listener).expect("tokio listener");
        tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
                server_config(&identity).expect("satellite tls"),
            ));
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    if let Err(err) = serve_one_settlement(acceptor, sock, &log).await {
                        eprintln!("test satellite: {err}");
                    }
                });
            }
        });
        addr
    }

    async fn serve_one_settlement(
        acceptor: tokio_rustls::TlsAcceptor,
        mut sock: TcpStream,
        log: &SettlementLog,
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
        if path != crate::orders::SETTLEMENT_WITH_WINDOW {
            return Err(format!("unexpected rpc {path}"));
        }
        let mut got = Vec::new();
        loop {
            let pkt = conn.read_packet().await.map_err(|err| err.to_string())?;
            if pkt.stream_id != invoke.stream_id {
                continue;
            }
            match pkt.kind {
                Kind::MESSAGE => {
                    let req = SettlementRequest::decode(pkt.data.as_slice())
                        .map_err(|err| err.to_string())?;
                    got.push(req);
                }
                Kind::CLOSE_SEND | Kind::CLOSE => break,
                Kind::ERROR => return Err("client error".into()),
                _ => {}
            }
        }
        log.windows.lock().expect("log").push(got);
        let response = SettlementWithWindowResponse {
            status: 0,
            action_settled: std::collections::HashMap::new(),
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
        Ok(())
    }

    #[tokio::test]
    async fn two_finished_orders_in_one_hour_are_settled_then_archived() {
        let satellite = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let log = SettlementLog::new();
        let sat_addr = spawn_settlement_satellite(satellite.clone(), Arc::clone(&log));
        let harness = Harness::start_with(
            std::slice::from_ref(&satellite),
            &[&format!("127.0.0.1:{}", sat_addr.port())],
        )
        .await;
        let created = proto_now();
        let mut serials = Vec::new();
        for (byte, body) in [(0x21u8, &b"one"[..]), (0x22, &b"two-two"[..])] {
            let piece_key = PiecePrivateKey::generate();
            let mut put = signed_limit(
                &satellite,
                &harness.identity,
                &piece_key,
                &[byte; 32],
                PieceAction::Put,
                body.len() as i64,
            );
            pin_creation(&mut put, &satellite, created);
            serials.push((put.serial_number.clone(), body.len() as i64));
            let mut client = harness
                .client(&uplink, &satellite)
                .await
                .with_hash_algo(PieceHashAlgo::Sha256);
            client.upload(&put, &piece_key, body).await.expect("upload");
        }
        wait_idle(&harness.node).await;

        // The hour is still open: creation was moments ago.
        harness.node.settle_orders(SystemTime::now()).await;
        assert!(log.windows().is_empty(), "open hour must not be sent");

        harness.node.settle_orders(closed_now()).await;
        let windows = log.windows();
        assert_eq!(windows.len(), 1, "one SettlementWithWindow call");
        assert_eq!(windows[0].len(), 2);
        let mut got: Vec<_> = windows[0]
            .iter()
            .map(|req| {
                let order = req.order.as_ref().expect("order");
                (order.serial_number.clone(), order.amount)
            })
            .collect();
        got.sort();
        let mut expect = serials.clone();
        expect.sort();
        assert_eq!(got, expect);

        let sat = satellite.node_id().to_string();
        let db = harness.node.store.orders();
        for (serial, amount) in &serials {
            let status = db.status(&sat, serial).unwrap().expect("row");
            assert_eq!(status.status, Some(0));
            assert_eq!(status.amount, *amount);
        }

        harness.node.settle_orders(closed_now()).await;
        assert_eq!(log.windows().len(), 1, "accepted window is not sent again");
    }

    #[tokio::test]
    async fn settlement_dial_follows_a_rotated_satellite_leaf() {
        let satellite = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let log = SettlementLog::new();
        let sat_addr = spawn_settlement_satellite(satellite.clone(), Arc::clone(&log));
        let harness = Harness::start_with(
            std::slice::from_ref(&satellite),
            &[&format!("127.0.0.1:{}", sat_addr.port())],
        )
        .await;
        let piece_key = PiecePrivateKey::generate();
        let put = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &[0x53; 32],
            PieceAction::Put,
            3,
        );
        let mut client = harness
            .client(&uplink, &satellite)
            .await
            .with_hash_algo(PieceHashAlgo::Sha256);
        client
            .upload(&put, &piece_key, b"abc")
            .await
            .expect("upload");
        wait_idle(&harness.node).await;

        // The certificate rotated and no check-in has seen the new leaf yet:
        // order limits signed by it are refused.
        let rotated = Identity::generate().unwrap();
        harness
            .node
            .observe_satellite_leaf(satellite.node_id(), rotated.leaf_der().as_ref());
        assert_eq!(
            harness.node.satellite_leaf(satellite.node_id()).unwrap(),
            rotated.leaf_der().as_ref()
        );

        // The settlement dial is pinned to the satellite id, so its current
        // leaf is trusted the moment it answers.
        harness.node.settle_orders(closed_now()).await;
        assert_eq!(
            harness.node.satellite_leaf(satellite.node_id()).unwrap(),
            satellite.leaf_der().as_ref()
        );
        assert_eq!(log.windows().len(), 1);
    }

    #[tokio::test]
    async fn open_upload_blocks_settlement_of_that_hour() {
        let satellite = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let log = SettlementLog::new();
        let sat_addr = spawn_settlement_satellite(satellite.clone(), Arc::clone(&log));
        let harness = Harness::start_with(
            std::slice::from_ref(&satellite),
            &[&format!("127.0.0.1:{}", sat_addr.port())],
        )
        .await;
        let created = proto_now();
        let piece_key = PiecePrivateKey::generate();
        let mut put = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &[0x31; 32],
            PieceAction::Put,
            4,
        );
        pin_creation(&mut put, &satellite, created);
        let mut client = harness
            .client(&uplink, &satellite)
            .await
            .with_hash_algo(PieceHashAlgo::Sha256);
        client
            .upload(&put, &piece_key, b"done")
            .await
            .expect("finished upload");
        wait_idle(&harness.node).await;

        let open_key = PiecePrivateKey::generate();
        let mut open = signed_limit(
            &satellite,
            &harness.identity,
            &open_key,
            &[0x32; 32],
            PieceAction::Put,
            8,
        );
        pin_creation(&mut open, &satellite, created);
        let mut conn = harness.conn(&uplink).await;
        let mut stream = conn.open_stream(PIECESTORE_UPLOAD).await.expect("stream");
        let request = PieceUploadRequest {
            limit: Some(open.clone()),
            hash_algorithm: PieceHashAlgo::Sha256.to_i32(),
            order: Some(order_for(&open, &open_key, 4)),
            chunk: Some(piece_upload_request::Chunk {
                offset: 0,
                data: b"abcd".to_vec(),
            }),
            done: None,
        };
        conn.send_msg(&mut stream, &request.encode_to_vec())
            .await
            .expect("partial upload");
        wait_in_flight(&harness.node).await;

        harness.node.settle_orders(closed_now()).await;
        assert!(
            log.windows().is_empty(),
            "hour with an open upload is not sent"
        );
        let status = harness
            .node
            .store
            .orders()
            .status(&satellite.node_id().to_string(), &put.serial_number)
            .unwrap()
            .expect("finished order");
        assert_eq!(status.status, None);
        // `conn` and `stream` stay open through the assertion. Dropping them
        // earlier would finish the upload and free the hour.
    }

    #[tokio::test]
    async fn limit_older_than_one_hour_is_rejected_at_upload() {
        let satellite = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let harness = Harness::start(std::slice::from_ref(&satellite)).await;
        let piece_key = PiecePrivateKey::generate();
        let mut put = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &[0x41; 32],
            PieceAction::Put,
            4,
        );
        pin_creation(
            &mut put,
            &satellite,
            proto_shift(Duration::from_secs(60 * 60 + 30), false),
        );
        let mut client = harness
            .client(&uplink, &satellite)
            .await
            .with_hash_algo(PieceHashAlgo::Sha256);
        let err = client
            .upload(&put, &piece_key, b"late")
            .await
            .expect_err("stale limit");
        assert!(
            err.to_string().contains("one hour"),
            "upload should reject the limit, got {err}"
        );
        assert!(
            harness
                .node
                .store
                .info(&satellite.node_id().to_string(), &encode_hex(&put.piece_id))
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn dial_error_leaves_the_hour_unsent_and_untrusted_is_archived() {
        let satellite = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let harness = Harness::start_with(std::slice::from_ref(&satellite), &["127.0.0.1:1"]).await;
        let piece_key = PiecePrivateKey::generate();
        let mut put = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &[0x51; 32],
            PieceAction::Put,
            3,
        );
        pin_creation(&mut put, &satellite, proto_now());
        let mut client = harness
            .client(&uplink, &satellite)
            .await
            .with_hash_algo(PieceHashAlgo::Sha256);
        client
            .upload(&put, &piece_key, b"abc")
            .await
            .expect("upload");
        wait_idle(&harness.node).await;

        let stranger = Identity::generate().unwrap();
        let stranger_id = stranger.node_id().to_string();
        harness
            .node
            .store
            .orders()
            .save(&s3store::StoredOrder {
                satellite: stranger_id.clone(),
                serial: vec![9, 9, 9],
                window_start: 1_700_000_000,
                limit: b"limit".to_vec(),
                order: b"order".to_vec(),
                amount: 3,
            })
            .unwrap();

        harness.node.settle_orders(closed_now()).await;
        let db = harness.node.store.orders();
        let sat = satellite.node_id().to_string();
        let kept = db.status(&sat, &put.serial_number).unwrap().expect("row");
        assert_eq!(kept.status, None, "dial failure must leave the hour unsent");
        let archived = db
            .status(&stranger_id, &[9, 9, 9])
            .unwrap()
            .expect("stranger");
        assert_eq!(archived.status, Some(1));
    }

    #[tokio::test]
    async fn download_before_the_piece_is_readable_is_not_settled() {
        let satellite = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let harness = Harness::start(std::slice::from_ref(&satellite)).await;
        let piece_key = PiecePrivateKey::generate();
        let piece_id = vec![0x61; 32];
        let body = b"abcd";
        let put = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &piece_id,
            PieceAction::Put,
            body.len() as i64,
        );
        let mut client = harness
            .client(&uplink, &satellite)
            .await
            .with_hash_algo(PieceHashAlgo::Sha256);
        client.upload(&put, &piece_key, body).await.expect("upload");
        wait_idle(&harness.node).await;

        let missing = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &[0x62; 32],
            PieceAction::Get,
            4,
        );
        let mut client = harness.client(&uplink, &satellite).await;
        let err = client
            .download(&missing, &piece_key, 0, 4)
            .await
            .expect_err("missing piece");
        assert!(err.to_string().contains("piece not found"), "{err}");

        let past_end = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &piece_id,
            PieceAction::Get,
            8,
        );
        let mut client = harness.client(&uplink, &satellite).await;
        let err = client
            .download(&past_end, &piece_key, 0, 8)
            .await
            .expect_err("past end");
        assert!(
            err.to_string().contains("more data than available"),
            "{err}"
        );

        let over = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &piece_id,
            PieceAction::Get,
            4,
        );
        let mut conn = harness.conn(&uplink).await;
        let mut stream = conn.open_stream(PIECESTORE_DOWNLOAD).await.expect("stream");
        let request = PieceDownloadRequest {
            limit: Some(over.clone()),
            order: Some(order_for(&over, &piece_key, 4)),
            chunk: Some(piece_download_request::Chunk {
                offset: 0,
                chunk_size: 8,
            }),
            maximum_chunk_size: 0,
        };
        conn.send_msg(&mut stream, &request.encode_to_vec())
            .await
            .expect("oversize request");
        let err = conn.recv_msg(&stream).await.expect_err("oversize");
        assert!(err.to_string().contains("order limit"), "{err}");
        wait_idle(&harness.node).await;

        let sat = satellite.node_id().to_string();
        let db = harness.node.store.orders();
        assert!(db.status(&sat, &missing.serial_number).unwrap().is_none());
        assert!(db.status(&sat, &past_end.serial_number).unwrap().is_none());
        assert!(db.status(&sat, &over.serial_number).unwrap().is_none());

        let get = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &piece_id,
            PieceAction::Get,
            body.len() as i64,
        );
        let mut client = harness.client(&uplink, &satellite).await;
        let got = client
            .download(&get, &piece_key, 0, body.len() as i64)
            .await
            .expect("get");
        assert_eq!(got, body);
        wait_idle(&harness.node).await;
        let saved = db
            .status(&sat, &get.serial_number)
            .unwrap()
            .expect("get order");
        assert_eq!(saved.status, None);
        assert_eq!(saved.amount, body.len() as i64);
    }

    #[tokio::test]
    async fn undecodable_order_does_not_block_later_hours() {
        let satellite = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let log = SettlementLog::new();
        let sat_addr = spawn_settlement_satellite(satellite.clone(), Arc::clone(&log));
        let harness = Harness::start_with(
            std::slice::from_ref(&satellite),
            &[&format!("127.0.0.1:{}", sat_addr.port())],
        )
        .await;
        let created = proto_now();
        let piece_key = PiecePrivateKey::generate();
        let body = b"paid";
        let mut put = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &[0x71; 32],
            PieceAction::Put,
            body.len() as i64,
        );
        pin_creation(&mut put, &satellite, created);
        let mut client = harness
            .client(&uplink, &satellite)
            .await
            .with_hash_algo(PieceHashAlgo::Sha256);
        client.upload(&put, &piece_key, body).await.expect("upload");
        wait_idle(&harness.node).await;

        let sat = satellite.node_id().to_string();
        let window = created.seconds / 3600 * 3600;
        let db = harness.node.store.orders();
        db.save(&s3store::StoredOrder {
            satellite: sat.clone(),
            serial: vec![7, 7],
            window_start: window,
            limit: b"not-a-limit".to_vec(),
            order: b"not-an-order".to_vec(),
            amount: 1,
        })
        .unwrap();
        db.save(&s3store::StoredOrder {
            satellite: sat.clone(),
            serial: vec![8, 8],
            window_start: 1_700_000_000,
            limit: b"not-a-limit".to_vec(),
            order: b"not-an-order".to_vec(),
            amount: 1,
        })
        .unwrap();

        harness.node.settle_orders(closed_now()).await;
        let windows = log.windows();
        assert_eq!(windows.len(), 1, "the readable order is still sent");
        assert_eq!(windows[0].len(), 1);
        let sent = windows[0][0].order.as_ref().expect("order");
        assert_eq!(sent.serial_number, put.serial_number);
        assert_eq!(sent.amount, body.len() as i64);

        let db = harness.node.store.orders();
        assert_eq!(
            db.status(&sat, &put.serial_number).unwrap().unwrap().status,
            Some(0)
        );
        assert_eq!(db.status(&sat, &[7, 7]).unwrap().unwrap().status, Some(1));
        assert_eq!(db.status(&sat, &[8, 8]).unwrap().unwrap().status, Some(1));
    }

    fn bandwidth_used(node: &Node) -> u64 {
        node.store
            .bandwidth_days(None, SystemTime::now())
            .expect("bandwidth")
            .iter()
            .map(|day| day.total())
            .sum()
    }

    /// The counter is written after the success bytes, on the server task.
    /// Another worker can return the client before that write runs.
    async fn wait_bandwidth(node: &Node, want: u64) {
        for _ in 0..100 {
            if bandwidth_used(node) == want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("bandwidth stayed at {}, want {want}", bandwidth_used(node));
    }

    #[tokio::test]
    async fn dashboard_json_reports_disk_bandwidth_and_empty_pages() {
        let satellite = Identity::generate().unwrap();
        let uplink = Identity::generate().unwrap();
        let address = "sat.example:7777";
        let harness = Harness::start_with(std::slice::from_ref(&satellite), &[address]).await;
        let ui = harness._root.path().join("no-ui");
        let dash = crate::dashboard::Dashboard::for_test(Arc::clone(&harness.node), &ui);
        let allocated = 1u64 << 40;

        let (status, body) = dash.handle("GET", "/").await;
        assert_eq!(status, 404);
        let text = String::from_utf8(body).expect("utf8");
        assert!(text.contains("not installed"), "{text}");
        let (status, _) = dash.handle("GET", "/static/no-such").await;
        assert_eq!(status, 404);

        let (status, body) = dash.handle("GET", "/api/sno/").await;
        assert_eq!(status, 200);
        let page: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(page["nodeID"], harness.identity.node_id().to_string());
        assert_eq!(page["wallet"], "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(page["walletFeatures"][0], "zksync-era");
        assert_eq!(page["diskSpace"]["used"], 0);
        assert_eq!(page["diskSpace"]["trash"], 0);
        assert_eq!(page["diskSpace"]["allocated"], allocated);
        assert_eq!(page["bandwidth"]["used"], 0);
        assert_eq!(page["quicStatus"], "");
        assert_eq!(page["lastPinged"], "0001-01-01T00:00:00Z");
        assert_eq!(page["lastQuicPingedAt"], "0001-01-01T00:00:00Z");
        assert_eq!(page["configuredPort"], "28967");
        assert_eq!(page["startedAt"], "2023-11-14T22:13:20Z");
        assert_eq!(page["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(page["upToDate"], true);
        assert!(page["satellites"][0]["disqualified"].is_null());
        assert!(page["satellites"][0]["suspended"].is_null());
        assert!(page["satellites"][0]["vettedAt"].is_null());
        assert_eq!(page["satellites"][0]["url"], address);

        let piece_key = PiecePrivateKey::generate();
        let piece_a = vec![0x31; 32];
        let piece_b = vec![0x32; 32];
        let live = b"live-bytes";
        let trashed = b"trash!!";
        let sat = satellite.node_id().to_string();
        for (piece, body) in [(&piece_a, live.as_slice()), (&piece_b, trashed.as_slice())] {
            let put = signed_limit(
                &satellite,
                &harness.identity,
                &piece_key,
                piece,
                PieceAction::Put,
                body.len() as i64,
            );
            let mut client = harness
                .client(&uplink, &satellite)
                .await
                .with_hash_algo(PieceHashAlgo::Sha256);
            client.upload(&put, &piece_key, body).await.expect("upload");
        }
        wait_bandwidth(&harness.node, (live.len() + trashed.len()) as u64).await;
        harness
            .node
            .store
            .trash(&sat, &encode_hex(&piece_b), SystemTime::now())
            .await
            .expect("trash");

        let get = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &piece_a,
            PieceAction::Get,
            live.len() as i64,
        );
        let mut client = harness.client(&uplink, &satellite).await;
        let got = client
            .download(&get, &piece_key, 0, live.len() as i64)
            .await
            .expect("download");
        assert_eq!(got, live);
        let used_bandwidth = (live.len() + trashed.len() + live.len()) as u64;
        wait_bandwidth(&harness.node, used_bandwidth).await;

        let missing = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &[0x33; 32],
            PieceAction::Get,
            4,
        );
        let mut client = harness.client(&uplink, &satellite).await;
        let err = client
            .download(&missing, &piece_key, 0, 4)
            .await
            .expect_err("missing piece");
        assert!(err.to_string().contains("piece not found"), "{err}");
        assert_eq!(bandwidth_used(&harness.node), used_bandwidth);

        // Client::download returns locally when size is 0 and never dials.
        let zero = signed_limit(
            &satellite,
            &harness.identity,
            &piece_key,
            &piece_a,
            PieceAction::Get,
            0,
        );
        let mut conn = harness.conn(&uplink).await;
        let mut stream = conn.open_stream(PIECESTORE_DOWNLOAD).await.expect("stream");
        let request = PieceDownloadRequest {
            limit: Some(zero.clone()),
            order: Some(order_for(&zero, &piece_key, 0)),
            chunk: Some(piece_download_request::Chunk {
                offset: 0,
                chunk_size: 0,
            }),
            maximum_chunk_size: 0,
        };
        conn.send_msg(&mut stream, &request.encode_to_vec())
            .await
            .expect("zero-byte request");
        let end = conn.recv_msg_opt(&stream).await.expect("zero-byte close");
        assert!(end.is_none(), "zero-byte download closed with {end:?}");
        assert_eq!(bandwidth_used(&harness.node), used_bandwidth);

        let (status, body) = dash.handle("GET", "/api/sno").await;
        assert_eq!(status, 200);
        let page: serde_json::Value = serde_json::from_slice(&body).expect("json");
        let disk_used = (live.len() + trashed.len()) as u64;
        assert_eq!(page["diskSpace"]["used"], disk_used);
        assert_eq!(page["diskSpace"]["trash"], trashed.len() as u64);
        assert_eq!(page["diskSpace"]["allocated"], allocated);
        assert_eq!(page["diskSpace"]["available"], allocated - disk_used);
        assert_eq!(page["diskSpace"]["overused"], 0);
        assert_eq!(page["diskSpace"]["reclaimable"], 0);
        assert_eq!(page["diskSpace"]["reserved"], 0);
        assert_eq!(page["bandwidth"]["used"], used_bandwidth);
        assert_eq!(page["bandwidth"]["available"], 0);
        assert_eq!(page["satellites"][0]["id"], sat);

        let (status, body) = dash.handle("GET", "/api/notifications/list").await;
        assert_eq!(status, 200);
        assert_eq!(
            body,
            br#"{ "page": { "notifications": [], "pageCount": 0 }, "unreadCount": 0, "totalCount": 0 }"#
        );
        let (status, _) = dash.handle("POST", "/api/notifications/abc/read").await;
        assert_eq!(status, 200);
        let (status, _) = dash.handle("POST", "/api/notifications/readall").await;
        assert_eq!(status, 200);

        let (status, body) = dash.handle("GET", "/api/sno/estimated-payout").await;
        assert_eq!(status, 200);
        let payout: serde_json::Value = serde_json::from_slice(&body).expect("json");
        for month in ["currentMonth", "previousMonth"] {
            for key in [
                "egressBandwidth",
                "egressBandwidthPayout",
                "egressRepairAudit",
                "egressRepairAuditPayout",
                "diskSpace",
                "diskSpacePayout",
                "heldRate",
                "payout",
                "held",
            ] {
                assert_eq!(payout[month][key], 0, "{month}.{key}");
            }
        }
        assert_eq!(payout["currentMonthExpectations"], 0);

        let (status, body) = dash
            .handle("GET", &format!("/api/sno/satellites/{sat}/pricing"))
            .await;
        assert_eq!(status, 200);
        let pricing: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(pricing["satelliteID"], sat);
        assert_eq!(pricing["egressBandwidth"], 0);
        assert_eq!(pricing["repairBandwidth"], 0);
        assert_eq!(pricing["auditBandwidth"], 0);
        assert_eq!(pricing["diskSpace"], 0);

        let (status, body) = dash.handle("GET", "/api/sno/satellites").await;
        assert_eq!(status, 200);
        let list: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(list["storageSummary"], live.len() as u64);
        assert_eq!(list["bandwidthSummary"], used_bandwidth);
        assert_eq!(list["egressSummary"], live.len() as u64);
        assert_eq!(list["ingressSummary"], (live.len() + trashed.len()) as u64);
        assert_eq!(list["earliestJoinedAt"], "0001-01-01T00:00:00Z");
        assert!(list["audits"].is_array());
        assert_eq!(list["audits"][0]["satelliteName"], address);
        assert_eq!(list["audits"][0]["auditScore"], 0);
        assert_eq!(list["audits"][0]["suspensionScore"], 0);
        assert_eq!(list["audits"][0]["onlineScore"], 0);
        assert_eq!(list["storageDaily"][0]["atRestTotal"], live.len() as u64);
        assert_eq!(
            list["bandwidthDaily"][0]["ingress"]["usage"],
            (live.len() + trashed.len()) as u64
        );
        assert_eq!(
            list["bandwidthDaily"][0]["egress"]["usage"],
            live.len() as u64
        );

        let (status, body) = dash
            .handle("GET", &format!("/api/sno/satellite/{sat}"))
            .await;
        assert_eq!(status, 200);
        let one: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(one["id"], sat);
        assert_eq!(one["nodeJoinedAt"], "0001-01-01T00:00:00Z");
        assert!(one["audits"].is_object());
        assert_eq!(one["audits"]["auditScore"], 0);
        let (status, body) = dash.handle("GET", "/api/sno/satellite/unknown").await;
        assert_eq!(status, 200);
        let unknown: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(unknown["id"], "unknown");
        assert_eq!(unknown["audits"]["satelliteName"], "");
        assert_eq!(unknown["storageSummary"], 0);

        for path in [
            "/api/heldamount/paystubs/2026-10",
            "/api/heldamount/paystubs/2026-01/2026-10",
            "/api/heldamount/held-history",
            "/api/heldamount/periods",
            "/api/heldamount/payout-history/2026-10",
        ] {
            let (status, body) = dash.handle("GET", path).await;
            assert_eq!(status, 200, "{path}");
            assert_eq!(body, b"[]", "{path}");
        }

        std::fs::create_dir_all(ui.join("js")).expect("ui dir");
        std::fs::write(ui.join("index.html"), b"<html>dash</html>").expect("index");
        std::fs::write(ui.join("js/app.js"), b"console.log(1)").expect("js");
        let (status, body) = dash.handle("GET", "/").await;
        assert_eq!(status, 200);
        assert_eq!(body, b"<html>dash</html>");
        let (status, body) = dash.handle("GET", "/payout").await;
        assert_eq!(status, 200);
        assert_eq!(body, b"<html>dash</html>");
        let (status, body) = dash.handle("GET", "/static/js/app.js").await;
        assert_eq!(status, 200);
        assert_eq!(body, b"console.log(1)");
        let (status, _) = dash.handle("GET", "/static/../index.html").await;
        assert_eq!(status, 404);
        let (status, _) = dash.handle("GET", "/static/%2e%2e/index.html").await;
        assert_eq!(status, 404);
        let outside = harness._root.path().join("outside.html");
        std::fs::write(&outside, b"secret").expect("outside");
        std::fs::remove_file(ui.join("index.html")).expect("replace index");
        std::os::unix::fs::symlink(&outside, ui.join("index.html")).expect("symlink");
        let (status, body) = dash.handle("GET", "/").await;
        assert_eq!(status, 404);
        assert!(!String::from_utf8_lossy(&body).contains("secret"));

        harness
            .node
            .store
            .record_check_in(&s3store::CheckInRow {
                satellite_id: sat.clone(),
                checked_in_at: SystemTime::now(),
                quic_ok: false,
            })
            .expect("check-in");
        let (status, body) = dash.handle("GET", "/api/sno/").await;
        assert_eq!(status, 200);
        let page: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(page["quicStatus"], "Misconfigured");
        assert_ne!(page["lastPinged"], "0001-01-01T00:00:00Z");
        assert!(page["satellites"][0]["disqualified"].is_null());
        assert!(page["satellites"][0]["vettedAt"].is_null());

        harness
            .node
            .store
            .record_check_in(&s3store::CheckInRow {
                satellite_id: sat,
                checked_in_at: SystemTime::now(),
                quic_ok: true,
            })
            .expect("check-in");
        let (_, body) = dash.handle("GET", "/api/sno/").await;
        let page: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(page["quicStatus"], "OK");
        assert_ne!(page["lastQuicPingedAt"], "0001-01-01T00:00:00Z");

        let reopened = Store::new(s3store::Config {
            endpoint: "http://127.0.0.1:9".to_owned(),
            bucket: BUCKET.to_owned(),
            access_key_id: ACCESS_KEY.to_owned(),
            secret_access_key: SECRET.to_owned(),
            volume: harness._root.path().join("volume"),
            ..s3store::Config::default()
        })
        .expect("reopen");
        let total: u64 = reopened
            .bandwidth_days(None, SystemTime::now())
            .expect("days")
            .iter()
            .map(|day| day.total())
            .sum();
        assert_eq!(total, used_bandwidth);
    }
}
