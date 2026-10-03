//! DRPC over TLS. One RPC per connection.
//!
//! TCP is peeked for 8 bytes. [`storj_rpc::DRPC_TLS_MUX_PREFIX`] starts TLS
//! with the node id pinned. Any other prefix is closed. Noise and QUIC are
//! later. The server reads with [`Conn::read_packet`]. `invoke` and
//! `open_stream` are client calls and are not used here.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use prost::Message;
use s3store::{HashAlgorithm, PieceMeta, PieceState, Store};
use storj_proto::orders::{Order, OrderLimit, PieceAction, PieceHash};
use storj_proto::piecestore::{
    ExistsRequest, ExistsResponse, PieceDownloadRequest, PieceDownloadResponse, PieceUploadRequest,
    PieceUploadResponse, StorageMethod, piece_download_response, piece_upload_request,
};
use storj_proto::rpc::{PIECESTORE_DOWNLOAD, PIECESTORE_UPLOAD};
use storj_rpc::frame::{Kind, Packet};
use storj_rpc::{Conn, DRPC_TLS_MUX_PREFIX, Identity, NodeId, marshal_error};
use storj_uplink::{
    PieceHashAlgo, PieceHasher, PiecePublicKey, sign_piece_hash_node, verify_order,
    verify_order_limit, verify_piece_hash_uplink,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

/// DRPC path for `piecestore.Piecestore/Exists`.
///
/// `storj-proto` exports upload and download only.
pub const PIECESTORE_EXISTS: &str = "/piecestore.Piecestore/Exists";

/// Order limits whose creation time is further than this from now are rejected.
/// The same window is the grace after piece and order expiration.
const ORDER_LIMIT_GRACE: Duration = Duration::from_secs(60 * 60);

/// Unix seconds of Go's zero `time.Time` (year 1). Unset on the wire.
const GO_ZERO_TIME_UNIX: i64 = -62_135_596_800;

const RPC_CANCELED: u64 = 1;
const RPC_INVALID_ARGUMENT: u64 = 3;
const RPC_NOT_FOUND: u64 = 5;
const RPC_PERMISSION_DENIED: u64 = 7;
const RPC_UNIMPLEMENTED: u64 = 12;
const RPC_INTERNAL: u64 = 13;
const RPC_UNAUTHENTICATED: u64 = 16;

/// A satellite whose order limits this node will accept.
///
/// `leaf_der` is the certificate that signed the limit. An empty leaf means
/// the id is trusted (Exists) but signatures cannot be checked yet.
#[derive(Clone, Debug)]
pub struct TrustedSatellite {
    /// Satellite node id.
    pub id: NodeId,
    /// Leaf certificate DER, or empty when the certificate has not been seen.
    pub leaf_der: Vec<u8>,
}

/// TLS piecestore server bound to one identity and one bucket.
pub struct Node {
    identity: Identity,
    store: Store,
    /// Satellite id to leaf certificate. Empty leaf: id only.
    satellites: HashMap<NodeId, Vec<u8>>,
    /// Replay window. In memory until orders are persisted.
    serials: Mutex<HashMap<(NodeId, Vec<u8>), SystemTime>>,
    acceptor: tokio_rustls::TlsAcceptor,
}

impl Node {
    /// Builds a TLS acceptor. Does not contact the bucket or bind a port.
    pub fn new(
        identity: Identity,
        store: Store,
        trusted: Vec<TrustedSatellite>,
    ) -> Result<Self, storj_rpc::IdentityError> {
        let config: rustls::ServerConfig = storj_rpc::server_config(&identity)?;
        let mut satellites = HashMap::with_capacity(trusted.len());
        for satellite in trusted {
            satellites.insert(satellite.id, satellite.leaf_der);
        }
        Ok(Self {
            identity,
            store,
            satellites,
            serials: Mutex::new(HashMap::new()),
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
        })
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

    /// Accepts until the listener fails. Each connection is one RPC.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> io::Result<()> {
        loop {
            let (sock, _) = listener.accept().await?;
            let node = Arc::clone(&self);
            tokio::spawn(async move {
                let _ = node.handle(sock).await;
            });
        }
    }

    async fn handle(&self, mut sock: TcpStream) -> io::Result<()> {
        let _ = sock.set_nodelay(true);
        let mut prefix = [0u8; 8];
        sock.read_exact(&mut prefix).await?;
        if prefix.as_slice() != DRPC_TLS_MUX_PREFIX {
            // Noise (`DRPC!N!1`) and anything else are later.
            return Ok(());
        }
        let tls = self.acceptor.accept(sock).await?;
        let peer = peer_node_id(&tls);
        let mut conn = Conn::new(tls);
        let invoke = conn.read_packet().await.map_err(io_err)?;
        if invoke.kind != Kind::INVOKE {
            return Ok(());
        }
        let path = String::from_utf8(invoke.data).unwrap_or_default();
        let mut out = Out {
            conn,
            stream_id: invoke.stream_id,
            // The reader starts at message 1 and rejects 0.
            next_id: 1,
        };
        match self.dispatch(&mut out, peer, &path).await {
            Ok(()) => Ok(()),
            Err(Fail::Proto { code, message }) => {
                let _ = out.fail(code, &message).await;
                Ok(())
            }
            Err(Fail::Transport(err)) => Err(io_err(err)),
        }
    }

    async fn dispatch(
        &self,
        out: &mut Out<tokio_rustls::server::TlsStream<TcpStream>>,
        peer: Option<NodeId>,
        path: &str,
    ) -> Result<(), Fail> {
        match path {
            PIECESTORE_UPLOAD => self.upload(out).await,
            PIECESTORE_DOWNLOAD => self.download(out).await,
            PIECESTORE_EXISTS => self.exists(out, peer).await,
            _ => Err(Fail::proto(RPC_UNIMPLEMENTED, "unknown rpc")),
        }
    }

    async fn upload<T>(&self, out: &mut Out<T>) -> Result<(), Fail>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let mut limit: Option<OrderLimit> = None;
        let mut algo = PieceHashAlgo::Sha256;
        let mut hasher = PieceHashAlgo::Sha256.hasher();
        let mut body = Vec::new();
        let mut authorized: i64 = 0;

        loop {
            let Some(bytes) = out.recv().await? else {
                return Err(Fail::proto(
                    RPC_INVALID_ARGUMENT,
                    "upload closed before the piece hash",
                ));
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
                self.check_limit(&next, true)?;
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
            }
            if let Some(chunk) = req.chunk.as_ref() {
                accept_chunk(&mut body, &mut hasher, limit_ref.limit, authorized, chunk)?;
            }
            if let Some(done) = req.done {
                let Some(limit) = limit.take() else {
                    return Err(Fail::proto(RPC_INVALID_ARGUMENT, "expected order limit"));
                };
                let digest = hasher.finalize();
                return self
                    .commit_upload(out, &limit, algo, &body, &digest, &done)
                    .await;
            }
        }
    }

    async fn commit_upload<T>(
        &self,
        out: &mut Out<T>,
        limit: &OrderLimit,
        algo: PieceHashAlgo,
        body: &[u8],
        digest: &[u8],
        done: &PieceHash,
    ) -> Result<(), Fail>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        if done.piece_id != limit.piece_id {
            return Err(Fail::proto(RPC_INVALID_ARGUMENT, "piece id changed"));
        }
        if done.hash_algorithm != algo.to_i32() {
            return Err(Fail::proto(RPC_INVALID_ARGUMENT, "hash algorithm mismatch"));
        }
        let piece_size = i64::try_from(body.len())
            .map_err(|_| Fail::proto(RPC_INVALID_ARGUMENT, "piece too large"))?;
        if done.piece_size != piece_size {
            return Err(Fail::proto(RPC_INVALID_ARGUMENT, "piece size mismatch"));
        }
        if done.hash.as_slice() != digest {
            return Err(Fail::proto(RPC_INVALID_ARGUMENT, "piece hash mismatch"));
        }
        let public = PiecePublicKey::from_bytes(&limit.uplink_public_key)
            .map_err(|_| Fail::proto(RPC_UNAUTHENTICATED, "invalid uplink public key"))?;
        verify_piece_hash_uplink(done, &public)
            .map_err(|_| Fail::proto(RPC_UNAUTHENTICATED, "invalid piece hash signature"))?;
        if digest.len() != 32 {
            return Err(Fail::proto(RPC_INTERNAL, "piece hash is not 32 bytes"));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(digest);

        let satellite_id = parse_node_id(&limit.satellite_id)?;
        // The hash is part of the object metadata, and the uplink sends it
        // only in the final message, so the body cannot be committed earlier.
        let meta = PieceMeta {
            hash,
            algorithm: store_algo(algo),
            created: done
                .timestamp
                .as_ref()
                .and_then(timestamp_to_system)
                .unwrap_or_else(SystemTime::now),
            expires: limit
                .piece_expiration
                .as_ref()
                .and_then(timestamp_to_system),
            order_limit: limit.encode_to_vec(),
        };
        self.store
            .put_piece(
                &satellite_id.to_string(),
                &encode_hex(&limit.piece_id),
                body,
                meta,
            )
            .await
            .map_err(store_err)?;

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
            node_certchain: Vec::new(),
        };
        out.message(&response.encode_to_vec()).await?;
        out.close().await?;
        Ok(())
    }

    async fn download<T>(&self, out: &mut Out<T>) -> Result<(), Fail>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let mut limit: Option<OrderLimit> = None;
        let mut chunk = None;
        let mut authorized: i64 = 0;
        let mut advisory: i32 = 0;
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
                self.check_limit(&next, false)?;
                limit = Some(next);
            }
            if let Some(order) = req.order {
                let Some(limit_ref) = limit.as_ref() else {
                    return Err(Fail::proto(RPC_INVALID_ARGUMENT, "order before limit"));
                };
                authorized = check_order(limit_ref, &order, authorized)?;
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
        let restored = info.state == PieceState::Trash;
        let bytes = if size == 0 {
            Vec::new()
        } else {
            let download = self
                .store
                .download(&sat, &piece, Some(offset..end))
                .await
                .map_err(store_err)?;
            if download.bytes.len() != usize::try_from(size).unwrap_or(usize::MAX) {
                return Err(Fail::proto(RPC_INTERNAL, "short piece read"));
            }
            download.bytes
        };

        // GET and GET_AUDIT do not send the hash. GET_REPAIR does, before bytes.
        if limit.action == PieceAction::GetRepair as i32 {
            let stored_limit = OrderLimit::decode(info.order_limit.as_slice())
                .map_err(|err| Fail::proto(RPC_INTERNAL, err.to_string()))?;
            let header = PieceDownloadResponse {
                hash: Some(PieceHash {
                    piece_id: limit.piece_id.clone(),
                    hash: info.hash.to_vec(),
                    piece_size: i64::try_from(info.size).unwrap_or(i64::MAX),
                    timestamp: Some(system_to_timestamp(info.created)),
                    signature: Vec::new(),
                    hash_algorithm: algo_i32(info.algorithm),
                }),
                limit: Some(stored_limit),
                restored_from_trash: restored,
                chunk: None,
            };
            out.message(&header.encode_to_vec()).await?;
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
        let mut sent: usize = 0;
        let mut file_off = offset;
        while sent < bytes.len() {
            let sent_i =
                i64::try_from(sent).map_err(|_| Fail::proto(RPC_INTERNAL, "offset overflow"))?;
            if sent_i >= authorized {
                let Some(more) = out.recv().await? else {
                    return Err(Fail::proto(
                        RPC_INVALID_ARGUMENT,
                        "order closed before the requested bytes were authorized",
                    ));
                };
                let req = PieceDownloadRequest::decode(more.as_slice())
                    .map_err(|err| Fail::proto(RPC_INVALID_ARGUMENT, err.to_string()))?;
                if let Some(order) = req.order {
                    authorized = check_order(&limit, &order, authorized)?;
                }
                continue;
            }
            let room = usize::try_from(authorized - sent_i)
                .map_err(|_| Fail::proto(RPC_INTERNAL, "offset overflow"))?;
            let n = room.min(bytes.len() - sent).min(chunk_size);
            let data = bytes[sent..sent + n].to_vec();
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
            file_off += u64::try_from(n).unwrap_or(0);
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

    fn check_limit(&self, limit: &OrderLimit, upload: bool) -> Result<(), Fail> {
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
        let Some(leaf) = self.satellites.get(&satellite_id) else {
            return Err(Fail::proto(RPC_PERMISSION_DENIED, "untrusted satellite"));
        };
        if leaf.is_empty() {
            return Err(Fail::proto(
                RPC_UNAUTHENTICATED,
                "satellite certificate is not known",
            ));
        }
        verify_order_limit(limit, leaf)
            .map_err(|_| Fail::proto(RPC_UNAUTHENTICATED, "invalid order limit signature"))?;
        self.reserve_serial(
            satellite_id,
            &limit.serial_number,
            serial_deadline(limit, now),
        )
    }

    fn reserve_serial(
        &self,
        satellite: NodeId,
        serial: &[u8],
        deadline: SystemTime,
    ) -> Result<(), Fail> {
        let mut used = self.serials.lock().unwrap_or_else(|err| err.into_inner());
        let now = SystemTime::now();
        used.retain(|_, exp| *exp > now);
        let key = (satellite, serial.to_vec());
        if used.contains_key(&key) {
            return Err(Fail::proto(RPC_UNAUTHENTICATED, "duplicate serial number"));
        }
        used.insert(key, deadline);
        Ok(())
    }
}

fn peer_node_id(tls: &tokio_rustls::server::TlsStream<TcpStream>) -> Option<NodeId> {
    let certs = tls.get_ref().1.peer_certificates()?;
    let ca = certs.get(1)?;
    NodeId::from_certificate_der(ca.as_ref()).ok()
}

fn io_err(err: storj_rpc::Error) -> io::Error {
    io::Error::other(err.to_string())
}

struct Out<T> {
    conn: Conn<T>,
    stream_id: u64,
    next_id: u64,
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

fn accept_chunk(
    body: &mut Vec<u8>,
    hasher: &mut PieceHasher,
    limit_bytes: i64,
    authorized: i64,
    chunk: &piece_upload_request::Chunk,
) -> Result<(), Fail> {
    if chunk.offset < 0 {
        return Err(Fail::proto(RPC_INVALID_ARGUMENT, "negative chunk offset"));
    }
    let have = i64::try_from(body.len())
        .map_err(|_| Fail::proto(RPC_INVALID_ARGUMENT, "piece too large"))?;
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
    hasher.update(&chunk.data);
    body.extend_from_slice(&chunk.data);
    Ok(())
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

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
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
        Some(time) => time
            .checked_add(ORDER_LIMIT_GRACE)
            .map(|deadline| deadline < now)
            .unwrap_or(true),
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
    let earliest = now.checked_sub(ORDER_LIMIT_GRACE).unwrap_or(UNIX_EPOCH);
    let Some(latest) = now.checked_add(ORDER_LIMIT_GRACE) else {
        return created >= earliest;
    };
    created >= earliest && created <= latest
}

fn serial_deadline(limit: &OrderLimit, now: SystemTime) -> SystemTime {
    let base = limit
        .order_expiration
        .as_ref()
        .and_then(timestamp_to_system)
        .unwrap_or(now);
    base.checked_add(ORDER_LIMIT_GRACE).unwrap_or(base)
}

#[cfg(test)]
mod tests {
    use super::{
        GO_ZERO_TIME_UNIX, Node, PIECESTORE_EXISTS, TrustedSatellite, creation_ok, encode_hex,
        expired, system_to_timestamp,
    };
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::process;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as ConnBuilder;
    use prost::Message;
    use s3s::auth::SimpleAuth;
    use s3s::service::S3ServiceBuilder;
    use s3s_fs::FileSystem;
    use s3store::{HashAlgorithm, PieceState, Store};
    use storj_proto::orders::{Order, OrderLimit, PieceAction};
    use storj_proto::piecestore::{
        ExistsRequest, ExistsResponse, PieceDownloadRequest, PieceDownloadResponse,
        PieceUploadRequest, StorageMethod, piece_download_request,
    };
    use storj_proto::rpc::{PIECESTORE_DOWNLOAD, PIECESTORE_UPLOAD};
    use storj_rpc::{Conn, Identity, client_config, write_tls_mux_prefix};
    use storj_uplink::{
        Client, PieceConfig, PieceHashAlgo, PiecePrivateKey, sign_order, sign_order_limit,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use crate::Config;

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
        async fn start() -> Self {
            let root = TempRoot::new();
            std::fs::create_dir(root.path().join(BUCKET)).expect("bucket dir");
            let addr = spawn_s3(root.path());
            let config = s3store::Config {
                endpoint: format!("http://{addr}"),
                bucket: BUCKET.to_owned(),
                access_key_id: ACCESS_KEY.to_owned(),
                secret_access_key: SECRET.to_owned(),
                volume: root.path().join("volume"),
                allocated_bytes: 1 << 40,
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
            let bucket = TestBucket::start().await;
            let identity = Identity::generate().expect("node identity");
            let trusted = satellites
                .iter()
                .map(|sat| TrustedSatellite {
                    id: sat.node_id(),
                    leaf_der: sat.leaf_der().as_ref().to_vec(),
                })
                .collect();
            let node = Arc::new(Node::new(identity.clone(), bucket.store, trusted).expect("node"));
            node.startup().await.expect("startup");
            let listener = Node::listen("127.0.0.1:0".parse().unwrap())
                .await
                .expect("listen");
            let addr = listener.local_addr().expect("addr");
            let serving = Arc::clone(&node);
            tokio::spawn(async move {
                let _ = serving.serve(listener).await;
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
    fn order_creation_grace_is_one_hour_both_ways() {
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
        assert!(!expired(
            Some(&at(Duration::from_secs(30 * 60), false)),
            now
        ));
        assert!(expired(
            Some(&at(Duration::from_secs(60 * 60 + 5), false)),
            now
        ));
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
        tcp.write_all(b"DRPC!N!1").await.unwrap();
        tcp.flush().await.unwrap();
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(2), tcp.read(&mut buf))
            .await
            .expect("connection should close")
            .unwrap();
        assert_eq!(n, 0);
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
}
