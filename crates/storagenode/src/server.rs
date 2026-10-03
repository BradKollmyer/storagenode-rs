//! DRPC over TLS. One RPC per connection.
//!
//! TCP is peeked for 8 bytes. [`storj_rpc::DRPC_TLS_MUX_PREFIX`] starts TLS
//! with the node id pinned. Any other prefix is closed. Noise and QUIC are
//! later. The server reads with [`Conn::read_packet`]. `invoke` and
//! `open_stream` are client calls and are not used here.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use prost::Message;
use s3store::{HashAlgorithm, PieceBody, PieceMeta, PieceState, Store, Upload};
use storj_proto::orders::{Order, OrderLimit, PieceAction, PieceHash};
use storj_proto::piecestore::{
    ExistsRequest, ExistsResponse, PieceDownloadRequest, PieceDownloadResponse, PieceUploadRequest,
    PieceUploadResponse, RetainRequest, RetainResponse, StorageMethod, piece_download_response,
    piece_upload_request,
};
use storj_proto::rpc::{PIECESTORE_DOWNLOAD, PIECESTORE_UPLOAD};
use storj_rpc::frame::{Kind, Packet};
use storj_rpc::{Conn, DRPC_TLS_MUX_PREFIX, Identity, NodeId, marshal_error};
use storj_uplink::{
    PieceHashAlgo, PiecePublicKey, sign_piece_hash_node, verify_order, verify_order_limit,
    verify_piece_hash_uplink,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

use crate::orders::{self, Orders};

/// DRPC path for `piecestore.Piecestore/Exists`.
///
/// `storj-proto` exports upload and download only.
pub const PIECESTORE_EXISTS: &str = "/piecestore.Piecestore/Exists";

/// DRPC path for `piecestore.Piecestore/Retain`.
pub const PIECESTORE_RETAIN: &str = "/piecestore.Piecestore/Retain";

/// DRPC path for `piecestore.Piecestore/RetainBig`.
pub const PIECESTORE_RETAIN_BIG: &str = "/piecestore.Piecestore/RetainBig";

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
}

struct KnownSatellite {
    leaf: Vec<u8>,
    address: String,
}

/// TLS piecestore server bound to one identity and one bucket.
pub struct Node {
    identity: Identity,
    store: Store,
    /// Satellite id to the leaf that verifies order limits, and its dial address.
    satellites: HashMap<NodeId, KnownSatellite>,
    /// Replay window for this process. Settlement orders are in `pieces.db`.
    serials: Mutex<HashMap<(NodeId, Vec<u8>), SystemTime>>,
    orders: Orders,
    acceptor: tokio_rustls::TlsAcceptor,
}

impl Node {
    /// Builds a TLS acceptor. Does not contact the bucket or bind a port.
    pub fn new(
        identity: Identity,
        store: Store,
        trusted: Vec<TrustedSatellite>,
    ) -> Result<Self, BuildError> {
        let config: rustls::ServerConfig = storj_rpc::server_config(&identity)?;
        let mut satellites = HashMap::with_capacity(trusted.len());
        for satellite in trusted {
            let leaf = verified_leaf(&satellite)?;
            satellites.insert(
                satellite.id,
                KnownSatellite {
                    leaf,
                    address: satellite.address,
                },
            );
        }
        Ok(Self {
            identity,
            store,
            satellites,
            serials: Mutex::new(HashMap::new()),
            orders: Orders::new(),
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
            Ok(()) => {
                // The client writes Close only after reading the response.
                // Dropping the socket first turns that write into EPIPE and
                // fails an RPC that already succeeded.
                let _ = out.conn.read_packet().await;
                Ok(())
            }
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
            PIECESTORE_RETAIN => self.retain(out, peer).await,
            PIECESTORE_RETAIN_BIG => self.retain_big(out, peer).await,
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
        let mut staging: Option<(Upload, String)> = None;
        let mut staged: i64 = 0;
        let mut authorized: i64 = 0;
        // Dropped on every return, including a failed upload, so the hour is
        // not stuck open and the largest order is still recorded.
        let mut tracked = None;

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
                tracked = Some(self.track_order(&next)?);
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
                // this is not the piece key yet.
                hasher.update(&chunk.data);
                spill.write(&chunk.data).await.map_err(store_err)?;
                staged = next_len;
            }
            if let Some(done) = req.done {
                let Some(limit) = limit.take() else {
                    return Err(Fail::proto(RPC_INVALID_ARGUMENT, "expected order limit"));
                };
                let digest = hasher.finalize();
                return self
                    .commit_upload(out, &limit, algo, (staging, staged), &digest, &done)
                    .await;
            }
        }
    }

    async fn commit_upload<T>(
        &self,
        out: &mut Out<T>,
        limit: &OrderLimit,
        algo: PieceHashAlgo,
        spill: (Option<(Upload, String)>, i64),
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
        let (staging, staged) = spill;
        if done.piece_size != staged {
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
        if done.signature.is_empty() {
            return Err(Fail::proto(
                RPC_UNAUTHENTICATED,
                "invalid piece hash signature",
            ));
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
            staging.finish().await.map_err(store_err)?;
            self.store
                .commit_staged_piece(&sat, &piece, &stage_id, meta)
                .await
                .map_err(store_err)?;
        }
        let piece_size = staged;

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
        // The guard holds the hour shut for this RPC. The order is noted only
        // after the piece is readable, so a missing piece is not settled.
        let mut tracked = None;
        let mut early_orders = Vec::new();
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
                tracked = Some(self.track_order(&next)?);
                limit = Some(next);
            }
            if let Some(order) = req.order {
                let Some(limit_ref) = limit.as_ref() else {
                    return Err(Fail::proto(RPC_INVALID_ARGUMENT, "order before limit"));
                };
                authorized = check_order(limit_ref, &order, authorized)?;
                early_orders.push(order);
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
        // A later failure can still save the largest order. Nothing before
        // this point transferred a byte, so those orders are discarded.
        if let Some(tracked) = tracked.as_mut() {
            for order in &early_orders {
                tracked.note(order);
            }
        }
        let mut pending = Vec::new();

        // GET and GET_AUDIT do not send the hash. GET_REPAIR does, before bytes.
        if limit.action == PieceAction::GetRepair as i32 {
            let stored_limit = OrderLimit::decode(info.order_limit.as_slice())
                .map_err(|err| Fail::proto(RPC_INTERNAL, err.to_string()))?;
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
        let mut sent: u64 = 0;
        let mut file_off = offset;
        while sent < size {
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
                    if let Some(tracked) = tracked.as_mut() {
                        tracked.note(&order);
                    }
                }
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
        let peer = self.trusted_satellite(peer)?;
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
        let peer = self.trusted_satellite(peer)?;
        // Same assembly as `RetainRequestFromStream`: chunks concatenate, and
        // the message that carries the hash ends the stream.
        let mut creation_date = None;
        let mut filter = Vec::new();
        loop {
            let Some(bytes) = out.recv().await? else {
                return Err(Fail::proto(
                    RPC_INVALID_ARGUMENT,
                    "retain closed before the hash",
                ));
            };
            let req = RetainRequest::decode(bytes.as_slice())
                .map_err(|err| Fail::proto(RPC_INVALID_ARGUMENT, err.to_string()))?;
            if creation_date.is_none() {
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

    /// Trashes this satellite's live rows created before `creation_date` when
    /// the filter does not contain them. The object stays; the 7-day chore
    /// deletes trash.
    async fn apply_retain(&self, peer: NodeId, req: &RetainRequest) -> Result<(), Fail> {
        check_retain_hash(req.hash_algorithm, &req.filter, &req.hash)?;
        let created_before = req
            .creation_date
            .as_ref()
            .and_then(timestamp_to_system)
            .ok_or_else(|| Fail::proto(RPC_INVALID_ARGUMENT, "missing creation date"))?;
        let filter = crate::bloom::Filter::from_bytes(&req.filter)
            .map_err(|err| Fail::proto(RPC_INVALID_ARGUMENT, err.to_string()))?;
        let sat = peer.to_string();
        let pieces = self
            .store
            .live_created_before(&sat, created_before)
            .map_err(store_err)?;
        let now = SystemTime::now();
        for piece_id in pieces {
            let raw = decode_piece_id(&piece_id)?;
            if filter.contains(&raw) {
                continue;
            }
            match self.store.trash(&sat, &piece_id, now).await {
                Ok(()) => {}
                // Gone, or no longer live, between the list and the flag.
                Err(s3store::Error::NotFound) => {}
                Err(err) => return Err(store_err(err)),
            }
        }
        Ok(())
    }

    fn trusted_satellite(&self, peer: Option<NodeId>) -> Result<NodeId, Fail> {
        // Same check as Exists: the TLS client is the satellite, not a field.
        let Some(peer) = peer else {
            return Err(Fail::proto(RPC_UNAUTHENTICATED, "missing peer identity"));
        };
        if !self.satellites.contains_key(&peer) {
            return Err(Fail::proto(
                RPC_PERMISSION_DENIED,
                "retain called with untrusted id",
            ));
        }
        Ok(peer)
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
        let Some(known) = self.satellites.get(&satellite_id) else {
            return Err(Fail::proto(RPC_PERMISSION_DENIED, "untrusted satellite"));
        };
        if known.leaf.is_empty() {
            return Err(Fail::proto(
                RPC_UNAUTHENTICATED,
                "satellite certificate is not known",
            ));
        }
        verify_order_limit(limit, &known.leaf)
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

    fn track_order(&self, limit: &OrderLimit) -> Result<orders::OrderGuard, Fail> {
        let satellite = parse_node_id(&limit.satellite_id)?;
        let window = order_window(limit)?;
        Ok(self
            .orders
            .begin(self.store.orders(), satellite, window, limit.clone()))
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
                now,
            )
            .await;
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

fn next_stage_id() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    format!("{:016x}", NEXT.fetch_add(1, Ordering::Relaxed))
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

fn encode_hex(bytes: &[u8]) -> String {
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
        // Equal to now is still valid. There is no expiration grace.
        Some(time) => time < now,
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

fn serial_deadline(limit: &OrderLimit, now: SystemTime) -> SystemTime {
    limit
        .order_expiration
        .as_ref()
        .and_then(timestamp_to_system)
        .unwrap_or(now)
}

#[cfg(test)]
mod tests {
    use super::{
        GO_ZERO_TIME_UNIX, Node, PIECESTORE_EXISTS, PIECESTORE_RETAIN, PIECESTORE_RETAIN_BIG,
        TrustedSatellite, creation_ok, encode_hex, expired, system_to_timestamp,
    };
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::process;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
        PieceUploadRequest, RetainRequest, RetainResponse, StorageMethod, piece_download_request,
        piece_upload_request,
    };
    use storj_proto::rpc::{PIECESTORE_DOWNLOAD, PIECESTORE_UPLOAD};
    use storj_rpc::frame::{Kind, Packet};
    use storj_rpc::{Conn, Identity, client_config, server_config, write_tls_mux_prefix};
    use storj_uplink::{
        Client, PieceConfig, PieceHashAlgo, PiecePrivateKey, sign_order, sign_order_limit,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
            Self::start_with(satellites, &[]).await
        }

        async fn start_with(satellites: &[Identity], addresses: &[&str]) -> Self {
            let bucket = TestBucket::start().await;
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
    fn order_creation_grace_is_one_hour_and_expiration_has_none() {
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
        assert!(!expired(Some(&at(Duration::from_secs(0), true)), now));
        assert!(!expired(Some(&at(Duration::from_secs(1), true)), now));
        assert!(expired(Some(&at(Duration::from_secs(1), false)), now));
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
        let old = cutoff - Duration::from_secs(60);
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
        put_piece_at(&harness.node.store, &sat, &fresh_id, cutoff, b"fresh").await;
        put_piece_at(&harness.node.store, &sat, &boundary_id, cutoff, b"edge").await;
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
}
