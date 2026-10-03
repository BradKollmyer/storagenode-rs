# Builder notes

Read [PLAN.md](PLAN.md) for what the node does. This file is how, and the traps. Do not re-derive the pins. Do not edit `storj/`, `uplink/`, or `uplink-rs/`. [README.md](README.md) is how to build and run the binary.

## Trees

| Path | Role |
|---|---|
| `/Volumes/SSD/repos/storj/storagenode-rs` | This project. |
| `/Volumes/SSD/repos/storj/uplink-rs` | Protocol API. Path-depend. Public crate `storj` does not export identity, frames, or order bytes. |
| `/Volumes/SSD/repos/storj/storj` | Go node and `web/storagenode`. Behavior reference and the Vue app. |
| `/Volumes/SSD/repos/storj/uplink` | Go uplink. Not a dependency. |
| `/Volumes/SSD/repos/storj-rust` | Early stub. Do not use. |
| `/Users/bradk/go/pkg/mod/storj.io/common@v0.0.0-20260818140313-d38275a3768b/pb/` | Proto sources at the pin. |

Parent `/Volumes/SSD/repos/storj` is not a git repo. `uplink-rs` is `github.com/BradKollmyer/uplink-rs` (DCO, GitHub PRs). `storj` and `uplink` review on Gerrit.

`uplink-rs` style: edition 2024, `MIT OR Apache-2.0`, workspace `crates/*` excluding fuzz. `rust-version` is 1.91.1. Copy `.cargo/config.toml` (aarch64 `aes_armv8` / `polyval_armv8`) if this workspace pulls `aes-gcm`. Docker Rust stage `rust:1.91.1-bookworm`.

Path deps from `crates/storagenode/Cargo.toml` (`crates/s3store` does not need them):

```
storj-proto = { path = "../../../uplink-rs/crates/storj-proto" }
storj-rpc = { path = "../../../uplink-rs/crates/storj-rpc" }
storj-uplink = { path = "../../../uplink-rs/crates/storj-uplink" }
```

Those relatives resolve from `storagenode-rs/crates/storagenode` to the sibling `uplink-rs`. The crate docs say depend on `storj` instead. This node depends on the internal crates anyway. Docker context is the parent directory so the same relatives still resolve. Copy both trees into the build context.

Public helpers, from `storj_uplink`: `encode_order_limit`, `verify_order_limit`, `verify_order`, `sign_piece_hash_node`, `verify_piece_hash_uplink`, `PieceHashAlgo`, `PieceHasher`, `Client`, `PieceConfig`. Identity and TLS: `Identity::{generate, from_pem, from_pem_parts, cert_chain, private_key, hash_and_sign, leaf_der}` and `server_config` in `storj-rpc/src/tls.rs` (requires a client certificate, `with_safe_default_protocol_versions`). `from_pem` wants CERTIFICATE blocks plus one PKCS#8 `PRIVATE KEY` (SEC1 `EC PRIVATE KEY` via `from_pem_parts`). There is no `to_pem`. Persist PEM yourself, leaf first.

## Protos

Pin, from `uplink-rs/proto/README.md` (same `storj.io/common` pseudoversion as `storj/go.mod`):

```
STORJ_COMMON_SHA=d38275a3768ba356144814f3ec5d62eeca670e49
STORJ_UPLINK_SHA=2fef38720d8395837567da60ab69016099dca9f5
```

Already generated in `storj-proto`: piecestore, orders, node (`NodeOperator`, `NodeCapacity`, `NodeVersion`), noise (`NoiseInfo`, `NoiseKeyAttestation`, `NoiseProtocol`). Do not regenerate that crate.

`uplink-rs/proto/node.proto` is byte-identical to the pin (95 lines, compared 2026-10-02). Do not copy a second `node.proto`. The `reserved 3 to 14` line is inside `message Node`. It is not a truncated file.

`SignedNodeTagSets` is not in `node.proto`. It is in `nodetags.proto`, which is also `package node`, and which uplink does not vendor. `CheckInRequest.signed_tags` uses that type. `storj_proto::node` was generated from `node.proto` alone, so it has no `SignedNodeTagSets`.

Copy into `storagenode-rs/proto/`, byte-identical, from the module cache. Do not hand-edit.

- `contact.proto` — `package contact`. Imports `node.proto`, `noise.proto`, `nodetags.proto`, `gogo.proto`, `timestamp.proto`.
- `nodetags.proto` — `package node`. `Tag`, `NodeTagSet`, `SignedNodeTagSet`, `SignedNodeTagSets`.
- `gracefulexit.proto` — imports `metainfo.proto` and `orders.proto`.
- `heldamount.proto`
- `nodestats.proto`

`prost-build` include dirs: this `proto/` first, then `uplink-rs/proto` (for `node.proto`, `noise.proto`, `gogo.proto`, `orders.proto`, `metainfo.proto`). Compile `nodetags.proto` in the same `protoc` invocation as `contact.proto` so package `node` contains `SignedNodeTagSets`.

`extern_path` `.orders`, `.metainfo`, and `.noise` to `::storj_proto::orders`, `::storj_proto::metainfo`, `::storj_proto::noise`. Do not `extern_path` `.node` onto `storj_proto::node`. Check-in uses the locally generated node types (a second `NodeOperator` / `NodeCapacity` / `NodeVersion`). Piecestore keeps using `storj_proto`. If an `extern_path` type is missing a field, drop that extern and translate with `encode_to_vec` / `decode`.

DRPC paths, copied from the pin's `*_drpc.pb.go`. Do not invent another prefix.

| RPC | Path |
|---|---|
| Upload / Download / Delete / DeletePieces / Retain / RetainBig / RestoreTrash / Exists | `/piecestore.Piecestore/<Method>` |
| SettlementWithWindow | `/orders.Orders/SettlementWithWindow` |
| CheckIn | `/contact.Node/CheckIn` |
| Graceful exit | `/gracefulexit.SatelliteGracefulExit/Process` and `/gracefulexit.SatelliteGracefulExit/GracefulExitFeasibility` |
| Paystubs | `/heldamount.HeldAmount/GetPayStub`, `GetAllPaystubs`, `GetPayment`, `GetAllPayments` |
| Stats | `/nodestats.NodeStats/GetStats`, `DailyStorageUsage`, `PricingModel` |

`storj-proto` only exports `PIECESTORE_UPLOAD` and `PIECESTORE_DOWNLOAD`. Add the other constants in this repo.

`CheckInRequest.features` stays 0. Bits: `TCP_FASTOPEN_ENABLED=1`, `HASHSTORE_FOR_NEW=2`, `HASHSTORE_MEMTBL=4`. Ignore `CheckInResponse.hashstore_settings`.

Noise attestation, from `storj.io/common/rpc/noise.GenerateKeyAttestation`: sign `b"noise-key-attestation-v1:" || uint64be(max(unix_nanos, 0)) || public_key` with `Identity::hash_and_sign`. Fill `node_certchain`, `noise_proto=1`, `noise_public_key`, `timestamp`, `signature`.

## DRPC server

`Conn::invoke` and `Conn::open_stream` are client calls. They allocate stream ids. The server reads with `Conn::read_packet`. The first packet on a stream is `Kind::INVOKE` (1) and the data is the path string. Following packets are `Kind::MESSAGE` (2). One RPC per connection, matching `storj-rpc`. Reply with MESSAGE, then CLOSE. Errors use the same frame encoding `unmarshal_error` expects (8-byte code plus text). Streaming RPCs (Upload, Download, RetainBig, SettlementWithWindow, GracefulExit.Process) do not use unary `invoke`.

QUIC has no TCP mux header. Model the listener on the private `quic_server` in `storj-rpc/src/transport.rs` (around line 1072): `server_config`, ALPN `storj`, `QuicServerConfig::try_from`, `quinn::Endpoint::server`. Idle timeout 15 minutes, keepalive 15 seconds, same as `quic()` in that file. Uplink rustls features include TLS 1.3 (`QuicClientConfig::try_from` already works).

Upload message order is in `uplink-rs/proto/piecestore2.proto`: OrderLimit, optional hash algorithm (field 5, when not SHA-256), repeated Order+Chunk, then uplink-signed PieceHash. Response is the node-signed PieceHash, plus `node_certchain` on Noise (TLS can take the cert from the connection). Download starts with OrderLimit and a range. `GET_REPAIR` sends the stored hash and the original order limit before the bytes. `GET` and `GET_AUDIT` do not. Actions allowed on download: GET, GET_REPAIR, GET_AUDIT.

`Exists` missing is `STORAGE_METHOD_UNSPECIFIED`. Present is `STORAGE_METHOD_PIECESTORE`. The enum lives in `storj.io/common`. Do not extend it.

Order limit grace is 1 hour both ways (`storj/storagenode/piecestore/verification.go`). Wallet regex `^0x[a-fA-F0-9]{40}$`. Empty email is a warning in the Go node. This plan still requires `STORJ_OPERATOR_EMAIL`. WalletFeatures is an optional comma list.

Settlement status enum in `orders.proto`: `ACCEPTED = 0`, `REJECTED = 1`. Group orders by satellite and by the UTC hour of `limit.OrderCreation`. Do not copy the Go `unsent-orders-<sat>-<hour>` filenames. Do not send a window that still has an open upload or download. Do not submit an ACCEPTED window again. REJECTED is archived too. A dial or RPC failure leaves the hour unsent.

The graceful-exit worker only calls Recv. The satellite speaks first. Return these strings, matching `storj/storagenode/gracefulexit/worker.go`:

- `satellite has requested piece transfer, but piece-transfer-based graceful exit is no longer supported`
- `satellite has requested piece deletion, but piece-transfer-based graceful exit is no longer supported`

`NotReady` retries. `FailedPrecondition` drops the pending row. `ExitFailed` stores the reason. `ExitCompleted` stores the receipt, then deletes that satellite's prefix and rows. Keep serving Download until then. One worker per pending satellite. CLI: `exit-satellite`, `exit-status`.

Noise: `NoiseStream::accept` takes the protocol as an argument. The 8-byte header `DRPC!N!1` does not include it. Go's default is protocol 1 (`NOISE_IK_25519_CHACHAPOLY_BLAKE2B`), set in `noise.DefaultProto` (`rpc/noise/noise.go` in the module cache) and used from `storj/private/server/server.go`. Advertise that protocol in the check-in attestation and accept only that protocol. Protocol 2 is `NOISE_IK_25519_AESGCM_BLAKE2B`. A test builds the server with protocol 2 and dials `NoiseStream::connect(io, 2, public_key)`. One handshake is one protocol.

## Bloom retain

Port `storj/shared/bloomfilter/filter.go`. There is no Rust copy in `uplink-rs`. Wire bytes: version `1`, seed, hashCount, then the table. Reject a version other than 1, a buffer shorter than 3 bytes, or a hashCount of 0.

`Contains`: a piece id is 32 bytes, copied twice into a 64-byte buffer. `offset = seed % 32`. `rangeOffset` is `{9, 13, 19, 23}[(seed / 32) % 4]`. For each of `hashCount` hashes: little-endian u64 at `offset`, the next byte is the bit index, `bucket = hash % table_len` (plain modulo; `fastdiv` is only a speed trick), bit is `1 << (bit % 8)`. If that bit is unset, the piece is not in the set, so trash it. Then `offset = (offset + rangeOffset) % 32`. Retain walks live rows for that satellite with `created_at` before the request's `CreatedBefore`.

## S3 object metadata

Body is raw chunk bytes. No 512-byte hashstore footer. User-metadata map keys (the SDK adds `x-amz-meta-`):

- `piece-hash` — hex
- `hash-algorithm` — `sha256` or `blake3`
- `created` — RFC3339
- `expires` — RFC3339, or absent
- `order-limit` — standard base64 of the encoded order limit

Trash is only an index flag. A rebuild cannot recover it or the unsent orders. Key `{prefix}/{satellite-id}/{piece-id}`, prefix default `pieces`.

## Dashboard JSON the Vue app reads

`diskSpace.reserved` is read by `DiskSpace` in `storj/web/storagenode/src/storagenode/sno/sno.ts` and is absent from the Go struct. Emit `0`.

`GET /api/sno/` keys: `nodeID`, `wallet`, `walletFeatures`, `satellites` (`id`, `url`, `disqualified`, `suspended`, `vettedAt`), `diskSpace` (`used`, `available`, `overused`, `allocated`, `trash`, `reclaimable`, `reserved`), `bandwidth` (`used`, `available`), `lastPinged`, `startedAt`, `version`, `allowedVersion`, `upToDate`, `quicStatus`, `configuredPort`, `lastQuicPingedAt`.

`GET /api/sno/satellite/{id}`: `id`, `storageDaily`, `bandwidthDaily`, `storageSummary`, `averageUsageBytes`, `bandwidthSummary`, `egressSummary`, `ingressSummary`, `audits` (`satelliteName`, `auditScore`, `suspensionScore`, `onlineScore`), `nodeJoinedAt`. `GET /api/sno/satellites` is the same rollups plus `audits` as an array. Scores stay 0 until a `GetStats` poll.

`GET /api/sno/estimated-payout`: `currentMonth` and `previousMonth` each with `egressBandwidth`, `egressBandwidthPayout`, `egressRepairAudit`, `egressRepairAuditPayout`, `diskSpace`, `diskSpacePayout`, `heldRate`, `payout`, `held`, plus `currentMonthExpectations`. Zeros before the first pricing poll.

`GET /api/notifications/list`: `{ "page": { "notifications": [], "pageCount": 0 }, "unreadCount": 0, "totalCount": 0 }`. `POST /api/notifications/{id}/read` and `POST /api/notifications/readall` return success.

## Go files to open, not to edit

- `storj/storagenode/piecestore/endpoint.go` — upload, download, retain queue, exists, order enqueue
- `storj/storagenode/piecestore/verification.go` — order-limit grace
- `storj/storagenode/orders/service.go` — `SendOrders` / `settleWindow`
- `storj/storagenode/gracefulexit/worker.go` — exit messages
- `storj/storagenode/contact/service.go` — check-in request fields
- `storj/storagenode/console/consoleserver/server.go` — HTTP routes
- `storj/storagenode/console/service.go` — `Dashboard` JSON
- `storj/web/storagenode/src/storagenode/api/storagenode.ts` — fields the page requires
- `storj/shared/bloomfilter/filter.go` — retain filter
- `uplink-rs/crates/storj-rpc/src/{conn,noise,tls,transport,identity}.rs` — frames, Noise, QUIC, identity

## Build order

1. Workspace and `s3store` with in-process `s3s` tests.
2. SQLite, object metadata, startup rebuild when `pieces.db` is missing.
3. DRPC TLS upload, download, exists.
4. Retain bloom.
5. Order settlement.
6. Noise and QUIC.
7. Check-in.
8. Graceful exit.
9. Dashboard JSON and the Docker UI stage.
10. HeldAmount and PricingModel poll.

## Tests

The list is in [PLAN.md](PLAN.md). No call to a real S3 endpoint. No live satellite.
