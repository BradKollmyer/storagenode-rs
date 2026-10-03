# Rust storage node, S3 piece store

A Rust process stores piece bytes only in an S3 API (AWS S3 or Ceph RGW). Identity and a small SQLite index stay on a local volume. Nothing in the Go `storj` tree changes.

[README.md](README.md) is how to build and run it. [BUILD.md](BUILD.md) has the proto pin, DRPC paths, Noise handshake, bloom filter, and dashboard JSON keys.

## Where it lives

This repo sits next to an `uplink-rs` checkout. Edition 2024, license `MIT OR Apache-2.0`, and DCO, same as `uplink-rs`. MSRV is 1.91.1.

```
storagenode-rs/
  README.md
  PLAN.md
  BUILD.md
  Dockerfile
  proto/
  third_party/s3s/       vendored s3s 0.12
  crates/s3store/        bucket + sqlite index
  crates/storagenode/    binary: identity, DRPC, check-in, exit, dashboard
```

## API

Protocol types and crypto come from `/Volumes/SSD/repos/storj/uplink-rs`. Path-depend on that workspace. Do not copy the crates, and do not add this node to the public `storj` client (`Access`, `Project`).

The public `storj` crate does not export identity, frames, or order bytes. The server calls the crates that do:

- `storj-proto` — piecestore and orders messages
- `storj-rpc` — identity (`generate`, `from_pem`, `server_config`, `hash_and_sign`) and the DRPC frame codec (`Conn`)
- `storj-uplink` — piecestore client plus order and piece-hash helpers (`encode_order_limit`, `verify_order_limit`, `verify_order`, `sign_piece_hash_node`, `verify_piece_hash_uplink`)

`storj-rpc` loads a PEM identity and builds a TLS server config. `Conn` reads and writes frames. It has no server dispatch. The accept loop lives in `storagenode`. Tests drive that server with `storj_uplink::piecestore::Client`.

## Not included

No filestore, hashstore, piece migration, or version updater. No on-chain payout transaction. No second piece backend. No hashstore 512-byte footer. The Go node is not modified, and this binary does not wrap it.

Exit is a CLI subcommand. The existing Vue dashboard has no exit control.

## Piece store (`s3store`)

One object per piece. Key: `{prefix}/{satellite-id}/{piece-id}`. Body is the raw chunk bytes from the uplink. User metadata on the object holds the piece hash, hash algorithm, created time, expiry, and the original order limit. `GET_REPAIR` reads that header back, which is the only download path that needs it (`endpoint.go` sends the hash and limit for repair, not for `GET` or `GET_AUDIT`). Metadata stays under S3's 2 KB user-metadata cap; an order limit is a few hundred bytes.

SQLite file `pieces.db` on the volume (`rusqlite`, bundled). WAL. It is a cache of that metadata plus trash flags and unsent orders. Row: satellite, piece id, size, piece hash, hash algorithm, order limit bytes, created_at, expires_at, trashed_at, state (`writing` | `live` | `trash`).

Commit order: insert `writing`, `PutObject` or complete multipart, then mark `live`. Cancel deletes the object and the row. A crash after the put and before `live` leaves an unreferenced object; the node will not serve it. A later upload of the same id overwrites the key.

Pieces under 5 MiB use one `PutObject` (a normal share is about 2 MiB). Larger pieces use multipart, 5 MiB parts, last part may be shorter. Client is `aws-sdk-s3`:

- Endpoint from config. Path-style when the host is not `amazonaws.com`. `path-style` overrides that.
- Checksum request and response validation `when_required`, so Ceph RGW does not reject the SDK's default CRC32 headers.
- Region defaults to `us-east-1`.
- Static access key and secret. The secret is not logged.

`Exists` sees `live` rows only. Trash is an index flag, not a second key. A chore deletes the S3 object once `trashed_at` is older than 7 days, and deletes rows past `expires_at`. `RestoreTrash` clears `trashed_at` for that satellite while the object is still there. A download of a trashed piece during that window still succeeds, puts that piece back to `live`, and reports restored-from-trash.

Space is not `statfs`. Configured allocation minus the sum of live sizes is the free space reported at check-in.

Startup calls `HeadBucket` and exits if the bucket is unreachable. If `pieces.db` is missing, startup lists the prefix and rebuilds live rows from object metadata. Trash flags are not on the object. After a rebuild every piece is live, and the next retain pass trashes what the bloom filter rejects. Unsent orders are not in the bucket. Losing them loses that hour's pay and does not lose pieces, which is the same as losing the Go node's orders directory.

## Transports

Port 28967, TCP and UDP. After the handshake, every transport uses the same DRPC dispatch. One RPC per connection.

TCP peeks 8 bytes:

- `DRPC!!!1` (`storj_rpc::DRPC_TLS_MUX_PREFIX`) — TLS with `storj_rpc::server_config`, node-id pinned.
- `DRPC!N!1` (`storj_rpc::noise::HEADER`) — the accept loop consumes those 8 bytes, then calls `NoiseStream::accept(io, protocol, private_key)`. The protocol number is not a following byte. Go picks one protocol for the process (`private/server/server.go` calls `noise.GenerateServerConf(noise.DefaultProto, …)`). `DefaultProto` is `NOISE_IK_25519_CHACHAPOLY_BLAKE2B` (1). Clients learn it from the check-in attestation, then dial that protocol. This node does the same: generate one X25519 key, store the 32-byte private key on the volume, accept protocol 1, attest protocol 1. Protocol 2 (`NOISE_IK_25519_AESGCM_BLAKE2B`) is already implemented in `storj-rpc`. A test constructs the server with protocol 2 and dials `NoiseStream::connect(io, 2, public_key)`. One handshake is one protocol. Trying the other cipher on the same bytes fails the handshake.
- Anything else is closed.

UDP is QUIC. `storj-rpc` dials QUIC and its tests build a server, but that server helper is private. This binary builds the listener itself: `server_config` plus ALPN `storj`, then `quinn`, matching `quic_server` in `storj-rpc`'s transport tests. The QUIC stream is a `Conn`.

## Protocol (`storagenode`)

Dispatch:

- `Upload` — verify the order limit (satellite signature, this node id, PUT or PUT_REPAIR, not expired), reject a replayed serial, verify each order signature, stream the body to S3, check the uplink piece hash (SHA-256 or BLAKE3), sign the hash with this identity, store the hash and the limit.
- `Download` — verify a GET or GET_REPAIR limit, range-GET the object, send the stored hash and limit on repair.
- `Exists` — index lookup. Present maps to `STORAGE_METHOD_PIECESTORE` (the wire value for "present"; the enum lives in `storj.io/common` and is not extended).
- `DeletePieces` — Unimplemented, as in the Go node ("delete pieces is no longer supported"). Deleted data is collected by `Retain`.
- `Retain` and `RetainBig` — walk this satellite's live rows created before the filter time and trash the ones the bloom filter rejects.
- `RestoreTrash` — clear trash flags for that satellite.

Trusted satellites come from config (node URL list). Order limits signed by anyone else are rejected. `storj_rpc::known_ids` covers the well-known public satellites when the operator lists those hostnames.

Check-in is how a satellite learns the node exists, so it is in this binary. `uplink-rs`'s vendored `node.proto` has no `CheckIn` RPC. Copy the `service Node` / `CheckIn` messages from `storj/common` at SHA `d38275a3768ba356144814f3ec5d62eeca670e49` (the pin in `uplink-rs/proto/README.md`) into this repo and generate prost here. Do not change the uplink pin. The loop dials each trusted satellite with `storj-rpc` and sends address, version, operator email and wallet, and capacity. No hashstore feature bits.

Identity: on first start, `Identity::generate()` and write the chain and key as PEM on the volume (`cert_chain` and `private_key` are already public). Difficulty defaults to 0. Public satellites reject a low-difficulty id; a private satellite does not. `STORJ_IDENTITY_DIFFICULTY` is left for later, not a grind inside the container start path.

## Getting paid

The node does not send a token transfer. The satellite counts settled bandwidth orders and Storj pays `STORJ_OPERATOR_WALLET`. That wallet is required: `0x` plus 40 hex characters, sent on every check-in as the operator wallet. An empty or non-address wallet is a startup error.

What has to be true before any payment shows up:

- The satellite accepts the node's identity and check-in. A difficulty-0 id is refused by the public satellites.
- The node keeps serving `Download` (audits) and applying retain. A disqualified node is not paid.
- Each upload and download saves the satellite-signed order limit and the final uplink-signed order (the one with the largest amount for that serial). Orders are grouped by satellite and by the hour of `OrderCreation`. A limit whose creation time is more than 1 hour from now is rejected, matching `OrderLimitGracePeriod`.
- Once an hour, plus a random delay up to 30 seconds, the node dials `Orders.SettlementWithWindow` for each closed hour. That RPC is already in `uplink-rs`'s `orders.proto`. The stream is one `SettlementRequest` per order, then close. `ACCEPTED` and `REJECTED` are both archived. A dial or RPC error leaves the hour unsent and retries next time. An untrusted satellite is archived without sending. A window with an upload or download still open is not sent yet.
- Sent orders stay in the archive for 7 days, then the row is deleted.

The satellite turns accepted orders into a monthly paystub and pays the wallet on its own schedule. New nodes have part of the amount held. This binary cannot change that.

So the payout page can show real numbers, a chore polls the satellite `HeldAmount` service (`GetPaystub`, `GetAllPaystubs`, payments) and `NodeStats.PricingModel`. Those messages are not in the vendored uplink protos. Copy them from `storj/common` at the same SHA as `CheckIn`. Store the stubs in sqlite. Estimated payout is pricing times this month's local usage. Until the first successful poll, the page shows zeros rather than an error.

## Graceful exit

Same behavior as the current Go worker (`storagenode/gracefulexit/worker.go`). The satellite moves the data. This node does not upload pieces to other nodes.

`TransferPiece` and `DeletePiece` are obsolete. The Go node returns an error for both ("piece-transfer-based graceful exit is no longer supported"). This binary does the same.

What the node does:

- `storagenode exit-satellite` records a pending exit for a trusted satellite, with the bytes currently live for it. `storagenode exit-status` prints that row.
- A chore dials `SatelliteGracefulExit.Process` for each pending satellite. Those messages are not in the vendored uplink protos. Copy them from `storj/common` at the same SHA as `CheckIn`.
- `NotReady` — retry on the next chore tick.
- Failed precondition — drop the pending row. Exit was refused.
- `ExitFailed` — store the reason and stop.
- `ExitCompleted` — store the receipt, then delete that satellite's keys and index rows (`s3store` delete-by-satellite).

Until `ExitCompleted`, the node keeps serving `Download` so the satellite can read the pieces with repair orders. Deleting earlier would fail the exit.

## Web dashboard

The existing storage-node UI, `storj/web/storagenode` (dashboard, notifications, payout). This process serves that app and the JSON it already requests. No second UI, and the Vue source is not copied into `storagenode-rs`.

The image build runs `npm ci && npm run build` in `storj/web/storagenode` and copies `dist/` to `/usr/share/storagenode/ui`. That tree is AGPL. The Rust source stays `MIT OR Apache-2.0`. The image contains both.

HTTP listen `0.0.0.0:14002` inside the container (the Go default is `127.0.0.1:14002`, which is unreachable from the host). There is no login. Publish the port to `127.0.0.1` on the host.

Routes match `storagenode/console/consoleserver/server.go`:

- `GET /api/sno/` — node id, wallet, version, start time, last check-in, QUIC ping status, configured port, disk, bandwidth, satellites. JSON field names match `console.Dashboard` (`nodeID`, `diskSpace`, `quicStatus`, …).
- `GET /api/sno/satellites` and `GET /api/sno/satellite/{id}` — per-satellite daily storage and bandwidth.
- `GET /api/sno/satellites/{id}/pricing` and `GET /api/sno/estimated-payout` — satellite pricing times this month's usage, or zeros before the first poll.
- `GET /api/notifications/list`, read endpoints — empty list, reads succeed.
- `/api/heldamount/...` — paystubs and payments stored from the `HeldAmount` poll. Empty until the satellite has a stub.
- Everything else under `/` serves `index.html`. `/static/` serves the built files.

Disk numbers come from the S3 index. JSON `diskSpace.used` is live bytes plus trash, so the Vue chart can subtract trash. `trash` is the trash sum. Overused and reclaimable are 0. Bandwidth is a sqlite daily counter updated on successful upload and download. Disqualified, suspended, and vetted times, and the audit scores, come from the `GetStats` poll. Until that poll succeeds, the times are null and the scores are 0. Check-in stores the last contact time and the QUIC bit. The vendored check-in response has no reputation fields. The keys are present so the Vue page does not throw.

## Container

`Dockerfile` in `storagenode-rs`. Build context is the parent directory so the image can see `uplink-rs` (path dependencies) and `storj/web/storagenode` (dashboard). Rust stage `rust:1.91.1-bookworm`. UI stage is the Node build already used by `storj/web/storagenode/Dockerfile`. Runtime is `debian:bookworm-slim` plus CA certificates. The image runs `storagenode`. One volume, mounted at `/var/lib/storj`, for the identity, `pieces.db`, and the bandwidth rollup. No piece disk.

Required environment: `STORJ_S3_ENDPOINT`, `STORJ_S3_BUCKET`, `STORJ_S3_ACCESS_KEY_ID`, `STORJ_S3_SECRET_ACCESS_KEY`, `STORJ_OPERATOR_EMAIL`, `STORJ_OPERATOR_WALLET`, `STORJ_CONTACT_EXTERNAL_ADDRESS`, `STORJ_SATELLITES` (comma-separated node URLs).

Optional: `STORJ_S3_REGION` (`us-east-1`), `STORJ_S3_PREFIX` (`pieces`), `STORJ_S3_PATH_STYLE` (auto), `STORJ_ALLOCATED_BYTES`.

Publish 28967/tcp, 28967/udp, and 14002/tcp.

## Tests

- `s3store` against an in-process `s3s` server (path-style, static keys): put, read range, cancel, overwrite, trash, retain, expiry, space.
- Upload and download through the DRPC server using `storj-uplink`'s piecestore client and a generated identity, with the same fake bucket. Repeat the dial over TLS, Noise (`NoiseStream::connect`), and QUIC (`storj_rpc` dial).
- `HeadBucket` failure exits the process.
- Graceful exit: a fake satellite stream that sends `ExitCompleted` deletes that satellite's objects and leaves other satellites' objects in place. `TransferPiece` returns the unsupported error.
- Settlement: two finished orders in one hour are sent on `SettlementWithWindow`, then archived. An open upload in that hour is not sent. A limit older than 1 hour is rejected at upload time.
- `GET /api/sno/` returns the index's used and trash bytes and the configured allocation. A missing UI directory returns a clear 404 for `/`, not a panic.
- Deleting `pieces.db` and restarting rebuilds a live row from the object's metadata, and a repair download returns that hash and order limit.
- No call to your real endpoint.

## Out of scope

- Sending the token transfer. The Go storagenode does not do this either. The satellite pays the wallet from settled orders. This node does not add an on-chain payout.
- Copying pieces off an existing disk node.
- The old piece-transfer graceful exit (`TransferPiece` / `DeletePiece`).
- Running Ceph in compose.
- Changes under `storj/`, `uplink/`, or `uplink-rs/`, other than path-depending on `uplink-rs`.

## Risks

- Losing `pieces.db` is not worse than the file node losing its piece disk. Hashstore keeps its index on that same disk, so a dead disk takes the pieces with it. Here the bytes, the hash, and the repair order limit are on the object, and startup rebuilds the index from them. Unsent orders still live only in sqlite, same as the Go orders directory. Losing the identity is fatal for both nodes: the id cannot be regenerated.
- Advertised free space is the configured allocation. A full bucket fails uploads; the node does not see the bucket quota.
- A difficulty-0 identity will not be accepted by the public satellites.
- A public satellite will not pay a difficulty-0 identity, a disqualified node, or a node that fails audits or retain. New nodes also have a portion of earnings held. The paystub, not this process, is the record of what is owed.
- Port 14002 has no authentication. Publishing it past localhost exposes the wallet address, node id, and usage.

