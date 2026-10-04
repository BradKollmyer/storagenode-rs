# storagenode-rs

A Rust storage node. Piece bytes live only in an S3 API (AWS S3 or Ceph RGW). The identity, a SQLite index, and unsent orders stay on a local volume.

The node speaks the storagenode piecestore protocol over TLS, Noise, and QUIC. It checks in with each trusted satellite, settles orders, applies retain bloom filters, and can exit one satellite. The existing Vue dashboard is served as JSON on port 14002. This repo does not contain the Vue source.

[PLAN.md](PLAN.md) is what the node does. [BUILD.md](BUILD.md) is the proto pin, DRPC paths, and the traps in the protocol.

Protocol types and crypto come from a sibling `uplink-rs` checkout (`storj-proto`, `storj-rpc`, `storj-uplink`). The Go node in `storj` is the behavior reference. Neither tree is modified.

License `MIT OR Apache-2.0` ([LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)). Edition 2024. Rust 1.91.1.

## Layout

```
crates/s3store/       S3 piece store and pieces.db
crates/storagenode/   storagenode binary
proto/                contact, tags, graceful exit, held amount, node stats
third_party/s3s/      s3s 0.12 with the crypto pins this MSRV can build
```

`crates/storagenode` path-depends on `../../../uplink-rs/crates/{storj-proto,storj-rpc,storj-uplink}`. Clone `uplink-rs` as a sibling of this repo before `cargo build`. `crates/s3store` does not.

## Build and test

```sh
cargo build --locked -p storagenode
cargo test --locked --workspace
```

Tests use an in-process S3 server and `127.0.0.1`. They do not call a real bucket or a public satellite.

The binary is `target/debug/storagenode`.

## Run

No arguments serves the node. It listens on `0.0.0.0:28967` (TCP and QUIC) and `0.0.0.0:14002` (dashboard HTTP, no login).

```sh
storagenode
storagenode exit-satellite <satellite-id>
storagenode exit-status
```

`exit-satellite` asks the satellite whether the node is old enough to exit, then records a pending exit for it and the bytes live for it. A refusal records nothing. Pieces stay until the satellite sends `ExitCompleted`. `exit-status` prints the stored rows.

The first start writes `{STORJ_VOLUME}/identity.pem` and `{STORJ_VOLUME}/noise.key`. The identity difficulty is 0. Public satellites refuse that id. Put each trusted satellite's certificate at `{STORJ_VOLUME}/satellites/{node-id}.pem` (leaf, then CA). The CA must hash to that node id.

`pieces.db` is in the same volume. Deleting it and restarting rebuilds live rows from object metadata. Unsent orders live only in that file.

Dashboard files are read from `/usr/share/storagenode/ui`. A missing directory returns 404 for `/`. The JSON routes still answer. `diskSpace.used` is live bytes plus trash.

## Environment

Required:

| Variable | Meaning |
|---|---|
| `STORJ_S3_ENDPOINT` | S3 API URL |
| `STORJ_S3_BUCKET` | Bucket name |
| `STORJ_S3_ACCESS_KEY_ID` | Access key |
| `STORJ_S3_SECRET_ACCESS_KEY` | Secret key |
| `STORJ_OPERATOR_EMAIL` | Operator email |
| `STORJ_OPERATOR_WALLET` | `0x` and 40 hex characters |
| `STORJ_CONTACT_EXTERNAL_ADDRESS` | Address sent at check-in |
| `STORJ_SATELLITES` | Comma-separated node URLs (`node-id@host:port`, or a known public hostname) |

Optional:

| Variable | Default |
|---|---|
| `STORJ_S3_REGION` | `us-east-1` |
| `STORJ_S3_PREFIX` | `pieces` |
| `STORJ_S3_PATH_STYLE` | path-style unless the host is `amazonaws.com` |
| `STORJ_ALLOCATED_BYTES` | `0`: no free space, uploads are refused |
| `STORJ_VOLUME` | `/var/lib/storj` |
| `STORJ_OPERATOR_WALLET_FEATURES` | empty; comma-separated |

`STORJ_S3_PATH_STYLE` is `true` or `false`. Unset keeps the default.

## Image

The build context is the parent of this repo, so the image can see `uplink-rs` and `storj/web/storagenode`.

```sh
docker build -f storagenode-rs/Dockerfile \
  --build-arg STORAGENODE_COMMIT=$(git -C storagenode-rs rev-parse HEAD) \
  --build-arg STORAGENODE_COMMIT_UNIX=$(git -C storagenode-rs log -1 --format=%ct) \
  .
```

The two build arguments are optional. They set the commit the node reports at check-in; the image build has no `.git` to read it from.

At check-in the node reports the Go storage node release it was checked against, `v1.164.1` (`GO_COMPATIBLE_VERSION` in `checkin.rs`), because a satellite's minimum version is a Go release number. A release build also reports `release`. The dashboard shows this crate's own version.

The Rust stage is `rust:1.91.1-bookworm`. The UI stage builds the Vue app and copies `dist/` to `/usr/share/storagenode/ui`. The runtime is `debian:bookworm-slim` with CA certificates. One volume, `/var/lib/storj`. The image publishes `28967/tcp`, `28967/udp`, and `14002/tcp`. Secrets and `STORJ_SATELLITES` are runtime configuration, not baked in. Publish 14002 to `127.0.0.1` on the host. There is no login.
