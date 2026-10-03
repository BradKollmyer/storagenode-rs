# storagenode-rs

A Rust storage node whose piece bytes live only in an S3 API (AWS S3 or Ceph RGW). Identity, a SQLite index, and unsent orders stay on a local volume.

- [PLAN.md](PLAN.md) — what this node does.
- [BUILD.md](BUILD.md) — paths, proto pins, DRPC and Noise traps, dashboard JSON, and the build order.

Protocol types and crypto come from a sibling `storj-uplink` checkout (`storj-proto`, `storj-rpc`, `storj-uplink`). The Go node in `storj` is the behavior reference and the source of the existing Vue dashboard. Neither tree is modified.
