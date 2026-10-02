# storagenode-rs

A Rust storage node whose piece bytes live only in an S3 API (AWS S3 or Ceph RGW). Identity, a SQLite index, and unsent orders stay on a local volume.

This directory is the spec. No crate, Dockerfile, or git repo has been created yet.

- [PLAN.md](PLAN.md) — what to build.
- [BUILD.md](BUILD.md) — paths, proto pins, DRPC and Noise traps, dashboard JSON, and the build order. Read this before writing code.

Protocol types and crypto come from the sibling checkout [`storj-uplink`](../storj-uplink). The Go node in [`storj`](../storj) is the behavior reference and the source of the existing Vue dashboard. Neither tree is modified. Do not use [`/Volumes/SSD/repos/storj-rust`](/Volumes/SSD/repos/storj-rust).

The parent directory `/Volumes/SSD/repos/storj` is not a git repo. This project gets its own repo when the first code change lands.
