//! Generate check-in and graceful-exit messages from the vendored protos.
//!
//! `proto/` is searched before `storj-uplink/proto`, so this repo's
//! `contact.proto`, `nodetags.proto`, and `gracefulexit.proto` win.
//! `nodetags.proto` is package `node` and is compiled in the same `protoc`
//! run as `contact.proto`, which is what puts `SignedNodeTagSets` on the
//! local node types. `.node` is not externed: uplink's `storj_proto::node`
//! was generated from `node.proto` alone and has no tag sets. Piecestore
//! keeps using `storj_proto`. `gracefulexit.proto` imports orders and
//! metainfo; those packages stay on `storj_proto`.

use std::io;
use std::path::PathBuf;

fn main() -> io::Result<()> {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").map_err(io::Error::other)?);
    let local = manifest.join("../../proto");
    let uplink = manifest.join("../../../storj-uplink/proto");
    if !local.join("contact.proto").is_file()
        || !local.join("nodetags.proto").is_file()
        || !local.join("gracefulexit.proto").is_file()
    {
        return Err(io::Error::other(format!(
            "missing vendored protos in {}",
            local.display()
        )));
    }
    if !uplink.join("node.proto").is_file() {
        return Err(io::Error::other(format!(
            "storj-uplink protos not found at {}",
            uplink.display()
        )));
    }
    println!(
        "cargo:rerun-if-changed={}",
        local.join("contact.proto").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        local.join("nodetags.proto").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        local.join("gracefulexit.proto").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        uplink.join("node.proto").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        uplink.join("orders.proto").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        uplink.join("metainfo.proto").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        uplink.join("noise.proto").display()
    );

    let protoc = protoc_bin_vendored::protoc_bin_path().map_err(io::Error::other)?;
    let protoc_include = protoc_bin_vendored::include_path().map_err(io::Error::other)?;
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc);
    // Later protos import orders and metainfo. Extern them now so those
    // packages stay on storj_proto instead of being generated again.
    config.extern_path(".orders", "::storj_proto::orders");
    config.extern_path(".metainfo", "::storj_proto::metainfo");
    config.extern_path(".noise", "::storj_proto::noise");
    config.compile_protos(
        &[
            local.join("contact.proto"),
            local.join("nodetags.proto"),
            local.join("gracefulexit.proto"),
        ],
        &[local, uplink, protoc_include],
    )?;
    Ok(())
}
