//! Generate check-in, graceful-exit, held-amount, and node-stats messages.
//!
//! `proto/` is searched before `uplink-rs/proto`, so this repo's
//! `contact.proto`, `nodetags.proto`, and `gracefulexit.proto` win.
//! `nodetags.proto` is package `node` and is compiled in the same `protoc`
//! run as `contact.proto`, which is what puts `SignedNodeTagSets` on the
//! local node types. `.node` is not externed: uplink's `storj_proto::node`
//! was generated from `node.proto` alone and has no tag sets. Piecestore
//! keeps using `storj_proto`. `gracefulexit.proto` imports orders and
//! metainfo; those packages stay on `storj_proto`. `heldamount.proto` and
//! `nodestats.proto` are not in the uplink pin.
//!
//! Also records the commit this binary is built from, for the version sent
//! at check-in: `STORAGENODE_COMMIT` and `STORAGENODE_COMMIT_UNIX`. Both come
//! from the environment when set (the image build has no `.git`), otherwise
//! from `git`, otherwise they are empty and 0.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() -> io::Result<()> {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").map_err(io::Error::other)?);
    let local = manifest.join("../../proto");
    let uplink = manifest.join("../../../uplink-rs/proto");
    if !local.join("contact.proto").is_file()
        || !local.join("nodetags.proto").is_file()
        || !local.join("gracefulexit.proto").is_file()
        || !local.join("heldamount.proto").is_file()
        || !local.join("nodestats.proto").is_file()
    {
        return Err(io::Error::other(format!(
            "missing vendored protos in {}",
            local.display()
        )));
    }
    if !uplink.join("node.proto").is_file() {
        return Err(io::Error::other(format!(
            "uplink-rs protos not found at {}",
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
        local.join("heldamount.proto").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        local.join("nodestats.proto").display()
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

    let (commit, commit_unix) = build_commit(&manifest);
    println!("cargo:rustc-env=STORAGENODE_COMMIT={commit}");
    println!("cargo:rustc-env=STORAGENODE_COMMIT_UNIX={commit_unix}");
    println!("cargo:rerun-if-env-changed=STORAGENODE_COMMIT");
    println!("cargo:rerun-if-env-changed=STORAGENODE_COMMIT_UNIX");
    // The reflog grows on every commit and checkout. A path that does not
    // exist would rerun this script on every build.
    let reflog = manifest.join("../../.git/logs/HEAD");
    if reflog.is_file() {
        println!("cargo:rerun-if-changed={}", reflog.display());
    }

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
            local.join("heldamount.proto"),
            local.join("nodestats.proto"),
        ],
        &[local, uplink, protoc_include],
    )?;
    Ok(())
}

/// Commit hash and its committer time in unix seconds.
fn build_commit(manifest: &Path) -> (String, u64) {
    let from_env = |key: &str| std::env::var(key).ok().filter(|value| !value.is_empty());
    if let Some(commit) = from_env("STORAGENODE_COMMIT") {
        let unix = from_env("STORAGENODE_COMMIT_UNIX")
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(0);
        return (commit.trim().to_owned(), unix);
    }
    let git = Command::new("git")
        .arg("-C")
        .arg(manifest)
        .args(["log", "-1", "--format=%H %ct"])
        .output();
    let Ok(output) = git else {
        return (String::new(), 0);
    };
    if !output.status.success() {
        return (String::new(), 0);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut parts = text.split_whitespace();
    let commit = parts.next().unwrap_or_default().to_owned();
    let unix = parts
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    (commit, unix)
}
