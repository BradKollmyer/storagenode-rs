//! HTTP dashboard on `0.0.0.0:14002`.
//!
//! Serves the JSON the existing Vue app requests and, when the image has
//! filled it, the built files under [`UI_DIR`]. There is no login. Disk
//! totals come from the piece index. Bandwidth is the sqlite daily counter.
//! Reputation times stay null until a stats poll stores them.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use s3store::{BandwidthDay, CheckInRow};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use crate::config::{self, Config};
use crate::server::Node;

/// Go's zero `time.Time` on the wire. Vue accepts it and treats the node as offline.
const ZERO_TIME: &str = "0001-01-01T00:00:00Z";

/// Built Vue files. The image copies `dist/` here. A missing directory is a 404.
pub(crate) const UI_DIR: &str = "/usr/share/storagenode/ui";

const NOTIFICATIONS_LIST: &str = concat!(
    r#"{ "page": { "notifications": [], "pageCount": 0 }, "unreadCount": 0, "totalCount": 0 }"#,
);

/// JSON and static files for one running node.
pub(crate) struct Dashboard {
    node: Arc<Node>,
    wallet: String,
    wallet_features: Vec<String>,
    started_at: SystemTime,
    ui_dir: PathBuf,
}

struct Reply {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

impl Dashboard {
    /// Dashboard for `config`, serving [`UI_DIR`].
    pub(crate) fn new(node: Arc<Node>, config: &Config) -> Self {
        Self {
            node,
            wallet: config.operator_wallet.clone(),
            wallet_features: config.wallet_features.clone(),
            started_at: SystemTime::now(),
            ui_dir: PathBuf::from(UI_DIR),
        }
    }

    /// Points the UI at `ui_dir` so a test does not need the image directory.
    #[cfg(test)]
    pub(crate) fn for_test(node: Arc<Node>, ui_dir: impl Into<PathBuf>) -> Self {
        Self {
            node,
            wallet: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            wallet_features: vec!["zksync-era".to_owned()],
            started_at: UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
            ui_dir: ui_dir.into(),
        }
    }

    /// Serves until `listener` fails. One connection is one request.
    pub(crate) async fn serve(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
        loop {
            let (socket, _) = listener.accept().await?;
            let dashboard = Arc::clone(&self);
            let service = service_fn(move |request: Request<Incoming>| {
                let dashboard = Arc::clone(&dashboard);
                async move {
                    let target = request
                        .uri()
                        .path_and_query()
                        .map(|part| part.as_str())
                        .unwrap_or("/");
                    let reply = dashboard.dispatch(request.method().as_str(), target).await;
                    Ok::<_, std::convert::Infallible>(into_response(reply))
                }
            });
            let connection =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(hyper_util::rt::TokioIo::new(socket), service)
                    .into_owned();
            tokio::spawn(async move {
                if let Err(err) = connection.await {
                    eprintln!("storagenode: dashboard connection: {err}");
                }
            });
        }
    }

    /// Handles one request without binding a port.
    #[cfg(test)]
    pub(crate) async fn handle(&self, method: &str, target: &str) -> (u16, Vec<u8>) {
        let reply = self.dispatch(method, target).await;
        (reply.status, reply.body)
    }

    async fn dispatch(&self, method: &str, target: &str) -> Reply {
        let method = method.to_ascii_uppercase();
        let (path, _) = split_target(target);
        let Some(path) = normalize_path(path) else {
            return text(404, "not found");
        };
        if let Some(rest) = path.strip_prefix("/static/") {
            if method != "GET" {
                return text(405, "method not allowed");
            }
            return self.static_file(rest).await;
        }
        if path == "/static" {
            return text(404, "not found");
        }
        if let Some(reply) = self.api(&method, &path) {
            return reply;
        }
        if path.starts_with("/api/") {
            return text(404, "not found");
        }
        if method != "GET" {
            return text(405, "method not allowed");
        }
        self.index_html().await
    }

    fn api(&self, method: &str, path: &str) -> Option<Reply> {
        let parts: Vec<&str> = path.split('/').skip(1).collect();
        let (get, reply) = match parts.as_slice() {
            ["api", "sno"] => (true, self.sno()),
            ["api", "sno", "satellites"] => (true, self.satellites_all()),
            ["api", "sno", "satellite", id] => (true, self.satellite(id)),
            ["api", "sno", "satellites", id, "pricing"] => (true, pricing(id)),
            ["api", "sno", "estimated-payout"] => (true, estimated_payout()),
            ["api", "notifications", "list"] => (true, notifications_list()),
            ["api", "notifications", "readall"] => (false, empty_object()),
            ["api", "notifications", _, "read"] => (false, empty_object()),
            ["api", "heldamount", "paystubs", _] => (true, empty_array()),
            ["api", "heldamount", "paystubs", _, _] => (true, empty_array()),
            ["api", "heldamount", "held-history"] => (true, empty_array()),
            ["api", "heldamount", "periods"] => (true, empty_array()),
            ["api", "heldamount", "payout-history", _] => (true, empty_array()),
            ["api", "sno", ..] | ["api", "notifications", ..] | ["api", "heldamount", ..] => {
                return Some(text(404, "not found"));
            }
            _ => return None,
        };
        let allowed = if get {
            method == "GET"
        } else {
            method == "POST"
        };
        if allowed {
            Some(reply)
        } else {
            Some(text(405, "method not allowed"))
        }
    }

    fn sno(&self) -> Reply {
        let store = self.node.piece_store();
        let space = match store.space() {
            Ok(space) => space,
            Err(err) => return json_error(&err),
        };
        let now = SystemTime::now();
        let bandwidth = match store.bandwidth_days(None, now) {
            Ok(days) => days,
            Err(err) => return json_error(&err),
        };
        let check_ins = match store.check_ins() {
            Ok(rows) => rows,
            Err(err) => return json_error(&err),
        };
        let used = bandwidth
            .iter()
            .fold(0u64, |sum, day| sum.saturating_add(day.total()));
        let (last_ping, quic_status, last_quic) = quic_summary(&check_ins);
        let satellites = self
            .trusted()
            .into_iter()
            .map(|(id, url)| {
                json!({
                    "id": id,
                    "url": url,
                    "disqualified": Value::Null,
                    "suspended": Value::Null,
                    "vettedAt": Value::Null,
                })
            })
            .collect::<Vec<_>>();
        // Vue draws `used - trash` as the live slice and free as `allocated - used`.
        let disk_used = space.used.saturating_add(space.trash);
        json_ok(json!({
            "nodeID": self.node.node_id().to_string(),
            "wallet": self.wallet,
            "walletFeatures": self.wallet_features,
            "satellites": satellites,
            "diskSpace": {
                "used": disk_used,
                "available": space.allocated.saturating_sub(disk_used),
                "overused": 0,
                "allocated": space.allocated,
                "trash": space.trash,
                "reclaimable": 0,
                "reserved": 0,
            },
            "bandwidth": {
                "used": used,
                "available": 0,
            },
            "lastPinged": time_value(last_ping),
            "startedAt": time_value(Some(self.started_at)),
            "version": env!("CARGO_PKG_VERSION"),
            "allowedVersion": env!("CARGO_PKG_VERSION"),
            "upToDate": true,
            "quicStatus": quic_status,
            "configuredPort": config::LISTEN_PORT.to_string(),
            "lastQuicPingedAt": time_value(last_quic),
        }))
    }

    fn satellites_all(&self) -> Reply {
        let now = SystemTime::now();
        let store = self.node.piece_store();
        let days = match store.bandwidth_days(None, now) {
            Ok(days) => days,
            Err(err) => return json_error(&err),
        };
        let live = match store.live_bytes(None) {
            Ok(live) => live,
            Err(err) => return json_error(&err),
        };
        let trusted = self.trusted();
        let audits = trusted
            .iter()
            .map(|(_, url)| audit_json(url))
            .collect::<Vec<_>>();
        json_ok(json!({
            "storageDaily": storage_daily(live, now),
            "bandwidthDaily": bandwidth_daily(&days),
            "storageSummary": live,
            "averageUsageBytes": live,
            "bandwidthSummary": days.iter().fold(0u64, |sum, day| sum.saturating_add(day.total())),
            "egressSummary": days.iter().fold(0u64, |sum, day| sum.saturating_add(day.egress())),
            "ingressSummary": days.iter().fold(0u64, |sum, day| sum.saturating_add(day.ingress())),
            "earliestJoinedAt": ZERO_TIME,
            "audits": audits,
        }))
    }

    fn satellite(&self, id: &str) -> Reply {
        let now = SystemTime::now();
        let store = self.node.piece_store();
        let days = match store.bandwidth_days(Some(id), now) {
            Ok(days) => days,
            Err(err) => return json_error(&err),
        };
        let live = match store.live_bytes(Some(id)) {
            Ok(live) => live,
            Err(err) => return json_error(&err),
        };
        let name = self
            .trusted()
            .into_iter()
            .find(|(sat, _)| sat == id)
            .map(|(_, url)| url)
            .unwrap_or_default();
        json_ok(json!({
            "id": id,
            "storageDaily": storage_daily(live, now),
            "bandwidthDaily": bandwidth_daily(&days),
            "storageSummary": live,
            "averageUsageBytes": live,
            "bandwidthSummary": days.iter().fold(0u64, |sum, day| sum.saturating_add(day.total())),
            "egressSummary": days.iter().fold(0u64, |sum, day| sum.saturating_add(day.egress())),
            "ingressSummary": days.iter().fold(0u64, |sum, day| sum.saturating_add(day.ingress())),
            "audits": audit_json(&name),
            "nodeJoinedAt": ZERO_TIME,
        }))
    }

    fn trusted(&self) -> Vec<(String, String)> {
        let mut rows: Vec<_> = self
            .node
            .contact_targets()
            .into_iter()
            .map(|(id, address)| (id.to_string(), address))
            .collect();
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        rows
    }

    async fn index_html(&self) -> Reply {
        let path = self.ui_dir.join("index.html");
        if !file_stays_under(&self.ui_dir, &path) {
            return text(404, "not found");
        }
        match tokio::fs::read(&path).await {
            Ok(body) => Reply {
                status: 200,
                content_type: "text/html; charset=utf-8",
                body,
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => text(
                404,
                format!("dashboard UI is not installed at {}", self.ui_dir.display()),
            ),
            Err(err) => text(500, format!("dashboard UI: {err}")),
        }
    }

    async fn static_file(&self, rel: &str) -> Reply {
        if rel.is_empty()
            || rel
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return text(404, "not found");
        }
        let path = self.ui_dir.join(rel);
        if !file_stays_under(&self.ui_dir, &path) {
            return text(404, "not found");
        }
        match tokio::fs::read(&path).await {
            Ok(body) => Reply {
                status: 200,
                content_type: content_type(rel),
                body,
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => text(404, "not found"),
            Err(err) => text(500, format!("dashboard UI: {err}")),
        }
    }
}

/// Binds the dashboard. The binary calls this before it serves DRPC.
pub(crate) async fn listen() -> std::io::Result<(TcpListener, SocketAddr)> {
    let addr = SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, config::DASHBOARD_PORT));
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    Ok((listener, local))
}

fn quic_summary(rows: &[CheckInRow]) -> (Option<SystemTime>, &'static str, Option<SystemTime>) {
    let Some(latest) = rows.iter().max_by_key(|row| row.checked_in_at) else {
        return (None, "", None);
    };
    let status = if latest.quic_ok {
        "OK"
    } else {
        "Misconfigured"
    };
    (
        Some(latest.checked_in_at),
        status,
        Some(latest.checked_in_at),
    )
}

fn bandwidth_daily(days: &[BandwidthDay]) -> Value {
    days.iter()
        .map(|day| {
            json!({
                "egress": {
                    "audit": day.get_audit,
                    "repair": day.get_repair,
                    "usage": day.get,
                },
                "ingress": {
                    "repair": day.put_repair,
                    "usage": day.put,
                },
                "delete": 0,
                "intervalStart": format_unix_millis(day.day_millis),
            })
        })
        .collect()
}

fn storage_daily(live: u64, now: SystemTime) -> Value {
    if live == 0 {
        return json!([]);
    }
    json!([{
        "atRestTotal": live,
        "atRestTotalBytes": live,
        "intervalStart": utc_day_start(now),
        "calculated": true,
    }])
}

fn audit_json(name: &str) -> Value {
    json!({
        "satelliteName": name,
        "auditScore": 0,
        "suspensionScore": 0,
        "onlineScore": 0,
    })
}

fn notifications_list() -> Reply {
    Reply {
        status: 200,
        content_type: "application/json",
        body: NOTIFICATIONS_LIST.as_bytes().to_vec(),
    }
}

fn pricing(id: &str) -> Reply {
    json_ok(json!({
        "satelliteID": id,
        "egressBandwidth": 0,
        "repairBandwidth": 0,
        "auditBandwidth": 0,
        "diskSpace": 0,
    }))
}

fn estimated_payout() -> Reply {
    let month = json!({
        "egressBandwidth": 0,
        "egressBandwidthPayout": 0,
        "egressRepairAudit": 0,
        "egressRepairAuditPayout": 0,
        "diskSpace": 0,
        "diskSpacePayout": 0,
        "heldRate": 0,
        "payout": 0,
        "held": 0,
    });
    json_ok(json!({
        "currentMonth": month.clone(),
        "previousMonth": month,
        "currentMonthExpectations": 0,
    }))
}

fn empty_array() -> Reply {
    json_ok(json!([]))
}

fn empty_object() -> Reply {
    json_ok(json!({}))
}

fn json_ok(value: Value) -> Reply {
    json_status(200, value)
}

fn json_error(err: &impl std::fmt::Display) -> Reply {
    json_status(500, json!({ "error": err.to_string() }))
}

fn json_status(status: u16, value: Value) -> Reply {
    let body = serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec());
    Reply {
        status,
        content_type: "application/json",
        body,
    }
}

fn text(status: u16, message: impl Into<String>) -> Reply {
    Reply {
        status,
        content_type: "text/plain; charset=utf-8",
        body: message.into().into_bytes(),
    }
}

fn into_response(reply: Reply) -> Response<Full<Bytes>> {
    match Response::builder()
        .status(reply.status)
        .header(http::header::CONTENT_TYPE, reply.content_type)
        .header("x-content-type-options", "nosniff")
        .body(Full::new(Bytes::from(reply.body)))
    {
        Ok(response) => response,
        Err(_) => Response::new(Full::new(Bytes::from_static(b"internal error"))),
    }
}

fn split_target(target: &str) -> (&str, &str) {
    let target = target.split('#').next().unwrap_or(target);
    target.split_once('?').unwrap_or((target, ""))
}

fn normalize_path(path: &str) -> Option<String> {
    let decoded = percent_decode(path)?;
    if !decoded.starts_with('/') || decoded.contains('\0') {
        return None;
    }
    let mut parts = Vec::new();
    for part in decoded.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return None;
        }
        parts.push(part);
    }
    if parts.is_empty() {
        Some("/".to_owned())
    } else {
        Some(format!("/{}", parts.join("/")))
    }
}

fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(out).ok()
}

/// A symlink that resolves outside `root` is not served. A missing file is a later 404.
fn file_stays_under(root: &Path, candidate: &Path) -> bool {
    if candidate
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return false;
    }
    let Ok(root) = root.canonicalize() else {
        return true;
    };
    match candidate.canonicalize() {
        Ok(file) => file.starts_with(root),
        Err(_) => true,
    }
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        _ => "application/octet-stream",
    }
}

fn time_value(time: Option<SystemTime>) -> Value {
    Value::String(match time {
        Some(time) => format_rfc3339(time),
        None => ZERO_TIME.to_owned(),
    })
}

fn format_unix_millis(millis: i64) -> String {
    let Ok(millis) = u64::try_from(millis) else {
        return ZERO_TIME.to_owned();
    };
    match UNIX_EPOCH.checked_add(Duration::from_millis(millis)) {
        Some(time) => format_rfc3339(time),
        None => ZERO_TIME.to_owned(),
    }
}

/// UTC midnight of `time`, as RFC3339. The daily stamp uses that boundary.
fn utc_day_start(time: SystemTime) -> String {
    let Ok(elapsed) = time.duration_since(UNIX_EPOCH) else {
        return ZERO_TIME.to_owned();
    };
    let Ok(nanos) = i128::try_from(elapsed.as_nanos()) else {
        return ZERO_TIME.to_owned();
    };
    let Ok(dt) = time::OffsetDateTime::from_unix_timestamp_nanos(nanos) else {
        return ZERO_TIME.to_owned();
    };
    dt.date()
        .midnight()
        .assume_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| ZERO_TIME.to_owned())
}

fn format_rfc3339(time: SystemTime) -> String {
    let Ok(elapsed) = time.duration_since(UNIX_EPOCH) else {
        return ZERO_TIME.to_owned();
    };
    let Ok(nanos) = i128::try_from(elapsed.as_nanos()) else {
        return ZERO_TIME.to_owned();
    };
    let Ok(dt) = time::OffsetDateTime::from_unix_timestamp_nanos(nanos) else {
        return ZERO_TIME.to_owned();
    };
    dt.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| ZERO_TIME.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_formats_a_known_utc_instant() {
        let time = UNIX_EPOCH + Duration::from_secs(1_791_039_845);
        assert_eq!(format_rfc3339(time), "2026-10-03T15:04:05Z");
        assert_eq!(
            format_unix_millis(1_790_985_600_000),
            "2026-10-03T00:00:00Z"
        );
        assert_eq!(utc_day_start(time), "2026-10-03T00:00:00Z");
    }

    #[test]
    fn notifications_list_matches_the_vue_page() {
        assert_eq!(
            NOTIFICATIONS_LIST,
            r#"{ "page": { "notifications": [], "pageCount": 0 }, "unreadCount": 0, "totalCount": 0 }"#
        );
    }
}
