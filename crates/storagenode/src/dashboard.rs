//! HTTP dashboard on `0.0.0.0:14002`.
//!
//! Serves the JSON the existing Vue app requests and, when the image has
//! filled it, the built files under [`UI_DIR`]. There is no login. Disk
//! totals come from the piece index. Bandwidth is the sqlite daily counter.
//! Reputation times stay null until a stats poll stores them.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use s3store::{BandwidthDay, CheckInRow, ExitStatus, PayStubRow, SatelliteStats};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use crate::config::{self, Config};
use crate::payout::{self, MonthPayout, Prices, UsageBytes};
use crate::server::Node;

/// Go's zero `time.Time` on the wire. Vue accepts it and treats the node as offline.
const ZERO_TIME: &str = "0001-01-01T00:00:00Z";

/// Built Vue files. The image copies `dist/` here. A missing directory is a 404.
pub(crate) const UI_DIR: &str = "/usr/share/storagenode/ui";

const NOTIFICATIONS_LIST: &str =
    r#"{ "page": { "notifications": [], "pageCount": 0 }, "unreadCount": 0, "totalCount": 0 }"#;

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
        let (path, query) = split_target(target);
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
        if let Some(reply) = self.api(&method, &path, query) {
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

    fn api(&self, method: &str, path: &str, query: &str) -> Option<Reply> {
        let parts: Vec<&str> = path.split('/').skip(1).collect();
        let (get, reply) = match parts.as_slice() {
            ["api", "sno"] => (true, self.sno()),
            ["api", "sno", "satellites"] => (true, self.satellites_all()),
            ["api", "sno", "satellite", id] => (true, self.satellite(id)),
            ["api", "sno", "satellites", id, "pricing"] => (true, self.pricing(id)),
            ["api", "sno", "estimated-payout"] => (true, self.estimated_payout(query)),
            ["api", "notifications", "list"] => (true, notifications_list()),
            ["api", "notifications", "readall"] => (false, empty_object()),
            ["api", "notifications", _, "read"] => (false, empty_object()),
            ["api", "heldamount", "paystubs", period] => (true, self.paystubs_one(period, query)),
            ["api", "heldamount", "paystubs", start, end] => {
                (true, self.paystubs_range(start, end, query))
            }
            ["api", "heldamount", "held-history"] => (true, self.held_history()),
            ["api", "heldamount", "periods"] => (true, self.periods(query)),
            ["api", "heldamount", "payout-history", period] => (true, self.payout_history(period)),
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
        let stats = match self.stats_by_id() {
            Ok(stats) => stats,
            Err(reply) => return reply,
        };
        let used = bandwidth
            .iter()
            .fold(0u64, |sum, day| sum.saturating_add(day.total()));
        let (last_ping, quic_status, last_quic) = quic_summary(&check_ins);
        let satellites = self
            .trusted()
            .into_iter()
            .map(|(id, url)| {
                let row = stats.get(&id);
                json!({
                    "id": id,
                    "url": url,
                    "disqualified": opt_time_json(row.and_then(|row| row.disqualified_at)),
                    "suspended": opt_time_json(row.and_then(|row| row.suspended_at)),
                    "vettedAt": opt_time_json(row.and_then(|row| row.vetted_at)),
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
        let stats = match self.stats_by_id() {
            Ok(stats) => stats,
            Err(reply) => return reply,
        };
        let trusted = self.trusted();
        let audits = trusted
            .iter()
            .map(|(id, url)| audit_json(url, stats.get(id)))
            .collect::<Vec<_>>();
        json_ok(json!({
            "storageDaily": storage_daily(live, now),
            "bandwidthDaily": bandwidth_daily(&days),
            "storageSummary": live,
            "averageUsageBytes": live,
            "bandwidthSummary": days.iter().fold(0u64, |sum, day| sum.saturating_add(day.total())),
            "egressSummary": days.iter().fold(0u64, |sum, day| sum.saturating_add(day.egress())),
            "ingressSummary": days.iter().fold(0u64, |sum, day| sum.saturating_add(day.ingress())),
            "earliestJoinedAt": earliest_joined(&trusted, &stats),
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
        let stats = match self.stats_by_id() {
            Ok(stats) => stats,
            Err(reply) => return reply,
        };
        let row = stats.get(id);
        let name = self
            .trusted()
            .into_iter()
            .find(|(sat, _)| sat == id)
            .map(|(_, url)| url)
            .unwrap_or_default();
        let joined = match row.and_then(|row| row.joined_at) {
            Some(time) => format_rfc3339(time),
            None => ZERO_TIME.to_owned(),
        };
        json_ok(json!({
            "id": id,
            "storageDaily": storage_daily(live, now),
            "bandwidthDaily": bandwidth_daily(&days),
            "storageSummary": live,
            "averageUsageBytes": live,
            "bandwidthSummary": days.iter().fold(0u64, |sum, day| sum.saturating_add(day.total())),
            "egressSummary": days.iter().fold(0u64, |sum, day| sum.saturating_add(day.egress())),
            "ingressSummary": days.iter().fold(0u64, |sum, day| sum.saturating_add(day.ingress())),
            "audits": audit_json(&name, row),
            "nodeJoinedAt": joined,
        }))
    }

    fn pricing(&self, id: &str) -> Reply {
        let row = match self.node.piece_store().pricing(id) {
            Ok(row) => row,
            Err(err) => return json_error(&err),
        };
        let (egress, repair, audit, disk) = match row {
            Some(row) => (
                row.egress_bandwidth,
                row.repair_bandwidth,
                row.audit_bandwidth,
                row.disk_space,
            ),
            None => (0, 0, 0, 0),
        };
        json_ok(json!({
            "satelliteID": id,
            "egressBandwidth": egress,
            "repairBandwidth": repair,
            "auditBandwidth": audit,
            "diskSpace": disk,
        }))
    }

    fn estimated_payout(&self, query: &str) -> Reply {
        let now = SystemTime::now();
        let stats = match self.stats_by_id() {
            Ok(stats) => stats,
            Err(reply) => return reply,
        };
        let Some(id) = query_param(query, "id") else {
            return self.estimated_payout_all(&stats, now);
        };
        if stats.get(&id).and_then(|row| row.disqualified_at).is_some() {
            return zero_estimated_payout();
        }
        let prices = match self.node.piece_store().pricing(&id) {
            Ok(Some(prices)) => prices,
            Ok(None) => return zero_estimated_payout(),
            Err(err) => return json_error(&err),
        };
        let joined = stats.get(&id).and_then(|row| row.joined_at);
        match self.price_satellite(&id, prices_of(prices), joined, now) {
            Ok((current, previous, expectations)) => payout_json(current, previous, expectations),
            Err(reply) => reply,
        }
    }

    fn estimated_payout_all(
        &self,
        stats: &HashMap<String, SatelliteStats>,
        now: SystemTime,
    ) -> Reply {
        let mut current = MonthPayout::default();
        let mut previous = MonthPayout::default();
        let mut expectations = 0i64;
        let mut priced = false;
        for (id, _) in self.trusted() {
            if stats.get(&id).and_then(|row| row.disqualified_at).is_some() {
                continue;
            }
            let prices = match self.node.piece_store().pricing(&id) {
                Ok(Some(prices)) => prices,
                Ok(None) => continue,
                Err(err) => return json_error(&err),
            };
            priced = true;
            let joined = stats.get(&id).and_then(|row| row.joined_at);
            let (one_current, one_previous, one_expectations) =
                match self.price_satellite(&id, prices_of(prices), joined, now) {
                    Ok(priced) => priced,
                    Err(reply) => return reply,
                };
            current.add(one_current);
            previous.add(one_previous);
            expectations = expectations.saturating_add(one_expectations);
        }
        if !priced {
            return zero_estimated_payout();
        }
        // `MonthPayout::add` leaves held_rate at 0. Go's all-satellite sum does the same.
        payout_json(current, previous, expectations)
    }

    fn price_satellite(
        &self,
        id: &str,
        prices: Prices,
        joined: Option<SystemTime>,
        now: SystemTime,
    ) -> Result<(MonthPayout, MonthPayout, i64), Reply> {
        let store = self.node.piece_store();
        let current_days = store
            .bandwidth_days(Some(id), now)
            .map_err(|err| json_error(&err))?;
        let previous = payout::previous_month(now);
        let previous_days = store
            .bandwidth_days(Some(id), previous)
            .map_err(|err| json_error(&err))?;
        let disk = store.live_bytes(Some(id)).map_err(|err| json_error(&err))?;
        // No join time yet: price as if the node joined this moment (held rate 75).
        let joined_for_rate = joined.unwrap_or(now);
        let current = payout::price_month(
            usage_of(&current_days, disk),
            prices,
            payout::held_rate(joined_for_rate, now),
        );
        // No hourly disk history. Previous month is bandwidth only.
        let previous_payout = payout::price_month(
            usage_of(&previous_days, 0),
            prices,
            payout::held_rate(joined_for_rate, previous),
        );
        let expectations = payout::month_expectations(current.payout, now, joined);
        Ok((current, previous_payout, expectations))
    }

    fn paystubs_one(&self, period: &str, query: &str) -> Reply {
        let period = canon_period(period).unwrap_or_else(|| period.to_owned());
        self.paystubs_filtered(|row| row.period == period, query)
    }

    fn paystubs_range(&self, start: &str, end: &str, query: &str) -> Reply {
        let months = match months_between_periods(start, end) {
            Ok(months) => months,
            Err(err) => return json_status(400, json!({ "error": err })),
        };
        self.paystubs_filtered(|row| months.iter().any(|month| month == &row.period), query)
    }

    fn paystubs_filtered(&self, keep: impl Fn(&PayStubRow) -> bool, query: &str) -> Reply {
        let id = query_param(query, "id");
        let stubs = match self.node.piece_store().paystubs() {
            Ok(stubs) => stubs,
            Err(err) => return json_error(&err),
        };
        let mut rows: Vec<_> = stubs
            .into_iter()
            .filter(|row| id.as_ref().is_none_or(|id| row.satellite_id == *id))
            .filter(|row| keep(row))
            .collect();
        rows.sort_by(|left, right| {
            left.period
                .cmp(&right.period)
                .then_with(|| left.satellite_id.cmp(&right.satellite_id))
        });
        json_ok(json!(rows.iter().map(paystub_json).collect::<Vec<_>>()))
    }

    fn periods(&self, query: &str) -> Reply {
        let id = query_param(query, "id");
        let stubs = match self.node.piece_store().paystubs() {
            Ok(stubs) => stubs,
            Err(err) => return json_error(&err),
        };
        let mut periods: Vec<String> = stubs
            .into_iter()
            .filter(|row| id.as_ref().is_none_or(|id| row.satellite_id == *id))
            .map(|row| row.period)
            .collect();
        periods.sort();
        periods.dedup();
        json_ok(json!(periods))
    }

    fn payout_history(&self, period: &str) -> Reply {
        let period = canon_period(period).unwrap_or_else(|| period.to_owned());
        let stubs = match self.node.piece_store().paystubs() {
            Ok(stubs) => stubs,
            Err(err) => return json_error(&err),
        };
        let payments = match self.node.piece_store().payments() {
            Ok(payments) => payments,
            Err(err) => return json_error(&err),
        };
        let exits = match self.node.piece_store().exit_rows() {
            Ok(exits) => exits,
            Err(err) => return json_error(&err),
        };
        let stats = match self.stats_by_id() {
            Ok(stats) => stats,
            Err(reply) => return reply,
        };
        let trusted = self.trusted();
        let mut rows: Vec<_> = stubs
            .into_iter()
            .filter(|row| row.period == period)
            .collect();
        rows.sort_by(|left, right| left.satellite_id.cmp(&right.satellite_id));
        let now = SystemTime::now();
        let history = rows
            .iter()
            .map(|stub| {
                let receipt = payments
                    .iter()
                    .find(|payment| {
                        payment.satellite_id == stub.satellite_id && payment.period == stub.period
                    })
                    .map(|payment| payment.receipt.as_str())
                    .unwrap_or("");
                let url = trusted
                    .iter()
                    .find(|(id, _)| id == &stub.satellite_id)
                    .map(|(_, url)| url.as_str())
                    .filter(|url| !url.is_empty())
                    .unwrap_or(stub.satellite_id.as_str());
                let exit_complete = exits.iter().any(|row| {
                    row.satellite_id == stub.satellite_id && row.status == ExitStatus::Completed
                });
                payout_history_json(
                    stub,
                    url,
                    receipt,
                    exit_complete,
                    stats.get(&stub.satellite_id).and_then(|row| row.joined_at),
                    now,
                )
            })
            .collect::<Vec<_>>();
        json_ok(json!(history))
    }

    fn held_history(&self) -> Reply {
        let stubs = match self.node.piece_store().paystubs() {
            Ok(stubs) => stubs,
            Err(err) => return json_error(&err),
        };
        let stats = match self.stats_by_id() {
            Ok(stats) => stats,
            Err(reply) => return reply,
        };
        let trusted = self.trusted();
        let mut by_satellite: BTreeMap<String, Vec<PayStubRow>> = BTreeMap::new();
        for stub in stubs {
            by_satellite
                .entry(stub.satellite_id.clone())
                .or_default()
                .push(stub);
        }
        let history = by_satellite
            .iter()
            .map(|(id, rows)| {
                let name = trusted
                    .iter()
                    .find(|(sat, _)| sat == id)
                    .map(|(_, url)| url.as_str())
                    .filter(|url| !url.is_empty())
                    .unwrap_or(id.as_str());
                let joined = stats.get(id).and_then(|row| row.joined_at);
                held_history_json(id, name, rows, joined)
            })
            .collect::<Vec<_>>();
        json_ok(json!(history))
    }

    fn stats_by_id(&self) -> Result<HashMap<String, SatelliteStats>, Reply> {
        match self.node.piece_store().satellite_stats() {
            Ok(rows) => Ok(rows
                .into_iter()
                .map(|row| (row.satellite_id.clone(), row))
                .collect()),
            Err(err) => Err(json_error(&err)),
        }
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

fn audit_json(name: &str, stats: Option<&SatelliteStats>) -> Value {
    json!({
        "satelliteName": name,
        "auditScore": score_json(stats.map(|row| row.audit_score).unwrap_or(0.0)),
        "suspensionScore": score_json(stats.map(|row| row.suspension_score).unwrap_or(0.0)),
        "onlineScore": score_json(stats.map(|row| row.online_score).unwrap_or(0.0)),
    })
}

/// `0.0` serializes as `0.0`, which is not the integer `0` the empty page returns.
fn score_json(score: f64) -> Value {
    if score == 0.0 { json!(0) } else { json!(score) }
}

fn earliest_joined(
    trusted: &[(String, String)],
    stats: &HashMap<String, SatelliteStats>,
) -> String {
    let mut earliest: Option<SystemTime> = None;
    for (id, _) in trusted {
        let Some(joined) = stats.get(id).and_then(|row| row.joined_at) else {
            continue;
        };
        earliest = Some(match earliest {
            Some(current) if current <= joined => current,
            _ => joined,
        });
    }
    match earliest {
        Some(time) => format_rfc3339(time),
        None => ZERO_TIME.to_owned(),
    }
}

fn opt_time_json(time: Option<SystemTime>) -> Value {
    match time {
        Some(time) => Value::String(format_rfc3339(time)),
        None => Value::Null,
    }
}

fn prices_of(row: s3store::PricingRow) -> Prices {
    Prices {
        egress: row.egress_bandwidth,
        audit: row.audit_bandwidth,
        disk: row.disk_space,
    }
}

fn usage_of(days: &[BandwidthDay], disk: u64) -> UsageBytes {
    let mut egress = 0u64;
    let mut repair_audit = 0u64;
    for day in days {
        egress = egress.saturating_add(day.get);
        repair_audit = repair_audit
            .saturating_add(day.get_audit)
            .saturating_add(day.get_repair);
    }
    UsageBytes {
        egress,
        repair_audit,
        disk,
    }
}

fn payout_json(current: MonthPayout, previous: MonthPayout, expectations: i64) -> Reply {
    json_ok(json!({
        "currentMonth": month_json(current),
        "previousMonth": month_json(previous),
        "currentMonthExpectations": expectations,
    }))
}

fn month_json(month: MonthPayout) -> Value {
    json!({
        "egressBandwidth": month.egress_bandwidth,
        "egressBandwidthPayout": month.egress_bandwidth_payout,
        "egressRepairAudit": month.egress_repair_audit,
        "egressRepairAuditPayout": month.egress_repair_audit_payout,
        "diskSpace": month.disk_space,
        "diskSpacePayout": month.disk_space_payout,
        "heldRate": month.held_rate,
        "payout": month.payout,
        "held": month.held,
    })
}

fn zero_estimated_payout() -> Reply {
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

fn paystub_json(row: &PayStubRow) -> Value {
    json!({
        "satelliteId": row.satellite_id,
        "period": row.period,
        "created": format_rfc3339(row.created_at),
        "codes": row.codes,
        "usageAtRest": row.usage_at_rest / 720.0,
        "usageGet": row.usage_get,
        "usagePut": row.usage_put,
        "usageGetRepair": row.usage_get_repair,
        "usagePutRepair": row.usage_put_repair,
        "usageGetAudit": row.usage_get_audit,
        "compAtRest": row.comp_at_rest,
        "compGet": row.comp_get,
        "compPut": row.comp_put,
        "compGetRepair": row.comp_get_repair,
        "compPutRepair": row.comp_put_repair,
        "compGetAudit": row.comp_get_audit,
        "surgePercent": row.surge_percent,
        "held": row.held,
        "owed": row.owed,
        "disposed": row.disposed,
        "paid": row.paid,
        "distributed": row.distributed,
    })
}

fn payout_history_json(
    stub: &PayStubRow,
    url: &str,
    receipt: &str,
    exit_complete: bool,
    joined: Option<SystemTime>,
    now: SystemTime,
) -> Value {
    // A stored surge of 0 means "no surge", which Go treats as 100 percent.
    let surge_percent = if stub.surge_percent == 0 {
        100
    } else {
        stub.surge_percent
    };
    let earned = stub
        .comp_get_audit
        .wrapping_add(stub.comp_get)
        .wrapping_add(stub.comp_get_repair)
        .wrapping_add(stub.comp_at_rest);
    let surge = earned.wrapping_mul(surge_percent).wrapping_div(100);
    let held_percent = match joined {
        Some(joined) => period_instant(&stub.period)
            .map(|period| payout::held_rate(joined, period))
            .unwrap_or(0.0),
        None if earned == 0 => 0.0,
        None => stub.held as f64 / earned as f64 * 100.0,
    };
    let age = joined
        .map(|joined| i64::from(payout::months_between(joined, now)))
        .unwrap_or(0);
    json!({
        "satelliteID": stub.satellite_id,
        "satelliteURL": url,
        "age": age,
        "earned": earned,
        "surge": surge,
        "surgePercent": surge_percent,
        "held": stub.held,
        "heldPercent": held_percent,
        "afterHeld": surge.wrapping_sub(stub.held),
        "disposed": stub.disposed,
        "paid": stub.paid,
        "receipt": receipt,
        "isExitComplete": exit_complete,
        "distributed": stub.distributed,
    })
}

fn held_history_json(
    id: &str,
    name: &str,
    rows: &[PayStubRow],
    joined: Option<SystemTime>,
) -> Value {
    let mut ordered = rows.to_vec();
    ordered.sort_by(|left, right| left.period.cmp(&right.period));
    let mut first = 0i64;
    let mut second = 0i64;
    let mut third = 0i64;
    let mut total_held = 0i64;
    let mut total_disposed = 0i64;
    for (index, stub) in ordered.iter().enumerate() {
        total_disposed = total_disposed.wrapping_add(stub.disposed);
        let bucket = match index {
            0..=2 => &mut first,
            3..=5 => &mut second,
            6..=8 => &mut third,
            _ => continue,
        };
        *bucket = bucket.wrapping_add(stub.held);
        total_held = total_held.wrapping_add(stub.held);
    }
    let joined_at = match joined {
        Some(time) => format_rfc3339(round_to_minute(time)),
        None => ZERO_TIME.to_owned(),
    };
    json!({
        "satelliteID": id,
        "satelliteName": name,
        "holdForFirstPeriod": first,
        "holdForSecondPeriod": second,
        "holdForThirdPeriod": third,
        "totalHeld": total_held,
        "totalDisposed": total_disposed,
        "joinedAt": joined_at,
    })
}

/// `time.Time.Round` rounds a half minute away from zero.
fn round_to_minute(time: SystemTime) -> SystemTime {
    let Ok(elapsed) = time.duration_since(UNIX_EPOCH) else {
        return UNIX_EPOCH;
    };
    let secs = elapsed.as_secs();
    let rem = secs % 60;
    let rounded = if rem >= 30 {
        secs + 60 - rem
    } else {
        secs - rem
    };
    UNIX_EPOCH + Duration::from_secs(rounded)
}

fn canon_period(raw: &str) -> Option<String> {
    let (year, month) = raw.split_once('-')?;
    if year.len() != 4 || month.is_empty() || month.len() > 2 {
        return None;
    }
    if !year.chars().all(|ch| ch.is_ascii_digit()) || !month.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    let year: i32 = year.parse().ok()?;
    let month: u32 = month.parse().ok()?;
    if !(1..=12).contains(&month) {
        return None;
    }
    Some(format!("{year:04}-{month:02}"))
}

fn months_between_periods(start: &str, end: &str) -> Result<Vec<String>, String> {
    let start = canon_period(start).ok_or_else(|| "period start has wrong format".to_owned())?;
    let end = canon_period(end).ok_or_else(|| "period end has wrong format".to_owned())?;
    if start > end {
        return Err("period has wrong format".into());
    }
    let mut year: i32 = start[..4]
        .parse()
        .map_err(|_| "period start has wrong format")?;
    let mut month: u32 = start[5..]
        .parse()
        .map_err(|_| "period start has wrong format")?;
    let end_year: i32 = end[..4]
        .parse()
        .map_err(|_| "period end has wrong format")?;
    let end_month: u32 = end[5..]
        .parse()
        .map_err(|_| "period end has wrong format")?;
    let mut months = Vec::new();
    loop {
        months.push(format!("{year:04}-{month:02}"));
        if year == end_year && month == end_month {
            break;
        }
        // A query can name thousands of years. One node's history is not that long.
        if months.len() >= 12 * 40 {
            return Err("period range is too long".into());
        }
        month += 1;
        if month == 13 {
            month = 1;
            year += 1;
        }
    }
    Ok(months)
}

fn period_instant(period: &str) -> Option<SystemTime> {
    let canon = canon_period(period)?;
    let year: i32 = canon[..4].parse().ok()?;
    let month = time::Month::try_from(canon[5..].parse::<u8>().ok()?).ok()?;
    let date = time::Date::from_calendar_date(year, month, 1).ok()?;
    let secs = u64::try_from(date.midnight().assume_utc().unix_timestamp()).ok()?;
    Some(UNIX_EPOCH + Duration::from_secs(secs))
}

fn query_param(query: &str, name: &str) -> Option<String> {
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == name {
            let decoded = percent_decode(value)?;
            if decoded.is_empty() {
                return None;
            }
            return Some(decoded);
        }
    }
    None
}

fn notifications_list() -> Reply {
    Reply {
        status: 200,
        content_type: "application/json",
        body: NOTIFICATIONS_LIST.as_bytes().to_vec(),
    }
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
