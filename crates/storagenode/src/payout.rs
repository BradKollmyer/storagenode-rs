//! Poll held amounts and pricing from each trusted satellite.
//!
//! Estimated payout is that price times this month's local usage: the sqlite
//! bandwidth counter and the index's live bytes. Until a pricing poll
//! succeeds, the dashboard shows zeros. A failed poll leaves the previous
//! sqlite rows in place. One satellite's error does not skip the others.
//!
//! `storj-rpc` serves one RPC per connection, so each method dials on its own.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use prost::Message;
use prost_types::Timestamp;
use s3store::{PayStubRow, PaymentRow, PricingRow, SatelliteStats};
use storj_rpc::transport::{self, TransportMode};
use storj_rpc::{Conn, NodeId};
use time::OffsetDateTime;

use crate::server::Node;

/// `/heldamount.HeldAmount/GetPayStub`.
pub(crate) const GET_PAY_STUB: &str = "/heldamount.HeldAmount/GetPayStub";

/// `/heldamount.HeldAmount/GetAllPaystubs`.
pub(crate) const GET_ALL_PAYSTUBS: &str = "/heldamount.HeldAmount/GetAllPaystubs";

/// `/heldamount.HeldAmount/GetPayment`.
pub(crate) const GET_PAYMENT: &str = "/heldamount.HeldAmount/GetPayment";

/// `/heldamount.HeldAmount/GetAllPayments`.
pub(crate) const GET_ALL_PAYMENTS: &str = "/heldamount.HeldAmount/GetAllPayments";

/// `/nodestats.NodeStats/GetStats`.
pub(crate) const GET_STATS: &str = "/nodestats.NodeStats/GetStats";

/// `/nodestats.NodeStats/PricingModel`.
pub(crate) const PRICING_MODEL: &str = "/nodestats.NodeStats/PricingModel";

/// `rpcstatus.OutOfRange`. A closed month with no paystub or payment uses this.
const OUT_OF_RANGE: u64 = 11;

/// Go reputation chore interval. Paystubs in Go wait longer; one loop is enough.
const INTERVAL: Duration = Duration::from_secs(4 * 60 * 60);

/// One unary RPC. A dead satellite must not stall the others for the check-in timeout.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Bytes in a terabyte. Prices are per TB (disk: per TB-month).
const BYTES_PER_TB: f64 = 1e12;

/// One pass per trusted satellite, in parallel. Then wait [`INTERVAL`].
pub(crate) async fn serve(node: std::sync::Arc<Node>) {
    loop {
        let mut joins = Vec::new();
        for (id, address) in node.contact_targets() {
            let node = std::sync::Arc::clone(&node);
            joins.push(tokio::spawn(async move {
                if let Err(err) = poll_one(&node, id, &address, TIMEOUT).await {
                    eprintln!("storagenode: payout {id}: {err}");
                }
            }));
        }
        for join in joins {
            let _ = join.await;
        }
        tokio::time::sleep(INTERVAL).await;
    }
}

/// Every trusted satellite, in order. An empty address is not dialed. Errors
/// are joined after every satellite has been attempted. `serve` fans the same
/// work out; tests call this so the path list stays ordered.
#[cfg(test)]
async fn poll(node: &Node, timeout: Duration) -> Result<(), String> {
    let mut errors = Vec::new();
    for (id, address) in node.contact_targets() {
        if let Err(err) = poll_one(node, id, &address, timeout).await {
            errors.push(format!("{id}: {err}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

async fn poll_one(node: &Node, id: NodeId, address: &str, timeout: Duration) -> Result<(), String> {
    if address.is_empty() {
        return Ok(());
    }
    let mut errors = Vec::new();
    if let Err(err) = fetch_paystubs(node, id, address, timeout).await {
        errors.push(err);
    }
    if let Err(err) = fetch_payments(node, id, address, timeout).await {
        errors.push(err);
    }
    if let Err(err) = fetch_stats(node, id, address, timeout).await {
        errors.push(err);
    }
    if let Err(err) = fetch_pricing(node, id, address, timeout).await {
        errors.push(err);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

async fn fetch_paystubs(
    node: &Node,
    id: NodeId,
    address: &str,
    timeout: Duration,
) -> Result<(), String> {
    let all: crate::heldamount::GetAllPaystubsResponse = invoke(
        node,
        id,
        address,
        GET_ALL_PAYSTUBS,
        &crate::heldamount::GetAllPaystubsRequest {},
        timeout,
    )
    .await
    .map_err(rpc_message)?;
    for stub in all.paystub {
        store_paystub(node, &id, stub)?;
    }
    // Closed months are what paystubs exist for. The current month is OutOfRange.
    let closed = Timestamp::from(month_start(previous_month(SystemTime::now())));
    let one = match invoke(
        node,
        id,
        address,
        GET_PAY_STUB,
        &crate::heldamount::GetHeldAmountRequest {
            period: Some(closed),
        },
        timeout,
    )
    .await
    {
        Ok(one) => one,
        Err(RpcFail::MissingPeriod(_)) => return Ok(()),
        Err(err) => return Err(rpc_message(err)),
    };
    store_paystub(node, &id, one)
}

fn store_paystub(
    node: &Node,
    id: &NodeId,
    stub: crate::heldamount::GetHeldAmountResponse,
) -> Result<(), String> {
    let period = period_of(stub.period.as_ref())?;
    let row = PayStubRow {
        satellite_id: id.to_string(),
        period,
        created_at: time_of(stub.created_at.as_ref()),
        codes: stub.codes,
        usage_at_rest: stub.usage_at_rest,
        usage_get: stub.usage_get,
        usage_put: stub.usage_put,
        usage_get_repair: stub.usage_get_repair,
        usage_put_repair: stub.usage_put_repair,
        usage_get_audit: stub.usage_get_audit,
        comp_at_rest: stub.comp_at_rest,
        comp_get: stub.comp_get,
        comp_put: stub.comp_put,
        comp_get_repair: stub.comp_get_repair,
        comp_put_repair: stub.comp_put_repair,
        comp_get_audit: stub.comp_get_audit,
        surge_percent: stub.surge_percent,
        held: stub.held,
        owed: stub.owed,
        disposed: stub.disposed,
        paid: stub.paid,
        distributed: stub.distributed,
    };
    node.piece_store()
        .upsert_paystub(&row)
        .map_err(|err| err.to_string())
}

async fn fetch_payments(
    node: &Node,
    id: NodeId,
    address: &str,
    timeout: Duration,
) -> Result<(), String> {
    let all: crate::heldamount::GetAllPaymentsResponse = invoke(
        node,
        id,
        address,
        GET_ALL_PAYMENTS,
        &crate::heldamount::GetAllPaymentsRequest {},
        timeout,
    )
    .await
    .map_err(rpc_message)?;
    for payment in all.payment {
        store_payment(node, &id, payment)?;
    }
    let closed = Timestamp::from(month_start(previous_month(SystemTime::now())));
    let one = match invoke(
        node,
        id,
        address,
        GET_PAYMENT,
        &crate::heldamount::GetPaymentRequest {
            period: Some(closed),
        },
        timeout,
    )
    .await
    {
        Ok(one) => one,
        Err(RpcFail::MissingPeriod(_)) => return Ok(()),
        Err(err) => return Err(rpc_message(err)),
    };
    store_payment(node, &id, one)
}

fn store_payment(
    node: &Node,
    id: &NodeId,
    payment: crate::heldamount::GetPaymentResponse,
) -> Result<(), String> {
    let period = period_of(payment.period.as_ref())?;
    let row = PaymentRow {
        satellite_id: id.to_string(),
        period,
        payment_id: payment.id,
        created_at: time_of(payment.created_at.as_ref()),
        amount: payment.amount,
        receipt: payment.receipt,
        notes: payment.notes,
    };
    node.piece_store()
        .upsert_payment(&row)
        .map_err(|err| err.to_string())
}

async fn fetch_stats(
    node: &Node,
    id: NodeId,
    address: &str,
    timeout: Duration,
) -> Result<(), String> {
    let resp: crate::nodestats::GetStatsResponse = invoke(
        node,
        id,
        address,
        GET_STATS,
        &crate::nodestats::GetStatsRequest {},
        timeout,
    )
    .await
    .map_err(rpc_message)?;
    for warning in offline_warnings(
        opt_time(resp.offline_suspended),
        opt_time(resp.offline_under_review),
    ) {
        eprintln!("storagenode: satellite {id}: {warning}");
    }
    let audit = resp.audit_check.as_ref();
    let row = SatelliteStats {
        satellite_id: id.to_string(),
        // Vue `Score` multiplies by 100. These are the 0–1 fractions Go stores.
        audit_score: audit.map(|stats| stats.reputation_score).unwrap_or(0.0),
        suspension_score: audit
            .map(|stats| stats.unknown_reputation_score)
            .unwrap_or(0.0),
        online_score: resp.online_score,
        disqualified_at: opt_time(resp.disqualified),
        suspended_at: opt_time(resp.suspended),
        vetted_at: opt_time(resp.vetted_at),
        joined_at: opt_time(resp.joined_at),
    };
    node.piece_store()
        .upsert_stats(&row)
        .map_err(|err| err.to_string())
}

async fn fetch_pricing(
    node: &Node,
    id: NodeId,
    address: &str,
    timeout: Duration,
) -> Result<(), String> {
    let resp: crate::nodestats::PricingModelResponse = invoke(
        node,
        id,
        address,
        PRICING_MODEL,
        &crate::nodestats::PricingModelRequest {},
        timeout,
    )
    .await
    .map_err(rpc_message)?;
    let row = PricingRow {
        egress_bandwidth: resp.egress_bandwidth_price,
        repair_bandwidth: resp.repair_bandwidth_price,
        audit_bandwidth: resp.audit_bandwidth_price,
        disk_space: resp.disk_space_price,
    };
    node.piece_store()
        .upsert_pricing(&id.to_string(), &row)
        .map_err(|err| err.to_string())
}

enum RpcFail {
    /// `rpcstatus.OutOfRange`. Go stores nothing for that period.
    MissingPeriod(String),
    Other(String),
}

fn rpc_message(err: RpcFail) -> String {
    match err {
        RpcFail::MissingPeriod(message) | RpcFail::Other(message) => message,
    }
}

async fn invoke<R: Message + Default>(
    node: &Node,
    id: NodeId,
    address: &str,
    path: &str,
    request: &impl Message,
    timeout: Duration,
) -> Result<R, RpcFail> {
    let bytes = dial(node, id, address, path, &request.encode_to_vec(), timeout).await?;
    R::decode(bytes.as_slice()).map_err(|err| RpcFail::Other(err.to_string()))
}

async fn dial(
    node: &Node,
    id: NodeId,
    address: &str,
    path: &str,
    request: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, RpcFail> {
    let rpc = async {
        let transport = transport::dial(
            node.identity(),
            id,
            address,
            TransportMode::Tcp,
            timeout,
            None,
        )
        .await
        .map_err(|err| RpcFail::Other(err.to_string()))?;
        let mut conn = Conn::new(transport);
        conn.invoke(path, request).await.map_err(|err| match err {
            storj_rpc::Error::Remote {
                code: OUT_OF_RANGE,
                message,
            } => RpcFail::MissingPeriod(format!(
                "DRPC remote error (code {OUT_OF_RANGE}): {message}"
            )),
            other => RpcFail::Other(other.to_string()),
        })
    };
    match tokio::time::timeout(timeout, rpc).await {
        Ok(result) => result,
        Err(_) => Err(RpcFail::Other(format!("{path} timed out"))),
    }
}

/// Local usage priced the way `estimatedpayouts` prices a month.
///
/// `disk` is current live bytes. Go divides byte-hours by 720 because its
/// storage table is hourly. This index has no hourly disk samples, so the
/// byte count is already the month's disk term.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UsageBytes {
    /// GET bytes this month.
    pub egress: u64,
    /// GET_AUDIT plus GET_REPAIR bytes.
    pub repair_audit: u64,
    /// Live piece bytes. Not divided by 720.
    pub disk: u64,
}

/// Prices passed into [`price_month`]. Repair egress uses [`Self::audit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Prices {
    /// Egress bandwidth price per TB.
    pub egress: i64,
    /// Audit bandwidth price per TB. Repair egress uses this, matching Go.
    pub audit: i64,
    /// Disk price per TB-month.
    pub disk: i64,
}

/// One month of the estimated-payout JSON, before field rename.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub(crate) struct MonthPayout {
    /// Egress bytes.
    pub egress_bandwidth: u64,
    /// Egress payout, rounded to cents.
    pub egress_bandwidth_payout: f64,
    /// Audit and repair egress bytes.
    pub egress_repair_audit: u64,
    /// Audit and repair payout, rounded to cents.
    pub egress_repair_audit_payout: f64,
    /// Disk bytes treated as byte-months.
    pub disk_space: f64,
    /// Disk payout, rounded to cents.
    pub disk_space_payout: f64,
    /// Percent held. Not summed across satellites.
    pub held_rate: f64,
    /// Payout after hold, rounded to cents.
    pub payout: f64,
    /// Held amount. Not rounded, matching `SetHeldAmount`.
    pub held: f64,
}

impl MonthPayout {
    /// Sums money and usage. [`Self::held_rate`] stays on `self`.
    pub(crate) fn add(&mut self, other: Self) {
        self.egress_bandwidth = self.egress_bandwidth.saturating_add(other.egress_bandwidth);
        self.egress_bandwidth_payout += other.egress_bandwidth_payout;
        self.egress_repair_audit = self
            .egress_repair_audit
            .saturating_add(other.egress_repair_audit);
        self.egress_repair_audit_payout += other.egress_repair_audit_payout;
        self.disk_space += other.disk_space;
        self.disk_space_payout += other.disk_space_payout;
        self.payout += other.payout;
        self.held += other.held;
    }
}

/// `payouts.GetHeldRate`. Months are whole calendar months, days ignored.
pub(crate) fn held_rate(joined: SystemTime, period: SystemTime) -> f64 {
    match months_between(joined, period) {
        0..=2 => 75.0,
        3..=5 => 50.0,
        6..=8 => 25.0,
        _ => 0.0,
    }
}

/// Whole UTC calendar months from `from` to `to`. Negative when `to` is earlier.
pub(crate) fn months_between(from: SystemTime, to: SystemTime) -> i32 {
    let Some((y1, m1)) = year_month(from) else {
        return i32::MAX;
    };
    let Some((y2, m2)) = year_month(to) else {
        return i32::MAX;
    };
    (y2 - y1) * 12 + (m2 - m1)
}

/// Go `EstimatedPayout.Set` expectations. A window under a minute is not
/// extrapolated: that division blows up when the node just appeared.
pub(crate) fn month_expectations(payout: f64, now: SystemTime, joined: Option<SystemTime>) -> i64 {
    let Some(now_dt) = utc(now) else {
        return 0;
    };
    let begin = month_begin_dt(now_dt);
    let end = month_end_dt(now_dt);
    let joined_dt = joined.and_then(utc).unwrap_or(now_dt);
    if joined_dt < begin {
        let minutes_past = minutes_between(begin, now_dt);
        if minutes_past < 1.0 {
            return trunc_i64(payout);
        }
        trunc_i64(payout / minutes_past * minutes_between(begin, end))
    } else {
        let minutes_since = minutes_between(joined_dt, now_dt);
        if minutes_since < 1.0 {
            return trunc_i64(payout);
        }
        trunc_i64(payout / minutes_since * minutes_between(joined_dt, end))
    }
}

/// Prices `usage` at `prices` and applies `held_rate` percent.
pub(crate) fn price_month(usage: UsageBytes, prices: Prices, rate: f64) -> MonthPayout {
    let egress_bandwidth_payout =
        round_cents(usage.egress as f64 * prices.egress as f64 / BYTES_PER_TB);
    let egress_repair_audit_payout =
        round_cents(usage.repair_audit as f64 * prices.audit as f64 / BYTES_PER_TB);
    let disk_space = usage.disk as f64;
    let disk_space_payout = round_cents(disk_space * prices.disk as f64 / BYTES_PER_TB);
    let held =
        (disk_space_payout + egress_bandwidth_payout + egress_repair_audit_payout) * rate / 100.0;
    let payout = round_cents(
        disk_space_payout + egress_bandwidth_payout + egress_repair_audit_payout - held,
    );
    MonthPayout {
        egress_bandwidth: usage.egress,
        egress_bandwidth_payout,
        egress_repair_audit: usage.repair_audit,
        egress_repair_audit_payout,
        disk_space,
        disk_space_payout,
        held_rate: rate,
        payout,
        held,
    }
}

fn round_cents(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn trunc_i64(value: f64) -> i64 {
    if !value.is_finite() {
        return 0;
    }
    let capped = value.clamp(i64::MIN as f64, i64::MAX as f64);
    capped as i64
}

fn year_month(time: SystemTime) -> Option<(i32, i32)> {
    let dt = utc(time)?;
    Some((dt.year(), i32::from(u8::from(dt.month()))))
}

fn utc(time: SystemTime) -> Option<OffsetDateTime> {
    let secs = i64::try_from(time.duration_since(UNIX_EPOCH).ok()?.as_secs()).ok()?;
    OffsetDateTime::from_unix_timestamp(secs).ok()
}

fn minutes_between(from: OffsetDateTime, to: OffsetDateTime) -> f64 {
    to.unix_timestamp_nanos()
        .saturating_sub(from.unix_timestamp_nanos()) as f64
        / 60_000_000_000.0
}

fn month_begin_dt(now: OffsetDateTime) -> OffsetDateTime {
    now.date()
        .replace_day(1)
        .unwrap_or(now.date())
        .midnight()
        .assume_utc()
}

/// First instant of the next month. One nanosecond later than Go's end-of-month.
fn month_end_dt(now: OffsetDateTime) -> OffsetDateTime {
    let start = now.date().replace_day(1).unwrap_or(now.date());
    let next = start
        .checked_add(time::Duration::days(31))
        .and_then(|date| date.replace_day(1).ok())
        .unwrap_or(start);
    next.midnight().assume_utc()
}

fn month_start(now: SystemTime) -> SystemTime {
    let Some(dt) = utc(now) else {
        return UNIX_EPOCH;
    };
    SystemTime::from(month_begin_dt(dt))
}

/// An instant in the previous UTC month, so the bandwidth counter selects it.
pub(crate) fn previous_month(now: SystemTime) -> SystemTime {
    let Some(dt) = utc(now) else {
        return UNIX_EPOCH;
    };
    let prev = month_begin_dt(dt)
        .checked_sub(time::Duration::days(1))
        .unwrap_or_else(|| month_begin_dt(dt));
    SystemTime::from(prev)
}

fn period_of(ts: Option<&Timestamp>) -> Result<String, String> {
    let Some(ts) = ts else {
        return Err("paystub period is missing".into());
    };
    let dt = OffsetDateTime::from_unix_timestamp(ts.seconds).map_err(|err| err.to_string())?;
    Ok(format!("{:04}-{:02}", dt.year(), u8::from(dt.month())))
}

fn time_of(ts: Option<&Timestamp>) -> SystemTime {
    opt_time(ts.cloned()).unwrap_or(UNIX_EPOCH)
}

/// What to tell the operator about the satellite's offline tracking.
///
/// The Go node stores both times; neither its console API nor the dashboard
/// reads them, so this node has no column for them. A node suspended for
/// being offline is no longer selected, and the log is the only place the
/// operator can learn why.
fn offline_warnings(
    suspended: Option<SystemTime>,
    under_review: Option<SystemTime>,
) -> Vec<String> {
    let unix = |time: SystemTime| {
        time.duration_since(UNIX_EPOCH)
            .map(|since| since.as_secs())
            .unwrap_or(0)
    };
    let mut warnings = Vec::new();
    if let Some(since) = suspended {
        warnings.push(format!(
            "this node is suspended for being offline (since unix {}) and is not selected for uploads",
            unix(since)
        ));
    }
    if let Some(since) = under_review {
        warnings.push(format!(
            "this node is under review for being offline (since unix {})",
            unix(since)
        ));
    }
    warnings
}

fn opt_time(ts: Option<Timestamp>) -> Option<SystemTime> {
    let ts = ts?;
    if ts.seconds < 0 {
        return None;
    }
    let nanos = u32::try_from(ts.nanos.max(0)).unwrap_or(0);
    Some(
        UNIX_EPOCH
            + Duration::from_secs(u64::try_from(ts.seconds).unwrap_or(u64::MAX))
            + Duration::from_nanos(u64::from(nanos)),
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use prost::Message;
    use s3store::BandwidthKind;
    use storj_rpc::frame::{Kind, Packet};
    use storj_rpc::{Conn, Identity, server_config};
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::checkin::{self, Operator};
    use crate::noise_key;
    use crate::server::TrustedSatellite;

    #[test]
    fn offline_suspension_and_review_are_reported() {
        let since = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert!(offline_warnings(None, None).is_empty());
        let both = offline_warnings(Some(since), Some(since));
        assert_eq!(both.len(), 2);
        assert!(
            both[0].contains("suspended for being offline"),
            "{}",
            both[0]
        );
        assert!(both[0].contains("1700000000"), "{}", both[0]);
        assert!(both[1].contains("under review"), "{}", both[1]);
        assert_eq!(offline_warnings(None, Some(since)).len(), 1);
    }
    #[test]
    fn held_rate_matches_go_month_table() {
        let oct = ts(2026, 10, 3);
        assert_eq!(held_rate(ts(2026, 8, 15), oct), 75.0);
        assert_eq!(held_rate(ts(2026, 7, 1), oct), 50.0);
        assert_eq!(held_rate(ts(2026, 4, 1), oct), 25.0);
        assert_eq!(held_rate(ts(2026, 1, 1), oct), 0.0);
        assert_eq!(months_between(ts(2026, 10, 3), ts(2026, 8, 1)), -2);
    }

    #[test]
    fn price_month_matches_go_rounding_and_hold() {
        let month = price_month(
            UsageBytes {
                egress: 1_000_000_000_000,
                repair_audit: 0,
                disk: 0,
            },
            Prices {
                egress: 20,
                audit: 7,
                disk: 5,
            },
            75.0,
        );
        assert_eq!(month.egress_bandwidth_payout, 20.0);
        assert_eq!(month.held, 15.0);
        assert_eq!(month.payout, 5.0);
        assert_eq!(month.held_rate, 75.0);

        // 5e9 * 1 / 1e12 = 0.005, and Go math.Round half away from zero is 0.01.
        let tiny = price_month(
            UsageBytes {
                egress: 5_000_000_000,
                repair_audit: 0,
                disk: 0,
            },
            Prices {
                egress: 1,
                audit: 0,
                disk: 0,
            },
            0.0,
        );
        assert_eq!(tiny.egress_bandwidth_payout, 0.01);
        assert_eq!(tiny.payout, 0.01);

        let dust = price_month(
            UsageBytes {
                egress: 1,
                repair_audit: 0,
                disk: 0,
            },
            Prices {
                egress: 1,
                audit: 0,
                disk: 0,
            },
            0.0,
        );
        assert_eq!(dust.egress_bandwidth_payout, 0.0);

        let mixed = price_month(
            UsageBytes {
                egress: 0,
                repair_audit: 2_000_000_000_000,
                disk: 1_000_000_000_000,
            },
            Prices {
                egress: 99,
                audit: 3,
                disk: 4,
            },
            0.0,
        );
        assert_eq!(mixed.egress_repair_audit_payout, 6.0);
        assert_eq!(mixed.disk_space, 1_000_000_000_000.0);
        assert_eq!(mixed.disk_space_payout, 4.0);
        assert_eq!(mixed.payout, 10.0);
    }

    #[test]
    fn expectations_project_this_month_from_a_fixed_instant() {
        // 2026-10-03T12:00:00Z. October has 44640 minutes; 3600 have passed.
        let now = UNIX_EPOCH + Duration::from_secs(1_791_028_800);
        let joined = UNIX_EPOCH + Duration::from_secs(1_000_000_080);
        assert_eq!(month_expectations(5.0, now, Some(joined)), 62);
        assert_eq!(
            month_expectations(5.0, now, Some(now)),
            5,
            "a join in this same second is not extrapolated"
        );
    }

    #[tokio::test]
    async fn poll_prices_local_usage_and_check_in_does_not_clear_stats() {
        let live = Identity::generate().expect("live");
        let empty = Identity::generate().expect("empty");
        let dead_id = Identity::generate().expect("dead");
        let untrusted = Identity::generate().expect("untrusted");
        let untrusted_id = untrusted.node_id().to_string();
        let script = Arc::new(Script::default());
        let untrusted_hits = Arc::new(AtomicUsize::new(0));
        let _untrusted_addr = spawn_counter(Arc::clone(&untrusted_hits));
        let dead_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("dead bind");
        let dead_addr = format!(
            "127.0.0.1:{}",
            dead_listener.local_addr().expect("dead addr").port()
        );
        drop(dead_listener);
        let address = spawn_satellite(live.clone(), Arc::clone(&script));
        let fixture = fixture(&live, &address, &empty, &dead_id, &dead_addr);
        let live_id = live.node_id().to_string();
        let empty_id = empty.node_id().to_string();
        let dead_node = dead_id.node_id().to_string();
        let ui = fixture.root.join("ui");
        std::fs::create_dir_all(&ui).expect("ui");
        let dash = crate::dashboard::Dashboard::for_test(Arc::clone(&fixture.node), &ui);

        let (status, body) = dash.handle("GET", "/api/sno/estimated-payout").await;
        assert_eq!(status, 200);
        assert_month_zeros(&body);
        let (status, body) = dash
            .handle("GET", &format!("/api/sno/satellites/{live_id}/pricing"))
            .await;
        assert_eq!(status, 200);
        let pricing: serde_json::Value = serde_json::from_slice(&body).expect("pricing");
        assert_eq!(pricing["egressBandwidth"], 0);
        let (status, body) = dash
            .handle("GET", &format!("/api/sno/satellite/{live_id}"))
            .await;
        assert_eq!(status, 200);
        let satellite: serde_json::Value = serde_json::from_slice(&body).expect("satellite");
        assert_eq!(satellite["audits"]["auditScore"], 0);
        assert_eq!(satellite["nodeJoinedAt"], "0001-01-01T00:00:00Z");
        let (status, body) = dash.handle("GET", "/api/heldamount/paystubs/2026-10").await;
        assert_eq!(status, 200);
        assert_eq!(body, b"[]");

        // The live satellite is recorded. The dead port and the empty address
        // still fail the pass; that must not be required for the live row.
        let err = checkin::check_in(&fixture.node, &operator(), Duration::from_secs(5))
            .await
            .expect_err("dead satellite and empty address");
        assert!(err.contains(&dead_node), "{err}");
        assert!(err.contains(&empty_id), "{err}");
        assert!(!err.contains(&live_id), "{err}");
        let (status, body) = dash
            .handle("GET", &format!("/api/sno/satellite/{live_id}"))
            .await;
        let satellite: serde_json::Value = serde_json::from_slice(&body).expect("satellite");
        assert_eq!(status, 200);
        assert_eq!(satellite["audits"]["auditScore"], 0);
        assert_eq!(satellite["audits"]["suspensionScore"], 0);
        assert_eq!(satellite["audits"]["onlineScore"], 0);

        fixture
            .node
            .piece_store()
            .add_bandwidth(
                &live_id,
                BandwidthKind::Get,
                1_000_000_000_000,
                SystemTime::now(),
            )
            .expect("bandwidth");
        let (status, body) = dash.handle("GET", "/api/sno/estimated-payout").await;
        assert_eq!(status, 200);
        assert_month_zeros(&body);

        script.paths.lock().expect("paths").clear();
        let err = poll(&fixture.node, Duration::from_secs(5))
            .await
            .expect_err("dead satellite");
        assert!(err.contains(&dead_node), "{err}");
        assert!(!err.contains(&live_id), "{err}");
        assert!(!err.contains(&empty_id), "{err}");
        assert!(!err.contains(&untrusted_id), "{err}");
        assert!(
            !fixture
                .node
                .contact_targets()
                .iter()
                .any(|(id, _)| id.to_string() == untrusted_id)
        );
        assert_eq!(untrusted_hits.load(Ordering::Relaxed), 0);
        let paths = script.paths.lock().expect("paths").clone();
        assert_eq!(
            paths,
            vec![
                GET_ALL_PAYSTUBS,
                GET_PAY_STUB,
                GET_ALL_PAYMENTS,
                GET_PAYMENT,
                GET_STATS,
                PRICING_MODEL,
            ]
        );
        let requests = script.requests.lock().expect("requests").clone();
        assert_previous_month(&requests, GET_PAY_STUB);
        assert_previous_month(&requests, GET_PAYMENT);

        let (status, body) = dash
            .handle("GET", &format!("/api/sno/estimated-payout?id={live_id}"))
            .await;
        assert_eq!(status, 200);
        let payout: serde_json::Value = serde_json::from_slice(&body).expect("payout");
        let current = &payout["currentMonth"];
        assert_eq!(current["egressBandwidth"].as_u64(), Some(1_000_000_000_000));
        assert_eq!(current["egressBandwidthPayout"].as_f64(), Some(20.0));
        assert_eq!(current["egressRepairAudit"].as_u64(), Some(0));
        assert_eq!(current["diskSpace"].as_f64(), Some(0.0));
        assert_eq!(current["heldRate"].as_f64(), Some(75.0));
        assert_eq!(current["held"].as_f64(), Some(15.0));
        assert_eq!(current["payout"].as_f64(), Some(5.0));
        let expectations = payout["currentMonthExpectations"]
            .as_i64()
            .expect("expectations");
        assert!(expectations >= 5, "{expectations}");
        assert!(expectations < 1_000_000, "{expectations}");
        assert_eq!(payout["previousMonth"]["egressBandwidth"].as_u64(), Some(0));
        assert_eq!(payout["previousMonth"]["payout"].as_f64(), Some(0.0));

        let (status, body) = dash.handle("GET", "/api/sno/estimated-payout").await;
        let all: serde_json::Value = serde_json::from_slice(&body).expect("all");
        assert_eq!(status, 200);
        assert_eq!(all["currentMonth"]["payout"].as_f64(), Some(5.0));
        assert_eq!(all["currentMonth"]["held"].as_f64(), Some(15.0));
        assert_eq!(
            all["currentMonth"]["heldRate"].as_f64(),
            Some(0.0),
            "Go's all-satellite sum does not copy heldRate"
        );

        let (status, body) = dash
            .handle("GET", &format!("/api/sno/satellites/{live_id}/pricing"))
            .await;
        let pricing: serde_json::Value = serde_json::from_slice(&body).expect("pricing");
        assert_eq!(status, 200);
        assert_eq!(pricing["satelliteID"], live_id);
        assert_eq!(pricing["egressBandwidth"], 20);
        assert_eq!(pricing["repairBandwidth"], 10);
        assert_eq!(pricing["auditBandwidth"], 7);
        assert_eq!(pricing["diskSpace"], 5);

        let (status, body) = dash.handle("GET", "/api/heldamount/periods").await;
        let periods: Vec<String> = serde_json::from_slice(&body).expect("periods");
        assert_eq!(status, 200);
        assert_eq!(periods.len(), 1);
        let period = &periods[0];
        let (status, body) = dash
            .handle("GET", &format!("/api/heldamount/paystubs/{period}"))
            .await;
        assert_eq!(status, 200);
        let stubs: serde_json::Value = serde_json::from_slice(&body).expect("stubs");
        assert_eq!(stubs[0]["usageGet"], 42);
        assert_eq!(stubs[0]["usageAtRest"].as_f64(), Some(2.0));
        assert_eq!(stubs[0]["satelliteId"], live_id);
        assert_eq!(stubs[0]["period"], period.as_str());
        let (status, body) = dash
            .handle("GET", &format!("/api/heldamount/payout-history/{period}"))
            .await;
        assert_eq!(status, 200);
        let history: serde_json::Value = serde_json::from_slice(&body).expect("history");
        assert_eq!(history[0]["satelliteID"], live_id);
        assert_eq!(history[0]["satelliteURL"], address);
        assert_eq!(history[0]["earned"], 1000);
        assert_eq!(history[0]["surgePercent"], 100);
        assert_eq!(history[0]["surge"], 1000);
        assert_eq!(history[0]["held"], 250);
        assert_eq!(history[0]["afterHeld"], 750);
        assert_eq!(history[0]["paid"], 100);
        assert_eq!(history[0]["disposed"], 25);
        assert_eq!(history[0]["distributed"], 10);
        assert_eq!(history[0]["receipt"], "rcpt");
        assert_eq!(history[0]["heldPercent"].as_f64(), Some(75.0));
        assert_eq!(history[0]["isExitComplete"], false);
        let (status, body) = dash.handle("GET", "/api/heldamount/held-history").await;
        assert_eq!(status, 200);
        let held: serde_json::Value = serde_json::from_slice(&body).expect("held");
        assert_eq!(held[0]["satelliteID"], live_id);
        assert_eq!(held[0]["holdForFirstPeriod"], 250);
        assert_eq!(held[0]["totalHeld"], 250);
        assert_eq!(held[0]["totalDisposed"], 25);

        let (status, body) = dash
            .handle("GET", &format!("/api/sno/satellite/{live_id}"))
            .await;
        let satellite: serde_json::Value = serde_json::from_slice(&body).expect("satellite");
        assert_eq!(status, 200);
        assert_eq!(satellite["audits"]["auditScore"].as_f64(), Some(0.98));
        assert_eq!(satellite["audits"]["suspensionScore"].as_f64(), Some(0.97));
        assert_eq!(satellite["audits"]["onlineScore"].as_f64(), Some(0.995));
        assert_ne!(satellite["nodeJoinedAt"], "0001-01-01T00:00:00Z");
        let (status, body) = dash.handle("GET", "/api/sno/").await;
        let page: serde_json::Value = serde_json::from_slice(&body).expect("sno");
        assert_eq!(status, 200);
        let row = page["satellites"]
            .as_array()
            .expect("satellites")
            .iter()
            .find(|row| row["id"] == live_id)
            .expect("live row");
        assert!(row["disqualified"].is_null());
        assert!(row["suspended"].is_string());
        assert!(row["vettedAt"].is_string());
        let suspended = row["suspended"].clone();
        let vetted = row["vettedAt"].clone();

        script.quic.store(true, Ordering::Relaxed);
        let err = checkin::check_in(&fixture.node, &operator(), Duration::from_secs(5))
            .await
            .expect_err("dead satellite still refuses");
        assert!(!err.contains(&live_id), "{err}");
        let (status, body) = dash
            .handle("GET", &format!("/api/sno/satellite/{live_id}"))
            .await;
        let satellite: serde_json::Value = serde_json::from_slice(&body).expect("satellite");
        assert_eq!(status, 200);
        assert_eq!(satellite["audits"]["auditScore"].as_f64(), Some(0.98));
        assert_eq!(satellite["audits"]["suspensionScore"].as_f64(), Some(0.97));
        assert_eq!(satellite["audits"]["onlineScore"].as_f64(), Some(0.995));
        let (status, body) = dash.handle("GET", "/api/sno/").await;
        let page: serde_json::Value = serde_json::from_slice(&body).expect("sno");
        assert_eq!(status, 200);
        assert_eq!(page["quicStatus"], "OK");
        let row = page["satellites"]
            .as_array()
            .expect("satellites")
            .iter()
            .find(|row| row["id"] == live_id)
            .expect("live row");
        assert_eq!(row["suspended"], suspended);
        assert_eq!(row["vettedAt"], vetted);
        assert!(row["disqualified"].is_null());

        script.missing.store(true, Ordering::Relaxed);
        let err = poll(&fixture.node, Duration::from_secs(5))
            .await
            .expect_err("dead satellite");
        assert!(err.contains(&dead_node), "{err}");
        assert!(
            !err.contains(&live_id),
            "a missing closed month is not a poll failure: {err}"
        );
        let stubs = fixture.node.piece_store().paystubs().expect("stubs");
        assert_eq!(stubs.len(), 1);
        assert_eq!(stubs[0].usage_get, 42);
        script.missing.store(false, Ordering::Relaxed);

        script.fail.store(true, Ordering::Relaxed);
        let err = poll(&fixture.node, Duration::from_secs(5))
            .await
            .expect_err("failed poll");
        assert!(err.contains(&live_id), "{err}");
        assert_eq!(
            fixture.node.piece_store().paystubs().expect("stubs").len(),
            1
        );
        assert_eq!(
            fixture
                .node
                .piece_store()
                .satellite_stats()
                .expect("stats")
                .iter()
                .find(|row| row.satellite_id == live_id)
                .expect("live stats")
                .audit_score,
            0.98
        );
        assert_eq!(untrusted_hits.load(Ordering::Relaxed), 0);

        let volume = fixture.volume.clone();
        drop(dash);
        // Keep the directory. Dropping `fixture` would delete pieces.db first.
        let Fixture { node, _root, .. } = fixture;
        drop(node);
        let store = s3store::Store::new(s3store::Config {
            endpoint: "http://127.0.0.1:1".into(),
            bucket: "pieces".into(),
            access_key_id: "ak".into(),
            secret_access_key: "sk".into(),
            volume,
            allocated_bytes: 5_000,
            ..s3store::Config::default()
        })
        .expect("reopen");
        let stubs = store.paystubs().expect("reopen stubs");
        assert_eq!(stubs.len(), 1);
        assert_eq!(stubs[0].usage_get, 42);
        assert_eq!(stubs[0].satellite_id, live_id);
        let stats = store.satellite_stats().expect("reopen stats");
        assert_eq!(stats[0].audit_score, 0.98);
        assert!(stats[0].suspended_at.is_some());
        let pricing = store
            .pricing(&live_id)
            .expect("reopen pricing")
            .expect("row");
        assert_eq!(pricing.egress_bandwidth, 20);
    }

    fn assert_previous_month(requests: &[(String, Vec<u8>)], path: &str) {
        let (_, bytes) = requests
            .iter()
            .find(|(got, _)| got == path)
            .unwrap_or_else(|| panic!("no request for {path}"));
        let seconds = if path == GET_PAY_STUB {
            crate::heldamount::GetHeldAmountRequest::decode(bytes.as_slice())
                .expect("paystub request")
                .period
                .expect("period")
                .seconds
        } else {
            crate::heldamount::GetPaymentRequest::decode(bytes.as_slice())
                .expect("payment request")
                .period
                .expect("period")
                .seconds
        };
        let expected = Timestamp::from(month_start(previous_month(SystemTime::now())));
        assert_eq!(seconds, expected.seconds, "{path}");
    }

    fn assert_month_zeros(body: &[u8]) {
        let payout: serde_json::Value = serde_json::from_slice(body).expect("json");
        for month in ["currentMonth", "previousMonth"] {
            for key in [
                "egressBandwidth",
                "egressBandwidthPayout",
                "egressRepairAudit",
                "egressRepairAuditPayout",
                "diskSpace",
                "diskSpacePayout",
                "heldRate",
                "payout",
                "held",
            ] {
                let value = &payout[month][key];
                assert!(
                    value.as_f64() == Some(0.0) || value.as_u64() == Some(0),
                    "{month}.{key} = {value}"
                );
            }
        }
        assert_eq!(payout["currentMonthExpectations"], 0);
    }

    fn ts(year: i32, month: u8, day: u8) -> SystemTime {
        let date = time::Date::from_calendar_date(year, time::Month::try_from(month).unwrap(), day)
            .unwrap();
        SystemTime::from(date.midnight().assume_utc())
    }

    fn operator() -> Operator {
        Operator {
            email: "op@example.com".into(),
            wallet: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            wallet_features: Vec::new(),
            address: "203.0.113.9:28967".into(),
        }
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "storagenode-payout-{nanos}-{seq}-{}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("temp");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct Fixture {
        node: Arc<Node>,
        root: PathBuf,
        volume: PathBuf,
        _root: TempDir,
    }

    fn fixture(
        live: &Identity,
        address: &str,
        empty: &Identity,
        dead: &Identity,
        dead_addr: &str,
    ) -> Fixture {
        let root = TempDir::new();
        let volume = root.0.join("volume");
        let store = s3store::Store::new(s3store::Config {
            endpoint: "http://127.0.0.1:1".into(),
            bucket: "pieces".into(),
            access_key_id: "ak".into(),
            secret_access_key: "sk".into(),
            volume: volume.clone(),
            allocated_bytes: 5_000,
            ..s3store::Config::default()
        })
        .expect("store");
        let identity = Identity::generate().expect("identity");
        let noise = noise_key::Key::generate().expect("noise");
        let node = Node::with_noise(
            identity,
            store,
            vec![
                trusted(live, address),
                trusted(empty, ""),
                trusted(dead, dead_addr),
            ],
            noise_key::DEFAULT_PROTOCOL,
            noise,
        )
        .expect("node");
        Fixture {
            node: Arc::new(node),
            root: root.0.clone(),
            volume,
            _root: root,
        }
    }

    fn trusted(identity: &Identity, address: &str) -> TrustedSatellite {
        TrustedSatellite {
            id: identity.node_id(),
            address: address.to_owned(),
            leaf_der: identity.leaf_der().as_ref().to_vec(),
            ca_der: identity.ca_der().as_ref().to_vec(),
        }
    }

    struct Script {
        paths: Mutex<Vec<String>>,
        requests: Mutex<Vec<(String, Vec<u8>)>>,
        fail: AtomicBool,
        missing: AtomicBool,
        quic: AtomicBool,
    }

    impl Default for Script {
        fn default() -> Self {
            Self {
                paths: Mutex::new(Vec::new()),
                requests: Mutex::new(Vec::new()),
                fail: AtomicBool::new(false),
                missing: AtomicBool::new(false),
                quic: AtomicBool::new(false),
            }
        }
    }

    fn spawn_counter(hits: Arc<AtomicUsize>) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let address = format!("127.0.0.1:{}", listener.local_addr().expect("addr").port());
        let listener = TcpListener::from_std(listener).expect("tokio");
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
                hits.fetch_add(1, Ordering::Relaxed);
            }
        });
        address
    }

    fn spawn_satellite(identity: Identity, script: Arc<Script>) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let address = format!("127.0.0.1:{}", listener.local_addr().expect("addr").port());
        let listener = TcpListener::from_std(listener).expect("tokio");
        tokio::spawn(async move {
            let acceptor =
                tokio_rustls::TlsAcceptor::from(Arc::new(server_config(&identity).expect("tls")));
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let script = Arc::clone(&script);
                tokio::spawn(async move {
                    if let Err(err) = serve_one(acceptor, sock, &script).await {
                        eprintln!("test satellite: {err}");
                    }
                });
            }
        });
        address
    }

    async fn serve_one(
        acceptor: tokio_rustls::TlsAcceptor,
        mut sock: TcpStream,
        script: &Script,
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
        script.paths.lock().expect("paths").push(path.clone());
        loop {
            let pkt = conn.read_packet().await.map_err(|err| err.to_string())?;
            if pkt.stream_id != invoke.stream_id {
                continue;
            }
            match pkt.kind {
                Kind::MESSAGE => {
                    script
                        .requests
                        .lock()
                        .expect("requests")
                        .push((path.clone(), pkt.data));
                    break;
                }
                Kind::CLOSE_SEND | Kind::CLOSE => break,
                Kind::ERROR => return Err("client error".into()),
                _ => {}
            }
        }
        if script.missing.load(Ordering::Relaxed) && (path == GET_PAY_STUB || path == GET_PAYMENT) {
            conn.write_packet(&Packet {
                stream_id: invoke.stream_id,
                message_id: 1,
                kind: Kind::ERROR,
                control: false,
                data: storj_rpc::marshal_error(OUT_OF_RANGE, "no paystub for period"),
            })
            .await
            .map_err(|err| err.to_string())?;
            return Ok(());
        }
        if script.fail.load(Ordering::Relaxed) {
            return Err("satellite down".into());
        }
        let response = response_for(&path, script.quic.load(Ordering::Relaxed))?;
        conn.write_packet(&Packet {
            stream_id: invoke.stream_id,
            message_id: 1,
            kind: Kind::MESSAGE,
            control: false,
            data: response,
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
        let _ = tokio::time::timeout(Duration::from_secs(2), conn.read_packet()).await;
        Ok(())
    }

    fn response_for(path: &str, quic: bool) -> Result<Vec<u8>, String> {
        let period = Timestamp::from(month_start(SystemTime::now()));
        let created = Timestamp {
            seconds: 1_700_000_000,
            nanos: 0,
        };
        match path {
            GET_ALL_PAYSTUBS => Ok(crate::heldamount::GetAllPaystubsResponse {
                paystub: vec![sample_stub(period, created)],
            }
            .encode_to_vec()),
            GET_PAY_STUB => Ok(sample_stub(period, created).encode_to_vec()),
            GET_ALL_PAYMENTS => Ok(crate::heldamount::GetAllPaymentsResponse {
                payment: vec![sample_payment(period, created)],
            }
            .encode_to_vec()),
            GET_PAYMENT => Ok(sample_payment(period, created).encode_to_vec()),
            GET_STATS => Ok(sample_stats(period).encode_to_vec()),
            PRICING_MODEL => Ok(crate::nodestats::PricingModelResponse {
                egress_bandwidth_price: 20,
                repair_bandwidth_price: 10,
                disk_space_price: 5,
                audit_bandwidth_price: 7,
            }
            .encode_to_vec()),
            checkin::CHECK_IN => Ok(crate::contact::CheckInResponse {
                ping_node_success: true,
                ping_error_message: String::new(),
                ping_node_success_quic: quic,
                node_tag_success: false,
                node_tag_error_message: String::new(),
                hashstore_settings: None,
            }
            .encode_to_vec()),
            other => Err(format!("unexpected path {other}")),
        }
    }

    fn sample_stub(
        period: Timestamp,
        created: Timestamp,
    ) -> crate::heldamount::GetHeldAmountResponse {
        crate::heldamount::GetHeldAmountResponse {
            period: Some(period),
            node_id: Vec::new(),
            created_at: Some(created),
            codes: String::new(),
            usage_at_rest: 1440.0,
            usage_get: 42,
            usage_put: 0,
            usage_get_repair: 0,
            usage_put_repair: 0,
            usage_get_audit: 0,
            comp_at_rest: 0,
            comp_get: 1000,
            comp_put: 0,
            comp_get_repair: 0,
            comp_put_repair: 0,
            comp_get_audit: 0,
            surge_percent: 0,
            held: 250,
            owed: 0,
            disposed: 25,
            paid: 100,
            distributed: 10,
        }
    }

    fn sample_payment(
        period: Timestamp,
        created: Timestamp,
    ) -> crate::heldamount::GetPaymentResponse {
        crate::heldamount::GetPaymentResponse {
            node_id: Vec::new(),
            created_at: Some(created),
            period: Some(period),
            amount: 100,
            receipt: "rcpt".into(),
            notes: String::new(),
            id: 3,
        }
    }

    fn sample_stats(joined: Timestamp) -> crate::nodestats::GetStatsResponse {
        let audit = crate::nodestats::ReputationStats {
            reputation_score: 0.98,
            unknown_reputation_score: 0.97,
            ..Default::default()
        };
        let uptime = crate::nodestats::ReputationStats {
            reputation_score: 0.5,
            unknown_reputation_score: 0.4,
            ..Default::default()
        };
        crate::nodestats::GetStatsResponse {
            uptime_check: Some(uptime),
            audit_check: Some(audit),
            disqualified: None,
            suspended: Some(Timestamp {
                seconds: 1_700_000_060,
                nanos: 0,
            }),
            joined_at: Some(joined),
            offline_suspended: None,
            online_score: 0.995,
            offline_under_review: None,
            vetted_at: Some(Timestamp {
                seconds: 1_700_000_120,
                nanos: 0,
            }),
            audit_history: Some(crate::nodestats::AuditHistory {
                windows: Vec::new(),
                score: 0.91,
            }),
        }
    }
}
