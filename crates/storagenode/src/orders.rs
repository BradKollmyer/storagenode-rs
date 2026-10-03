//! Bandwidth orders and `Orders.SettlementWithWindow`.
//!
//! Each finished upload or download keeps the largest uplink order for that
//! serial. Rows share `pieces.db` with the piece index and are grouped by
//! satellite and by the UTC hour of `OrderCreation`.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use prost::Message;
use s3store::{OrderRows, StoredOrder};
use storj_proto::orders::{Order, OrderLimit, SettlementRequest, SettlementWithWindowResponse};
use storj_rpc::transport::{self, TransportMode};
use storj_rpc::{Conn, Identity, NodeId};

/// `/orders.Orders/SettlementWithWindow`.
pub(crate) const SETTLEMENT_WITH_WINDOW: &str = "/orders.Orders/SettlementWithWindow";

/// How far `OrderCreation` may sit from now. Matches `OrderLimitGracePeriod`.
pub(crate) const ORDER_LIMIT_GRACE: Duration = Duration::from_secs(60 * 60);

/// Go `orders.Config.SenderInterval`.
pub(crate) const SEND_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Go `orders.Config.MaxSleep`. The delay is shorter than this, or zero.
pub(crate) const SEND_JITTER: Duration = Duration::from_secs(30);

/// Go `orders.Config.ArchiveTTL` (168h).
const ARCHIVE_KEEP: Duration = Duration::from_secs(7 * 24 * 60 * 60);

const HOUR: Duration = Duration::from_secs(60 * 60);

/// `SettlementWithWindowResponse.Status`.
const ACCEPTED: i32 = 0;
const REJECTED: i32 = 1;

/// Dial budget for one satellite (`SenderDialTimeout`).
const DIAL_TIMEOUT: Duration = Duration::from_secs(60);

/// In-flight uploads and downloads, keyed by satellite and creation hour.
///
/// Process-local, like the Go node's active map. A crash drops the count
/// and the order that had not been saved yet.
#[derive(Clone)]
struct Flight {
    counts: Arc<Mutex<HashMap<(NodeId, i64), usize>>>,
}

impl Flight {
    fn new() -> Self {
        Self {
            counts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(NodeId, i64), usize>> {
        self.counts.lock().unwrap_or_else(|err| err.into_inner())
    }

    fn add(&self, satellite: NodeId, window: i64) {
        let mut counts = self.lock();
        *counts.entry((satellite, window)).or_default() += 1;
    }

    fn end(counts: &mut HashMap<(NodeId, i64), usize>, satellite: NodeId, window: i64) {
        let key = (satellite, window);
        let Some(n) = counts.get_mut(&key) else {
            return;
        };
        *n = n.saturating_sub(1);
        if *n == 0 {
            counts.remove(&key);
        }
    }

    fn busy(counts: &HashMap<(NodeId, i64), usize>, satellite: NodeId, window: i64) -> bool {
        counts.get(&(satellite, window)).copied().unwrap_or(0) > 0
    }

    #[cfg(test)]
    fn total(&self) -> usize {
        self.lock().values().copied().sum()
    }
}

pub(crate) struct Orders {
    flight: Flight,
}

impl Orders {
    pub(crate) fn new() -> Self {
        Self {
            flight: Flight::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn in_flight(&self) -> usize {
        self.flight.total()
    }

    /// The hour stays unsendable until the guard drops.
    pub(crate) fn begin(
        &self,
        db: OrderRows,
        satellite: NodeId,
        window: i64,
        limit: OrderLimit,
    ) -> OrderGuard {
        self.flight.add(satellite, window);
        OrderGuard {
            flight: self.flight.clone(),
            db,
            satellite,
            satellite_id: satellite.to_string(),
            window,
            limit,
            best: None,
        }
    }

    /// Sends every closed idle hour. Dial and RPC errors leave the hour unsent.
    pub(crate) async fn settle(
        &self,
        identity: &Identity,
        db: &OrderRows,
        address_of: impl Fn(NodeId) -> Option<String>,
        now: SystemTime,
    ) {
        let cutoff = now.checked_sub(ARCHIVE_KEEP).unwrap_or(UNIX_EPOCH);
        if let Err(err) = db.delete_archived_before(cutoff) {
            eprintln!("storagenode: delete archived orders: {err}");
        }
        let windows = match db.unsent_windows() {
            Ok(windows) => windows,
            Err(err) => {
                eprintln!("storagenode: list orders: {err}");
                return;
            }
        };
        let mut failed = HashSet::new();
        for (satellite_id, window) in windows {
            if !window_closed(window, now) {
                continue;
            }
            let Ok(satellite) = satellite_id.parse::<NodeId>() else {
                eprintln!("storagenode: order satellite id {satellite_id} is not a node id");
                continue;
            };
            if failed.contains(&satellite) {
                continue;
            }
            // Busy means an upload or download in this hour has not saved its
            // final order yet. Sending now would archive a partial window.
            let Some(orders) = self.idle_orders(db, &satellite_id, satellite, window) else {
                continue;
            };
            if orders.is_empty() {
                continue;
            }
            match address_of(satellite) {
                None => self.archive(db, &orders, REJECTED, now),
                Some(address) if address.is_empty() => {
                    failed.insert(satellite);
                }
                Some(address) => {
                    // One corrupt blob is this node's row, not a satellite
                    // outage. Archiving it here lets the rest of the hour,
                    // and every later hour, still be sent.
                    let (good, bad) = split_decodable(orders);
                    if !bad.is_empty() {
                        eprintln!(
                            "storagenode: archived {} undecodable order(s) for {satellite} hour {window}",
                            bad.len()
                        );
                        self.archive(db, &bad, REJECTED, now);
                    }
                    if good.is_empty() {
                        continue;
                    }
                    match settle_window(identity, &address, satellite, &good).await {
                        Ok(status) => self.archive(db, &good, status, now),
                        Err(err) => {
                            eprintln!(
                                "storagenode: settlement for {satellite} hour {window} left unsent: {err}"
                            );
                            failed.insert(satellite);
                        }
                    }
                }
            }
        }
    }

    /// `None` when the hour is busy or the read failed. Failure leaves it unsent.
    fn idle_orders(
        &self,
        db: &OrderRows,
        satellite_id: &str,
        satellite: NodeId,
        window: i64,
    ) -> Option<Vec<StoredOrder>> {
        let counts = self.flight.lock();
        if Flight::busy(&counts, satellite, window) {
            return None;
        }
        match db.window(satellite_id, window) {
            Ok(orders) => Some(orders),
            Err(err) => {
                eprintln!("storagenode: read order window: {err}");
                None
            }
        }
    }

    fn archive(&self, db: &OrderRows, orders: &[StoredOrder], status: i32, now: SystemTime) {
        for order in orders {
            // Archiving is bookkeeping. A failure must not look like a dial
            // error, or the next pass would submit an accepted window again
            // only for the serials that did get marked.
            if let Err(err) = db.archive(&order.satellite, &order.serial, status, now) {
                eprintln!("storagenode: archive order: {err}");
            }
        }
    }
}

/// Holds one piecestore RPC's place in the hour until the largest order is saved.
pub(crate) struct OrderGuard {
    flight: Flight,
    db: OrderRows,
    satellite: NodeId,
    satellite_id: String,
    window: i64,
    limit: OrderLimit,
    best: Option<Order>,
}

impl OrderGuard {
    /// Keeps `order` when its amount is the largest seen for this serial.
    pub(crate) fn note(&mut self, order: &Order) {
        if order.amount <= 0 {
            return;
        }
        let replace = self
            .best
            .as_ref()
            .is_none_or(|best| order.amount > best.amount);
        if replace {
            self.best = Some(order.clone());
        }
    }
}

impl Drop for OrderGuard {
    fn drop(&mut self) {
        // Save before releasing the hour. Settlement holds this lock while it
        // reads, so it cannot archive a window that is missing this order.
        let mut counts = self.flight.lock();
        if let Some(order) = self.best.take() {
            let row = StoredOrder {
                satellite: self.satellite_id.clone(),
                serial: order.serial_number.clone(),
                window_start: self.window,
                limit: self.limit.encode_to_vec(),
                order: order.encode_to_vec(),
                amount: order.amount,
            };
            // The piece is already committed by the time a successful RPC
            // drops this guard. Losing the order row must not surface as a
            // failed upload or download.
            if let Err(err) = self.db.save(&row) {
                eprintln!("storagenode: save order: {err}");
            }
        }
        Flight::end(&mut counts, self.satellite, self.window);
    }
}

/// `true` once the hour can no longer accept a new order.
///
/// The newest creation time in hour H is just before H+1h, and creation is
/// refused once it is more than [`ORDER_LIMIT_GRACE`] ago. The window is
/// closed only after both have passed.
fn window_closed(window_start: i64, now: SystemTime) -> bool {
    let Ok(start) = u64::try_from(window_start) else {
        return false;
    };
    let Some(opened) = UNIX_EPOCH.checked_add(Duration::from_secs(start)) else {
        return false;
    };
    let Some(deadline) = opened.checked_add(HOUR + ORDER_LIMIT_GRACE) else {
        return false;
    };
    now > deadline
}

async fn settle_window(
    identity: &Identity,
    address: &str,
    satellite: NodeId,
    orders: &[StoredOrder],
) -> Result<i32, String> {
    let requests = decode_orders(orders)?;
    let transport = transport::dial(
        identity,
        satellite,
        address,
        TransportMode::Tcp,
        DIAL_TIMEOUT,
        None,
    )
    .await
    .map_err(|err| err.to_string())?;
    let mut conn = Conn::new(transport);
    let mut stream = conn
        .open_stream(SETTLEMENT_WITH_WINDOW)
        .await
        .map_err(|err| err.to_string())?;
    for request in &requests {
        conn.send_msg(&mut stream, &request.encode_to_vec())
            .await
            .map_err(|err| err.to_string())?;
    }
    conn.close_send(&mut stream)
        .await
        .map_err(|err| err.to_string())?;
    let bytes = conn
        .recv_msg(&stream)
        .await
        .map_err(|err| err.to_string())?;
    let response =
        SettlementWithWindowResponse::decode(bytes.as_slice()).map_err(|err| err.to_string())?;
    match response.status {
        ACCEPTED | REJECTED => Ok(response.status),
        other => Err(format!("unexpected settlement status {other}")),
    }
}

/// Corrupt rows are separated so one of them cannot hold the satellite's later hours.
fn split_decodable(orders: Vec<StoredOrder>) -> (Vec<StoredOrder>, Vec<StoredOrder>) {
    let mut good = Vec::new();
    let mut bad = Vec::new();
    for order in orders {
        let limit_ok = OrderLimit::decode(order.limit.as_slice()).is_ok();
        let order_ok = Order::decode(order.order.as_slice()).is_ok();
        if limit_ok && order_ok {
            good.push(order);
        } else {
            bad.push(order);
        }
    }
    (good, bad)
}

fn decode_orders(orders: &[StoredOrder]) -> Result<Vec<SettlementRequest>, String> {
    let mut requests = Vec::with_capacity(orders.len());
    for order in orders {
        let limit = OrderLimit::decode(order.limit.as_slice()).map_err(|err| err.to_string())?;
        let signed = Order::decode(order.order.as_slice()).map_err(|err| err.to_string())?;
        requests.push(SettlementRequest {
            limit: Some(limit),
            order: Some(signed),
        });
    }
    Ok(requests)
}

/// Uniform delay in `[0, SEND_JITTER)`.
pub(crate) fn jitter(node: NodeId) -> Duration {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut x = now.as_secs() ^ u64::from(now.subsec_nanos());
    for byte in node.as_bytes() {
        x = x
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(u64::from(*byte));
    }
    Duration::from_millis(x % SEND_JITTER.as_millis().try_into().unwrap_or(30_000))
}
