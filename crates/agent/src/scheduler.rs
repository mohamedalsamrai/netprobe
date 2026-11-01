//! Section 6: light probes run continuously, the speed test is gated by data budget,
//! metered networks, battery and background traffic.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use netprobe_core::Record;
use netprobe_core::model::ProbeData;
use netprobe_storage::{DAY_MS, RecordQuery, Store};
use rand::Rng;
use time::OffsetDateTime;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{Instant, MissedTickBehavior};

use crate::agent::{Agent, MB};
use crate::report;

type SharedStore = Arc<Mutex<Store>>;

const TCP_SYSTEM_INTERVAL: Duration = Duration::from_secs(300);
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(3600);
const NETWORK_WATCH_INTERVAL: Duration = Duration::from_secs(30);
/// Retry delay when the speed test is held back by something likely to change soon.
const SPEEDTEST_RETRY: Duration = Duration::from_secs(30 * 60);
const BUSY_RETRY: Duration = Duration::from_secs(10 * 60);
const BUSY_MAX_POSTPONES: u32 = 3;
const BUSY_SAMPLE: Duration = Duration::from_secs(3);
/// Background traffic threshold when there is no previous speed test to compare with.
const BUSY_FALLBACK_MBPS: f64 = 1.0;
const MIN_TEST_BUDGET: u64 = 20 * MB;

pub async fn run(agent: Arc<Agent>, store: SharedStore, mut shutdown: watch::Receiver<bool>) {
    if !wait_for_network(&agent, &mut shutdown).await {
        return;
    }
    tracing::info!("network is up, starting probes");

    let mut set = JoinSet::new();
    let c = &agent.cfg;
    let light = [
        ("latency", c.latency.interval_secs),
        ("dns", c.dns.interval_secs),
        ("connection", c.connection.interval_secs),
    ];
    for (name, secs) in light {
        let (agent, store) = (agent.clone(), store.clone());
        set.spawn(every(Duration::from_secs(secs.max(10)), shutdown.clone(), move || {
            let (agent, store) = (agent.clone(), store.clone());
            async move {
                let records = match name {
                    "latency" => agent.run_latency().await,
                    "dns" => agent.run_dns().await,
                    _ => agent.run_connection().await,
                };
                save(&store, &records);
            }
        }));
    }
    set.spawn(throughput_loop(agent.clone(), store.clone(), shutdown.clone()));
    set.spawn(tcp_system_loop(agent.clone(), store.clone(), shutdown.clone()));
    set.spawn(maintenance_loop(agent.clone(), store.clone(), shutdown.clone()));
    set.spawn(network_watch(agent.clone(), shutdown.clone()));

    stopped(&mut shutdown).await;
    // let in-flight probes finish their writes, but don't hold up launchd for long
    let _ = tokio::time::timeout(Duration::from_secs(5), set.join_all()).await;
}

/// Waits for a default route and working DNS, backing off from 1 s to 60 s.
async fn wait_for_network(agent: &Agent, shutdown: &mut watch::Receiver<bool>) -> bool {
    let mut delay = Duration::from_secs(1);
    loop {
        let route = agent.platform.default_gateway().is_some();
        let dns = route && tokio::net::lookup_host(("www.apple.com", 443)).await.is_ok();
        if dns {
            return true;
        }
        tracing::info!(route, "waiting for the network");
        if sleep_or_shutdown(delay, shutdown).await {
            return false;
        }
        delay = (delay * 2).min(Duration::from_secs(60));
    }
}

/// Runs `f` every `period`, starting after a random offset so probes don't line up.
async fn every<F, Fut>(period: Duration, mut shutdown: watch::Receiver<bool>, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    let offset = rand::rng().random_range(Duration::ZERO..period.min(Duration::from_secs(20)));
    if sleep_or_shutdown(offset, &mut shutdown).await {
        return;
    }
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = stopped(&mut shutdown) => return,
        }
        f().await;
    }
}

/// Returns true if shutdown was requested while sleeping.
async fn sleep_or_shutdown(d: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(d) => false,
        _ = stopped(shutdown) => true,
    }
}

/// Resolves once shutdown has been requested.
async fn stopped(shutdown: &mut watch::Receiver<bool>) {
    let _ = shutdown.wait_for(|s| *s).await;
}

fn save(store: &SharedStore, records: &[Record]) {
    for r in records {
        tracing::debug!("{}", report::summary_line(r));
    }
    if let Err(e) = store.lock().unwrap().insert_all(records) {
        tracing::error!(error = %e, "could not save results");
    }
}

enum Gate {
    Run { cap: u64 },
    Retry { reason: String, after: Duration },
}

async fn throughput_loop(agent: Arc<Agent>, store: SharedStore, mut shutdown: watch::Receiver<bool>) {
    let c = &agent.cfg.throughput;
    if !c.enabled {
        return;
    }
    let interval = Duration::from_secs_f64((c.interval_hours * 3600.0).max(600.0));
    let jitter = Duration::from_secs(c.jitter_minutes * 60);
    let next_slot = || {
        let j = if jitter.is_zero() { 0.0 } else { rand::rng().random_range(-1.0..=1.0) * jitter.as_secs_f64() };
        Instant::now() + Duration::from_secs_f64((interval.as_secs_f64() + j).max(60.0))
    };

    // continue the schedule across restarts, so a crash loop can't burn through data
    let last = store.lock().unwrap().last_ts_ms("throughput").ok().flatten();
    let mut next = match last {
        Some(ts) => {
            let since = Duration::from_millis((now_ms() - ts).max(0) as u64);
            Instant::now() + interval.saturating_sub(since)
        }
        None => Instant::now() + Duration::from_secs(120) + rand::rng().random_range(Duration::ZERO..Duration::from_secs(300)),
    };
    // and never within the first minutes after boot
    let boot_delay = Duration::from_secs(c.boot_delay_minutes * 60);
    if let Some(up) = agent.platform.uptime()
        && up < boot_delay
    {
        next = next.max(Instant::now() + (boot_delay - up));
    }

    let mut postponed = 0;
    let mut last_reason = String::new();
    loop {
        if last_reason.is_empty() {
            tracing::info!("next speed test in {}", report::human_duration(next.saturating_duration_since(Instant::now())));
        }
        tokio::select! {
            _ = tokio::time::sleep_until(next) => {}
            _ = stopped(&mut shutdown) => return,
        }
        match gate(&agent, &store, &mut postponed).await {
            Gate::Run { cap } => {
                tracing::info!(cap_mb = cap / MB, "speed test starting");
                let rec = agent.run_throughput(cap).await;
                tracing::info!("{}", report::summary_line(&rec));
                save(&store, &[rec]);
                postponed = 0;
                last_reason.clear();
                next = next_slot();
            }
            Gate::Retry { reason, after } => {
                // log each new reason once; repeats every half hour would only be noise
                let retry_in = report::human_duration(after);
                if reason != last_reason {
                    tracing::info!(%reason, "speed test postponed, retrying every {retry_in}");
                    last_reason = reason;
                } else {
                    tracing::debug!(%reason, "speed test still postponed");
                }
                next = Instant::now() + after;
            }
        }
    }
}

async fn gate(agent: &Agent, store: &SharedStore, postponed: &mut u32) -> Gate {
    let c = &agent.cfg.throughput;
    let retry = |reason: &str, after| Gate::Retry { reason: reason.into(), after };
    let snap = agent.snapshot();
    if snap.ctx.gateway.is_none() {
        return retry("no network", Duration::from_secs(300));
    }
    if c.skip_on_metered && agent.platform.is_metered() {
        return retry("metered connection (hotspot, cellular or Low Data Mode)", SPEEDTEST_RETRY);
    }
    if c.skip_on_battery && agent.platform.on_battery() {
        return retry("running on battery", SPEEDTEST_RETRY);
    }
    let (used, last) = {
        let s = store.lock().unwrap();
        let used = s.throughput_bytes_since(now_ms() - DAY_MS).unwrap_or(0);
        let q = RecordQuery { probe: Some("throughput"), limit: Some(1), ..Default::default() };
        (used, s.query(&q).ok().and_then(|mut v| v.pop()))
    };
    let remaining = (c.daily_cap_mb * MB).saturating_sub(used);
    if remaining < MIN_TEST_BUDGET {
        return retry("daily data budget used up", SPEEDTEST_RETRY);
    }

    if *postponed < BUSY_MAX_POSTPONES
        && let Some(ifname) = &snap.ctx.interface
        && let Some((rx_mbps, tx_mbps)) = background_mbps(agent, ifname).await
    {
        let (down_ref, up_ref) = last
            .and_then(|r| match r.data {
                ProbeData::Throughput(t) => Some((t.download.map(|d| d.mbps), t.upload.map(|u| u.mbps))),
                _ => None,
            })
            .unwrap_or((None, None));
        let limit = |reference: Option<f64>| {
            reference.filter(|v| *v > 0.0).map_or(BUSY_FALLBACK_MBPS, |v| v * c.busy_threshold_pct / 100.0)
        };
        if rx_mbps > limit(down_ref) || tx_mbps > limit(up_ref) {
            *postponed += 1;
            return retry(&format!("link busy ({rx_mbps:.1} Mbps in, {tx_mbps:.1} Mbps out)"), BUSY_RETRY);
        }
    }
    Gate::Run { cap: (c.per_test_cap_mb * MB).min(remaining) }
}

/// Traffic on the interface over a few seconds, in Mbps (received, sent).
async fn background_mbps(agent: &Agent, ifname: &str) -> Option<(f64, f64)> {
    let (rx0, tx0) = agent.platform.interface_bytes(ifname)?;
    tokio::time::sleep(BUSY_SAMPLE).await;
    let (rx1, tx1) = agent.platform.interface_bytes(ifname)?;
    let rate = |a: u64, b: u64| b.saturating_sub(a) as f64 * 8.0 / BUSY_SAMPLE.as_secs_f64() / 1e6;
    Some((rate(rx0, rx1), rate(tx0, tx1)))
}

async fn tcp_system_loop(agent: Arc<Agent>, store: SharedStore, mut shutdown: watch::Receiver<bool>) {
    let Some(mut prev) = agent.platform.system_tcp_counters() else {
        tracing::info!("system TCP counters are not readable (macOS needs root); per-test retransmissions are still measured");
        return;
    };
    let mut prev_at = Instant::now();
    loop {
        if sleep_or_shutdown(TCP_SYSTEM_INTERVAL, &mut shutdown).await {
            return;
        }
        let Some(cur) = agent.platform.system_tcp_counters() else { continue };
        let rec = agent.tcp_system_record(prev, cur, prev_at.elapsed());
        save(&store, &[rec]);
        prev = cur;
        prev_at = Instant::now();
    }
}

async fn maintenance_loop(agent: Arc<Agent>, store: SharedStore, mut shutdown: watch::Receiver<bool>) {
    let s = &agent.cfg.storage;
    loop {
        if sleep_or_shutdown(Duration::from_secs(60), &mut shutdown).await {
            return;
        }
        let result = {
            let mut db = store.lock().unwrap();
            db.rollup(now_ms()).and_then(|rows| Ok((rows, db.prune(now_ms(), s.raw_retention_days, s.hourly_retention_days)?)))
        };
        match result {
            Ok((rows, (raw, hourly))) => tracing::debug!(rows, raw, hourly, "rollup and prune done"),
            Err(e) => tracing::error!(error = %e, "maintenance failed"),
        }
        if sleep_or_shutdown(MAINTENANCE_INTERVAL - Duration::from_secs(60), &mut shutdown).await {
            return;
        }
    }
}

/// Logs when the machine moves to a different network (new Wi-Fi, sleep/resume).
async fn network_watch(agent: Arc<Agent>, mut shutdown: watch::Receiver<bool>) {
    let mut last = agent.snapshot().network_id;
    loop {
        if sleep_or_shutdown(NETWORK_WATCH_INTERVAL, &mut shutdown).await {
            return;
        }
        let snap = agent.snapshot();
        if snap.network_id != last {
            tracing::info!(
                network = snap.network_id.as_deref().unwrap_or("none"),
                interface = snap.ctx.interface.as_deref().unwrap_or("none"),
                gateway = ?snap.ctx.gateway,
                "network changed"
            );
            last = snap.network_id;
        }
    }
}

pub fn now_ms() -> i64 {
    (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64
}
