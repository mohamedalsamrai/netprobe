//! Human-readable output for the CLI.

use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::Duration;

use netprobe_core::Record;
use netprobe_core::model::{DirectionData, ProbeData, flag};
use netprobe_core::stats::{mean, round2};
use serde::Serialize;
use time::macros::format_description;
use time::{OffsetDateTime, UtcOffset};

static LOCAL_OFFSET: OnceLock<UtcOffset> = OnceLock::new();

/// Must run while the process is still single-threaded (a requirement of `time`).
pub fn init_local_offset() {
    let _ = LOCAL_OFFSET.set(UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC));
}

pub fn local_time(ts: OffsetDateTime) -> String {
    let local = ts.to_offset(*LOCAL_OFFSET.get().unwrap_or(&UtcOffset::UTC));
    local.format(format_description!("[year]-[month]-[day] [hour]:[minute]:[second]")).unwrap_or_default()
}

pub fn human_duration(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0..60 => format!("{s}s"),
        60..3600 => format!("{}m", s / 60),
        3600..86400 => format!("{}h {}m", s / 3600, s % 3600 / 60),
        _ => format!("{}d {}h", s / 86400, s % 86400 / 3600),
    }
}

fn age(ts: OffsetDateTime) -> Duration {
    (OffsetDateTime::now_utc() - ts).try_into().unwrap_or_default()
}

fn ms(v: Option<f64>) -> String {
    v.map_or_else(|| "-".into(), |x| format!("{x:.1}"))
}

fn pct(v: Option<f64>) -> String {
    v.map_or_else(|| "-".into(), |x| format!("{x:.1}%"))
}

fn mb(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / 1e6)
}

/// One line per record, used in logs and `netprobe history`.
pub fn summary_line(r: &Record) -> String {
    let body = match &r.data {
        ProbeData::Latency(d) => format!(
            "median {} ms  p95 {}  jitter {}  loss {:.1}%  ({} {}/{})",
            ms(d.rtt_ms.map(|x| x.median)),
            ms(d.rtt_ms.map(|x| x.p95)),
            ms(d.jitter_ms.map(|j| j.ipdv)),
            d.loss_pct.total,
            d.method,
            d.received,
            d.sent
        ),
        ProbeData::Dns(_) if r.has_flag(flag::OUTAGE) => "line down (outage)".into(),
        ProbeData::Dns(d) if r.target.as_deref() == Some("system") => {
            format!("getaddrinfo {} ms  failed {}/{}", ms(d.cached_ms), d.failed, d.total)
        }
        ProbeData::Dns(d) => format!(
            "cached {} ms  uncached {} ms  failed {}/{}",
            ms(d.cached_ms),
            ms(d.uncached_ms),
            d.failed,
            d.total
        ),
        ProbeData::Connection(d) => match &d.error {
            Some(e) => format!("error: {e}"),
            None => format!(
                "tcp {}  tls {}  ttfb {}  total {} ms",
                ms(d.tcp_ms),
                ms(d.tls_ms),
                ms(d.ttfb_ms),
                ms(d.total_ms)
            ),
        },
        ProbeData::Throughput(d) => match (&d.error, &d.download) {
            (Some(e), None) => format!("error: {e}"),
            _ => format!(
                "down {} Mbps  up {} Mbps  loaded latency {}/{} ms  retrans {}/{}  {}",
                ms(d.download.as_ref().map(|x| x.mbps)),
                ms(d.upload.as_ref().map(|x| x.mbps)),
                ms(d.download.as_ref().and_then(|x| x.loaded_latency_ms).map(|l| l.median)),
                ms(d.upload.as_ref().and_then(|x| x.loaded_latency_ms).map(|l| l.median)),
                pct(d.download.as_ref().and_then(|x| x.retrans_pct)),
                pct(d.upload.as_ref().and_then(|x| x.retrans_pct)),
                mb(d.bytes_total)
            ),
        },
        ProbeData::TcpSystem(d) => format!("retrans {} of {} segments", pct(d.retrans_pct), d.sent_segments),
    };
    let flags = if r.flags.is_empty() { String::new() } else { format!("  [{}]", r.flags.join(", ")) };
    format!("{:<10} {:<24} {body}{flags}", r.probe(), r.target.as_deref().unwrap_or("-"))
}

/// Detailed output for `netprobe once`.
pub fn print_records(records: &[Record]) {
    let mut current = "";
    for r in records {
        if r.probe() != current {
            current = r.probe();
            println!("\n{}", current.to_uppercase().replace('_', " "));
        }
        let target = r.target.as_deref().unwrap_or("-");
        let flags = if r.flags.is_empty() { String::new() } else { format!("  [{}]", r.flags.join(", ")) };
        match &r.data {
            ProbeData::Latency(d) => {
                let label = if target == d.addr { target.to_string() } else { format!("{target} ({})", d.addr) };
                match (d.rtt_ms, d.jitter_ms) {
                    (Some(rtt), jitter) => println!(
                        "  {label:<26} median {:.1} ms · p95 {:.1} · min {:.1} · max {:.1} · jitter {} (rfc3550 {}) · loss {:.1}% ({}/{} {}{}){flags}",
                        rtt.median,
                        rtt.p95,
                        rtt.min,
                        rtt.max,
                        ms(jitter.map(|j| j.ipdv)),
                        ms(jitter.map(|j| j.rfc3550)),
                        d.loss_pct.total,
                        d.received,
                        d.sent,
                        d.method,
                        if d.late > 0 { format!(", {} late", d.late) } else { String::new() }
                    ),
                    (None, _) => println!("  {label:<26} no replies · loss {:.1}% ({}){flags}", d.loss_pct.total, d.method),
                }
            }
            ProbeData::Dns(d) => {
                if r.has_flag(flag::OUTAGE) {
                    println!("  {target:<26} skipped: line is down");
                    continue;
                }
                if target == "system" {
                    println!("  {target:<26} getaddrinfo {} ms · failed {}/{}{flags}", ms(d.cached_ms), d.failed, d.total);
                } else {
                    println!(
                        "  {target:<26} cached {} ms · uncached {} ms · failed {}/{}{flags}",
                        ms(d.cached_ms),
                        ms(d.uncached_ms),
                        d.failed,
                        d.total
                    );
                }
                let detail: Vec<String> = d
                    .queries
                    .iter()
                    .map(|q| format!("{} {:?} {}", q.name, q.outcome, ms(q.ms)).to_lowercase())
                    .collect();
                println!("  {:<26} {}", "", detail.join(" | "));
            }
            ProbeData::Connection(d) => match &d.error {
                Some(e) => println!("  {target:<26} error: {e}"),
                None => println!(
                    "  {target:<26} dns {} · tcp {} · tls {} · ttfb {} · total {} ms · {} {} · HTTP {}{flags}",
                    ms(d.dns_ms),
                    ms(d.tcp_ms),
                    ms(d.tls_ms),
                    ms(d.ttfb_ms),
                    ms(d.total_ms),
                    d.tls_version.as_deref().unwrap_or("plain"),
                    d.cipher.as_deref().unwrap_or(""),
                    d.http_status.map_or("-".into(), |s| s.to_string())
                ),
            },
            ProbeData::Throughput(d) => {
                println!("  server {target}{}{flags}", d.colo.as_ref().map(|c| format!(" (colo {c})")).unwrap_or_default());
                if let Some(e) = &d.error {
                    println!("  error: {e}");
                }
                println!("  idle latency  {} ms", ms(d.idle_latency_ms));
                for (name, dir) in [("download", &d.download), ("upload", &d.upload)] {
                    if let Some(x) = dir {
                        print_direction(name, x);
                    }
                }
                println!(
                    "  total {} in {:.1} s · cpu {}",
                    mb(d.bytes_total),
                    d.duration_s,
                    d.cpu_pct.map_or("-".into(), |c| format!("{c:.0}%"))
                );
            }
            ProbeData::TcpSystem(d) => {
                println!("  retransmissions {} of {} segments in {:.0} s", pct(d.retrans_pct), d.sent_segments, d.interval_s)
            }
        }
    }
}

fn print_direction(name: &str, d: &DirectionData) {
    println!(
        "  {name:<12}  {:.2} Mbps (p90 {:.2}) · {} streams · {} · {:.1} s{}{}",
        d.mbps,
        d.mbps_p90,
        d.streams,
        mb(d.bytes),
        d.duration_s,
        if d.stable { " · stable" } else { "" },
        if d.errors > 0 { format!(" · {} stream errors", d.errors) } else { String::new() }
    );
    let loaded = d.loaded_latency_ms.map_or_else(
        || "-".into(),
        |l| format!("{:.1} ms median, {:.1} p90 ({} samples, {} lost)", l.median, l.p90, l.samples, l.lost),
    );
    let mut extra = vec![format!("loaded latency {loaded}")];
    if let Some(b) = d.bufferbloat_ms {
        extra.push(format!("bufferbloat {b:+.1} ms"));
    }
    extra.push(format!("retrans {}", pct(d.retrans_pct)));
    if let Some(o) = d.rx_out_of_order_pct {
        extra.push(format!("out-of-order {o:.2}%"));
    }
    if let Some(b) = d.background_pct {
        extra.push(format!("background {b:.1}%"));
    }
    println!("  {:<12}  {}", "", extra.join(" · "));
}

// ---- netprobe status ----

#[derive(Debug, Serialize)]
pub struct Status {
    pub version: &'static str,
    pub service: String,
    pub data_dir: String,
    pub network: Option<NetworkStatus>,
    pub latency: Vec<LatencyRow>,
    pub dns: Vec<DnsRow>,
    pub connection: Vec<ConnRow>,
    pub speed: Option<SpeedRow>,
    pub speed_data_24h_mb: f64,
    pub daily_cap_mb: u64,
    pub tcp_retrans_1h_pct: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct NetworkStatus {
    pub interface: Option<String>,
    pub link: Option<String>,
    pub gateway: Option<String>,
    pub network_id: Option<String>,
    pub metered: bool,
    pub on_battery: bool,
}

#[derive(Debug, Serialize)]
pub struct LatencyRow {
    pub target: String,
    pub addr: String,
    pub median_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub loss_pct: f64,
    pub median_1h_ms: Option<f64>,
    pub loss_1h_pct: Option<f64>,
    pub loss_24h_pct: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct DnsRow {
    pub target: String,
    pub cached_ms: Option<f64>,
    pub uncached_ms: Option<f64>,
    pub fail_1h_pct: Option<f64>,
    pub fail_24h_pct: Option<f64>,
    pub outages_24h: u32,
}

#[derive(Debug, Serialize)]
pub struct ConnRow {
    pub target: String,
    pub tcp_ms: Option<f64>,
    pub tls_ms: Option<f64>,
    pub ttfb_ms: Option<f64>,
    pub total_ms: Option<f64>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SpeedRow {
    pub age_s: u64,
    pub colo: Option<String>,
    pub idle_latency_ms: Option<f64>,
    pub download: Option<DirectionData>,
    pub upload: Option<DirectionData>,
    pub flags: Vec<String>,
    pub error: Option<String>,
}

/// Groups records (newest first) by target, keeping first-seen order.
fn by_target<'a>(records: &'a [Record], probe: &str) -> Vec<(String, Vec<&'a Record>)> {
    let mut order: Vec<String> = Vec::new();
    let mut groups: BTreeMap<String, Vec<&Record>> = BTreeMap::new();
    for r in records.iter().filter(|r| r.probe() == probe) {
        let t = r.target.clone().unwrap_or_default();
        if !groups.contains_key(&t) {
            order.push(t.clone());
        }
        groups.entry(t).or_default().push(r);
    }
    // the gateway first and the OS resolver last; everything else by name
    order.sort_by_key(|t| (if t == "gateway" { 0 } else if t == "system" { 2 } else { 1 }, t.clone()));
    order.into_iter().map(|t| (t.clone(), groups.remove(&t).unwrap_or_default())).collect()
}

fn within(r: &Record, d: Duration) -> bool {
    age(r.ts) <= d
}

const HOUR: Duration = Duration::from_secs(3600);
const DAY: Duration = Duration::from_secs(86400);

pub struct Sections {
    pub latency: Vec<LatencyRow>,
    pub dns: Vec<DnsRow>,
    pub connection: Vec<ConnRow>,
    pub speed: Option<SpeedRow>,
    pub tcp_retrans_1h_pct: Option<f64>,
}

/// Builds the status sections from the last 24 hours of records (newest first).
pub fn build_status(records: &[Record], last_speed: Option<&Record>) -> Sections {
    let latency = by_target(records, "latency")
        .into_iter()
        .filter_map(|(target, rs)| {
            let ProbeData::Latency(last) = &rs.first()?.data else { return None };
            let hour: Vec<_> = rs.iter().filter(|r| within(r, HOUR)).collect();
            let loss = |set: &[&&Record]| {
                let (sent, recv) = set.iter().fold((0u32, 0u32), |(s, v), r| match &r.data {
                    ProbeData::Latency(d) => (s + d.sent, v + d.received),
                    _ => (s, v),
                });
                (sent > 0).then(|| round2(netprobe_core::stats::loss_pct(sent, recv)))
            };
            let medians: Vec<f64> = hour
                .iter()
                .filter_map(|r| match &r.data {
                    ProbeData::Latency(d) => d.rtt_ms.map(|x| x.median),
                    _ => None,
                })
                .collect();
            let day: Vec<_> = rs.iter().collect();
            Some(LatencyRow {
                target,
                addr: last.addr.clone(),
                median_ms: last.rtt_ms.map(|x| x.median),
                p95_ms: last.rtt_ms.map(|x| x.p95),
                jitter_ms: last.jitter_ms.map(|j| j.ipdv),
                loss_pct: last.loss_pct.total,
                median_1h_ms: mean(&medians).map(round2),
                loss_1h_pct: loss(&hour),
                loss_24h_pct: loss(&day),
            })
        })
        .collect();

    let dns = by_target(records, "dns")
        .into_iter()
        .map(|(target, rs)| {
            let fail = |d: Duration| {
                let (total, failed) = rs
                    .iter()
                    .filter(|r| within(r, d) && !r.has_flag(flag::OUTAGE))
                    .fold((0u32, 0u32), |(t, f), r| match &r.data {
                        ProbeData::Dns(x) => (t + x.total, f + x.failed),
                        _ => (t, f),
                    });
                (total > 0).then(|| round2(f64::from(failed) / f64::from(total) * 100.0))
            };
            let last_ok = rs.iter().find(|r| !r.has_flag(flag::OUTAGE));
            let (cached_ms, uncached_ms) = match last_ok.map(|r| &r.data) {
                Some(ProbeData::Dns(d)) => (d.cached_ms, d.uncached_ms),
                _ => (None, None),
            };
            DnsRow {
                target,
                cached_ms,
                uncached_ms,
                fail_1h_pct: fail(HOUR),
                fail_24h_pct: fail(DAY),
                outages_24h: rs.iter().filter(|r| r.has_flag(flag::OUTAGE)).count() as u32,
            }
        })
        .collect();

    let connection = by_target(records, "connection")
        .into_iter()
        .filter_map(|(target, rs)| match &rs.first()?.data {
            ProbeData::Connection(d) => Some(ConnRow {
                target,
                tcp_ms: d.tcp_ms,
                tls_ms: d.tls_ms,
                ttfb_ms: d.ttfb_ms,
                total_ms: d.total_ms,
                error: d.error.clone(),
            }),
            _ => None,
        })
        .collect();

    let speed = last_speed.and_then(|r| match &r.data {
        ProbeData::Throughput(d) => Some(SpeedRow {
            age_s: age(r.ts).as_secs(),
            colo: d.colo.clone(),
            idle_latency_ms: d.idle_latency_ms,
            download: d.download.clone(),
            upload: d.upload.clone(),
            flags: r.flags.clone(),
            error: d.error.clone(),
        }),
        _ => None,
    });

    let (sent, retrans) = records
        .iter()
        .filter(|r| within(r, HOUR))
        .fold((0u64, 0u64), |(s, x), r| match &r.data {
            ProbeData::TcpSystem(d) => (s + d.sent_segments, x + d.retrans_segments),
            _ => (s, x),
        });
    let tcp_retrans_1h_pct = netprobe_core::stats::ratio_pct(retrans as f64, sent as f64).map(round2);
    Sections { latency, dns, connection, speed, tcp_retrans_1h_pct }
}

pub fn print_status(s: &Status) {
    println!("netprobe {} · service: {}", s.version, s.service);
    println!("data: {}", s.data_dir);
    if let Some(n) = &s.network {
        let mut parts = vec![format!(
            "{} ({})",
            n.interface.as_deref().unwrap_or("no interface"),
            n.link.as_deref().unwrap_or("?")
        )];
        if let Some(g) = &n.gateway {
            parts.push(format!("gateway {g}"));
        }
        if let Some(id) = &n.network_id {
            parts.push(format!("id {id}"));
        }
        if n.metered {
            parts.push("metered".into());
        }
        if n.on_battery {
            parts.push("on battery".into());
        }
        println!("network: {}", parts.join(" · "));
    }

    if !s.latency.is_empty() {
        println!("\nLATENCY (last run; 1h / 24h)    median     p95  jitter    loss  │ 1h median  1h loss  24h loss");
        for r in &s.latency {
            let label = if r.target == r.addr { r.target.clone() } else { format!("{} {}", r.target, r.addr) };
            println!(
                "  {label:<29} {:>7} {:>7} {:>7} {:>7}  │ {:>9} {:>8} {:>9}",
                ms(r.median_ms),
                ms(r.p95_ms),
                ms(r.jitter_ms),
                pct(Some(r.loss_pct)),
                ms(r.median_1h_ms),
                pct(r.loss_1h_pct),
                pct(r.loss_24h_pct)
            );
        }
    }
    if !s.dns.is_empty() {
        println!("\nDNS (ms)                         cached  uncached  fail 1h  fail 24h  outages 24h");
        for r in &s.dns {
            println!(
                "  {:<29} {:>7} {:>9} {:>8} {:>9} {:>12}",
                r.target,
                ms(r.cached_ms),
                ms(r.uncached_ms),
                pct(r.fail_1h_pct),
                pct(r.fail_24h_pct),
                r.outages_24h
            );
        }
    }
    if !s.connection.is_empty() {
        println!("\nCONNECTION (last run, ms)           tcp      tls     ttfb    total");
        for r in &s.connection {
            match &r.error {
                Some(e) => println!("  {:<29} error: {e}", r.target),
                None => println!(
                    "  {:<29} {:>8} {:>8} {:>8} {:>8}",
                    r.target,
                    ms(r.tcp_ms),
                    ms(r.tls_ms),
                    ms(r.ttfb_ms),
                    ms(r.total_ms)
                ),
            }
        }
    }
    println!();
    match &s.speed {
        None => println!("SPEED  no speed test yet"),
        Some(sp) => {
            println!(
                "SPEED (last test {} ago{}){}",
                human_duration(Duration::from_secs(sp.age_s)),
                sp.colo.as_ref().map(|c| format!(", colo {c}")).unwrap_or_default(),
                if sp.flags.is_empty() { String::new() } else { format!("  [{}]", sp.flags.join(", ")) }
            );
            if let Some(e) = &sp.error {
                println!("  error: {e}");
            }
            println!("  idle latency  {} ms", ms(sp.idle_latency_ms));
            for (name, dir) in [("download", &sp.download), ("upload", &sp.upload)] {
                if let Some(d) = dir {
                    print_direction(name, d);
                }
            }
        }
    }
    println!("  data used by speed tests (24h): {:.0} / {} MB", s.speed_data_24h_mb, s.daily_cap_mb);
    if let Some(t) = s.tcp_retrans_1h_pct {
        println!("\nTCP retransmissions, whole system (1h): {t:.2}%");
    }
}
