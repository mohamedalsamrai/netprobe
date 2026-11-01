//! Measurement records. Every probe run produces one or more `Record`s that are stored
//! locally as JSON (section 10 of the plan).

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Flags attached to a record when its numbers need context.
pub mod flag {
    /// The line was completely down; the run is not counted in failure rates.
    pub const OUTAGE: &str = "outage";
    /// ICMP got no replies and TCP connect timing was used instead.
    pub const ICMP_BLOCKED: &str = "icmp_blocked";
    /// The agent's own CPU was near its limit during a speed test.
    pub const CPU_LIMITED: &str = "cpu_limited";
    /// Significant background traffic shared the link during a speed test.
    pub const LINK_BUSY: &str = "link_busy";
    /// The per-test data cap stopped the speed test early.
    pub const CAP_REACHED: &str = "cap_reached";
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub agent_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub ts: OffsetDateTime,
    pub platform: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iface: Option<IfaceInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(flatten)]
    pub data: ProbeData,
    #[serde(default)]
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IfaceInfo {
    /// "lan" when measured from a desktop, "wan" from a router.
    pub kind: String,
    /// "wifi", "ethernet", "cellular" or "other".
    #[serde(rename = "type")]
    pub link: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "probe", rename_all = "snake_case")]
pub enum ProbeData {
    Latency(LatencyData),
    Dns(DnsData),
    Connection(ConnectionData),
    Throughput(ThroughputData),
    TcpSystem(TcpSystemData),
}

impl ProbeData {
    pub fn kind(&self) -> &'static str {
        match self {
            ProbeData::Latency(_) => "latency",
            ProbeData::Dns(_) => "dns",
            ProbeData::Connection(_) => "connection",
            ProbeData::Throughput(_) => "throughput",
            ProbeData::TcpSystem(_) => "tcp_system",
        }
    }
}

// ---- 4.1 Latency probe ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyData {
    /// The address actually probed (e.g. the gateway's IP).
    pub addr: String,
    /// "icmp" or "tcp".
    pub method: String,
    pub sent: u32,
    /// Replies received, including late ones.
    pub received: u32,
    /// Replies that arrived after the timeout.
    pub late: u32,
    pub duplicates: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<RttStats>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jitter_ms: Option<Jitter>,
    pub loss_pct: Loss,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct RttStats {
    pub min: f64,
    pub median: f64,
    pub p95: f64,
    pub max: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct Jitter {
    pub ipdv: f64,
    pub rfc3550: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct Loss {
    pub total: f64,
    /// Direction split needs our own echo server; absent until then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down: Option<f64>,
}

// ---- 4.2 DNS probe ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsData {
    pub queries: Vec<DnsQuery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uncached_ms: Option<f64>,
    pub total: u32,
    pub failed: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub name: String,
    pub kind: DnsKind,
    pub outcome: DnsOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ms: Option<f64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsKind {
    /// A popular name, most likely answered from the resolver's cache.
    Cached,
    /// A random name that forces full recursion.
    Uncached,
    /// getaddrinfo through the OS resolver (includes the OS cache).
    System,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsOutcome {
    Ok,
    Timeout,
    Servfail,
    Refused,
    Nxdomain,
    Error,
}

impl DnsOutcome {
    pub fn is_ok(self) -> bool {
        self == DnsOutcome::Ok
    }
}

// ---- 4.3 Connection probe ----

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionData {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttfb_ms: Option<f64>,
    /// From the start of the DNS lookup to the first response byte.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cipher: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ---- 4.4 Throughput test ----

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThroughputData {
    pub server: String,
    /// Data center that served the test (Cloudflare's cf-meta-colo header).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub colo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_latency_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download: Option<DirectionData>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload: Option<DirectionData>,
    pub bytes_total: u64,
    pub duration_s: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_pct: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DirectionData {
    /// Mean over the measurement window (after TCP slow start).
    pub mbps: f64,
    /// 90th percentile of the 250 ms samples.
    pub mbps_p90: f64,
    pub streams: u32,
    pub bytes: u64,
    pub duration_s: f64,
    /// Whether the rate settled before the time limit.
    pub stable: bool,
    /// Latency measured while the link was saturated (Download/Upload Latency).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loaded_latency_ms: Option<LoadedLatency>,
    /// Loaded median minus idle median.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bufferbloat_ms: Option<f64>,
    /// Sender-side retransmissions; upload only until we run our own server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrans_pct: Option<f64>,
    /// Receiver-side out-of-order bytes, a loss indicator for downloads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_out_of_order_pct: Option<f64>,
    /// Traffic on the interface that was not ours, as % of ours.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background_pct: Option<f64>,
    #[serde(default)]
    pub errors: u32,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
pub struct LoadedLatency {
    pub median: f64,
    pub p90: f64,
    pub samples: u32,
    pub lost: u32,
}

// ---- System-wide TCP counters ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpSystemData {
    pub interval_s: f64,
    pub sent_segments: u64,
    pub retrans_segments: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrans_pct: Option<f64>,
}

impl Record {
    pub fn probe(&self) -> &'static str {
        self.data.kind()
    }

    pub fn has_flag(&self, flag: &str) -> bool {
        self.flags.iter().any(|f| f == flag)
    }

    /// The headline numbers of this record, used for hourly rollups and summaries.
    pub fn metrics(&self) -> Vec<(&'static str, f64)> {
        let mut out = Vec::new();
        let mut push = |name: &'static str, v: Option<f64>| {
            if let Some(v) = v {
                out.push((name, v));
            }
        };
        match &self.data {
            ProbeData::Latency(d) => {
                push("rtt_median_ms", d.rtt_ms.map(|r| r.median));
                push("rtt_p95_ms", d.rtt_ms.map(|r| r.p95));
                push("jitter_ms", d.jitter_ms.map(|j| j.ipdv));
                push("loss_pct", Some(d.loss_pct.total));
            }
            ProbeData::Dns(d) => {
                push("cached_ms", d.cached_ms);
                push("uncached_ms", d.uncached_ms);
                if !self.has_flag(flag::OUTAGE) && d.total > 0 {
                    push("failure_pct", Some(f64::from(d.failed) / f64::from(d.total) * 100.0));
                }
            }
            ProbeData::Connection(d) => {
                push("tcp_ms", d.tcp_ms);
                push("tls_ms", d.tls_ms);
                push("ttfb_ms", d.ttfb_ms);
                push("total_ms", d.total_ms);
            }
            ProbeData::Throughput(d) => {
                push("idle_latency_ms", d.idle_latency_ms);
                if let Some(dl) = &d.download {
                    push("down_mbps", Some(dl.mbps));
                    push("down_latency_ms", dl.loaded_latency_ms.map(|l| l.median));
                }
                if let Some(ul) = &d.upload {
                    push("up_mbps", Some(ul.mbps));
                    push("up_latency_ms", ul.loaded_latency_ms.map(|l| l.median));
                    push("up_retrans_pct", ul.retrans_pct);
                }
            }
            ProbeData::TcpSystem(d) => push("retrans_pct", d.retrans_pct),
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_json_round_trip() {
        let rec = Record {
            id: "01JC8Z3K7Q2X5V9T4N6M8P0R2S".into(),
            agent_id: "a3f1c9e2-7b4d-4f1a-9c3e-2d8b6a1f0e47".into(),
            ts: time::macros::datetime!(2026-11-02 09:15:00 UTC),
            platform: "macos-26.4.1/aarch64".into(),
            network_id: Some("h:9f2c41".into()),
            iface: Some(IfaceInfo { kind: "lan".into(), link: "wifi".into(), name: Some("en0".into()) }),
            target: Some("1.1.1.1".into()),
            data: ProbeData::Latency(LatencyData {
                addr: "1.1.1.1".into(),
                method: "icmp".into(),
                sent: 20,
                received: 20,
                late: 0,
                duplicates: 0,
                rtt_ms: Some(RttStats { min: 18.2, median: 21.4, p95: 33.0, max: 41.7 }),
                jitter_ms: Some(Jitter { ipdv: 2.1, rfc3550: 1.8 }),
                loss_pct: Loss { total: 0.0, up: None, down: None },
            }),
            flags: vec![],
        };
        let json = serde_json::to_value(&rec).unwrap();
        assert_eq!(json["probe"], "latency");
        assert_eq!(json["iface"]["type"], "wifi");
        assert_eq!(json["ts"], "2026-11-02T09:15:00Z");
        let back: Record = serde_json::from_value(json).unwrap();
        assert_eq!(back.probe(), "latency");
        assert!(back.metrics().iter().any(|(k, v)| *k == "rtt_median_ms" && *v == 21.4));
    }
}
