//! 4.1 Latency probe: RTT, jitter and packet loss from a burst of ICMP echoes, falling
//! back to TCP connect timing when ICMP gets no answer. Also the latency-under-load
//! sampler used by the throughput test.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use netprobe_core::model::{Jitter, LatencyData, LoadedLatency, Loss, flag};
use netprobe_core::stats::{self, round2};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::icmp::{self, Reply, Series, SeriesOpts};
use crate::rt;

#[derive(Debug, Clone)]
pub struct LatencyParams {
    pub count: u16,
    pub spacing: Duration,
    pub timeout: Duration,
}

pub struct LatencyOutcome {
    pub data: LatencyData,
    pub flags: Vec<String>,
}

/// Probes `addr` with ICMP; if nothing comes back, times TCP connects to `tcp_port`.
pub async fn measure(addr: Ipv4Addr, tcp_port: u16, p: &LatencyParams) -> LatencyOutcome {
    let opts = SeriesOpts {
        count: Some(p.count),
        spacing: p.spacing,
        timeout: p.timeout,
        late_grace: Duration::from_secs(1),
        stop: None,
    };
    let icmp = icmp::ping_series(addr, &opts).await;
    if let Ok(s) = &icmp
        && !s.replies.is_empty()
    {
        return LatencyOutcome { data: to_data("icmp", addr, s), flags: vec![] };
    }
    if let Err(e) = &icmp {
        tracing::debug!(%addr, error = %e, "icmp unavailable, using tcp connect");
    }
    let tcp = tcp_series(SocketAddr::new(addr.into(), tcp_port), p.count.min(10), p.spacing, p.timeout).await;
    match icmp {
        _ if !tcp.replies.is_empty() => {
            LatencyOutcome { data: to_data("tcp", addr, &tcp), flags: vec![flag::ICMP_BLOCKED.into()] }
        }
        Ok(s) => LatencyOutcome { data: to_data("icmp", addr, &s), flags: vec![] },
        Err(_) => LatencyOutcome { data: to_data("tcp", addr, &tcp), flags: vec![] },
    }
}

/// Times `count` TCP handshakes. A refused connection still costs exactly one round trip.
async fn tcp_series(addr: SocketAddr, count: u16, spacing: Duration, timeout: Duration) -> Series {
    let mut set = JoinSet::new();
    for seq in 0..count {
        set.spawn(async move {
            tokio::time::sleep(spacing * u32::from(seq)).await;
            let start = Instant::now();
            match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
                Ok(Ok(_)) => Some(Reply { seq, rtt: start.elapsed(), late: false }),
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    Some(Reply { seq, rtt: start.elapsed(), late: false })
                }
                _ => None,
            }
        });
    }
    let replies = set.join_all().await.into_iter().flatten().collect();
    Series { sent: u32::from(count), replies, duplicates: 0 }
}

pub fn to_data(method: &str, addr: Ipv4Addr, s: &Series) -> LatencyData {
    let rtts = s.rtts_ms();
    let received = s.replies.len() as u32;
    let jitter = stats::jitter_ipdv(&rtts)
        .zip(stats::jitter_rfc3550(&rtts))
        .map(|(ipdv, rfc3550)| Jitter { ipdv: round2(ipdv), rfc3550: round2(rfc3550) });
    LatencyData {
        addr: addr.to_string(),
        method: method.into(),
        sent: s.sent,
        received,
        late: s.replies.iter().filter(|r| r.late).count() as u32,
        duplicates: s.duplicates,
        rtt_ms: stats::rtt_stats(&rtts),
        jitter_ms: jitter,
        loss_pct: Loss { total: round2(stats::loss_pct(s.sent, received)), up: None, down: None },
    }
}

/// Pings a target continuously on its own thread while a speed test saturates the link.
pub struct LoadedSampler {
    stop: Arc<AtomicBool>,
    interval: Duration,
    handle: tokio::task::JoinHandle<anyhow::Result<std::io::Result<Series>>>,
}

impl LoadedSampler {
    pub fn start(target: Ipv4Addr, interval: Duration) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let opts = SeriesOpts {
            count: None,
            spacing: interval,
            timeout: Duration::from_secs(2),
            late_grace: Duration::ZERO,
            stop: Some(stop.clone()),
        };
        let handle = tokio::spawn(rt::on_dedicated_thread("loaded-latency", move || async move {
            icmp::ping_series(target, &opts).await
        }));
        Self { stop, interval, handle }
    }

    /// Stops sampling and summarizes the samples sent after `skip` (the ramp-up).
    pub async fn finish(self, skip: Duration) -> Option<LoadedLatency> {
        self.stop.store(true, Ordering::Relaxed);
        let series = match self.handle.await {
            Ok(Ok(Ok(s))) => s,
            other => {
                tracing::debug!(?other, "loaded latency sampler failed");
                return None;
            }
        };
        let first_seq = (skip.as_millis() / self.interval.as_millis().max(1)) as u32;
        let sent = series.sent.saturating_sub(first_seq);
        let rtts: Vec<f64> = series
            .replies
            .iter()
            .filter(|r| u32::from(r.seq) >= first_seq)
            .map(|r| r.rtt.as_secs_f64() * 1000.0)
            .collect();
        Some(LoadedLatency {
            median: round2(stats::median(&rtts)?),
            p90: round2(stats::percentile(&rtts, 90.0)?),
            samples: rtts.len() as u32,
            lost: sent.saturating_sub(rtts.len() as u32),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_handles_loss_and_late() {
        let s = Series {
            sent: 4,
            replies: vec![
                Reply { seq: 2, rtt: Duration::from_millis(30), late: false },
                Reply { seq: 0, rtt: Duration::from_millis(10), late: false },
                Reply { seq: 3, rtt: Duration::from_millis(2500), late: true },
            ],
            duplicates: 1,
        };
        let d = to_data("icmp", Ipv4Addr::LOCALHOST, &s);
        assert_eq!(d.received, 3);
        assert_eq!(d.late, 1);
        assert_eq!(d.duplicates, 1);
        assert_eq!(d.loss_pct.total, 25.0);
        // ordered by seq: 10, 30, 2500 -> diffs 20, 2470
        assert_eq!(d.jitter_ms.unwrap().ipdv, 1245.0);
        assert_eq!(d.rtt_ms.unwrap().min, 10.0);
    }

    #[tokio::test]
    async fn tcp_fallback_counts_refused_as_reply() {
        // nothing listens on this port, so the kernel answers with RST
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let s = tcp_series(SocketAddr::from(([127, 0, 0, 1], port)), 3, Duration::from_millis(5), Duration::from_secs(1)).await;
        assert_eq!(s.sent, 3);
        assert_eq!(s.replies.len(), 3);
    }
}
