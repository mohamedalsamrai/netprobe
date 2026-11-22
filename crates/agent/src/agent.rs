//! Runs each probe with the current config and wraps the results in records.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use netprobe_core::model::{HeartbeatData, IfaceInfo, ProbeData, TcpSystemData, flag};
use netprobe_core::stats::{counter_delta, ratio_pct, round2};
use netprobe_core::{Config, Record};
use netprobe_platform::{NetworkContext, Platform, TcpCounters};
use netprobe_probes::dns::{self, DnsParams};
use netprobe_probes::latency::{self, LatencyParams};
use netprobe_probes::{connection, iperf, net, rt, throughput};
use rustls::ClientConfig;
use time::OffsetDateTime;
use tokio::task::JoinSet;

use crate::identity::Identity;

/// Worker threads of the desktop runtime; also the CPU budget a speed test may use.
pub const WORKER_THREADS: usize = 2;
pub const MB: u64 = 1_000_000;

pub struct Agent {
    pub cfg: Config,
    pub platform: Arc<dyn Platform>,
    pub identity: Identity,
    tls: Arc<ClientConfig>,
    platform_name: String,
    /// Held by every test while it runs, so tests never overlap and one test's traffic
    /// never shows up in another's numbers. The heartbeat stays outside it.
    pub test_lock: tokio::sync::Mutex<()>,
}

/// The network the measurements are taken on.
pub struct NetSnapshot {
    pub ctx: NetworkContext,
    pub network_id: Option<String>,
    pub iface: Option<IfaceInfo>,
}

impl Agent {
    pub fn new(cfg: Config, identity: Identity) -> Self {
        let platform = netprobe_platform::current();
        let platform_name = platform.name();
        Self { cfg, platform, identity, tls: net::tls_config(), platform_name, test_lock: tokio::sync::Mutex::new(()) }
    }

    pub fn platform_name(&self) -> &str {
        &self.platform_name
    }

    pub fn snapshot(&self) -> NetSnapshot {
        let ctx = self.platform.network_context();
        let network_id = self.identity.network_id(&ctx);
        let iface = ctx.interface.as_ref().map(|name| IfaceInfo {
            kind: "lan".into(),
            link: ctx.link.map_or("other", |l| l.as_str()).into(),
            name: Some(name.clone()),
        });
        NetSnapshot { ctx, network_id, iface }
    }

    fn record(&self, snap: &NetSnapshot, target: Option<String>, data: ProbeData, flags: Vec<String>) -> Record {
        Record {
            id: ulid::Ulid::new().to_string(),
            agent_id: self.identity.agent_id.clone(),
            ts: OffsetDateTime::now_utc(),
            platform: self.platform_name.clone(),
            network_id: snap.network_id.clone(),
            iface: snap.iface.clone(),
            target,
            data,
            flags,
        }
    }

    /// 4.1: every latency target in parallel, on a dedicated thread.
    pub async fn run_latency(&self) -> Vec<Record> {
        let snap = self.snapshot();
        let c = &self.cfg.latency;
        let mut targets: Vec<(String, Ipv4Addr, u16)> = Vec::new();
        for t in &c.targets {
            if t == "gateway" {
                if let Some(IpAddr::V4(gw)) = snap.ctx.gateway {
                    targets.push((t.clone(), gw, 53));
                }
            } else if t == "server" {
                // our own server comes from [iperf] so its address stays out of shared defaults;
                // TCP fallback goes to SSH, which such a server keeps open
                match self.own_server_ipv4().await {
                    Some(ip) => targets.push((t.clone(), ip, 22)),
                    None => {
                        static WARNED: std::sync::Once = std::sync::Once::new();
                        WARNED.call_once(|| {
                            tracing::warn!("latency target \"server\" skipped: set `server` under [iperf] to an IPv4 address or a name");
                        });
                    }
                }
            } else if let Ok(ip) = t.parse::<Ipv4Addr>() {
                targets.push((t.clone(), ip, 443));
            } else {
                tracing::warn!(target = %t, "latency targets must be \"gateway\", \"server\" or an IPv4 address");
            }
        }
        let params = LatencyParams {
            count: c.count.clamp(1, u32::from(u16::MAX - 1)) as u16,
            spacing: Duration::from_millis(c.spacing_ms),
            timeout: Duration::from_millis(c.timeout_ms),
        };
        let results = rt::on_dedicated_thread("latency", move || async move {
            let mut set = JoinSet::new();
            for (i, (label, ip, port)) in targets.into_iter().enumerate() {
                let params = params.clone();
                set.spawn(async move { (i, label, latency::measure(ip, port, &params).await) });
            }
            let mut out = set.join_all().await;
            out.sort_by_key(|(i, ..)| *i);
            out
        })
        .await;
        match results {
            Ok(results) => results
                .into_iter()
                .map(|(_, label, o)| self.record(&snap, Some(label), ProbeData::Latency(o.data), o.flags))
                .collect(),
            Err(e) => {
                tracing::error!(error = %e, "latency probe failed");
                Vec::new()
            }
        }
    }

    /// 4.2: every resolver the OS uses (plus configured extras) and the OS resolver path.
    pub async fn run_dns(&self) -> Vec<Record> {
        let snap = self.snapshot();
        let c = &self.cfg.dns;
        let mut resolvers = self.platform.dns_servers();
        for r in &c.extra_resolvers {
            match r.parse::<IpAddr>() {
                Ok(ip) if !resolvers.contains(&ip) => resolvers.push(ip),
                Ok(_) => {}
                Err(_) => tracing::warn!(resolver = %r, "extra_resolvers must be IP addresses"),
            }
        }
        // a dead line is an outage, not a DNS failure
        if !self.has_internet().await {
            let empty = || ProbeData::Dns(netprobe_core::model::DnsData {
                queries: vec![],
                cached_ms: None,
                uncached_ms: None,
                total: 0,
                failed: 0,
            });
            let mut out: Vec<Record> = resolvers
                .iter()
                .map(|r| self.record(&snap, Some(r.to_string()), empty(), vec![flag::OUTAGE.into()]))
                .collect();
            if c.system_lookup {
                out.push(self.record(&snap, Some("system".into()), empty(), vec![flag::OUTAGE.into()]));
            }
            return out;
        }

        let params = DnsParams {
            timeout: Duration::from_millis(c.timeout_ms),
            cached_names: c.cached_names.clone(),
            uncached_template: c.uncached_template.clone(),
        };
        let mut set = JoinSet::new();
        for (i, resolver) in resolvers.into_iter().enumerate() {
            let params = params.clone();
            set.spawn(async move { (i, resolver, dns::probe_resolver(resolver, &params).await) });
        }
        let mut results = set.join_all().await;
        results.sort_by_key(|(i, ..)| *i);
        let mut out: Vec<Record> = results
            .into_iter()
            .map(|(_, r, d)| self.record(&snap, Some(r.to_string()), ProbeData::Dns(d), vec![]))
            .collect();
        if c.system_lookup
            && let Some(name) = c.cached_names.first()
        {
            let d = dns::probe_system(name, params.timeout).await;
            out.push(self.record(&snap, Some("system".into()), ProbeData::Dns(d), vec![]));
        }
        out
    }

    /// 4.3: the targets one after another so they don't compete.
    pub async fn run_connection(&self) -> Vec<Record> {
        let snap = self.snapshot();
        let c = &self.cfg.connection;
        let mut out = Vec::new();
        for url in &c.targets {
            let d = connection::measure(url, &self.tls, Duration::from_millis(c.timeout_ms)).await;
            let target = net::parse_url(url).map(|t| t.host).unwrap_or_else(|_| url.clone());
            out.push(self.record(&snap, Some(target), ProbeData::Connection(d), vec![]));
        }
        out
    }

    /// 4.4: one speed test limited to `byte_cap` bytes.
    pub async fn run_throughput(&self, byte_cap: u64) -> Record {
        let snap = self.snapshot();
        let c = &self.cfg.throughput;
        let params = throughput::Params {
            server: c.server.clone(),
            download_path: c.download_path.clone(),
            upload_path: c.upload_path.clone(),
            download_chunk: c.download_chunk_mb * MB,
            upload_chunk: c.upload_chunk_mb * MB,
            max_duration: Duration::from_secs(c.max_duration_secs),
            initial_streams: c.initial_streams,
            max_streams: c.max_streams,
            byte_cap,
            latency_target: c.latency_target.parse().unwrap_or(Ipv4Addr::new(1, 1, 1, 1)),
            interface: snap.ctx.interface.clone(),
            busy_threshold_pct: c.busy_threshold_pct,
            cpu_limit_pct: WORKER_THREADS as f64 * 90.0,
        };
        let out = throughput::run(params, self.platform.clone(), self.tls.clone()).await;
        let target = net::parse_url(&c.server).map(|t| t.host).ok();
        self.record(&snap, target, ProbeData::Throughput(out.data), out.flags)
    }

    /// System-wide retransmission rate between two counter readings.
    pub fn tcp_system_record(&self, prev: TcpCounters, cur: TcpCounters, interval: Duration) -> Record {
        let bits = cur.counter_bits;
        let retrans = counter_delta(prev.retrans_segments, cur.retrans_segments, bits);
        let sent = counter_delta(prev.sent_segments, cur.sent_segments, bits) + retrans;
        let data = TcpSystemData {
            interval_s: round2(interval.as_secs_f64()),
            sent_segments: sent,
            retrans_segments: retrans,
            retrans_pct: ratio_pct(retrans as f64, sent as f64).map(round2),
        };
        self.record(&self.snapshot(), Some("system".into()), ProbeData::TcpSystem(data), vec![])
    }

    /// The IPv4 address of `[iperf] server`, resolving a name if needed.
    async fn own_server_ipv4(&self) -> Option<Ipv4Addr> {
        let host = self.cfg.iperf.server.trim();
        if host.is_empty() {
            return None;
        }
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Some(ip);
        }
        let addrs = tokio::time::timeout(Duration::from_secs(3), tokio::net::lookup_host((host, 0))).await.ok()?.ok()?;
        addrs.into_iter().find_map(|a| match a.ip() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
    }

    /// iperf3 upload and download against our own server.
    pub async fn run_iperf(&self) -> Record {
        let snap = self.snapshot();
        let c = &self.cfg.iperf;
        let params = iperf::Params {
            binary: c.binary.clone(),
            server: c.server.clone(),
            port: c.port,
            duration_s: c.duration_secs.max(1),
            streams: c.streams.max(1),
            connect_timeout_ms: c.connect_timeout_ms,
        };
        let out = iperf::run(&params).await;
        self.record(&snap, Some(format!("{}:{}", c.server, c.port)), ProbeData::Iperf(out.data), out.flags)
    }

    /// "Alive" record; `started` is when the agent process began.
    pub async fn heartbeat_record(&self, started: std::time::Instant, interval: Duration) -> Record {
        let data = HeartbeatData {
            interval_s: interval.as_secs(),
            agent_uptime_s: started.elapsed().as_secs(),
            system_uptime_s: self.platform.uptime().map(|u| u.as_secs()),
            internet: self.has_internet().await,
            version: env!("CARGO_PKG_VERSION").into(),
        };
        self.record(&self.snapshot(), None, ProbeData::Heartbeat(data), vec![])
    }

    /// Whether anything on the internet answers a TCP handshake.
    pub async fn has_internet(&self) -> bool {
        let probe = |ip: [u8; 4]| async move {
            let addr = SocketAddr::from((ip, 443));
            matches!(tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(addr)).await, Ok(Ok(_)))
        };
        let (a, b) = tokio::join!(probe([1, 1, 1, 1]), probe([8, 8, 8, 8]));
        a || b
    }
}
