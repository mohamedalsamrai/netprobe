//! 4.4 Throughput test: download then upload over parallel HTTP streams, with latency
//! sampled under load and retransmission rates for both directions.
//!
//! Upload retransmissions come from our own sockets (we are the sender). Download
//! retransmissions need the server's view: Cloudflare reports its TCP counters in a
//! `server-timing: cfL4` header on every response, so download requests are sized to
//! about one second each and the counters are read from successive responses.

use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::AsFd;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::body::{Body, Frame, SizeHint};
use hyper::client::conn::http1::{self, SendRequest};
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderMap, USER_AGENT};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use netprobe_core::model::{DirectionData, ThroughputData, flag};
use netprobe_core::stats::{self, round2};
use netprobe_platform::{Platform, TcpSockStats};
use rand::RngCore;
use rustls::ClientConfig;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{Instant, MissedTickBehavior};

use crate::latency::{self, LatencyParams, LoadedSampler};
use crate::net::{self, MeteredIo, NetStream};
use crate::rt;

const SAMPLE: Duration = Duration::from_millis(250);
/// Samples taken during TCP slow start are left out.
const WARMUP: Duration = Duration::from_millis(1500);
/// Moving average over 4 s of samples; the rate is stable when the last four averages
/// deviate less than 5% (the stability rule of the IETF responsiveness draft).
const MA_SAMPLES: usize = 16;
const STABLE_DEVIATION: f64 = 0.05;
/// At these times, add streams if each existing stream is fast.
const RAMP_CHECKS: [Duration; 2] = [Duration::from_millis(1500), Duration::from_millis(3000)];
const RAMP_PER_STREAM_MBPS: f64 = 40.0;
const RAMP_STEP: u32 = 4;
const LOADED_INTERVAL: Duration = Duration::from_millis(100);
const MIN_DOWNLOAD_CHUNK: u64 = 256 * 1024;
const UPLOAD_FRAME: usize = 64 * 1024;
const UPLOAD_BUF: usize = 1 << 20;
/// TLS, TCP/IP and link headers on top of the payload we count.
const WIRE_OVERHEAD: f64 = 0.08;

#[derive(Debug, Clone)]
pub struct Params {
    pub server: String,
    /// `{bytes}` is replaced with the request size.
    pub download_path: String,
    pub upload_path: String,
    /// Upper bound for one download request.
    pub download_chunk: u64,
    pub upload_chunk: u64,
    /// Per direction.
    pub max_duration: Duration,
    pub initial_streams: u32,
    pub max_streams: u32,
    /// Bytes for the whole test (both directions).
    pub byte_cap: u64,
    pub latency_target: Ipv4Addr,
    /// Interface to watch for background traffic.
    pub interface: Option<String>,
    pub busy_threshold_pct: f64,
    /// Process CPU (% of one core) above which the result is marked cpu_limited.
    pub cpu_limit_pct: f64,
}

pub struct Outcome {
    pub data: ThroughputData,
    pub flags: Vec<String>,
}

pub async fn run(p: Params, platform: Arc<dyn Platform>, tls: Arc<ClientConfig>) -> Outcome {
    let started = Instant::now();
    let cpu_before = cpu_time();
    let mut data = ThroughputData { server: p.server.clone(), ..Default::default() };
    let mut flags: Vec<String> = Vec::new();

    let shared = match Shared::new(&p, platform, tls).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            data.error = Some(format!("{e:#}"));
            return Outcome { data, flags };
        }
    };

    let target = p.latency_target;
    let idle = rt::on_dedicated_thread("idle-latency", move || async move {
        let params = LatencyParams { count: 10, spacing: LOADED_INTERVAL, timeout: Duration::from_secs(2) };
        latency::measure(target, 443, &params).await
    })
    .await;
    data.idle_latency_ms = idle.ok().and_then(|o| o.data.rtt_ms).map(|r| r.median);

    // leave a third of the budget for the upload
    let down = phase(Dir::Down, &shared, p.byte_cap * 2 / 3).await;
    let remaining = p.byte_cap.saturating_sub(down.data.bytes);
    let up = if remaining >= 1 << 20 {
        Some(phase(Dir::Up, &shared, remaining).await)
    } else {
        flags.push(flag::CAP_REACHED.into());
        None
    };

    let mut add_flag = |f: &str| {
        if !flags.iter().any(|x| x == f) {
            flags.push(f.into());
        }
    };
    for (name, ph) in [("download", Some(&down)), ("upload", up.as_ref())] {
        let Some(ph) = ph else { continue };
        if ph.capped {
            add_flag(flag::CAP_REACHED);
        }
        if ph.data.background_pct.is_some_and(|b| b > p.busy_threshold_pct) {
            add_flag(flag::LINK_BUSY);
        }
        if ph.data.bytes == 0
            && let Some(e) = &ph.first_error
        {
            data.error.get_or_insert_with(|| format!("{name}: {e}"));
        }
    }

    let idle_ms = data.idle_latency_ms;
    let finish = |ph: PhaseResult| {
        let mut d = ph.data;
        d.bufferbloat_ms = d.loaded_latency_ms.zip(idle_ms).map(|(l, i)| round2(l.median - i));
        d
    };
    data.bytes_total = down.data.bytes + up.as_ref().map_or(0, |u| u.data.bytes);
    data.download = Some(finish(down));
    data.upload = up.map(finish);

    let wall = started.elapsed();
    data.duration_s = round2(wall.as_secs_f64());
    let cpu_pct = (cpu_time().saturating_sub(cpu_before)).as_secs_f64() / wall.as_secs_f64().max(0.001) * 100.0;
    data.cpu_pct = Some(round2(cpu_pct));
    if cpu_pct > p.cpu_limit_pct {
        add_flag(flag::CPU_LIMITED);
    }
    data.colo = shared.colo.lock().unwrap().clone();
    Outcome { data, flags }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
    Down,
    Up,
}

struct Shared {
    addr: SocketAddr,
    host: String,
    https: bool,
    tls: Arc<ClientConfig>,
    platform: Arc<dyn Platform>,
    p: Params,
    /// Random, incompressible upload data generated once and reused.
    upload_buf: Bytes,
    colo: Mutex<Option<String>>,
}

impl Shared {
    async fn new(p: &Params, platform: Arc<dyn Platform>, tls: Arc<ClientConfig>) -> anyhow::Result<Self> {
        let target = net::parse_url(&p.server)?;
        let (addr, _) = net::resolve(&target.host, target.port).await?;
        let mut buf = vec![0u8; UPLOAD_BUF];
        rand::rng().fill_bytes(&mut buf);
        Ok(Self {
            addr,
            host: target.host,
            https: target.https,
            tls,
            platform,
            p: p.clone(),
            upload_buf: Bytes::from(buf),
            colo: Mutex::new(None),
        })
    }

    fn request(&self, method: Method, path: &str) -> http::request::Builder {
        Request::builder()
            .method(method)
            .uri(path)
            .header(HOST, self.host.as_str())
            .header(USER_AGENT, net::USER_AGENT)
    }

    fn note_headers(&self, headers: &HeaderMap, l4: &mut L4Track) {
        if let Some(colo) = headers.get("colo").or(headers.get("cf-meta-colo")).and_then(|v| v.to_str().ok()) {
            self.colo.lock().unwrap().get_or_insert_with(|| colo.to_string());
        }
        for v in headers.get_all("server-timing") {
            if let Some(c) = v.to_str().ok().and_then(parse_cf_l4) {
                l4.first.get_or_insert(c);
                l4.last = Some(c);
            }
        }
    }

    fn iface_bytes(&self, dir: Dir) -> Option<u64> {
        let (rx, tx) = self.platform.interface_bytes(self.p.interface.as_deref()?)?;
        Some(if dir == Dir::Down { rx } else { tx })
    }
}

/// Server-side TCP counters for one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct L4 {
    sent: u64,
    retrans: u64,
}

#[derive(Debug, Default, Clone, Copy)]
struct L4Track {
    first: Option<L4>,
    last: Option<L4>,
}

/// Parses `cfL4;desc="?proto=TCP&rtt=..&sent=5&recv=7&lost=0&retrans=0&sent_bytes=.."`.
fn parse_cf_l4(value: &str) -> Option<L4> {
    if !value.contains("cfL4") {
        return None;
    }
    let (mut sent, mut retrans) = (None, None);
    for part in value.split(['&', '?', '"', ';']) {
        if let Some(v) = part.strip_prefix("sent=") {
            sent = v.parse().ok();
        } else if let Some(v) = part.strip_prefix("retrans=") {
            retrans = v.parse().ok();
        }
    }
    Some(L4 { sent: sent?, retrans: retrans? })
}

struct PhaseResult {
    data: DirectionData,
    capped: bool,
    first_error: Option<String>,
}

async fn phase(dir: Dir, sh: &Arc<Shared>, cap: u64) -> PhaseResult {
    let p = &sh.p;
    let counter = Arc::new(AtomicU64::new(0));
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut tasks = JoinSet::new();
    let spawn = |tasks: &mut JoinSet<StreamResult>, n: u32| {
        for _ in 0..n {
            tasks.spawn(stream_task(dir, sh.clone(), counter.clone(), stop_rx.clone()));
        }
    };
    let max_streams = p.max_streams.max(1);
    let mut streams = p.initial_streams.clamp(1, max_streams);
    spawn(&mut tasks, streams);
    let iface_before = sh.iface_bytes(dir);
    let sampler = LoadedSampler::start(p.latency_target, LOADED_INTERVAL);

    let start = Instant::now();
    let mut ticker = tokio::time::interval(SAMPLE);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticker.tick().await;
    let mut prev = (start, 0u64);
    let mut tick_rates: Vec<f64> = Vec::new();
    // measurement window: begins after warm-up, restarts when streams are added
    let mut measure_from = start + WARMUP;
    let mut window: Option<(Instant, u64)> = None;
    let mut rates: Vec<f64> = Vec::new();
    let mut averages: Vec<f64> = Vec::new();
    let mut next_ramp = 0;
    let (mut stable, mut capped) = (false, false);
    let mut results = Vec::new();

    loop {
        ticker.tick().await;
        let now = Instant::now();
        let bytes = counter.load(Ordering::Relaxed);
        let rate = mbps(bytes - prev.1, now - prev.0);
        prev = (now, bytes);
        tick_rates.push(rate);

        while let Some(r) = tasks.try_join_next() {
            results.extend(r.ok());
        }
        if tasks.is_empty() {
            break; // every stream ended early
        }

        if next_ramp < RAMP_CHECKS.len() && now - start >= RAMP_CHECKS[next_ramp] {
            next_ramp += 1;
            let last_second = stats::mean(&tick_rates[tick_rates.len().saturating_sub(4)..]).unwrap_or(0.0);
            if streams < max_streams && last_second / f64::from(streams) > RAMP_PER_STREAM_MBPS {
                let add = RAMP_STEP.min(max_streams - streams);
                spawn(&mut tasks, add);
                streams += add;
                measure_from = now + WARMUP;
                window = None;
                rates.clear();
                averages.clear();
            }
        }

        if now >= measure_from {
            if window.is_none() {
                window = Some((now, bytes));
            } else {
                rates.push(rate);
                if rates.len() >= MA_SAMPLES {
                    averages.extend(stats::mean(&rates[rates.len() - MA_SAMPLES..]));
                }
                if averages.len() >= 4 {
                    let last = &averages[averages.len() - 4..];
                    if let (Some(m), Some(sd)) = (stats::mean(last), stats::std_dev(last))
                        && m > 0.0
                        && sd / m < STABLE_DEVIATION
                    {
                        stable = true;
                    }
                }
            }
        }
        if stable || now - start >= p.max_duration {
            break;
        }
        if bytes >= cap {
            capped = true;
            break;
        }
    }

    let end = Instant::now();
    let end_bytes = counter.load(Ordering::Relaxed);
    let _ = stop_tx.send(true);
    let loaded = sampler.finish(Duration::from_secs(1)).await;
    let collect = async {
        while let Some(r) = tasks.join_next().await {
            results.extend(r.ok());
        }
    };
    if tokio::time::timeout(Duration::from_secs(3), collect).await.is_err() {
        tasks.abort_all();
    }
    let total_bytes = counter.load(Ordering::Relaxed);
    let iface_after = sh.iface_bytes(dir);

    let (mean_mbps, measured) = match window {
        Some((from, from_bytes)) if end - from >= Duration::from_millis(500) => {
            (mbps(end_bytes - from_bytes, end - from), end - from)
        }
        _ => (mbps(end_bytes, end - start), end - start),
    };
    let socks: Vec<TcpSockStats> = results.iter().filter_map(|r| r.sock).collect();
    let sum = |f: fn(&TcpSockStats) -> u64| socks.iter().map(f).sum::<u64>() as f64;
    let retrans_pct = match dir {
        Dir::Up => stats::ratio_pct(sum(|s| s.tx_retrans_packets), sum(|s| s.tx_packets)),
        Dir::Down => {
            let (mut sent, mut retrans) = (0u64, 0u64);
            for r in &results {
                if let (Some(a), Some(b)) = (r.l4.first, r.l4.last) {
                    sent += b.sent.saturating_sub(a.sent);
                    retrans += b.retrans.saturating_sub(a.retrans);
                }
            }
            stats::ratio_pct(retrans as f64, sent as f64)
        }
    };
    let rx_out_of_order_pct = match dir {
        Dir::Down => stats::ratio_pct(sum(|s| s.rx_out_of_order_bytes), sum(|s| s.rx_bytes)),
        Dir::Up => None,
    };
    let background_pct = iface_before.zip(iface_after).and_then(|(before, after)| {
        let ours = total_bytes as f64;
        let theirs = after.saturating_sub(before) as f64 - ours * (1.0 + WIRE_OVERHEAD);
        stats::ratio_pct(theirs.max(0.0), ours)
    });

    PhaseResult {
        data: DirectionData {
            mbps: round2(mean_mbps),
            mbps_p90: round2(stats::percentile(&rates, 90.0).unwrap_or(mean_mbps)),
            streams,
            bytes: total_bytes,
            duration_s: round2(measured.as_secs_f64()),
            stable,
            loaded_latency_ms: loaded,
            bufferbloat_ms: None,
            retrans_pct: retrans_pct.map(round2),
            rx_out_of_order_pct: rx_out_of_order_pct.map(round2),
            background_pct: background_pct.map(round2),
            errors: results.iter().filter(|r| r.error.is_some()).count() as u32,
        },
        capped,
        first_error: results.iter().find_map(|r| r.error.clone()),
    }
}

#[derive(Default)]
struct StreamResult {
    sock: Option<TcpSockStats>,
    l4: L4Track,
    error: Option<String>,
}

async fn stream_task(dir: Dir, sh: Arc<Shared>, counter: Arc<AtomicU64>, mut stop: watch::Receiver<bool>) -> StreamResult {
    let mut res = StreamResult::default();
    let conn = match net::connect(sh.addr, &sh.host, sh.https.then_some(&sh.tls)).await {
        Ok(c) => c,
        Err(e) => {
            res.error = Some(format!("{e:#}"));
            return res;
        }
    };
    let (read_ctr, write_ctr) = match dir {
        Dir::Down => (Some(counter), None),
        Dir::Up => (None, Some(counter)),
    };
    let io = TokioIo::new(MeteredIo::new(conn.stream, read_ctr, write_ctr, Arc::default()));
    let mut l4 = L4Track::default();
    res.error = {
        let work = async {
            match dir {
                Dir::Down => download(&sh, io, &mut l4).await,
                Dir::Up => upload(&sh, io, &mut l4).await,
            }
        };
        tokio::select! {
            r = work => r.err().map(|e| format!("{e:#}")),
            _ = stop.wait_for(|s| *s) => None,
        }
    };
    // the HTTP connection is gone, but our duplicate keeps the socket readable
    res.sock = sh.platform.socket_tcp_stats(conn.sock.as_fd());
    res.l4 = l4;
    res
}

type Io = TokioIo<MeteredIo<NetStream>>;

async fn download(sh: &Shared, io: Io, l4: &mut L4Track) -> anyhow::Result<()> {
    let (mut sender, conn) = http1::handshake::<_, Empty<Bytes>>(io).await?;
    tokio::select! {
        r = conn => {
            r?;
            anyhow::bail!("server closed the connection")
        }
        r = download_requests(sh, &mut sender, l4) => r,
    }
}

async fn download_requests(sh: &Shared, sender: &mut SendRequest<Empty<Bytes>>, l4: &mut L4Track) -> anyhow::Result<()> {
    let mut chunk = MIN_DOWNLOAD_CHUNK;
    loop {
        sender.ready().await?;
        let path = sh.p.download_path.replace("{bytes}", &chunk.to_string());
        let req = sh.request(Method::GET, &path).body(Empty::new())?;
        let begun = Instant::now();
        let resp = sender.send_request(req).await?;
        anyhow::ensure!(resp.status().is_success(), "download HTTP {}", resp.status());
        sh.note_headers(resp.headers(), l4);
        let mut body = resp.into_body();
        let mut got = 0u64;
        while let Some(frame) = body.frame().await {
            if let Some(d) = frame?.data_ref() {
                got += d.len() as u64;
            }
        }
        // about one second of this stream's rate per request
        let rate = got as f64 / begun.elapsed().as_secs_f64().max(0.001);
        chunk = (rate as u64).clamp(MIN_DOWNLOAD_CHUNK, sh.p.download_chunk.max(MIN_DOWNLOAD_CHUNK));
    }
}

async fn upload(sh: &Shared, io: Io, l4: &mut L4Track) -> anyhow::Result<()> {
    let (mut sender, conn) = http1::handshake::<_, UploadBody>(io).await?;
    tokio::select! {
        r = conn => {
            r?;
            anyhow::bail!("server closed the connection")
        }
        r = upload_requests(sh, &mut sender, l4) => r,
    }
}

async fn upload_requests(sh: &Shared, sender: &mut SendRequest<UploadBody>, l4: &mut L4Track) -> anyhow::Result<()> {
    loop {
        sender.ready().await?;
        let len = sh.p.upload_chunk;
        let req = sh
            .request(Method::POST, &sh.p.upload_path)
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(CONTENT_LENGTH, len)
            .body(UploadBody { buf: sh.upload_buf.clone(), offset: 0, remaining: len })?;
        let resp = sender.send_request(req).await?;
        anyhow::ensure!(resp.status().is_success(), "upload HTTP {}", resp.status());
        sh.note_headers(resp.headers(), l4);
        resp.into_body().collect().await?;
    }
}

/// Streams `remaining` bytes by cycling through the shared random buffer.
struct UploadBody {
    buf: Bytes,
    offset: usize,
    remaining: u64,
}

impl Body for UploadBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if this.remaining == 0 {
            return Poll::Ready(None);
        }
        let n = (UPLOAD_FRAME as u64).min(this.remaining).min((this.buf.len() - this.offset) as u64) as usize;
        let chunk = this.buf.slice(this.offset..this.offset + n);
        this.offset = (this.offset + n) % this.buf.len();
        this.remaining -= n as u64;
        Poll::Ready(Some(Ok(Frame::data(chunk))))
    }

    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
}

fn mbps(bytes: u64, dur: Duration) -> f64 {
    let secs = dur.as_secs_f64();
    if secs <= 0.0 { 0.0 } else { bytes as f64 * 8.0 / secs / 1e6 }
}

fn cpu_time() -> Duration {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) } != 0 {
        return Duration::ZERO;
    }
    let tv = |t: libc::timeval| Duration::new(t.tv_sec as u64, t.tv_usec as u32 * 1000);
    tv(ru.ru_utime) + tv(ru.ru_stime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cloudflare_l4_header() {
        let v = r#"cfL4;desc="?proto=TCP&rtt=29026&min_rtt=28473&rtt_var=11784&sent=5&recv=7&lost=0&retrans=2&sent_bytes=2842&recv_bytes=516&delivery_rate=124741&cwnd=53&unsent_bytes=0&cid=f98d3447508b8d58&ts=74&x=0""#;
        assert_eq!(parse_cf_l4(v), Some(L4 { sent: 5, retrans: 2 }));
        assert_eq!(parse_cf_l4("cfSpeedEdge;dur=2, cfSpeedWorker;dur=22"), None);
    }

    #[test]
    fn upload_body_streams_exact_length() {
        let buf = Bytes::from(vec![1u8; 100_000]);
        let mut body = UploadBody { buf, offset: 0, remaining: 250_000 };
        assert_eq!(body.size_hint().exact(), Some(250_000));
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut total = 0;
        while let Poll::Ready(Some(Ok(frame))) = Pin::new(&mut body).poll_frame(&mut cx) {
            total += frame.into_data().unwrap().len();
        }
        assert_eq!(total, 250_000);
        assert!(body.is_end_stream());
    }

    #[test]
    fn mbps_math() {
        assert_eq!(mbps(1_250_000, Duration::from_secs(1)), 10.0);
        assert_eq!(mbps(5, Duration::ZERO), 0.0);
    }
}
