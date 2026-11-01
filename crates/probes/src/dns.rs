//! 4.2 DNS probe: direct UDP queries to each resolver (one cached name and one random,
//! uncached name) plus timing of the OS resolver path.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use netprobe_core::model::{DnsData, DnsKind, DnsOutcome, DnsQuery};
use netprobe_core::stats::{median, round2};
use rand::Rng;
use tokio::net::UdpSocket;

#[derive(Debug, Clone)]
pub struct DnsParams {
    pub timeout: Duration,
    pub cached_names: Vec<String>,
    /// `{rand}` is replaced with a fresh random label on every run.
    pub uncached_template: String,
}

/// Queries one resolver for every cached name and one random name.
pub async fn probe_resolver(resolver: IpAddr, p: &DnsParams) -> DnsData {
    let mut queries = Vec::new();
    for name in &p.cached_names {
        queries.push(query(resolver, name, DnsKind::Cached, p.timeout).await);
    }
    let name = p.uncached_template.replace("{rand}", &random_label());
    queries.push(query(resolver, &name, DnsKind::Uncached, p.timeout).await);
    summarize(queries)
}

/// Times getaddrinfo, which is what applications experience (OS cache included).
pub async fn probe_system(name: &str, timeout: Duration) -> DnsData {
    let start = Instant::now();
    let (outcome, ms) = match tokio::time::timeout(timeout, tokio::net::lookup_host((name, 443))).await {
        Ok(Ok(mut addrs)) if addrs.next().is_some() => (DnsOutcome::Ok, Some(elapsed_ms(start))),
        Ok(_) => (DnsOutcome::Error, Some(elapsed_ms(start))),
        Err(_) => (DnsOutcome::Timeout, None),
    };
    summarize(vec![DnsQuery { name: name.to_string(), kind: DnsKind::System, outcome, ms }])
}

async fn query(resolver: IpAddr, name: &str, kind: DnsKind, timeout: Duration) -> DnsQuery {
    let (outcome, ms) = match tokio::time::timeout(timeout, udp_query(resolver, name)).await {
        Err(_) => (DnsOutcome::Timeout, None),
        Ok(Err(e)) => {
            tracing::debug!(%resolver, name, error = %e, "dns query failed");
            (DnsOutcome::Error, None)
        }
        Ok(Ok((code, elapsed))) => {
            let outcome = match code {
                ResponseCode::NoError => DnsOutcome::Ok,
                // every name we ask for exists, so NXDOMAIN is a failure too
                ResponseCode::NXDomain => DnsOutcome::Nxdomain,
                ResponseCode::ServFail => DnsOutcome::Servfail,
                ResponseCode::Refused => DnsOutcome::Refused,
                _ => DnsOutcome::Error,
            };
            (outcome, Some(round2(elapsed.as_secs_f64() * 1000.0)))
        }
    };
    DnsQuery { name: name.to_string(), kind, outcome, ms }
}

async fn udp_query(resolver: IpAddr, name: &str) -> anyhow::Result<(ResponseCode, Duration)> {
    let bind: SocketAddr = if resolver.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { ([0u16; 8], 0).into() };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect((resolver, 53)).await?;

    let id: u16 = rand::random();
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(Name::from_ascii(format!("{name}."))?, RecordType::A));
    let wire = msg.to_vec()?;

    let start = Instant::now();
    sock.send(&wire).await?;
    let mut buf = [0u8; 4096];
    loop {
        let n = sock.recv(&mut buf).await?;
        let elapsed = start.elapsed();
        match Message::from_vec(&buf[..n]) {
            Ok(resp) if resp.metadata.id == id && resp.metadata.message_type == MessageType::Response => {
                return Ok((resp.metadata.response_code, elapsed));
            }
            _ => continue,
        }
    }
}

fn summarize(queries: Vec<DnsQuery>) -> DnsData {
    let times = |kind: DnsKind| -> Vec<f64> {
        queries.iter().filter(|q| q.kind == kind && q.outcome.is_ok()).filter_map(|q| q.ms).collect()
    };
    let cached = [times(DnsKind::Cached), times(DnsKind::System)].concat();
    DnsData {
        cached_ms: median(&cached).map(round2),
        uncached_ms: median(&times(DnsKind::Uncached)).map(round2),
        total: queries.len() as u32,
        failed: queries.iter().filter(|q| !q.outcome.is_ok()).count() as u32,
        queries,
    }
}

fn random_label() -> String {
    rand::rng().sample_iter(rand::distr::Alphanumeric).take(12).map(|b| char::from(b).to_ascii_lowercase()).collect()
}

fn elapsed_ms(start: Instant) -> f64 {
    round2(start.elapsed().as_secs_f64() * 1000.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn answers_from_fake_resolver() {
        // a resolver on loopback that answers SERVFAIL to everything
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = server.recv_from(&mut buf).await {
                let req = Message::from_vec(&buf[..n]).unwrap();
                let resp = Message::error_msg(req.metadata.id, OpCode::Query, ResponseCode::ServFail);
                server.send_to(&resp.to_vec().unwrap(), from).await.unwrap();
            }
        });
        // udp_query always uses port 53, so exercise the parsing path directly
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.connect(addr).await.unwrap();
        let mut msg = Message::new(7, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(Name::from_ascii("example.com.").unwrap(), RecordType::A));
        sock.send(&msg.to_vec().unwrap()).await.unwrap();
        let mut buf = [0u8; 512];
        let n = sock.recv(&mut buf).await.unwrap();
        let resp = Message::from_vec(&buf[..n]).unwrap();
        assert_eq!(resp.metadata.id, 7);
        assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
    }

    #[test]
    fn summary_separates_cached_and_uncached() {
        let q = |kind, outcome, ms| DnsQuery { name: "x".into(), kind, outcome, ms };
        let d = summarize(vec![
            q(DnsKind::Cached, DnsOutcome::Ok, Some(4.0)),
            q(DnsKind::Cached, DnsOutcome::Ok, Some(6.0)),
            q(DnsKind::Uncached, DnsOutcome::Ok, Some(80.0)),
            q(DnsKind::Uncached, DnsOutcome::Servfail, Some(1.0)),
        ]);
        assert_eq!(d.cached_ms, Some(5.0));
        assert_eq!(d.uncached_ms, Some(80.0));
        assert_eq!((d.total, d.failed), (4, 1));
    }

    #[test]
    fn random_labels_are_dns_safe() {
        let l = random_label();
        assert_eq!(l.len(), 12);
        assert!(l.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        assert_ne!(l, random_label());
    }
}
