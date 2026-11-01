//! Unprivileged ICMP echo over SOCK_DGRAM + IPPROTO_ICMP. macOS allows this for any user;
//! Linux allows it within net.ipv4.ping_group_range.

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::time::Instant;

const ECHO_REQUEST: u8 = 8;
const ECHO_REPLY: u8 = 0;
/// ICMP header + payload, as in the plan's 64 byte probes.
const PACKET_LEN: usize = 64;
const MAGIC: &[u8; 8] = b"netprobe";

#[derive(Debug, Clone, Copy)]
pub struct Reply {
    pub seq: u16,
    pub rtt: Duration,
    /// Arrived after the timeout.
    pub late: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Series {
    pub sent: u32,
    pub replies: Vec<Reply>,
    pub duplicates: u32,
}

impl Series {
    /// RTTs in milliseconds, ordered by sequence number.
    pub fn rtts_ms(&self) -> Vec<f64> {
        let mut r = self.replies.clone();
        r.sort_by_key(|r| r.seq);
        r.iter().map(|r| r.rtt.as_secs_f64() * 1000.0).collect()
    }
}

#[derive(Debug, Clone)]
pub struct SeriesOpts {
    /// `None` keeps sending until `stop` is set.
    pub count: Option<u16>,
    pub spacing: Duration,
    pub timeout: Duration,
    /// Extra time to wait after the timeout to catch late replies.
    pub late_grace: Duration,
    pub stop: Option<Arc<AtomicBool>>,
}

pub fn open_socket() -> io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
    sock.set_nonblocking(true)?;
    UdpSocket::from_std(sock.into())
}

/// Sends echo requests to `target` at a fixed spacing and collects the replies.
pub async fn ping_series(target: Ipv4Addr, opts: &SeriesOpts) -> io::Result<Series> {
    let sock = open_socket()?;
    let ident: u16 = rand::random();
    let token: u32 = rand::random();
    let dest = SocketAddr::new(IpAddr::V4(target), 0);

    let send_times: Mutex<Vec<Instant>> = Mutex::new(Vec::new());
    // set once the sender is done: time of the last send
    let last_send: Mutex<Option<Instant>> = Mutex::new(None);

    let sender = async {
        let mut next = Instant::now();
        let mut seq: u16 = 0;
        loop {
            if opts.count.is_some_and(|c| seq >= c) || seq == u16::MAX {
                break;
            }
            if opts.stop.as_ref().is_some_and(|s| s.load(Ordering::Relaxed)) {
                break;
            }
            tokio::time::sleep_until(next).await;
            let pkt = echo_request(ident, seq, token);
            send_times.lock().unwrap().push(Instant::now());
            if let Err(e) = sock.send_to(&pkt, dest).await {
                // counts as sent-and-lost (e.g. no route while the network is down)
                tracing::debug!(%target, seq, error = %e, "icmp send failed");
            }
            seq += 1;
            next += opts.spacing;
        }
        *last_send.lock().unwrap() = Some(send_times.lock().unwrap().last().copied().unwrap_or_else(Instant::now));
    };

    let receiver = async {
        let mut buf = [0u8; 1500];
        let mut seen = HashSet::new();
        let mut series = Series::default();
        loop {
            let done = *last_send.lock().unwrap();
            let sent = send_times.lock().unwrap().len();
            if done.is_some() && seen.len() >= sent {
                break;
            }
            let wake = match done {
                Some(last) => last + opts.timeout + opts.late_grace,
                None => Instant::now() + Duration::from_millis(50),
            };
            match tokio::time::timeout_at(wake, sock.recv_from(&mut buf)).await {
                Err(_) if done.is_some() => break,
                Err(_) => continue,
                Ok(Err(e)) => {
                    tracing::debug!(%target, error = %e, "icmp recv failed");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Ok(Ok((n, from))) => {
                    let now = Instant::now();
                    if from.ip() != IpAddr::V4(target) {
                        continue;
                    }
                    let Some(seq) = parse_reply(&buf[..n], token) else { continue };
                    let Some(sent_at) = send_times.lock().unwrap().get(usize::from(seq)).copied() else {
                        continue;
                    };
                    if !seen.insert(seq) {
                        series.duplicates += 1;
                        continue;
                    }
                    let rtt = now - sent_at;
                    series.replies.push(Reply { seq, rtt, late: rtt > opts.timeout });
                }
            }
        }
        series
    };

    let ((), mut series) = tokio::join!(sender, receiver);
    series.sent = send_times.lock().unwrap().len() as u32;
    Ok(series)
}

fn echo_request(ident: u16, seq: u16, token: u32) -> [u8; PACKET_LEN] {
    let mut p = [0u8; PACKET_LEN];
    p[0] = ECHO_REQUEST;
    p[4..6].copy_from_slice(&ident.to_be_bytes());
    p[6..8].copy_from_slice(&seq.to_be_bytes());
    p[8..16].copy_from_slice(MAGIC);
    p[16..20].copy_from_slice(&token.to_be_bytes());
    let sum = checksum(&p);
    p[2..4].copy_from_slice(&sum.to_be_bytes());
    p
}

/// Returns the sequence number if `buf` is a reply to one of our requests.
/// macOS includes the IPv4 header on datagram ICMP sockets, Linux does not, and Linux
/// rewrites the identifier, so replies are matched on the payload token instead.
fn parse_reply(buf: &[u8], token: u32) -> Option<u16> {
    let mut p = buf;
    if p.len() >= 20 && p[0] >> 4 == 4 {
        let ihl = usize::from(p[0] & 0x0f) * 4;
        p = p.get(ihl..)?;
    }
    if p.len() < 20 || p[0] != ECHO_REPLY || &p[8..16] != MAGIC {
        return None;
    }
    if u32::from_be_bytes(p[16..20].try_into().ok()?) != token {
        return None;
    }
    Some(u16::from_be_bytes([p[6], p[7]]))
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_packet_with_checksum_is_zero() {
        let p = echo_request(0x1234, 7, 42);
        assert_eq!(checksum(&p), 0);
    }

    #[test]
    fn parses_reply_with_and_without_ip_header() {
        let mut reply = echo_request(1, 9, 77);
        reply[0] = ECHO_REPLY;
        assert_eq!(parse_reply(&reply, 77), Some(9));
        assert_eq!(parse_reply(&reply, 78), None);

        let mut with_ip = vec![0x45u8];
        with_ip.extend_from_slice(&[0; 19]);
        with_ip.extend_from_slice(&reply);
        assert_eq!(parse_reply(&with_ip, 77), Some(9));
    }

    #[tokio::test]
    async fn pings_loopback() {
        let opts = SeriesOpts {
            count: Some(5),
            spacing: Duration::from_millis(10),
            timeout: Duration::from_millis(500),
            late_grace: Duration::ZERO,
            stop: None,
        };
        let s = ping_series(Ipv4Addr::LOCALHOST, &opts).await.unwrap();
        assert_eq!(s.sent, 5);
        assert_eq!(s.replies.len(), 5, "{s:?}");
        assert_eq!(s.duplicates, 0);
    }
}
