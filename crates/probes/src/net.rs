//! Connection plumbing shared by the connection probe and the throughput test: TCP and TLS
//! setup with per-phase timestamps, and an IO wrapper that counts bytes and records when
//! the request was written and when the first response byte arrived.

use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsFd, OwnedFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use rustls::ClientConfig;
use rustls::client::Resumption;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

pub const USER_AGENT: &str = concat!("netprobe/", env!("CARGO_PKG_VERSION"));

/// rustls with the ring provider and webpki roots built in (some systems have no CA
/// bundle). Session resumption is off so every handshake is a full, comparable one.
pub fn tls_config() -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.resumption = Resumption::disabled();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

#[derive(Debug, Clone)]
pub struct Target {
    pub https: bool,
    pub host: String,
    pub port: u16,
    /// Path and query, e.g. "/generate_204".
    pub path: String,
}

pub fn parse_url(url: &str) -> anyhow::Result<Target> {
    let uri: http::Uri = url.parse().with_context(|| format!("bad url {url}"))?;
    let https = match uri.scheme_str() {
        Some("https") => true,
        Some("http") => false,
        _ => anyhow::bail!("unsupported scheme in {url}"),
    };
    let host = uri.host().context("url has no host")?.to_string();
    let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
    let path = uri.path_and_query().map_or("/", |p| p.as_str()).to_string();
    Ok(Target { https, host, port, path })
}

/// Resolves through the OS (getaddrinfo), preferring IPv4, and returns the lookup time.
pub async fn resolve(host: &str, port: u16) -> anyhow::Result<(SocketAddr, Duration)> {
    let start = Instant::now();
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    let elapsed = start.elapsed();
    let addr = addrs.iter().find(|a| a.is_ipv4()).or(addrs.first()).copied();
    Ok((addr.with_context(|| format!("{host} has no addresses"))?, elapsed))
}

pub enum NetStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

pub struct Connected {
    pub stream: NetStream,
    /// A duplicate of the socket, so kernel TCP stats can be read even after the HTTP
    /// layer has dropped its copy.
    pub sock: OwnedFd,
    pub tcp: Duration,
    pub tls: Option<Duration>,
    pub tls_version: Option<String>,
    pub cipher: Option<String>,
    pub alpn: Option<String>,
}

/// t0 → t1 is the TCP handshake, t1 → t2 the TLS handshake.
pub async fn connect(addr: SocketAddr, host: &str, tls: Option<&Arc<ClientConfig>>) -> anyhow::Result<Connected> {
    let t0 = Instant::now();
    let tcp = TcpStream::connect(addr).await.with_context(|| format!("connect {addr}"))?;
    let t1 = Instant::now();
    tcp.set_nodelay(true)?;
    let sock = tcp.as_fd().try_clone_to_owned()?;
    let Some(cfg) = tls else {
        return Ok(Connected {
            stream: NetStream::Plain(tcp),
            sock,
            tcp: t1 - t0,
            tls: None,
            tls_version: None,
            cipher: None,
            alpn: None,
        });
    };
    let name = ServerName::try_from(host.to_string())?;
    let stream = TlsConnector::from(cfg.clone()).connect(name, tcp).await.context("tls handshake")?;
    let t2 = Instant::now();
    let conn = stream.get_ref().1;
    let tls_version = conn.protocol_version().map(|v| format!("{v:?}").replace('_', "."));
    let cipher = conn.negotiated_cipher_suite().map(|s| format!("{:?}", s.suite()));
    let alpn = conn.alpn_protocol().map(|a| String::from_utf8_lossy(a).into_owned());
    Ok(Connected {
        stream: NetStream::Tls(Box::new(stream)),
        sock,
        tcp: t1 - t0,
        tls: Some(t2 - t1),
        tls_version,
        cipher,
        alpn,
    })
}

impl AsyncRead for NetStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            NetStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            NetStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for NetStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            NetStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            NetStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            NetStream::Plain(s) => Pin::new(s).poll_flush(cx),
            NetStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            NetStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            NetStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// When the request went out and the response started, as seen above TLS.
#[derive(Debug, Default, Clone, Copy)]
pub struct IoMarks {
    pub last_write: Option<Instant>,
    pub first_read: Option<Instant>,
    /// `last_write` at the moment the first byte arrived: the end of the request.
    pub request_sent: Option<Instant>,
}

pub struct MeteredIo<S> {
    inner: S,
    read_ctr: Option<Arc<AtomicU64>>,
    write_ctr: Option<Arc<AtomicU64>>,
    marks: Arc<Mutex<IoMarks>>,
}

impl<S> MeteredIo<S> {
    pub fn new(
        inner: S,
        read_ctr: Option<Arc<AtomicU64>>,
        write_ctr: Option<Arc<AtomicU64>>,
        marks: Arc<Mutex<IoMarks>>,
    ) -> Self {
        Self { inner, read_ctr, write_ctr, marks }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for MeteredIo<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        let n = buf.filled().len() - before;
        if n > 0 {
            if let Some(c) = &this.read_ctr {
                c.fetch_add(n as u64, Ordering::Relaxed);
            }
            let mut m = this.marks.lock().unwrap();
            if m.first_read.is_none() {
                m.first_read = Some(Instant::now());
                m.request_sent = m.last_write;
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for MeteredIo<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let n = ready!(Pin::new(&mut this.inner).poll_write(cx, buf))?;
        if n > 0 {
            if let Some(c) = &this.write_ctr {
                c.fetch_add(n as u64, Ordering::Relaxed);
            }
            this.marks.lock().unwrap().last_write = Some(Instant::now());
        }
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub fn ms(d: Duration) -> f64 {
    netprobe_core::stats::round2(d.as_secs_f64() * 1000.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_urls() {
        let t = parse_url("https://www.google.com/generate_204").unwrap();
        assert!(t.https);
        assert_eq!((t.host.as_str(), t.port, t.path.as_str()), ("www.google.com", 443, "/generate_204"));
        let t = parse_url("http://10.0.0.1:8080/down?bytes=5").unwrap();
        assert!(!t.https);
        assert_eq!((t.port, t.path.as_str()), (8080, "/down?bytes=5"));
        assert!(parse_url("ftp://x").is_err());
    }
}
