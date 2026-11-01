//! 4.3 Connection probe: one HTTPS request with every phase timed separately.
//! hyper's connection-level client is used instead of reqwest so the phases stay visible.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper::header::{CONNECTION, HOST, USER_AGENT};
use hyper_util::rt::TokioIo;
use netprobe_core::model::ConnectionData;
use rustls::ClientConfig;

use crate::net::{self, IoMarks, MeteredIo, ms};

/// Never read more than this from a connection-probe target.
const MAX_BODY: usize = 1 << 20;

pub async fn measure(url: &str, tls: &Arc<ClientConfig>, timeout: Duration) -> ConnectionData {
    let mut d = ConnectionData { url: url.to_string(), ..Default::default() };
    match tokio::time::timeout(timeout, measure_inner(url, tls, &mut d)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => d.error = Some(format!("{e:#}")),
        Err(_) => d.error = Some("timeout".into()),
    }
    d
}

async fn measure_inner(url: &str, tls: &Arc<ClientConfig>, d: &mut ConnectionData) -> anyhow::Result<()> {
    let target = net::parse_url(url)?;
    let start = Instant::now();
    // the connection is made to this pre-resolved IP so DNS time stays out of the TCP figure
    let (addr, dns) = net::resolve(&target.host, target.port).await?;
    d.dns_ms = Some(ms(dns));
    d.ip = Some(addr.ip().to_string());

    let c = net::connect(addr, &target.host, target.https.then_some(tls)).await?;
    d.tcp_ms = Some(ms(c.tcp));
    d.tls_ms = c.tls.map(ms);
    d.tls_version = c.tls_version;
    d.cipher = c.cipher;
    d.alpn = c.alpn;

    let marks = Arc::new(Mutex::new(IoMarks::default()));
    let io = MeteredIo::new(c.stream, None, None, marks.clone());
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
    let driver = tokio::spawn(conn);

    let req = Request::get(target.path.as_str())
        .header(HOST, target.host.as_str())
        .header(USER_AGENT, net::USER_AGENT)
        .header(CONNECTION, "close")
        .body(Empty::<Bytes>::new())?;
    let resp = sender.send_request(req).await?;
    d.http_status = Some(resp.status().as_u16());
    let mut body = resp.into_body();
    let mut got = 0;
    while let Some(frame) = body.frame().await {
        if let Some(data) = frame?.data_ref() {
            got += data.len();
            if got > MAX_BODY {
                break;
            }
        }
    }
    driver.abort();

    let m = *marks.lock().unwrap();
    if let (Some(first), Some(sent)) = (m.first_read, m.request_sent) {
        d.ttfb_ms = Some(ms(first - sent));
        d.total_ms = Some(ms(first - start));
    }
    Ok(())
}
