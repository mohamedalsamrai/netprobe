//! The per-OS layer. Each OS implements `Platform` in its own file; the rest of the agent
//! never needs to know which OS it is running on.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(not(target_os = "macos"))]
mod fallback;

/// A borrowed OS socket handle, used to read per-connection TCP statistics.
#[cfg(unix)]
pub type SockRef<'a> = std::os::fd::BorrowedFd<'a>;
#[cfg(windows)]
pub type SockRef<'a> = std::os::windows::io::BorrowedSocket<'a>;

/// Kernel statistics for one TCP connection.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct TcpSockStats {
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub tx_retrans_packets: u64,
    pub tx_retrans_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub rx_out_of_order_bytes: u64,
    pub srtt_ms: f64,
}

/// System-wide TCP segment counters as the kernel reports them.
///
/// `sent_segments` excludes retransmissions (as on macOS, Windows and Linux), so the
/// retransmission rate is `Δretrans / (Δsent + Δretrans)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpCounters {
    pub sent_segments: u64,
    pub retrans_segments: u64,
    /// Width of the kernel counters, for wraparound handling.
    pub counter_bits: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Wifi,
    Ethernet,
    Cellular,
    Other,
}

impl LinkType {
    pub fn as_str(self) -> &'static str {
        match self {
            LinkType::Wifi => "wifi",
            LinkType::Ethernet => "ethernet",
            LinkType::Cellular => "cellular",
            LinkType::Other => "other",
        }
    }
}

/// Where the default route currently goes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkContext {
    pub interface: Option<String>,
    pub link: Option<LinkType>,
    pub gateway: Option<IpAddr>,
    pub gateway_mac: Option<[u8; 6]>,
}

pub trait Platform: Send + Sync {
    /// e.g. "macos-26.4.1/aarch64"
    fn name(&self) -> String;
    fn socket_tcp_stats(&self, sock: SockRef<'_>) -> Option<TcpSockStats>;
    fn system_tcp_counters(&self) -> Option<TcpCounters>;
    fn dns_servers(&self) -> Vec<IpAddr>;
    fn default_gateway(&self) -> Option<IpAddr> {
        self.network_context().gateway
    }
    fn network_context(&self) -> NetworkContext;
    /// Total (received, sent) bytes of an interface since boot, as 64-bit counters.
    fn interface_bytes(&self, ifname: &str) -> Option<(u64, u64)>;
    fn is_metered(&self) -> bool;
    fn on_battery(&self) -> bool;
    fn uptime(&self) -> Option<Duration>;
}

/// The implementation for the OS this binary was built for.
pub fn current() -> Arc<dyn Platform> {
    #[cfg(target_os = "macos")]
    return Arc::new(macos::MacOs::new());
    #[cfg(not(target_os = "macos"))]
    return Arc::new(fallback::Unsupported);
}
