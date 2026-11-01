//! Placeholder for operating systems that have no platform layer yet. Probes still run;
//! anything that needs OS statistics reports "unknown".

use std::net::IpAddr;
use std::time::Duration;

use crate::{NetworkContext, Platform, SockRef, TcpCounters, TcpSockStats};

pub struct Unsupported;

impl Platform for Unsupported {
    fn name(&self) -> String {
        format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH)
    }
    fn socket_tcp_stats(&self, _sock: SockRef<'_>) -> Option<TcpSockStats> {
        None
    }
    fn system_tcp_counters(&self) -> Option<TcpCounters> {
        None
    }
    fn dns_servers(&self) -> Vec<IpAddr> {
        Vec::new()
    }
    fn network_context(&self) -> NetworkContext {
        NetworkContext::default()
    }
    fn interface_bytes(&self, _ifname: &str) -> Option<(u64, u64)> {
        None
    }
    fn is_metered(&self) -> bool {
        false
    }
    fn on_battery(&self) -> bool {
        false
    }
    fn uptime(&self) -> Option<Duration> {
        None
    }
}
