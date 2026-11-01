//! macOS: SystemConfiguration for the route and resolvers, sysctl for kernel counters,
//! Network.framework for metered paths and IOKit for the power source.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::AsRawFd;
use std::ptr;
use std::sync::Once;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use block2::RcBlock;
use system_configuration::core_foundation::array::CFArray;
use system_configuration::core_foundation::base::{CFType, CFTypeRef, TCFType};
use system_configuration::core_foundation::dictionary::CFDictionary;
use system_configuration::core_foundation::string::{CFString, CFStringRef};
use system_configuration::dynamic_store::SCDynamicStoreBuilder;
use system_configuration::network_configuration::{SCNetworkInterfaceType, get_interfaces};

use crate::{LinkType, NetworkContext, Platform, SockRef, TcpCounters, TcpSockStats};

pub struct MacOs {
    os_version: String,
}

impl MacOs {
    pub fn new() -> Self {
        let os_version = sysctl_string(c"kern.osproductversion").unwrap_or_else(|| "unknown".into());
        Self { os_version }
    }
}

impl Platform for MacOs {
    fn name(&self) -> String {
        format!("macos-{}/{}", self.os_version, std::env::consts::ARCH)
    }

    fn socket_tcp_stats(&self, sock: SockRef<'_>) -> Option<TcpSockStats> {
        let mut info = TcpConnectionInfo::default();
        let mut len = size_of::<TcpConnectionInfo>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_CONNECTION_INFO,
                (&raw mut info).cast(),
                &mut len,
            )
        };
        if rc != 0 || (len as usize) < size_of::<TcpConnectionInfo>() {
            return None;
        }
        Some(TcpSockStats {
            tx_packets: info.txpackets,
            tx_bytes: info.txbytes,
            tx_retrans_packets: info.txretransmitpackets,
            tx_retrans_bytes: info.txretransmitbytes,
            rx_packets: info.rxpackets,
            rx_bytes: info.rxbytes,
            rx_out_of_order_bytes: info.rxoutoforderbytes,
            srtt_ms: f64::from(info.srtt),
        })
    }

    fn system_tcp_counters(&self) -> Option<TcpCounters> {
        // struct tcpstat (netinet/tcp_var.h) starts with u32 counters:
        // [15] tcps_sndtotal, [16] tcps_sndpack, [17] tcps_sndbyte, [18] tcps_sndrexmitpack
        let mut buf = vec![0u8; 4096];
        let len = sysctl_by_name(c"net.inet.tcp.stats", &mut buf)?;
        let word = |i: usize| -> Option<u64> {
            let b = buf.get(i * 4..i * 4 + 4)?;
            Some(u64::from(u32::from_ne_bytes(b.try_into().ok()?)))
        };
        if len < 19 * 4 {
            return None;
        }
        // macOS 26 zeroes these counters for processes that are not root
        if word(15)? == 0 {
            return None;
        }
        Some(TcpCounters { sent_segments: word(16)?, retrans_segments: word(18)?, counter_bits: 32 })
    }

    fn dns_servers(&self) -> Vec<IpAddr> {
        let Some(dict) = sc_dict("State:/Network/Global/DNS") else {
            return Vec::new();
        };
        let mut out: Vec<IpAddr> = Vec::new();
        for s in dict_strings(&dict, "ServerAddresses") {
            // link-local IPv6 resolvers carry a zone, e.g. fe80::1%en0
            let addr = s.split('%').next().unwrap_or_default();
            if let Ok(ip) = addr.parse()
                && !out.contains(&ip)
            {
                out.push(ip);
            }
        }
        out
    }

    fn network_context(&self) -> NetworkContext {
        let Some(dict) = sc_dict("State:/Network/Global/IPv4") else {
            return NetworkContext::default();
        };
        let interface = dict_string(&dict, "PrimaryInterface");
        let gateway: Option<IpAddr> = dict_string(&dict, "Router").and_then(|s| s.parse().ok());
        let gateway_mac = match gateway {
            Some(IpAddr::V4(gw)) => gateway_mac(gw),
            _ => None,
        };
        let link = interface.as_deref().map(link_type);
        NetworkContext { interface, link, gateway, gateway_mac }
    }

    fn interface_bytes(&self, ifname: &str) -> Option<(u64, u64)> {
        let cname = std::ffi::CString::new(ifname).ok()?;
        let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        if index == 0 {
            return None;
        }
        let mut mib = [libc::CTL_NET, libc::PF_ROUTE, 0, 0, libc::NET_RT_IFLIST2, 0];
        let buf = sysctl_buf(&mut mib)?;
        let mut off = 0;
        while off + 4 <= buf.len() {
            let msglen = usize::from(u16::from_ne_bytes([buf[off], buf[off + 1]]));
            if msglen == 0 {
                break;
            }
            let msg_type = c_int::from(buf[off + 3]);
            if msg_type == libc::RTM_IFINFO2 && off + size_of::<libc::if_msghdr2>() <= buf.len() {
                let hdr: libc::if_msghdr2 = unsafe { ptr::read_unaligned(buf.as_ptr().add(off).cast()) };
                if u32::from(hdr.ifm_index) == index {
                    return Some((hdr.ifm_data.ifi_ibytes, hdr.ifm_data.ifi_obytes));
                }
            }
            off += msglen;
        }
        None
    }

    fn is_metered(&self) -> bool {
        path_monitor::is_metered()
    }

    fn on_battery(&self) -> bool {
        unsafe {
            let snapshot = IOPSCopyPowerSourcesInfo();
            if snapshot.is_null() {
                return false;
            }
            let snapshot = CFType::wrap_under_create_rule(snapshot);
            let source = IOPSGetProvidingPowerSourceType(snapshot.as_CFTypeRef());
            if source.is_null() {
                return false;
            }
            CFString::wrap_under_get_rule(source) == "Battery Power"
        }
    }

    fn uptime(&self) -> Option<Duration> {
        let mut tv = libc::timeval { tv_sec: 0, tv_usec: 0 };
        let mut len = size_of::<libc::timeval>();
        let rc = unsafe {
            libc::sysctlbyname(c"kern.boottime".as_ptr(), (&raw mut tv).cast(), &mut len, ptr::null_mut(), 0)
        };
        if rc != 0 {
            return None;
        }
        let boot = UNIX_EPOCH + Duration::new(tv.tv_sec as u64, tv.tv_usec as u32 * 1000);
        SystemTime::now().duration_since(boot).ok()
    }
}

/// `struct tcp_connection_info` from netinet/tcp.h. The libc crate expands the TFO
/// bitfield into separate u32s, which shifts every field after it, so it is defined here.
#[repr(C)]
#[derive(Default)]
struct TcpConnectionInfo {
    state: u8,
    snd_wscale: u8,
    rcv_wscale: u8,
    pad1: u8,
    options: u32,
    flags: u32,
    rto: u32,
    maxseg: u32,
    snd_ssthresh: u32,
    snd_cwnd: u32,
    snd_wnd: u32,
    snd_sbbytes: u32,
    rcv_wnd: u32,
    rttcur: u32,
    srtt: u32,
    rttvar: u32,
    tfo_bits: u32,
    txpackets: u64,
    txbytes: u64,
    txretransmitbytes: u64,
    rxpackets: u64,
    rxbytes: u64,
    rxoutoforderbytes: u64,
    txretransmitpackets: u64,
}

const _: () = assert!(size_of::<TcpConnectionInfo>() == 112);

fn sc_dict(key: &str) -> Option<CFDictionary<CFString, CFType>> {
    let store = SCDynamicStoreBuilder::new("netprobe").build()?;
    let dict = store.get(key)?.downcast_into::<CFDictionary>()?;
    Some(unsafe { CFDictionary::wrap_under_get_rule(dict.as_concrete_TypeRef()) })
}

fn dict_string(dict: &CFDictionary<CFString, CFType>, key: &str) -> Option<String> {
    dict.find(CFString::new(key))?.downcast::<CFString>().map(|s| s.to_string())
}

fn dict_strings(dict: &CFDictionary<CFString, CFType>, key: &str) -> Vec<String> {
    let Some(array) = dict.find(CFString::new(key)).and_then(|v| v.downcast::<CFArray>()) else {
        return Vec::new();
    };
    let array: CFArray<CFType> = unsafe { CFArray::wrap_under_get_rule(array.as_concrete_TypeRef()) };
    array.iter().filter_map(|v| v.downcast::<CFString>().map(|s| s.to_string())).collect()
}

fn link_type(bsd_name: &str) -> LinkType {
    for iface in get_interfaces().iter() {
        if iface.bsd_name().is_some_and(|n| n == bsd_name) {
            return match iface.interface_type() {
                Some(SCNetworkInterfaceType::IEEE80211) => LinkType::Wifi,
                Some(SCNetworkInterfaceType::Ethernet) => LinkType::Ethernet,
                Some(SCNetworkInterfaceType::WWAN | SCNetworkInterfaceType::Modem) => LinkType::Cellular,
                _ => LinkType::Other,
            };
        }
    }
    LinkType::Other
}

/// Looks the gateway up in the kernel ARP table (sysctl NET_RT_FLAGS / RTF_LLINFO).
fn gateway_mac(gw: Ipv4Addr) -> Option<[u8; 6]> {
    let mut mib = [libc::CTL_NET, libc::PF_ROUTE, 0, libc::AF_INET, libc::NET_RT_FLAGS, libc::RTF_LLINFO];
    let buf = sysctl_buf(&mut mib)?;
    let hdr_len = size_of::<libc::rt_msghdr>();
    let mut off = 0;
    while off + hdr_len <= buf.len() {
        let msglen = usize::from(u16::from_ne_bytes([buf[off], buf[off + 1]]));
        if msglen == 0 {
            break;
        }
        let msg = &buf[off..(off + msglen).min(buf.len())];
        off += msglen;
        // RTA_DST (sockaddr_in) followed by RTA_GATEWAY (sockaddr_dl)
        let mut p = hdr_len;
        if msg.len() < p + 8 || c_int::from(msg[p + 1]) != libc::AF_INET {
            continue;
        }
        let dst = Ipv4Addr::new(msg[p + 4], msg[p + 5], msg[p + 6], msg[p + 7]);
        p += sa_roundup(usize::from(msg[p]));
        if dst != gw || msg.len() < p + 8 || c_int::from(msg[p + 1]) != libc::AF_LINK {
            continue;
        }
        // sockaddr_dl: len, family, index(2), type, nlen, alen, slen, data[]
        let nlen = usize::from(msg[p + 5]);
        let alen = usize::from(msg[p + 6]);
        let start = p + 8 + nlen;
        if alen == 6 && msg.len() >= start + 6 {
            return msg[start..start + 6].try_into().ok();
        }
    }
    None
}

fn sa_roundup(len: usize) -> usize {
    if len == 0 { 4 } else { 1 + ((len - 1) | 3) }
}

fn sysctl_buf(mib: &mut [c_int]) -> Option<Vec<u8>> {
    let mut len = 0usize;
    let rc = unsafe {
        libc::sysctl(mib.as_mut_ptr(), mib.len() as u32, ptr::null_mut(), &mut len, ptr::null_mut(), 0)
    };
    if rc != 0 {
        return None;
    }
    // the table can grow between the two calls
    let mut buf = vec![0u8; len + len / 4 + 1024];
    let mut len = buf.len();
    let rc = unsafe {
        libc::sysctl(mib.as_mut_ptr(), mib.len() as u32, buf.as_mut_ptr().cast(), &mut len, ptr::null_mut(), 0)
    };
    if rc != 0 {
        return None;
    }
    buf.truncate(len);
    Some(buf)
}

fn sysctl_by_name(name: &CStr, out: &mut [u8]) -> Option<usize> {
    let mut len = out.len();
    let rc = unsafe { libc::sysctlbyname(name.as_ptr(), out.as_mut_ptr().cast(), &mut len, ptr::null_mut(), 0) };
    (rc == 0).then_some(len)
}

fn sysctl_string(name: &CStr) -> Option<String> {
    let mut buf = [0u8; 256];
    let len = sysctl_by_name(name, &mut buf)?;
    let s = CStr::from_bytes_until_nul(&buf[..len]).ok()?;
    Some(s.to_string_lossy().into_owned())
}

#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn IOPSCopyPowerSourcesInfo() -> CFTypeRef;
    fn IOPSGetProvidingPowerSourceType(snapshot: CFTypeRef) -> CFStringRef;
}

/// Keeps an `nw_path_monitor` running for the life of the process and caches whether the
/// current path is expensive (cellular, Personal Hotspot) or constrained (Low Data Mode).
mod path_monitor {
    use super::*;

    const KNOWN: u8 = 0x80;
    const EXPENSIVE: u8 = 0x01;
    const CONSTRAINED: u8 = 0x02;

    static STATE: AtomicU8 = AtomicU8::new(0);
    static START: Once = Once::new();

    #[link(name = "Network", kind = "framework")]
    unsafe extern "C" {
        fn nw_path_monitor_create() -> *mut c_void;
        fn nw_path_monitor_set_queue(monitor: *mut c_void, queue: *mut c_void);
        fn nw_path_monitor_set_update_handler(monitor: *mut c_void, handler: &block2::Block<dyn Fn(*mut c_void)>);
        fn nw_path_monitor_start(monitor: *mut c_void);
        fn nw_path_is_expensive(path: *mut c_void) -> bool;
        fn nw_path_is_constrained(path: *mut c_void) -> bool;
    }

    unsafe extern "C" {
        fn dispatch_queue_create(label: *const c_char, attr: *mut c_void) -> *mut c_void;
    }

    fn start() {
        START.call_once(|| unsafe {
            let queue = dispatch_queue_create(c"netprobe.path-monitor".as_ptr(), ptr::null_mut());
            let monitor = nw_path_monitor_create();
            let handler = RcBlock::new(|path: *mut c_void| {
                let mut state = KNOWN;
                if nw_path_is_expensive(path) {
                    state |= EXPENSIVE;
                }
                if nw_path_is_constrained(path) {
                    state |= CONSTRAINED;
                }
                STATE.store(state, Ordering::Relaxed);
            });
            // the monitor copies the block; the monitor and queue live until exit
            nw_path_monitor_set_update_handler(monitor, &handler);
            nw_path_monitor_set_queue(monitor, queue);
            nw_path_monitor_start(monitor);
        });
    }

    pub fn is_metered() -> bool {
        start();
        // the first update arrives on the queue shortly after start
        for _ in 0..100 {
            let state = STATE.load(Ordering::Relaxed);
            if state & KNOWN != 0 {
                return state & (EXPENSIVE | CONSTRAINED) != 0;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_live_system_state() {
        let p = MacOs::new();
        assert!(p.name().starts_with("macos-"));
        assert!(p.uptime().unwrap() > Duration::from_secs(1));
        // only available to root on macOS 26
        if let Some(c) = p.system_tcp_counters() {
            assert!(c.sent_segments > 0);
        }
        let ctx = p.network_context();
        if let Some(ifname) = &ctx.interface {
            let (rx, tx) = p.interface_bytes(ifname).unwrap();
            assert!(rx > 0 && tx > 0);
        }
        println!("{ctx:?} dns={:?} metered={} battery={}", p.dns_servers(), p.is_metered(), p.on_battery());
    }

    #[test]
    fn socket_stats_on_live_connection() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1 << 16];
            let mut total = 0;
            while total < 1 << 20 {
                total += s.read(&mut buf).unwrap();
            }
        });
        let mut c = std::net::TcpStream::connect(addr).unwrap();
        c.write_all(&vec![7u8; 1 << 20]).unwrap();
        t.join().unwrap();
        let stats = MacOs::new().socket_tcp_stats(std::os::fd::AsFd::as_fd(&c)).unwrap();
        assert!(stats.tx_bytes >= 1 << 20, "{stats:?}");
        assert!(stats.tx_packets > 0);
    }
}
