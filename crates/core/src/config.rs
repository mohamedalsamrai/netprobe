//! One TOML config file for every platform. Every field has a default, so an empty or
//! partial file is valid.

use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub latency: LatencyConfig,
    pub dns: DnsConfig,
    pub connection: ConnectionConfig,
    pub throughput: ThroughputConfig,
    pub storage: StorageConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LatencyConfig {
    pub interval_secs: u64,
    pub count: u32,
    pub spacing_ms: u64,
    pub timeout_ms: u64,
    /// "gateway" or IPv4 addresses.
    pub targets: Vec<String>,
}

impl Default for LatencyConfig {
    fn default() -> Self {
        Self {
            interval_secs: 60,
            count: 20,
            spacing_ms: 50,
            timeout_ms: 2000,
            targets: vec!["gateway".into(), "1.1.1.1".into(), "8.8.8.8".into()],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    pub interval_secs: u64,
    pub timeout_ms: u64,
    /// Popular names that resolvers almost always have cached.
    pub cached_names: Vec<String>,
    /// A name that always exists but is never cached; `{rand}` becomes a random label.
    pub uncached_template: String,
    /// Resolvers to test in addition to the ones the OS uses.
    pub extra_resolvers: Vec<String>,
    /// Also time getaddrinfo (what applications actually see).
    pub system_lookup: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            interval_secs: 300,
            timeout_ms: 2000,
            cached_names: vec!["www.google.com".into(), "www.apple.com".into()],
            uncached_template: "{rand}.1.1.1.1.sslip.io".into(),
            extra_resolvers: vec![],
            system_lookup: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConnectionConfig {
    pub interval_secs: u64,
    pub timeout_ms: u64,
    pub targets: Vec<String>,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            interval_secs: 900,
            timeout_ms: 10_000,
            targets: vec![
                "https://www.cloudflare.com/cdn-cgi/trace".into(),
                "https://www.google.com/generate_204".into(),
                "https://www.apple.com/library/test/success.html".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ThroughputConfig {
    pub enabled: bool,
    pub interval_hours: f64,
    /// Random offset added to every run (plus or minus) so agents don't line up.
    pub jitter_minutes: u64,
    /// The first test waits at least this long after boot.
    pub boot_delay_minutes: u64,
    pub server: String,
    /// `{bytes}` is replaced with the request size.
    pub download_path: String,
    pub upload_path: String,
    pub download_chunk_mb: u64,
    pub upload_chunk_mb: u64,
    pub max_duration_secs: u64,
    pub initial_streams: u32,
    pub max_streams: u32,
    pub per_test_cap_mb: u64,
    /// Rolling 24 hour budget for speed tests.
    pub daily_cap_mb: u64,
    pub skip_on_metered: bool,
    pub skip_on_battery: bool,
    /// Postpone when background traffic exceeds this % of the last measured speed.
    pub busy_threshold_pct: f64,
    /// Target for latency under load (IPv4).
    pub latency_target: String,
}

impl Default for ThroughputConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_hours: 6.0,
            jitter_minutes: 30,
            boot_delay_minutes: 10,
            server: "https://speed.cloudflare.com".into(),
            download_path: "/__down?bytes={bytes}".into(),
            upload_path: "/__up".into(),
            download_chunk_mb: 25,
            upload_chunk_mb: 10,
            max_duration_secs: 10,
            initial_streams: 4,
            max_streams: 16,
            per_test_cap_mb: 300,
            daily_cap_mb: 1024,
            skip_on_metered: true,
            skip_on_battery: true,
            busy_threshold_pct: 10.0,
            latency_target: "1.1.1.1".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    pub raw_retention_days: u32,
    pub hourly_retention_days: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self { raw_retention_days: 7, hourly_retention_days: 90 }
    }
}

impl Config {
    /// Loads `path`, or returns the defaults when the file does not exist.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text).with_context(|| format!("invalid config {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
        }
    }

    pub fn parse(text: &str) -> anyhow::Result<Self> {
        Ok(toml::from_str(text)?)
    }

    /// The commented config file written by `netprobe install`.
    pub fn default_toml() -> &'static str {
        DEFAULT_TOML
    }
}

const DEFAULT_TOML: &str = r#"# netprobe configuration. Every key is optional; these are the defaults.

[latency]
interval_secs = 60
count = 20              # packets per target per run
spacing_ms = 50
timeout_ms = 2000       # a reply after this is counted as "late"
targets = ["gateway", "1.1.1.1", "8.8.8.8"]

[dns]
interval_secs = 300
timeout_ms = 2000
cached_names = ["www.google.com", "www.apple.com"]
# A name that always resolves but is never cached; {rand} becomes a random label.
uncached_template = "{rand}.1.1.1.1.sslip.io"
extra_resolvers = []    # e.g. ["1.1.1.1", "8.8.8.8"] to compare with the ISP resolver
system_lookup = true

[connection]
interval_secs = 900
timeout_ms = 10000
targets = [
  "https://www.cloudflare.com/cdn-cgi/trace",
  "https://www.google.com/generate_204",
  "https://www.apple.com/library/test/success.html",
]

[throughput]
enabled = true
interval_hours = 6.0
jitter_minutes = 30
boot_delay_minutes = 10
server = "https://speed.cloudflare.com"
download_path = "/__down?bytes={bytes}"
upload_path = "/__up"
download_chunk_mb = 25
upload_chunk_mb = 10
max_duration_secs = 10  # per direction
initial_streams = 4
max_streams = 16
per_test_cap_mb = 300
daily_cap_mb = 1024     # rolling 24 hours
skip_on_metered = true  # Personal Hotspot, cellular, Low Data Mode
skip_on_battery = true
busy_threshold_pct = 10.0
latency_target = "1.1.1.1"

[storage]
raw_retention_days = 7
hourly_retention_days = 90
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_toml_matches_defaults() {
        assert_eq!(Config::parse(DEFAULT_TOML).unwrap(), Config::default());
    }

    #[test]
    fn partial_file_keeps_other_defaults() {
        let cfg = Config::parse("[throughput]\ndaily_cap_mb = 200\n").unwrap();
        assert_eq!(cfg.throughput.daily_cap_mb, 200);
        assert_eq!(cfg.throughput.per_test_cap_mb, 300);
        assert_eq!(cfg.latency, LatencyConfig::default());
    }

    #[test]
    fn unknown_keys_are_rejected() {
        assert!(Config::parse("[latency]\nintervall = 5\n").is_err());
    }
}
