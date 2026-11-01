# netprobe

A Rust background service that measures network quality on a schedule and stores the results locally. This version is macOS only; other platforms come in the next phase of the plan.

## Build

```sh
cargo build --release          # binary: target/release/netprobe (about 3 MB)
cargo test                     # formula, storage and probe tests
```

## Usage

```sh
# Quick check, nothing stored (skips the speed test)
netprobe once --quick

# Every probe once, with a data cap for the speed test
netprobe once --cap-mb 50
netprobe once --probes latency,dns --json

# Install as a service that starts at every boot (LaunchDaemon)
sudo ./target/release/netprobe install

# Current state, latest results and history
netprobe status
netprobe history --probe throughput --since 7d
netprobe history --hourly --probe latency --since 30d

# Remove (measurements are kept unless you pass --purge)
sudo netprobe uninstall
sudo netprobe uninstall --purge
```

## Files after install

| What | Path |
| --- | --- |
| Binary | `/usr/local/bin/netprobe` |
| Service | `/Library/LaunchDaemons/com.netprobe.agent.plist` |
| Config | `/Library/Application Support/netprobe/config.toml` |
| Database | `/Library/Application Support/netprobe/netprobe.db` |
| Log | `/Library/Logs/netprobe/netprobe.log` |

The service runs as a dedicated hidden account (`_netprobe`), not as root. After editing the config, restart it with
`sudo launchctl kickstart -k system/com.netprobe.agent`. To see the full default config with comments, run `netprobe config --default`.

## The 13 metrics

| Probe | Metrics | How |
| --- | --- | --- |
| latency (every 60 s) | RTT, Jitter, Packet Loss | Unprivileged ICMP to the gateway, 1.1.1.1 and 8.8.8.8, with TCP connect timing as a fallback |
| dns (every 5 min) | DNS Resolution Time, DNS Failure Rate | Direct queries to each resolver (a cached name plus a random name under sslip.io), plus getaddrinfo |
| connection (every 15 min) | TCP Connect, TLS Handshake, TTFB | hyper + rustls, with each phase timed |
| throughput (every 6 h ± 30 min) | Download/Upload Speed, Download/Upload Latency, Retransmission Rate | Cloudflare speed.cloudflare.com, 4 to 16 streams |

- **Upload retransmissions** come from `TCP_CONNECTION_INFO` on our own sockets.
- **Download retransmissions** come from the `server-timing: cfL4` header, where Cloudflare reports its server-side TCP counters.
- **The system-wide retransmission rate** is not available: macOS 26 hides those counters from processes that are not root, and the service runs as `_netprobe`.

## Speed test rules

- Postponed on metered connections (Personal Hotspot, cellular, Low Data Mode) and on battery power, with a retry every 30 minutes.
- Capped at 300 MB per test and 1 GB per rolling 24 hours.
- Postponed when other traffic is using the link (up to 3 times).
- Never runs within 10 minutes of boot.
- The schedule carries over across restarts, so restarting the service does not trigger a new test.

## Privacy

netprobe does not read user traffic. The network identifier is a salted hash of the gateway's MAC address. From Cloudflare's responses it keeps only the data center name (`colo`); it does not store your IP address or location. Nothing is uploaded anywhere.
