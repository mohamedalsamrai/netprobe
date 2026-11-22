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
| latency (every 5 min, 50 probes at 0.2 s) | RTT, Jitter, Packet Loss | Unprivileged ICMP to 1.1.1.1, 8.8.8.8 and your own server (`"server"` = the `[iperf] server`, so its address stays out of the repo), with TCP connect timing as a fallback |
| dns (every 5 min) | DNS Resolution Time, DNS Failure Rate | Direct queries to each resolver (a cached name plus a random name under sslip.io), plus getaddrinfo |
| connection (every 5 min) | TCP Connect, TLS Handshake, TTFB | hyper + rustls, with each phase timed |
| throughput (every 1 h ± 5 min) | Download/Upload Speed, Download/Upload Latency, Retransmission Rate | Cloudflare speed.cloudflare.com, 4 to 16 streams |

- **Upload retransmissions** come from `TCP_CONNECTION_INFO` on our own sockets.
- **Download retransmissions** come from the `server-timing: cfL4` header, where Cloudflare reports its server-side TCP counters.
- **The system-wide retransmission rate** is not available: macOS 26 hides those counters from processes that are not root, and the service runs as `_netprobe`.

## One test at a time

Every test (ping, DNS, TCP/TLS/TTFB, speed test, iperf3) takes a shared lock while it runs, so tests never overlap and one test's traffic never shows up in another's numbers. For example, a ping is never measured over a link that a speed test is filling. A test that finds the lock taken waits its turn in arrival order. It is delayed, never skipped. The heartbeat stays outside the lock so it is always on time. With `NETPROBE_LOG=netprobe=debug` the log shows each wait.

## Heartbeat

Every 5 minutes (`[heartbeat] interval_secs`) the agent stores a `heartbeat` record: agent uptime, system uptime and whether the internet answered at that moment. Heartbeats start right away, even while the network is down. A gap with no heartbeats means the agent was off. Heartbeats with `internet: false` mean the agent was running but the line was down. `netprobe status` shows the last heartbeat and how many were written in 24 hours, and `netprobe history --probe heartbeat` lists them.

## iperf3 (own server)

Every 3 hours the agent runs `iperf3 -J` against your own server: TCP, 10 s per direction, 4 parallel streams, upload and then download (`-R`). It needs the `iperf3` program on the agent (`brew install iperf3`); Homebrew's folders are searched even though launchd gives services a short PATH. If iperf3 is missing or the server cannot be reached, the failed test is stored with the error.

Each agent needs its own port, because an iperf3 server runs one test at a time, and its own `slot`. Tests start `slot × slot_minutes` after each 3-hour boundary in UTC (slot 0 at 00:00, 03:00, …; slot 2 at 00:10, 03:10, …), so agents sharing a server take turns. If the server is still busy, the agent retries up to 3 times, a minute apart. Both iperf3 and the speed test count toward the same daily data budget.

```toml
[iperf]
server = "your.server"   # empty = off
port = 5203
slot = 2
```

On the server (Debian/Ubuntu), one listener per agent port:

```sh
sudo apt install -y iperf3
sudo systemctl enable --now iperf3@5201 iperf3@5202 iperf3@5203 iperf3@5204 iperf3@5205
sudo ufw allow 5201:5205/tcp
```

Try it once with `netprobe once --probes iperf`. The server's own bandwidth caps the result, so it must be faster than the fastest plan you test.

## Speed test rules

- Postponed on metered connections (Personal Hotspot, cellular, Low Data Mode) and on battery power, with a retry every 30 minutes.
- Capped at 300 MB per test and 4 GB per rolling 24 hours. On a capped 4G plan set `interval_hours = 3.0` and lower `daily_cap_mb`.
- Postponed when other traffic is using the link (up to 3 times).
- Never runs within 10 minutes of boot.
- The schedule carries over across restarts, so restarting the service does not trigger a new test.

## Privacy

netprobe does not read user traffic. The network identifier is a salted hash of the gateway's MAC address. From Cloudflare's responses it keeps only the data center name (`colo`); it does not store your IP address or location. Nothing is uploaded anywhere.
