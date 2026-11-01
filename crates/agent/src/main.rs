//! netprobe: measures network quality in the background and keeps the results locally.

mod agent;
mod identity;
mod paths;
mod report;
mod scheduler;
mod service;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use clap::{Parser, Subcommand, ValueEnum};
use netprobe_core::Config;
use netprobe_storage::{RecordQuery, Store};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

use crate::agent::{Agent, MB, WORKER_THREADS};
use crate::identity::Identity;
use crate::scheduler::now_ms;

#[derive(Parser)]
#[command(name = "netprobe", version, about = "Measures network quality in the background")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the agent in the foreground (launchd starts it this way)
    Run {
        #[arg(long)]
        config: Option<PathBuf>,
        /// Where to keep the database [default: ~/Library/Application Support/netprobe]
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Run the probes once and print the results (nothing is stored)
    Once {
        /// Probes to run, comma separated
        #[arg(long, value_enum, value_delimiter = ',', default_value = "latency,dns,connection,throughput")]
        probes: Vec<Probe>,
        /// Skip the speed test
        #[arg(long)]
        quick: bool,
        /// Data cap for the speed test in MB [default: per_test_cap_mb from the config]
        #[arg(long)]
        cap_mb: Option<u64>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Show the service state and recent results
    Status {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// List stored measurements, newest first
    History {
        #[arg(long, value_enum)]
        probe: Option<Probe>,
        #[arg(long)]
        target: Option<String>,
        /// How far back, e.g. 30m, 24h, 7d
        #[arg(long, default_value = "24h")]
        since: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Hourly summaries instead of raw records (kept for 90 days)
        #[arg(long)]
        hourly: bool,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Install as a LaunchDaemon that starts with every boot (needs sudo)
    Install,
    /// Remove the LaunchDaemon (needs sudo)
    Uninstall {
        /// Also delete the stored measurements and the service account
        #[arg(long)]
        purge: bool,
    },
    /// Print the configuration in effect
    Config {
        /// Print the commented default config instead
        #[arg(long)]
        default: bool,
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Probe {
    Latency,
    Dns,
    Connection,
    Throughput,
    TcpSystem,
}

impl Probe {
    fn name(self) -> &'static str {
        match self {
            Probe::Latency => "latency",
            Probe::Dns => "dns",
            Probe::Connection => "connection",
            Probe::Throughput => "throughput",
            Probe::TcpSystem => "tcp_system",
        }
    }
}

fn main() -> ExitCode {
    report::init_local_offset();
    let cli = Cli::parse();
    let default_level = if matches!(cli.command, Cmd::Run { .. }) { "info" } else { "warn" };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_env("NETPROBE_LOG").unwrap_or_else(|_| EnvFilter::new(default_level)))
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .init();

    let result = match cli.command {
        Cmd::Run { config, data_dir } => cmd_run(config, data_dir),
        Cmd::Once { probes, quick, cap_mb, json, config } => cmd_once(probes, quick, cap_mb, json, config),
        Cmd::Status { json, data_dir } => cmd_status(json, data_dir),
        Cmd::History { probe, target, since, limit, hourly, json, data_dir } => {
            cmd_history(probe, target, &since, limit, hourly, json, data_dir)
        }
        Cmd::Install => service::install(),
        Cmd::Uninstall { purge } => service::uninstall(purge),
        Cmd::Config { default, config } => cmd_config(default, config),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread().worker_threads(WORKER_THREADS).enable_all().build()?)
}

fn cmd_run(config: Option<PathBuf>, data_dir: Option<PathBuf>) -> anyhow::Result<()> {
    // results must stay readable by `netprobe status` run as another user
    unsafe { libc::umask(0o022) };
    let data_dir = data_dir.unwrap_or_else(paths::user_dir);
    std::fs::create_dir_all(&data_dir).with_context(|| format!("create {}", data_dir.display()))?;
    let config_path = config.unwrap_or_else(|| data_dir.join(paths::CONFIG_FILE));
    let cfg = Config::load(&config_path)?;
    let identity = Identity::load_or_create(&data_dir)?;
    let store = Store::open(&data_dir.join(paths::DB_FILE))?;

    runtime()?.block_on(async move {
        let agent = Arc::new(Agent::new(cfg, identity));
        tracing::info!(
            version = env!("CARGO_PKG_VERSION"),
            platform = agent.platform_name(),
            data_dir = %data_dir.display(),
            config = %config_path.display(),
            "netprobe starting"
        );
        let (stop_tx, stop_rx) = watch::channel(false);
        let scheduler = tokio::spawn(scheduler::run(agent, Arc::new(Mutex::new(store)), stop_rx));
        let mut term = signal(SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
        tracing::info!("stopping");
        let _ = stop_tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(8), scheduler).await;
        Ok(())
    })
}

fn cmd_once(probes: Vec<Probe>, quick: bool, cap_mb: Option<u64>, json: bool, config: Option<PathBuf>) -> anyhow::Result<()> {
    let cfg = Config::load(&config.unwrap_or_else(paths::default_config))?;
    let identity = Identity::load_or_ephemeral(&paths::read_dir(None));
    runtime()?.block_on(async move {
        let agent = Agent::new(cfg, identity);
        let started = Instant::now();
        let tcp_before = agent.platform.system_tcp_counters();
        let mut records = Vec::new();
        for p in &probes {
            if quick && *p == Probe::Throughput || *p == Probe::TcpSystem {
                continue;
            }
            if !json {
                eprintln!("running {} probe…", p.name());
            }
            match p {
                Probe::Latency => records.extend(agent.run_latency().await),
                Probe::Dns => records.extend(agent.run_dns().await),
                Probe::Connection => records.extend(agent.run_connection().await),
                Probe::Throughput => {
                    let cap = cap_mb.unwrap_or(agent.cfg.throughput.per_test_cap_mb) * MB;
                    if agent.platform.is_metered() {
                        eprintln!("note: this connection is metered; the speed test may use up to {} MB", cap / MB);
                    }
                    records.push(agent.run_throughput(cap).await);
                }
                Probe::TcpSystem => {}
            }
        }
        if probes.contains(&Probe::TcpSystem) {
            match tcp_before {
                Some(prev) => {
                    let min = Duration::from_secs(5);
                    tokio::time::sleep(min.saturating_sub(started.elapsed())).await;
                    if let Some(cur) = agent.platform.system_tcp_counters() {
                        records.push(agent.tcp_system_record(prev, cur, started.elapsed()));
                    }
                }
                None => eprintln!("system TCP counters are only readable by root on macOS"),
            }
        }
        if json {
            println!("{}", serde_json::to_string_pretty(&records)?);
        } else {
            report::print_records(&records);
        }
        Ok(())
    })
}

fn open_store(dir: &Path) -> anyhow::Result<Option<Store>> {
    let db = dir.join(paths::DB_FILE);
    if !db.exists() {
        return Ok(None);
    }
    Ok(Some(Store::open_read_only(&db)?))
}

fn cmd_status(json: bool, data_dir: Option<PathBuf>) -> anyhow::Result<()> {
    let dir = paths::read_dir(data_dir.as_deref());
    let cfg = Config::load(&dir.join(paths::CONFIG_FILE)).unwrap_or_default();
    let platform = netprobe_platform::current();
    let ctx = platform.network_context();

    let store = open_store(&dir)?;
    let day_ago = now_ms() - netprobe_storage::DAY_MS;
    let (records, last_speed, used) = match &store {
        Some(s) => (
            s.query(&RecordQuery { since_ms: Some(day_ago), ..Default::default() })?,
            s.query(&RecordQuery { probe: Some("throughput"), limit: Some(1), ..Default::default() })?.pop(),
            s.throughput_bytes_since(day_ago)?,
        ),
        None => (Vec::new(), None, 0),
    };
    let sections = report::build_status(&records, last_speed.as_ref());
    let status = report::Status {
        version: env!("CARGO_PKG_VERSION"),
        service: service::state(),
        data_dir: dir.display().to_string(),
        network: Some(report::NetworkStatus {
            interface: ctx.interface.clone(),
            link: ctx.link.map(|l| l.as_str().to_string()),
            gateway: ctx.gateway.map(|g| g.to_string()),
            // the id is salted with the service's secret, which only the service can read
            network_id: Identity::load(&dir).and_then(|i| i.network_id(&ctx)),
            metered: platform.is_metered(),
            on_battery: platform.on_battery(),
        }),
        latency: sections.latency,
        dns: sections.dns,
        connection: sections.connection,
        speed: sections.speed,
        speed_data_24h_mb: used as f64 / MB as f64,
        daily_cap_mb: cfg.throughput.daily_cap_mb,
        tcp_retrans_1h_pct: sections.tcp_retrans_1h_pct,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }
    report::print_status(&status);
    if store.is_none() {
        println!("\nno measurements yet. Start the service with `sudo netprobe install`, or try `netprobe once`.");
    }
    Ok(())
}

fn cmd_history(
    probe: Option<Probe>,
    target: Option<String>,
    since: &str,
    limit: usize,
    hourly: bool,
    json: bool,
    data_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    let dir = paths::read_dir(data_dir.as_deref());
    let Some(store) = open_store(&dir)? else {
        bail!("no measurements in {}", dir.display());
    };
    let since_ms = now_ms() - parse_since(since)?.as_millis() as i64;
    if hourly {
        let mut rows = store.hourly(probe.map(Probe::name), since_ms)?;
        if let Some(t) = &target {
            rows.retain(|r| &r.target == t);
        }
        rows.truncate(limit);
        if json {
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
        for r in rows.iter().filter(|_| !json) {
            let hour = time::OffsetDateTime::from_unix_timestamp(r.hour_ms / 1000)?;
            println!(
                "{}  {:<10} {:<24} {:<16} avg {:>8.2}  min {:>8.2}  max {:>8.2}  n={}",
                report::local_time(hour),
                r.probe,
                r.target,
                r.metric,
                r.avg,
                r.min,
                r.max,
                r.count
            );
        }
        return Ok(());
    }
    let records = store.query(&RecordQuery {
        probe: probe.map(Probe::name),
        target: target.as_deref(),
        since_ms: Some(since_ms),
        limit: Some(limit),
    })?;
    if json {
        println!("{}", serde_json::to_string_pretty(&records)?);
    } else {
        for r in &records {
            println!("{}  {}", report::local_time(r.ts), report::summary_line(r));
        }
    }
    Ok(())
}

fn cmd_config(default: bool, config: Option<PathBuf>) -> anyhow::Result<()> {
    if default {
        print!("{}", Config::default_toml());
        return Ok(());
    }
    let path = config.unwrap_or_else(paths::default_config);
    let cfg = Config::load(&path)?;
    let source = if path.exists() { path.display().to_string() } else { format!("defaults ({} not found)", path.display()) };
    println!("# {source}\n{}", toml::to_string(&cfg)?);
    Ok(())
}

fn parse_since(s: &str) -> anyhow::Result<Duration> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num.parse().with_context(|| format!("bad duration {s:?}, use e.g. 30m, 24h, 7d"))?;
    let secs = match unit {
        "m" => n * 60,
        "h" | "" => n * 3600,
        "d" => n * 86_400,
        "w" => n * 604_800,
        _ => bail!("bad duration unit in {s:?}, use m, h, d or w"),
    };
    Ok(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_durations() {
        assert_eq!(parse_since("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_since("24h").unwrap(), Duration::from_secs(86400));
        assert_eq!(parse_since("7d").unwrap(), Duration::from_secs(7 * 86400));
        assert!(parse_since("abc").is_err());
        assert!(parse_since("5y").is_err());
    }

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
