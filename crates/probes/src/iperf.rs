//! iperf3 against our own server: TCP, upload then download (reverse mode), each with
//! several parallel streams. Runs the external `iperf3 -J` program and reads its JSON.
//! The interface (params in, `IperfData` out) is kept narrow so a built-in client can
//! replace the external program later.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use netprobe_core::model::{IperfData, IperfDirection, flag};
use netprobe_core::stats::round2;
use serde_json::Value;
use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct Params {
    pub binary: String,
    pub server: String,
    pub port: u16,
    pub duration_s: u32,
    pub streams: u32,
    pub connect_timeout_ms: u64,
}

pub struct Outcome {
    pub data: IperfData,
    pub flags: Vec<String>,
}

#[derive(Debug, PartialEq)]
struct RunError {
    message: String,
    busy: bool,
}

/// Folders searched for a bare program name in addition to PATH: launchd gives services
/// a minimal PATH that leaves out Homebrew.
const EXTRA_DIRS: &[&str] = &["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/usr/sbin"];

pub async fn run(p: &Params) -> Outcome {
    let mut data = IperfData {
        server: p.server.clone(),
        port: p.port,
        streams: p.streams,
        duration_s: p.duration_s,
        ..Default::default()
    };
    let mut flags = Vec::new();
    let Some(binary) = resolve_binary(&p.binary) else {
        data.error = Some(format!("iperf3 not installed (looked for `{}`)", p.binary));
        return Outcome { data, flags };
    };

    for reverse in [false, true] {
        match run_direction(&binary, p, reverse).await {
            Ok((dir, sent, version)) => {
                data.bytes_total += sent;
                data.version = data.version.or(version);
                if reverse {
                    data.download = Some(dir);
                } else {
                    data.upload = Some(dir);
                }
            }
            Err(e) => {
                let name = if reverse { "download" } else { "upload" };
                data.error = Some(format!("{name}: {}", e.message));
                if e.busy {
                    flags.push(flag::SERVER_BUSY.into());
                }
                // the second direction would fail the same way and only cost time
                break;
            }
        }
    }
    Outcome { data, flags }
}

/// Runs one direction and returns it with the bytes sent and the iperf3 version.
async fn run_direction(binary: &Path, p: &Params, reverse: bool) -> Result<(IperfDirection, u64, Option<String>), RunError> {
    let mut cmd = Command::new(binary);
    cmd.args(["-c", &p.server, "-p", &p.port.to_string(), "-t", &p.duration_s.to_string()])
        .args(["-P", &p.streams.to_string(), "-J", "--connect-timeout", &p.connect_timeout_ms.to_string()]);
    if reverse {
        cmd.arg("-R");
    }
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);

    let limit = Duration::from_secs(u64::from(p.duration_s) + 30) + Duration::from_millis(p.connect_timeout_ms);
    let out = match tokio::time::timeout(limit, cmd.output()).await {
        Err(_) => return Err(err(format!("no result after {} s", limit.as_secs()))),
        Ok(Err(e)) => return Err(err(format!("cannot run {}: {e}", binary.display()))),
        Ok(Ok(out)) => out,
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    match serde_json::from_str::<Value>(&stdout) {
        Ok(json) => parse(&json),
        Err(_) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let detail = stderr.trim().lines().last().unwrap_or("no output").to_string();
            Err(err(format!("iperf3 exited with {}: {detail}", out.status)))
        }
    }
}

fn err(message: String) -> RunError {
    RunError { message, busy: false }
}

/// Reads one `iperf3 -J` result. In both modes `sum_received` is what arrived at the
/// receiving end and `sum_sent` comes from the sender, so the same fields apply.
fn parse(json: &Value) -> Result<(IperfDirection, u64, Option<String>), RunError> {
    if let Some(e) = json.get("error").and_then(Value::as_str) {
        return Err(RunError { message: e.to_string(), busy: e.contains("busy") });
    }
    let end = &json["end"];
    let (sent, recv) = (&end["sum_sent"], &end["sum_received"]);
    let f = |v: &Value, k: &str| v.get(k).and_then(Value::as_f64);
    let u = |v: &Value, k: &str| v.get(k).and_then(Value::as_u64);
    let (Some(recv_bps), Some(recv_bytes)) = (f(recv, "bits_per_second"), u(recv, "bytes")) else {
        return Err(err("iperf3 result has no totals".into()));
    };
    let cpu = &end["cpu_utilization_percent"];
    let dir = IperfDirection {
        mbps: round2(recv_bps / 1e6),
        sender_mbps: round2(f(sent, "bits_per_second").unwrap_or(0.0) / 1e6),
        bytes: recv_bytes,
        duration_s: round2(f(recv, "seconds").unwrap_or(0.0)),
        retransmits: u(sent, "retransmits"),
        cpu_local_pct: f(cpu, "host_total").map(round2),
        cpu_remote_pct: f(cpu, "remote_total").map(round2),
    };
    let version = json["start"]["version"].as_str().map(str::to_string);
    Ok((dir, u(sent, "bytes").unwrap_or(recv_bytes), version))
}

/// A path is used as is; a bare name is searched in PATH and then in `EXTRA_DIRS`.
fn resolve_binary(name: &str) -> Option<PathBuf> {
    if name.contains('/') {
        let p = PathBuf::from(name);
        return p.is_file().then_some(p);
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .chain(EXTRA_DIRS.iter().map(PathBuf::from))
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_a_result() {
        let j = json!({
            "start": { "version": "iperf 3.22.1" },
            "end": {
                "sum_sent": { "seconds": 10.0, "bytes": 75_000_000u64, "bits_per_second": 60_000_000.0, "retransmits": 12 },
                "sum_received": { "seconds": 10.05, "bytes": 74_000_000u64, "bits_per_second": 58_900_000.0 },
                "cpu_utilization_percent": { "host_total": 7.5, "remote_total": 3.25 }
            }
        });
        let (d, sent, version) = parse(&j).unwrap();
        assert_eq!(d.mbps, 58.9);
        assert_eq!(d.sender_mbps, 60.0);
        assert_eq!(d.bytes, 74_000_000);
        assert_eq!(d.retransmits, Some(12));
        assert_eq!(d.cpu_local_pct, Some(7.5));
        assert_eq!(sent, 75_000_000);
        assert_eq!(version.as_deref(), Some("iperf 3.22.1"));
    }

    #[test]
    fn reports_busy_server() {
        let j = json!({ "start": {}, "end": {}, "error": "the server is busy running a test. try again later" });
        assert!(parse(&j).unwrap_err().busy);
        let j = json!({ "end": {}, "error": "unable to connect to server: Connection refused" });
        assert!(!parse(&j).unwrap_err().busy);
    }

    #[test]
    fn missing_totals_is_an_error() {
        assert!(parse(&json!({ "end": {} })).is_err());
    }

    #[tokio::test]
    async fn missing_program_is_recorded() {
        let p = Params {
            binary: "/nonexistent/iperf3".into(),
            server: "127.0.0.1".into(),
            port: 5201,
            duration_s: 1,
            streams: 1,
            connect_timeout_ms: 100,
        };
        let out = run(&p).await;
        assert!(out.data.error.unwrap().contains("not installed"));
        assert!(out.data.upload.is_none());
    }
}
