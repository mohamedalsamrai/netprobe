//! `netprobe install` / `uninstall`: a LaunchDaemon that starts at boot and runs as a
//! dedicated hidden account (section 7).

use std::ffi::CString;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, bail};
use netprobe_core::Config;

use crate::paths::{BIN_PATH, CONFIG_FILE, LABEL, LOG_DIR, PLIST_PATH, SERVICE_USER, SYSTEM_DIR};

const PLIST: &str = include_str!("../../../packaging/macos/com.netprobe.agent.plist");

pub fn install() -> anyhow::Result<()> {
    ensure_root()?;

    let exe = std::env::current_exe()?.canonicalize()?;
    if exe != Path::new(BIN_PATH) {
        std::fs::create_dir_all("/usr/local/bin")?;
        // copy then rename, so a running copy is replaced atomically
        let tmp = format!("{BIN_PATH}.new");
        std::fs::copy(&exe, &tmp).with_context(|| format!("copy {} to {tmp}", exe.display()))?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
        std::fs::rename(&tmp, BIN_PATH)?;
        println!("installed {BIN_PATH}");
    }

    let (uid, gid) = ensure_service_account()?;

    for dir in [SYSTEM_DIR, LOG_DIR] {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
        chown(dir, uid, gid)?;
    }
    let config = Path::new(SYSTEM_DIR).join(CONFIG_FILE);
    if !config.exists() {
        // owned by root: the service can read its config but not change it
        std::fs::write(&config, Config::default_toml())?;
        chown(&config.to_string_lossy(), 0, 0)?;
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644))?;
        println!("wrote default config {}", config.display());
    }

    if is_loaded() {
        let _ = launchctl(&["bootout", &format!("system/{LABEL}")]);
    }
    std::fs::write(PLIST_PATH, PLIST)?;
    chown(PLIST_PATH, 0, 0)?;
    std::fs::set_permissions(PLIST_PATH, std::fs::Permissions::from_mode(0o644))?;
    launchctl(&["enable", &format!("system/{LABEL}")])?;
    launchctl(&["bootstrap", "system", PLIST_PATH])?;

    println!("netprobe is installed and starts with every boot.");
    println!("  status:  netprobe status");
    println!("  logs:    tail -f {LOG_DIR}/netprobe.log");
    println!("  config:  {} (then: sudo launchctl kickstart -k system/{LABEL})", config.display());
    Ok(())
}

pub fn uninstall(purge: bool) -> anyhow::Result<()> {
    ensure_root()?;
    if is_loaded() {
        launchctl(&["bootout", &format!("system/{LABEL}")])?;
        println!("stopped the service");
    }
    for path in [PLIST_PATH, BIN_PATH] {
        if Path::new(path).exists() {
            std::fs::remove_file(path)?;
            println!("removed {path}");
        }
    }
    if Path::new(LOG_DIR).exists() {
        std::fs::remove_dir_all(LOG_DIR)?;
        println!("removed {LOG_DIR}");
    }
    if purge {
        if Path::new(SYSTEM_DIR).exists() {
            std::fs::remove_dir_all(SYSTEM_DIR)?;
            println!("removed {SYSTEM_DIR}");
        }
        if lookup_user(SERVICE_USER).is_some() {
            dscl(&["-delete", &format!("/Users/{SERVICE_USER}")])?;
        }
        if lookup_group(SERVICE_USER).is_some() {
            dscl(&["-delete", &format!("/Groups/{SERVICE_USER}")])?;
        }
        println!("removed the {SERVICE_USER} account");
    } else {
        println!("kept measurements in {SYSTEM_DIR} (use --purge to delete them)");
    }
    Ok(())
}

/// "running (pid 123)", "installed, not running" or "not installed".
pub fn state() -> String {
    if !Path::new(PLIST_PATH).exists() {
        return "not installed".into();
    }
    let Ok(out) = Command::new("launchctl").args(["print", &format!("system/{LABEL}")]).output() else {
        return "installed".into();
    };
    if !out.status.success() {
        return "installed, not loaded".into();
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let field = |key: &str| {
        text.lines().map(str::trim).find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_string()))
    };
    match (field("state = "), field("pid = ")) {
        (Some(state), Some(pid)) if state == "running" => format!("running (pid {pid})"),
        (Some(state), _) => format!("installed, {state}"),
        _ => "installed".into(),
    }
}

fn is_loaded() -> bool {
    Command::new("launchctl")
        .args(["print", &format!("system/{LABEL}")])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn ensure_root() -> anyhow::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("this needs administrator rights: run it with sudo");
    }
    Ok(())
}

/// Creates the hidden `_netprobe` user and group if they don't exist yet.
fn ensure_service_account() -> anyhow::Result<(u32, u32)> {
    if let Some(ids) = lookup_user(SERVICE_USER) {
        return Ok(ids);
    }
    // system accounts live below 500; pick an id free as both uid and gid
    let id = (300..500)
        .rev()
        .find(|&id| unsafe { libc::getpwuid(id).is_null() && libc::getgrgid(id).is_null() })
        .context("no free system uid/gid below 500")?;
    let gid = match lookup_group(SERVICE_USER) {
        Some(gid) => gid,
        None => {
            let group = format!("/Groups/{SERVICE_USER}");
            dscl(&["-create", &group])?;
            dscl(&["-create", &group, "PrimaryGroupID", &id.to_string()])?;
            dscl(&["-create", &group, "RealName", "netprobe agent"])?;
            dscl(&["-create", &group, "Password", "*"])?;
            id
        }
    };
    let user = format!("/Users/{SERVICE_USER}");
    dscl(&["-create", &user])?;
    dscl(&["-create", &user, "UniqueID", &id.to_string()])?;
    dscl(&["-create", &user, "PrimaryGroupID", &gid.to_string()])?;
    dscl(&["-create", &user, "UserShell", "/usr/bin/false"])?;
    dscl(&["-create", &user, "NFSHomeDirectory", "/var/empty"])?;
    dscl(&["-create", &user, "RealName", "netprobe agent"])?;
    dscl(&["-create", &user, "Password", "*"])?;
    dscl(&["-create", &user, "IsHidden", "1"])?;
    println!("created the hidden {SERVICE_USER} account (uid {id})");

    // directory services can take a moment to see the new account
    for _ in 0..20 {
        if let Some(ids) = lookup_user(SERVICE_USER) {
            return Ok(ids);
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    Ok((id, gid))
}

fn lookup_user(name: &str) -> Option<(u32, u32)> {
    let c = CString::new(name).ok()?;
    let pw = unsafe { libc::getpwnam(c.as_ptr()) };
    if pw.is_null() {
        return None;
    }
    unsafe { Some(((*pw).pw_uid, (*pw).pw_gid)) }
}

fn lookup_group(name: &str) -> Option<u32> {
    let c = CString::new(name).ok()?;
    let gr = unsafe { libc::getgrnam(c.as_ptr()) };
    if gr.is_null() { None } else { unsafe { Some((*gr).gr_gid) } }
}

fn chown(path: &str, uid: u32, gid: u32) -> anyhow::Result<()> {
    std::os::unix::fs::chown(path, Some(uid), Some(gid)).with_context(|| format!("chown {path}"))
}

fn dscl(args: &[&str]) -> anyhow::Result<()> {
    run("dscl", &[&["."], args].concat())
}

fn launchctl(args: &[&str]) -> anyhow::Result<()> {
    run("launchctl", args)
}

fn run(cmd: &str, args: &[&str]) -> anyhow::Result<()> {
    let out = Command::new(cmd).args(args).output().with_context(|| format!("run {cmd}"))?;
    if !out.status.success() {
        bail!("{cmd} {} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}
