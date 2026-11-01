//! Where things live on macOS.

use std::path::{Path, PathBuf};

pub const LABEL: &str = "com.netprobe.agent";
pub const SYSTEM_DIR: &str = "/Library/Application Support/netprobe";
pub const PLIST_PATH: &str = "/Library/LaunchDaemons/com.netprobe.agent.plist";
pub const BIN_PATH: &str = "/usr/local/bin/netprobe";
pub const LOG_DIR: &str = "/Library/Logs/netprobe";
pub const SERVICE_USER: &str = "_netprobe";
pub const DB_FILE: &str = "netprobe.db";
pub const CONFIG_FILE: &str = "config.toml";

/// Per-user data directory, used by `netprobe run` when started by hand.
pub fn user_dir() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    home.join("Library/Application Support/netprobe")
}

/// The directory to read results from: the explicit one, else the service's if it has
/// a database, else the user's.
pub fn read_dir(explicit: Option<&Path>) -> PathBuf {
    if let Some(dir) = explicit {
        return dir.to_path_buf();
    }
    let system = Path::new(SYSTEM_DIR);
    if system.join(DB_FILE).exists() { system.to_path_buf() } else { user_dir() }
}

/// The config file to use when none is given: the service's, else the user's.
pub fn default_config() -> PathBuf {
    let system = Path::new(SYSTEM_DIR).join(CONFIG_FILE);
    if system.exists() { system } else { user_dir().join(CONFIG_FILE) }
}
