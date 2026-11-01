//! The agent's identity and the salt used to hash network identifiers, so results can be
//! grouped per network without storing raw MAC addresses.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::Context;
use netprobe_platform::NetworkContext;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const FILE: &str = "identity.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub agent_id: String,
    pub salt: String,
}

impl Identity {
    fn generate() -> Self {
        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut salt);
        Self { agent_id: uuid::Uuid::new_v4().to_string(), salt: hex(&salt) }
    }

    pub fn load_or_create(dir: &Path) -> anyhow::Result<Self> {
        let path = dir.join(FILE);
        if let Ok(text) = std::fs::read_to_string(&path) {
            return serde_json::from_str(&text).with_context(|| format!("invalid {}", path.display()));
        }
        let id = Self::generate();
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("create {}", path.display()))?;
        f.write_all(serde_json::to_string_pretty(&id)?.as_bytes())?;
        Ok(id)
    }

    /// The saved identity if readable, otherwise a throwaway one (for `netprobe once`).
    pub fn load_or_ephemeral(dir: &Path) -> Self {
        std::fs::read_to_string(dir.join(FILE))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_else(Self::generate)
    }

    /// `h:` + a salted hash of the gateway's MAC (or its IP and interface when the MAC
    /// is unknown).
    pub fn network_id(&self, ctx: &NetworkContext) -> Option<String> {
        let mut h = Sha256::new();
        h.update(self.salt.as_bytes());
        match (ctx.gateway_mac, ctx.gateway) {
            (Some(mac), _) => h.update(mac),
            (None, Some(gw)) => {
                h.update(gw.to_string().as_bytes());
                h.update(ctx.interface.as_deref().unwrap_or_default().as_bytes());
            }
            (None, None) => return None,
        }
        Some(format!("h:{}", &hex(&h.finalize())[..8]))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_id_is_salted_and_stable() {
        let a = Identity::generate();
        let b = Identity::generate();
        let ctx = NetworkContext { gateway_mac: Some([1, 2, 3, 4, 5, 6]), ..Default::default() };
        let id = a.network_id(&ctx).unwrap();
        assert!(id.starts_with("h:") && id.len() == 10);
        assert_eq!(id, a.network_id(&ctx).unwrap());
        assert_ne!(id, b.network_id(&ctx).unwrap());
        assert_eq!(a.network_id(&NetworkContext::default()), None);
    }
}
