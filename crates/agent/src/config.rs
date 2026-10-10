use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

const DEFAULT_CONFIG_PATH: &str = "/etc/screenguard/agent.toml";
const CONFIG_PATH_ENV: &str = "SCREENGUARD_AGENT_CONFIG";

/// Default endpoint for **experimental** cloud mode (`--cloud-account`).
/// Overridable via `cloud_url` in agent.toml or `--server-url` on the CLI.
pub const DEFAULT_CLOUD_URL: &str = "wss://api.screenguard.cc/ws";

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct AgentConfig {
    /// Direct server WSS URL; if set, mDNS discovery is skipped.
    pub server_url: Option<String>,

    /// Web UI URL shown in the tray "Open Admin Page" menu item.
    /// If unset, derived from server_url (same host, same port).
    pub webui_url: Option<String>,

    /// **Experimental.** Cloud account (email) to bind this agent to. When set
    /// (here or via `--cloud-account`), mDNS/local discovery is skipped and the
    /// agent connects to the cloud endpoint. Keep it here so it survives
    /// restarts — the agent must present it on every reconnect.
    pub cloud_account: Option<String>,

    /// **Experimental.** Override for the cloud endpoint used in cloud mode.
    /// Defaults to [`DEFAULT_CLOUD_URL`]. `--server-url` overrides this too.
    pub cloud_url: Option<String>,

    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: u64,

    #[serde(default = "default_user_scan_interval")]
    pub user_scan_interval: u64,

    #[serde(default = "default_cache_ttl_hours")]
    pub cache_ttl_hours: u64,

    #[serde(default = "default_min_uid")]
    pub min_uid: u32,
}

fn default_heartbeat_interval() -> u64 { 10 }
fn default_user_scan_interval() -> u64 { 300 }
fn default_cache_ttl_hours() -> u64 { 48 }
/// Accounts below this uid belong to the system. Linux distributions start
/// human users at 1000; macOS starts them at 501.
#[cfg(target_os = "linux")]
fn default_min_uid() -> u32 { 1000 }
#[cfg(target_os = "macos")]
fn default_min_uid() -> u32 { 501 }

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server_url: None,
            webui_url: None,
            cloud_account: None,
            cloud_url: None,
            heartbeat_interval: default_heartbeat_interval(),
            user_scan_interval: default_user_scan_interval(),
            cache_ttl_hours: default_cache_ttl_hours(),
            min_uid: default_min_uid(),
        }
    }
}

pub fn load(path: Option<&str>) -> Result<AgentConfig> {
    let env_path = std::env::var(CONFIG_PATH_ENV).ok();
    let path = path.or(env_path.as_deref()).unwrap_or(DEFAULT_CONFIG_PATH);
    if !Path::new(path).exists() {
        tracing::warn!("Config file not found at {path}, using defaults");
        return Ok(AgentConfig::default());
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {path}"))?;
    let config: AgentConfig = toml::from_str(&raw)
        .with_context(|| format!("Failed to parse config file: {path}"))?;
    Ok(config)
}
