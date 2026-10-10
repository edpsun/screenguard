//! Host identity, timezone, log retrieval and service-supervisor integration.

use std::time::Duration;

/// Best-effort detection of the host's IANA timezone name (e.g. `Europe/Warsaw`).
///
/// The server evaluates schedule windows, the daily-limit weekday, and the
/// usage-counter rollover in whatever zone the agent reports here, so a wrong
/// answer silently shifts enforcement away from the user's wall clock.
pub fn timezone() -> String {
    // Debian/Ubuntu style: plain text file. (Absent on macOS.)
    if let Ok(s) = std::fs::read_to_string("/etc/timezone") {
        let s = s.trim().to_string();
        if !s.is_empty() {
            tracing::info!("Detected system timezone {s} (from /etc/timezone)");
            return s;
        }
    }
    // systemd/Fedora/RHEL/Arch and macOS alike: /etc/localtime is a symlink
    // into a zoneinfo tree. `timedatectl set-timezone` writes a *relative* link
    // (`../usr/share/zoneinfo/Europe/Warsaw`), the path may be
    // `/usr/lib/zoneinfo/` on some distros and `/var/db/timezone/zoneinfo/` on
    // macOS, so match on the last `zoneinfo/` segment rather than a fixed
    // absolute prefix. Also handles multi-segment zones such as
    // `America/Argentina/Buenos_Aires`.
    if let Ok(path) = std::fs::read_link("/etc/localtime") {
        let s = path.to_string_lossy();
        if let Some(idx) = s.rfind("zoneinfo/") {
            let tz = s[idx + "zoneinfo/".len()..].trim_matches('/').to_string();
            if !tz.is_empty() {
                tracing::info!("Detected system timezone {tz} (from /etc/localtime)");
                return tz;
            }
        }
    }
    if let Some(tz) = imp::timezone_fallback() {
        return tz;
    }
    tracing::warn!(
        "Could not detect the system timezone — falling back to UTC. Schedule \
         windows, the daily-limit weekday, and usage rollover will all be \
         evaluated in UTC. Fix with: {}",
        imp::SET_TIMEZONE_HINT
    );
    "UTC".to_string()
}

pub fn hostname() -> String {
    imp::hostname()
}

/// A stable per-machine identifier. Used as the agent's identity across
/// re-pairings, so it must survive reboots and agent reinstalls.
pub fn machine_id() -> String {
    imp::machine_id()
}

/// The last 50 lines of the agent's own log, for the server's `fetch_logs`.
pub fn recent_logs() -> Vec<String> {
    imp::recent_logs()
}

/// Tell the service supervisor the agent is up and serving.
pub fn notify_ready() {
    imp::notify_ready();
}

/// Tell the service supervisor a shutdown is in progress.
pub fn notify_stopping() {
    imp::notify_stopping();
}

/// Free-form status line for the supervisor, shown in `systemctl status`.
pub fn notify_status(status: &str) {
    imp::notify_status(status);
}

/// How often the supervisor expects a liveness ping, if it watches at all.
pub fn watchdog_interval() -> Option<Duration> {
    imp::watchdog_interval()
}

/// Send one liveness ping. Only meaningful while [`watchdog_interval`] is `Some`.
pub fn notify_watchdog() {
    imp::notify_watchdog();
}

/// Download and run the published installer as root, replacing this agent with
/// the latest release. Returns an error when the platform has no update path.
pub fn self_update() -> anyhow::Result<()> {
    imp::self_update()
}

// ── Linux ─────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod imp {
    use libsystemd::daemon::{self, NotifyState};
    use std::time::Duration;

    pub(super) const SET_TIMEZONE_HINT: &str = "timedatectl set-timezone <your-timezone>";

    pub(super) fn timezone_fallback() -> Option<String> {
        // Older Fedora/RHEL ship /etc/localtime as a plain copy, not a symlink,
        // so the caller's read_link fails outright — ask systemd directly.
        let out = std::process::Command::new("timedatectl")
            .args(["show", "-p", "Timezone", "--value"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let tz = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if tz.is_empty() || tz == "n/a" {
            return None;
        }
        tracing::info!("Detected system timezone {tz} (from timedatectl)");
        Some(tz)
    }

    pub(super) fn hostname() -> String {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }

    pub(super) fn machine_id() -> String {
        std::fs::read_to_string("/etc/machine-id")
            .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string())
    }

    pub(super) fn recent_logs() -> Vec<String> {
        let output = std::process::Command::new("journalctl")
            .args([
                "-u",
                "screenguard-agent",
                "-n",
                "50",
                "--no-pager",
                "--output=short-iso",
            ])
            .output();
        match output {
            Ok(out) => String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(|l| l.to_string())
                .collect(),
            Err(e) => vec![format!("Failed to read journal: {e}")],
        }
    }

    pub(super) fn notify_ready() {
        let _ = daemon::notify(false, &[NotifyState::Ready]);
    }

    pub(super) fn notify_stopping() {
        let _ = daemon::notify(false, &[NotifyState::Stopping]);
    }

    pub(super) fn notify_status(status: &str) {
        let _ = daemon::notify(false, &[NotifyState::Status(status.to_string())]);
    }

    pub(super) fn watchdog_interval() -> Option<Duration> {
        daemon::watchdog_enabled(false).map(|d| d / 2)
    }

    pub(super) fn notify_watchdog() {
        let _ = daemon::notify(false, &[NotifyState::Watchdog]);
    }

    pub(super) fn self_update() -> anyhow::Result<()> {
        // systemd-run detaches the installer into its own unit so it survives
        // the agent being stopped and restarted halfway through.
        std::process::Command::new("systemd-run")
            .args([
                "--no-block",
                "--unit=screenguard-update",
                "/bin/bash",
                "-c",
                "curl -fsSL https://github.com/adambie/screenguard/releases/latest/download/install.sh | bash -s -- --update",
            ])
            .spawn()?;
        Ok(())
    }
}

// ── macOS ─────────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod imp {
    use std::time::Duration;

    /// Where the LaunchDaemon plist sends the agent's stdout/stderr.
    pub(super) const LOG_PATH: &str = "/var/log/screenguard-agent.log";

    pub(super) const SET_TIMEZONE_HINT: &str =
        "sudo systemsetup -settimezone <your-timezone>";

    pub(super) fn timezone_fallback() -> Option<String> {
        // `systemsetup -gettimezone` prints "Time Zone: Europe/Warsaw".
        let out = std::process::Command::new("/usr/sbin/systemsetup")
            .arg("-gettimezone")
            .output()
            .ok()?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let tz = stdout.split_once(':')?.1.trim().to_string();
        if tz.is_empty() {
            return None;
        }
        tracing::info!("Detected system timezone {tz} (from systemsetup)");
        Some(tz)
    }

    pub(super) fn hostname() -> String {
        // ComputerName is the user-facing name in System Settings, and unlike
        // LocalHostName it is not mangled by Bonjour collision suffixes.
        let out = std::process::Command::new("/usr/sbin/scutil")
            .args(["--get", "ComputerName"])
            .output();
        match out {
            Ok(o) if o.status.success() => {
                let name = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if name.is_empty() { "unknown".to_string() } else { name }
            }
            _ => "unknown".to_string(),
        }
    }

    pub(super) fn machine_id() -> String {
        // The hardware UUID: stable across reinstalls of both macOS and the agent.
        match crate::macos::ioreg::platform_uuid() {
            Ok(uuid) => uuid,
            Err(e) => {
                tracing::warn!(
                    "Could not read IOPlatformUUID ({e}) — falling back to a random \
                     machine id, which will re-pair this machine as a new device"
                );
                uuid::Uuid::new_v4().to_string()
            }
        }
    }

    pub(super) fn recent_logs() -> Vec<String> {
        // No journal to query: the daemon logs to a plain file (see LOG_PATH),
        // so tail it directly rather than going through `log show`, which only
        // sees os_log output and not our stdout.
        match std::fs::read_to_string(LOG_PATH) {
            Ok(content) => content
                .lines()
                .rev()
                .take(50)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .map(|l| l.to_string())
                .collect(),
            Err(e) => vec![format!("Failed to read {LOG_PATH}: {e}")],
        }
    }

    // launchd has no readiness protocol: a daemon is "up" once it is running,
    // and KeepAlive restarts it if it exits. Nothing to report.
    pub(super) fn notify_ready() {}
    pub(super) fn notify_stopping() {}
    pub(super) fn notify_status(_status: &str) {}
    pub(super) fn watchdog_interval() -> Option<Duration> {
        None
    }
    pub(super) fn notify_watchdog() {}

    pub(super) fn self_update() -> anyhow::Result<()> {
        anyhow::bail!(
            "remote update is not supported on macOS yet — re-run install-macos.sh to update"
        )
    }
}
