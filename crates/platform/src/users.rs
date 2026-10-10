//! Local user enumeration.
//!
//! The filtering rules (which accounts count as a real, manageable human) are
//! shared; only the source of the account records is platform-specific:
//! `/etc/passwd` on Linux, Directory Services on macOS — where real accounts
//! never appear in `/etc/passwd` at all.

use anyhow::Result;
use common::models::LocalUser;
use std::collections::HashMap;

const SKIP_SHELLS: &[&str] = &[
    "/usr/sbin/nologin",
    "/bin/nologin",
    "/bin/false",
    "/sbin/nologin",
    "/usr/bin/false",
];

/// Return all real local users with a uid at or above `min_uid`.
pub fn scan_local_users(min_uid: u32) -> Result<Vec<LocalUser>> {
    let records = source::read_accounts()?;
    Ok(filter_accounts(&records, min_uid))
}

/// One raw account record as read from the platform's user database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Account {
    pub username: String,
    pub uid: u32,
    /// Human-readable name (GECOS on Linux, RealName on macOS).
    pub display_name: String,
    pub shell: String,
}

/// Apply the shared "is this a manageable human account" rules.
fn filter_accounts(accounts: &[Account], min_uid: u32) -> Vec<LocalUser> {
    accounts
        .iter()
        .filter(|a| a.uid >= min_uid)
        .filter(|a| a.username != "nobody")
        // macOS hides its service accounts behind a leading underscore rather
        // than a low uid (e.g. _spotlight is uid 89, but _driverkit is 32767).
        .filter(|a| !a.username.starts_with('_'))
        .filter(|a| !SKIP_SHELLS.contains(&a.shell.as_str()))
        .map(|a| {
            let display_name = a.display_name.trim();
            LocalUser {
                local_uid: a.uid,
                username: a.username.clone(),
                display_name: if display_name.is_empty() {
                    a.username.clone()
                } else {
                    display_name.to_string()
                },
            }
        })
        .collect()
}

/// Computes the diff between a previous user snapshot and the current scan.
/// Returns (added, removed_uids).
pub fn diff_users(
    previous: &HashMap<u32, LocalUser>,
    current: &[LocalUser],
) -> (Vec<LocalUser>, Vec<u32>) {
    let current_map: HashMap<u32, &LocalUser> =
        current.iter().map(|u| (u.local_uid, u)).collect();

    let added: Vec<LocalUser> = current
        .iter()
        .filter(|u| !previous.contains_key(&u.local_uid))
        .cloned()
        .collect();

    let removed_uids: Vec<u32> = previous
        .keys()
        .filter(|uid| !current_map.contains_key(uid))
        .copied()
        .collect();

    (added, removed_uids)
}

pub fn users_to_map(users: &[LocalUser]) -> HashMap<u32, LocalUser> {
    users.iter().map(|u| (u.local_uid, u.clone())).collect()
}

// ── Linux: /etc/passwd ────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod source {
    use super::Account;
    use anyhow::Result;

    pub(super) fn read_accounts() -> Result<Vec<Account>> {
        Ok(parse_passwd(&std::fs::read_to_string("/etc/passwd")?))
    }

    pub(super) fn parse_passwd(content: &str) -> Vec<Account> {
        let mut accounts = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // username:password:uid:gid:gecos:home:shell
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 7 {
                continue;
            }
            let Ok(uid) = parts[2].parse::<u32>() else { continue };
            accounts.push(Account {
                username: parts[0].to_string(),
                uid,
                // GECOS: the display name is only the first comma-delimited
                // field, the rest being office/phone. (macOS RealName has no
                // such structure, so this splitting stays on this side.)
                display_name: parts[4].split(',').next().unwrap_or("").to_string(),
                shell: parts[6].to_string(),
            });
        }
        accounts
    }
}

// ── macOS: Directory Services ─────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod source {
    use super::Account;
    use anyhow::{Context, Result};
    use std::collections::HashMap;
    use std::process::Command;

    /// Reads the local directory node.
    ///
    /// `getpwent(3)` is not used: on macOS the real accounts live in Open
    /// Directory, not `/etc/passwd` (which holds only root/daemon/nobody), and
    /// enumeration through the Directory Services compatibility layer is not
    /// guaranteed to return them. `dscl` always does.
    pub(super) fn read_accounts() -> Result<Vec<Account>> {
        let uids = dscl_list("UniqueID").context("dscl . -list /Users UniqueID failed")?;
        let names = dscl_list("RealName").unwrap_or_default();
        let shells = dscl_list("UserShell").unwrap_or_default();

        let mut accounts = Vec::new();
        for (username, uid_str) in uids {
            let Ok(uid) = uid_str.trim().parse::<u32>() else { continue };
            accounts.push(Account {
                display_name: names.get(&username).cloned().unwrap_or_default(),
                shell: shells.get(&username).cloned().unwrap_or_default(),
                username,
                uid,
            });
        }
        Ok(accounts)
    }

    /// `dscl . -list /Users <attr>` → one `username<spaces>value` line per
    /// account. Accounts missing the attribute are simply absent from the map.
    fn dscl_list(attribute: &str) -> Result<HashMap<String, String>> {
        let out = Command::new("/usr/bin/dscl")
            .args([".", "-list", "/Users", attribute])
            .output()?;
        if !out.status.success() {
            anyhow::bail!(
                "dscl -list /Users {attribute} exited with {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(parse_dscl_list(&String::from_utf8_lossy(&out.stdout)))
    }

    pub(super) fn parse_dscl_list(stdout: &str) -> HashMap<String, String> {
        stdout
            .lines()
            .filter_map(|line| {
                // Usernames cannot contain whitespace, so the first run of
                // spaces separates the key from a value that may itself
                // contain spaces ("admin        Admin User").
                let (user, value) = line.split_once(char::is_whitespace)?;
                if user.is_empty() {
                    return None;
                }
                Some((user.to_string(), value.trim().to_string()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(username: &str, uid: u32, display_name: &str, shell: &str) -> Account {
        Account {
            username: username.to_string(),
            uid,
            display_name: display_name.to_string(),
            shell: shell.to_string(),
        }
    }

    #[test]
    fn filter_keeps_real_users_only() {
        let accounts = [
            account("root", 0, "root", "/bin/bash"),
            account("nobody", 65534, "nobody", "/bin/bash"),
            account("svc", 1002, "Service", "/bin/false"),
            account("_spotlight", 1089, "Spotlight", "/bin/bash"),
            account("tom", 1000, " Tom Smith ", "/bin/bash"),
            account("alice", 1001, "", "/bin/zsh"),
        ];
        let users = filter_accounts(&accounts, 1000);
        assert_eq!(users.len(), 2);
        assert_eq!(users[0].username, "tom");
        assert_eq!(users[0].display_name, "Tom Smith");
        assert_eq!(users[1].username, "alice");
        // Falls back to the username when there is no real name.
        assert_eq!(users[1].display_name, "alice");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_passwd_filters_correctly() {
        let content = "\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:Daemon:/usr/sbin:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
tom:x:1000:1000:Tom Smith,,,:/home/tom:/bin/bash
alice:x:1001:1001:Alice:/home/alice:/bin/zsh
svc:x:999:999:Service:/srv:/bin/false
";
        let users = filter_accounts(&source::parse_passwd(content), 1000);
        assert_eq!(users.len(), 2);
        assert_eq!(users[0].username, "tom");
        assert_eq!(users[0].display_name, "Tom Smith");
        assert_eq!(users[1].username, "alice");
        assert_eq!(users[1].display_name, "Alice");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parse_dscl_list_splits_on_first_whitespace_run() {
        let stdout = "\
_spotlight                             Spotlight
admin                                  Admin User
kid                                    Kid
daemon
";
        let map = source::parse_dscl_list(stdout);
        assert_eq!(map.get("admin").map(String::as_str), Some("Admin User"));
        assert_eq!(map.get("kid").map(String::as_str), Some("Kid"));
        assert_eq!(map.get("_spotlight").map(String::as_str), Some("Spotlight"));
        // A line with no value at all is not an account record.
        assert!(!map.contains_key("daemon"));
    }
}
