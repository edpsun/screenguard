//! Reads GUI session state, input idle time and the hardware UUID out of the
//! IOKit registry via `ioreg -a` (an XML plist).
//!
//! macOS has no logind: there is no system-level API that reports "is this
//! user's screen locked" to a root daemon. The IOKit registry root does carry
//! it, in the `IOConsoleUsers` property maintained by the window server, and
//! that is readable by root without any privacy (TCC) prompt — which is why
//! this is the backend's source of truth rather than CoreGraphics session APIs
//! (those only describe the *calling* process's session).

use anyhow::{Context, Result, anyhow, bail};
use plist::Value;
use std::io::Cursor;
use std::process::Command;
use std::time::Duration;

const IOREG: &str = "/usr/sbin/ioreg";

/// One GUI session, as the window server sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleSession {
    pub uid: u32,
    /// Window-server session id. Stable for the life of the session and used as
    /// the agent's session key, so it survives fast user switching.
    pub session_id: String,
    pub username: String,
    /// Owns the physical display right now. False for sessions parked in the
    /// background by fast user switching, and for a session suspended to the
    /// login window.
    pub on_console: bool,
    pub screen_locked: bool,
    /// False while the session is still sitting at the login window.
    pub login_done: bool,
}

/// Every logged-in GUI session. Users with no GUI session (ssh only) are absent.
pub fn console_sessions() -> Result<Vec<ConsoleSession>> {
    let root = ioreg(&["-n", "Root", "-d", "1", "-a"])?;
    parse_console_sessions(&root)
}

/// Time since the last keyboard/mouse/trackpad input, system-wide.
///
/// This is not per-session: macOS tracks HID idle time for the machine, so the
/// value only describes whichever session currently owns the display. The
/// backend therefore applies it to the on-console session only.
pub fn hid_idle_time() -> Result<Duration> {
    let v = ioreg(&["-c", "IOHIDSystem", "-d", "1", "-r", "-a"])?;
    let nanos = find_key(&v, "HIDIdleTime")
        .ok_or_else(|| anyhow!("HIDIdleTime not present under IOHIDSystem"))?;
    let nanos = nanos
        .as_unsigned_integer()
        .or_else(|| nanos.as_signed_integer().map(|n| n.max(0) as u64))
        .ok_or_else(|| anyhow!("HIDIdleTime is not an integer"))?;
    Ok(Duration::from_nanos(nanos))
}

/// The machine's hardware UUID — stable across OS and agent reinstalls.
pub fn platform_uuid() -> Result<String> {
    let v = ioreg(&["-c", "IOPlatformExpertDevice", "-d", "2", "-r", "-a"])?;
    find_key(&v, "IOPlatformUUID")
        .and_then(Value::as_string)
        .map(str::to_string)
        .ok_or_else(|| anyhow!("IOPlatformUUID not present under IOPlatformExpertDevice"))
}

fn ioreg(args: &[&str]) -> Result<Value> {
    let out = Command::new(IOREG)
        .args(args)
        .output()
        .with_context(|| format!("failed to run {IOREG} {}", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "{IOREG} {} exited with {}: {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Value::from_reader_xml(Cursor::new(out.stdout))
        .with_context(|| format!("failed to parse the plist from {IOREG} {}", args.join(" ")))
}

fn parse_console_sessions(root: &Value) -> Result<Vec<ConsoleSession>> {
    let users = find_key(root, "IOConsoleUsers")
        .ok_or_else(|| anyhow!("IOConsoleUsers not present in the IOKit registry"))?
        .as_array()
        .ok_or_else(|| anyhow!("IOConsoleUsers is not an array"))?;

    let mut sessions = Vec::new();
    for entry in users {
        let Some(dict) = entry.as_dictionary() else { continue };
        let Some(uid) = dict.get("kCGSSessionUserIDKey").and_then(as_u32) else {
            continue;
        };
        // uid 0 is the window server's own pre-login session, never a user.
        if uid == 0 {
            continue;
        }
        let session_id = dict
            .get("kCGSSessionIDKey")
            .and_then(as_u32)
            .map(|id| id.to_string())
            .unwrap_or_else(|| format!("uid:{uid}"));
        sessions.push(ConsoleSession {
            uid,
            session_id,
            username: dict
                .get("kCGSSessionUserNameKey")
                .and_then(Value::as_string)
                .unwrap_or_default()
                .to_string(),
            // Both flags are absent on some macOS versions when false.
            on_console: flag(dict, &["kCGSSessionOnConsoleKey", "kCGSessionOnConsoleKey"]),
            // Apple is not consistent about the CGS/CGSession prefix: on macOS
            // 26 the login flag arrives as `kCGSessionLoginDoneKey` (one S)
            // while the keys around it keep two. Accept either spelling —
            // guessing wrong here reads as "still at the login window", which
            // would stop usage ever accruing.
            login_done: flag(dict, &["kCGSessionLoginDoneKey", "kCGSSessionLoginDoneKey"]),
            // Only ever present while the screen is actually locked.
            screen_locked: flag(
                dict,
                &["CGSSessionScreenIsLocked", "CGSessionScreenIsLocked"],
            ),
        });
    }
    Ok(sessions)
}

/// Depth-first search for a property name. The shape of `ioreg -a` output
/// differs between the flag combinations used above (a bare array of entries,
/// or entries nested under `IORegistryEntryChildren`), so the key is located
/// rather than addressed by path.
fn find_key<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Dictionary(dict) => dict
            .get(key)
            .or_else(|| dict.values().find_map(|v| find_key(v, key))),
        Value::Array(items) => items.iter().find_map(|v| find_key(v, key)),
        _ => None,
    }
}

/// First of `keys` that the session dictionary carries, read as a boolean.
/// Absent everywhere ⇒ false, which is how the window server expresses a false
/// flag on some macOS versions.
fn flag(dict: &plist::Dictionary, keys: &[&str]) -> bool {
    keys.iter().filter_map(|k| dict.get(k)).any(as_bool)
}

/// Registry booleans come back as `<true/>` on current macOS but as `1`/`0` in
/// some older dumps, so accept either.
fn as_bool(value: &Value) -> bool {
    value
        .as_boolean()
        .or_else(|| value.as_signed_integer().map(|n| n != 0))
        .unwrap_or(false)
}

fn as_u32(value: &Value) -> Option<u32> {
    value
        .as_unsigned_integer()
        .and_then(|n| u32::try_from(n).ok())
        .or_else(|| value.as_signed_integer().and_then(|n| u32::try_from(n).ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trimmed to the properties the backend reads, but otherwise shaped
    /// exactly like `ioreg -n Root -d1 -a` on macOS 15: an array holding the
    /// Root entry, two sessions, the second one parked by fast user switching
    /// and the first one locked.
    const ROOT_PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
  <dict>
    <key>IOObjectClass</key><string>IORegistryEntry</string>
    <key>IOConsoleUsers</key>
    <array>
      <dict>
        <key>kCGSSessionUserNameKey</key><string>kid</string>
        <key>kCGSSessionUserIDKey</key><integer>501</integer>
        <key>kCGSSessionIDKey</key><integer>257</integer>
        <key>kCGSSessionOnConsoleKey</key><true/>
        <key>kCGSSessionLoginDoneKey</key><true/>
        <key>CGSSessionScreenIsLocked</key><true/>
      </dict>
      <dict>
        <key>kCGSSessionUserNameKey</key><string>admin</string>
        <key>kCGSSessionUserIDKey</key><integer>502</integer>
        <key>kCGSSessionIDKey</key><integer>258</integer>
        <key>kCGSSessionOnConsoleKey</key><false/>
        <key>kCGSSessionLoginDoneKey</key><true/>
      </dict>
    </array>
  </dict>
</array>
</plist>"#;

    fn parse(xml: &str) -> Vec<ConsoleSession> {
        let v = Value::from_reader_xml(Cursor::new(xml.as_bytes())).unwrap();
        parse_console_sessions(&v).unwrap()
    }

    #[test]
    fn reads_both_sessions_with_their_flags() {
        let sessions = parse(ROOT_PLIST);
        assert_eq!(sessions.len(), 2);

        assert_eq!(sessions[0].uid, 501);
        assert_eq!(sessions[0].session_id, "257");
        assert_eq!(sessions[0].username, "kid");
        assert!(sessions[0].on_console);
        assert!(sessions[0].login_done);
        assert!(sessions[0].screen_locked);

        assert_eq!(sessions[1].uid, 502);
        assert!(!sessions[1].on_console);
        // Absent key means unlocked, not unknown.
        assert!(!sessions[1].screen_locked);
    }

    #[test]
    fn skips_the_pre_login_window_server_session() {
        let xml = ROOT_PLIST.replace(
            "<key>kCGSSessionUserIDKey</key><integer>501</integer>",
            "<key>kCGSSessionUserIDKey</key><integer>0</integer>",
        );
        let sessions = parse(&xml);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].uid, 502);
    }

    #[test]
    fn accepts_integer_booleans() {
        let xml = ROOT_PLIST.replace(
            "<key>kCGSSessionOnConsoleKey</key><true/>",
            "<key>kCGSSessionOnConsoleKey</key><integer>1</integer>",
        );
        assert!(parse(&xml)[0].on_console);
    }

    /// macOS 26 spells the login flag `kCGSessionLoginDoneKey` — one S, unlike
    /// every key around it. Reading it as absent means "still at the login
    /// window", so the session never counts as active and no usage accrues.
    #[test]
    fn accepts_the_single_s_login_done_spelling() {
        let xml = ROOT_PLIST.replace("kCGSSessionLoginDoneKey", "kCGSessionLoginDoneKey");
        assert!(parse(&xml)[0].login_done);
    }

    #[test]
    fn missing_console_users_is_an_error_not_an_empty_list() {
        // Reporting "no sessions" here would silently stop all usage
        // accounting; the backend must fail loudly instead.
        let v = Value::from_reader_xml(Cursor::new(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><array><dict><key>IOObjectClass</key><string>X</string></dict></array></plist>"#
                .as_slice(),
        ))
        .unwrap();
        assert!(parse_console_sessions(&v).is_err());
    }

    #[test]
    fn falls_back_to_a_uid_keyed_session_id() {
        let xml = ROOT_PLIST.replace("<key>kCGSSessionIDKey</key><integer>257</integer>", "");
        assert_eq!(parse(&xml)[0].session_id, "uid:501");
    }
}
