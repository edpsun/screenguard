//! macOS backend (Apple silicon and Intel alike).
//!
//! Runs as a root LaunchDaemon. Everything it needs about GUI sessions comes
//! from the IOKit registry (see [`ioreg`]), which a root daemon can read with
//! no privacy prompt; anything that has to happen *inside* a user's session is
//! dispatched through `launchctl asuser`.
//!
//! Known limits, all of them deliberate for the first release:
//!
//! * **Sessions are polled**, every [`POLL_INTERVAL`]. macOS delivers lock and
//!   unlock events only as per-session distributed notifications, which a root
//!   daemon cannot subscribe to.
//! * **Idle time is machine-wide**, so it is attributed to whichever session
//!   owns the display. With fast user switching, a background session is
//!   treated as idle — which is correct for screen-time purposes.
//! * **Unlocking is impossible.** macOS offers no way to dismiss the lock
//!   screen programmatically, so [`unlock_sessions`] is a no-op and the user
//!   simply logs back in once the server grants time again.
//! * **No web filtering.** [`web_filter::is_available`] is always false, so the
//!   capability is withheld from `agent_hello` and the server hides the feature
//!   for this device.

pub(crate) mod ioreg;

use crate::session::{SessionEvent, SessionUsageState};
use anyhow::{Context, Result};
use ioreg::ConsoleSession;
use std::collections::HashMap;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::mpsc;

/// How often GUI session state is re-read. Lock/unlock and login/logout are
/// noticed within this window; usage accounting granularity is unaffected
/// because the agent credits time on its own heartbeat tick.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// How long without keyboard or mouse input counts as idle.
///
/// Fixed rather than configurable because it has to mean the same thing as
/// logind's `IdleHint` does on Linux, where it is not configurable either.
const IDLE_THRESHOLD: Duration = Duration::from_secs(300);

const LAUNCHCTL: &str = "/bin/launchctl";
const SUDO: &str = "/usr/bin/sudo";
const OSASCRIPT: &str = "/usr/bin/osascript";
const OPEN: &str = "/usr/bin/open";
const DEFAULTS: &str = "/usr/bin/defaults";
const PMSET: &str = "/usr/bin/pmset";

/// Suspends the session to the login window ("Login Window…" in the fast
/// user-switching menu). Undocumented but long-standing; absence is handled.
const CGSESSION: &str =
    "/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession";

/// How long to wait for a lock attempt to show up in the registry before
/// falling through to the next mechanism.
const LOCK_VERIFY_TIMEOUT: Duration = Duration::from_secs(3);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

/// macOS needs no per-user re-execution of the agent for notifications or
/// locking — `launchctl asuser` puts commands into the right session directly.
///
/// The one mode it does claim is `--probe`, which prints everything this
/// backend reads out of the host and exits. It needs neither root nor a
/// pairing, so it is the first thing to run on a new machine.
pub async fn run_helper_mode(args: &[String]) -> Option<i32> {
    match args.get(1).map(String::as_str) {
        Some("--probe") => Some(probe().await),
        _ => None,
    }
}

/// Report what the backend can and cannot see on this machine. Exit code 0
/// means everything the agent depends on is readable.
async fn probe() -> i32 {
    let mut ok = true;

    println!("host");
    println!("  hostname:   {}", crate::host::hostname());
    println!("  machine id: {}", crate::host::machine_id());
    println!("  timezone:   {}", crate::host::timezone());

    println!("\nlocal users (uid >= 501)");
    match crate::users::scan_local_users(501) {
        Ok(users) if users.is_empty() => {
            println!("  none found — nothing could be managed on this machine");
            ok = false;
        }
        Ok(users) => {
            for u in users {
                println!("  {:>6}  {:<16} {}", u.local_uid, u.username, u.display_name);
            }
        }
        Err(e) => {
            println!("  FAILED: {e:#}");
            ok = false;
        }
    }

    println!("\nGUI sessions");
    match read_sessions().await {
        Ok(sessions) if sessions.is_empty() => println!("  none logged in"),
        Ok(sessions) => {
            for s in sessions {
                println!(
                    "  uid={} session={} user={} on_console={} login_done={} locked={}",
                    s.uid, s.session_id, s.username, s.on_console, s.login_done, s.screen_locked
                );
            }
        }
        Err(e) => {
            println!("  FAILED: {e:#}");
            ok = false;
        }
    }

    println!("\nidle time");
    match read_idle().await {
        Ok(d) => println!("  {:?} since the last input (idle at {:?})", d, IDLE_THRESHOLD),
        Err(e) => {
            println!("  FAILED: {e:#} — no screen time could ever be counted");
            ok = false;
        }
    }

    println!("\nlock mechanisms");
    println!(
        "  CGSession:        {}",
        if std::path::Path::new(CGSESSION).exists() { "present" } else { "ABSENT — will fall back to the screen saver" }
    );
    for path in [LAUNCHCTL, SUDO, OSASCRIPT, OPEN, PMSET] {
        if !std::path::Path::new(path).exists() {
            println!("  {path}: ABSENT");
            ok = false;
        }
    }

    println!("\nweb filtering: unavailable on macOS (by design)");
    println!("\n{}", if ok { "OK — the agent has everything it needs" } else { "PROBLEMS FOUND (see FAILED/ABSENT above)" });
    i32::from(!ok)
}

// ── session monitoring ────────────────────────────────────────────────────────

pub struct SessionMonitor {
    tx: mpsc::Sender<SessionEvent>,
}

impl SessionMonitor {
    pub async fn new(tx: mpsc::Sender<SessionEvent>) -> Result<Self> {
        // Probe both queries up front. If either is unusable the agent would
        // otherwise run forever while counting nobody's screen time, so fail
        // loudly at startup instead.
        read_sessions()
            .await
            .context("cannot read GUI sessions from the IOKit registry")?;
        read_idle()
            .await
            .context("cannot read HID idle time from the IOKit registry")?;
        Ok(Self { tx })
    }

    pub async fn run(self) -> Result<()> {
        let mut known: HashMap<String, (u32, SessionUsageState)> = HashMap::new();
        let mut started = false;
        let mut ticker = tokio::time::interval(POLL_INTERVAL);

        loop {
            ticker.tick().await;

            let sessions = match read_sessions().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("Session poll failed, keeping previous state: {e}");
                    continue;
                }
            };
            let idle = match read_idle().await {
                Ok(d) => Some(d),
                Err(e) => {
                    // Leaves `idle: None`, which fails closed: no usage is
                    // counted while idle time is unknown.
                    tracing::warn!("Idle-time poll failed: {e}");
                    None
                }
            };

            let current = session_states(&sessions, idle);

            if !started {
                started = true;
                let snapshot = current
                    .iter()
                    .map(|(id, (uid, _))| (*uid, id.clone()))
                    .collect();
                // Sent first so the agent can reconcile its session table
                // before any SessionStarted arrives.
                self.send(SessionEvent::StartupSnapshot { sessions: snapshot })
                    .await;
            }

            for (session_id, (uid, state)) in &current {
                match known.get(session_id) {
                    None => {
                        tracing::info!("Session started: uid={uid} session={session_id}");
                        self.send(SessionEvent::SessionStarted {
                            uid: *uid,
                            session_id: session_id.clone(),
                        })
                        .await;
                        self.send(SessionEvent::StateChanged {
                            uid: *uid,
                            session_id: session_id.clone(),
                            state: *state,
                        })
                        .await;
                    }
                    Some((_, previous)) if previous != state => {
                        self.send(SessionEvent::StateChanged {
                            uid: *uid,
                            session_id: session_id.clone(),
                            state: *state,
                        })
                        .await;
                    }
                    Some(_) => {}
                }
            }

            for (session_id, (uid, _)) in &known {
                if !current.contains_key(session_id) {
                    tracing::info!("Session ended: uid={uid} session={session_id}");
                    self.send(SessionEvent::SessionEnded {
                        uid: *uid,
                        session_id: session_id.clone(),
                    })
                    .await;
                }
            }

            known = current;
        }
    }

    async fn send(&self, event: SessionEvent) {
        let _ = self.tx.send(event).await;
    }
}

/// Translate raw registry rows into the agent's usage model.
///
/// A session counts as active only once login has finished and it owns the
/// display; `idle` is machine-wide, so a session parked in the background by
/// fast user switching is reported idle regardless of the HID timer.
fn session_states(
    sessions: &[ConsoleSession],
    idle: Option<Duration>,
) -> HashMap<String, (u32, SessionUsageState)> {
    sessions
        .iter()
        .map(|s| {
            let state = SessionUsageState {
                active: Some(s.on_console && s.login_done),
                locked: Some(s.screen_locked),
                idle: match idle {
                    Some(d) if s.on_console => Some(d >= IDLE_THRESHOLD),
                    Some(_) => Some(true),
                    None => None,
                },
            };
            (s.session_id.clone(), (s.uid, state))
        })
        .collect()
}

async fn read_sessions() -> Result<Vec<ConsoleSession>> {
    tokio::task::spawn_blocking(ioreg::console_sessions).await?
}

async fn read_idle() -> Result<Duration> {
    tokio::task::spawn_blocking(ioreg::hid_idle_time).await?
}

// ── enforcement ───────────────────────────────────────────────────────────────

/// Lock the screen for every listed session.
///
/// Sessions already locked, or already parked at the login window by fast user
/// switching, are left alone — returning to either one needs the account
/// password, so they are as locked as this backend can make them.
pub async fn lock_sessions(session_ids: &[String]) -> Result<()> {
    for session in sessions_matching(session_ids).await? {
        if session.screen_locked || !session.on_console {
            tracing::debug!(
                "uid={} session={} already locked or off-console, nothing to do",
                session.uid,
                session.session_id
            );
            continue;
        }
        lock_one(&session).await;
    }
    Ok(())
}

/// Tries each lock mechanism in turn, verifying against the registry, because
/// which ones exist and work varies by macOS version and by the user's own
/// screen-lock settings. The mechanism that succeeded is logged so a failure
/// in the field is diagnosable from `fetch_logs` alone.
async fn lock_one(session: &ConsoleSession) -> bool {
    let (uid, user) = (session.uid, session.username.as_str());

    // 1. Suspend to the login window. Preferred: it needs no cooperation from
    //    the user's screensaver settings, always demands the password to come
    //    back, and leaves their apps and unsaved work running.
    if std::path::Path::new(CGSESSION).exists() {
        if as_root_in_session(uid, CGSESSION, &["-suspend"]).await && locked_now(uid).await {
            tracing::info!("Locked uid={uid} by suspending the session to the login window");
            return true;
        }
        tracing::warn!("CGSession -suspend did not lock uid={uid}; trying the screen saver");
    } else {
        tracing::debug!("{CGSESSION} is absent on this macOS version; trying the screen saver");
    }

    // 2. Screen saver, after making sure it actually demands a password. Best
    //    effort: on a managed Mac these keys may be enforced by a profile, in
    //    which case the writes fail and the existing policy applies.
    for (key, value) in [("askForPassword", "1"), ("askForPasswordDelay", "0")] {
        let _ = as_user(
            uid,
            user,
            DEFAULTS,
            &["-currentHost", "write", "com.apple.screensaver", key, "-int", value],
        )
        .await;
    }
    if as_user(uid, user, OPEN, &["-a", "ScreenSaverEngine"]).await && locked_now(uid).await {
        tracing::info!("Locked uid={uid} with the screen saver");
        return true;
    }
    tracing::warn!("Screen saver did not lock uid={uid}; trying display sleep");

    // 3. Display sleep. Relies on the same password-on-wake setting as (2), so
    //    it is the last resort rather than a real third option.
    if as_root_in_session(uid, PMSET, &["displaysleepnow"]).await && locked_now(uid).await {
        tracing::info!("Locked uid={uid} by putting the display to sleep");
        return true;
    }

    tracing::error!(
        "Could not lock uid={uid}: no lock mechanism took effect. Screen time is \
         still being enforced, and the session will be logged out when the grace \
         period ends unless the profile preserves running tasks."
    );
    false
}

/// Poll the registry until the session shows as locked (or off-console, which a
/// suspend to the login window produces), up to [`LOCK_VERIFY_TIMEOUT`].
async fn locked_now(uid: u32) -> bool {
    let deadline = tokio::time::Instant::now() + LOCK_VERIFY_TIMEOUT;
    loop {
        if let Ok(sessions) = read_sessions().await
            && sessions
                .iter()
                .filter(|s| s.uid == uid)
                .all(|s| s.screen_locked || !s.on_console)
        {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// macOS has no way to dismiss the lock screen from outside the session, so
/// granting time back cannot pull the user straight through it.
pub async fn unlock_sessions(session_ids: &[String]) -> Result<()> {
    tracing::info!(
        "Not unlocking {} session(s) {:?}: macOS cannot dismiss the lock screen \
         programmatically. The user can log back in now that time has been granted.",
        session_ids.len(),
        session_ids
    );
    Ok(())
}

/// Log the user out entirely, killing their applications — the counterpart to
/// terminating a logind session when the grace period expires.
pub async fn terminate_sessions(session_ids: &[String]) -> Result<()> {
    for session in sessions_matching(session_ids).await? {
        let uid = session.uid;
        if run(LAUNCHCTL, &["bootout", &format!("gui/{uid}")]).await {
            tracing::info!("Logged out uid={uid} (launchctl bootout gui/{uid})");
        } else {
            tracing::warn!("launchctl bootout gui/{uid} failed for session {}", session.session_id);
        }
    }
    Ok(())
}

// ── notifications ─────────────────────────────────────────────────────────────

/// Show a notification in a user's session.
///
/// Delivered by AppleScript, which means macOS attributes it to Script Editor:
/// if the user has denied that app notification permission, nothing appears.
/// Enforcement never depends on a notification being seen.
pub async fn send_desktop_notification(uid: u32, summary: &str, body: &str) -> Result<()> {
    let Some(session) = session_for_uid(uid).await? else {
        tracing::debug!("No GUI session for uid={uid}, skipping notification");
        return Ok(());
    };
    let script = format!(
        "display notification {} with title {}",
        applescript_literal(body),
        applescript_literal(summary)
    );
    if !as_user(uid, &session.username, OSASCRIPT, &["-e", &script]).await {
        tracing::warn!("osascript notification failed for uid={uid}");
    }
    Ok(())
}

/// Quote a string as an AppleScript literal. The result is passed to
/// `osascript -e` as a single argv element, so no shell quoting is involved —
/// only AppleScript's own escaping matters.
fn applescript_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' | '\r' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

// ── running commands in a user's session ──────────────────────────────────────

async fn sessions_matching(session_ids: &[String]) -> Result<Vec<ConsoleSession>> {
    Ok(read_sessions()
        .await?
        .into_iter()
        .filter(|s| session_ids.contains(&s.session_id))
        .collect())
}

async fn session_for_uid(uid: u32) -> Result<Option<ConsoleSession>> {
    Ok(read_sessions().await?.into_iter().find(|s| s.uid == uid))
}

/// Run inside a user's GUI session but still as root. Needed for commands that
/// talk to the window server yet must not be owned by the user.
async fn as_root_in_session(uid: u32, program: &str, args: &[&str]) -> bool {
    let uid = uid.to_string();
    let mut argv = vec!["asuser", &uid, program];
    argv.extend_from_slice(args);
    run(LAUNCHCTL, &argv).await
}

/// Run inside a user's GUI session *as* that user. `launchctl asuser` only
/// changes the bootstrap namespace, not the uid, so `sudo -u` does the rest.
async fn as_user(uid: u32, username: &str, program: &str, args: &[&str]) -> bool {
    let uid_s = uid.to_string();
    let mut argv = vec!["asuser", &uid_s, SUDO, "-u", username, program];
    argv.extend_from_slice(args);
    run(LAUNCHCTL, &argv).await
}

async fn run(program: &str, args: &[&str]) -> bool {
    let result = tokio::time::timeout(
        COMMAND_TIMEOUT,
        Command::new(program)
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await;

    match result {
        Ok(Ok(out)) if out.status.success() => true,
        Ok(Ok(out)) => {
            tracing::debug!(
                "{program} {} exited with {}: {}",
                args.join(" "),
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
            false
        }
        Ok(Err(e)) => {
            tracing::debug!("{program} {} could not be run: {e}", args.join(" "));
            false
        }
        Err(_) => {
            tracing::warn!("{program} {} timed out", args.join(" "));
            false
        }
    }
}

// ── capability stubs ──────────────────────────────────────────────────────────

/// There is no tray application on macOS, so status updates have nowhere to go.
/// A no-op handle keeps the agent's reporting path uniform across platforms.
pub mod status_ipc {
    use anyhow::Result;

    pub struct Handle;

    impl Handle {
        pub async fn update_uid(
            &self,
            _uid: u32,
            _remaining_seconds: i64,
            _enforce: &str,
            _language: &str,
        ) {
        }
    }

    pub async fn start(_server_url: String) -> Result<Handle> {
        Ok(Handle)
    }
}

/// Web filtering is not implemented on macOS.
///
/// The Linux backend redirects each UID's DNS traffic to a per-user proxy with
/// nftables. macOS `pf` cannot match the owning user on redirect rules for
/// locally generated traffic, so per-user filtering needs a NetworkExtension
/// DNS proxy — a signed system extension, out of scope here. Reporting the
/// capability as unavailable makes the server hide the feature for this device.
pub mod web_filter {
    use anyhow::Result;

    pub fn is_available() -> bool {
        false
    }

    pub struct WebFilter;

    impl WebFilter {
        pub fn new(_available: bool) -> Self {
            Self
        }

        pub async fn apply(&mut self, _uid_configs: &[(u32, Vec<String>)]) -> Result<()> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(uid: u32, on_console: bool, locked: bool, login_done: bool) -> ConsoleSession {
        ConsoleSession {
            uid,
            session_id: format!("{}", 256 + uid),
            username: format!("user{uid}"),
            on_console,
            screen_locked: locked,
            login_done,
        }
    }

    fn state_of(
        map: &HashMap<String, (u32, SessionUsageState)>,
        uid: u32,
    ) -> SessionUsageState {
        map.values().find(|(u, _)| *u == uid).unwrap().1
    }

    #[test]
    fn active_unlocked_session_with_recent_input_counts() {
        let states = session_states(&[session(501, true, false, true)], Some(Duration::ZERO));
        assert!(crate::session::session_counts_usage(&state_of(&states, 501)));
    }

    #[test]
    fn long_idle_session_does_not_count() {
        let states = session_states(
            &[session(501, true, false, true)],
            Some(IDLE_THRESHOLD + Duration::from_secs(1)),
        );
        assert_eq!(state_of(&states, 501).idle, Some(true));
    }

    #[test]
    fn session_parked_by_fast_user_switching_is_inactive_and_idle() {
        let states = session_states(&[session(502, false, false, true)], Some(Duration::ZERO));
        let state = state_of(&states, 502);
        assert_eq!(state.active, Some(false));
        // Machine-wide idle time belongs to whoever owns the display, so it
        // must not make a background session look busy.
        assert_eq!(state.idle, Some(true));
        assert!(!crate::session::session_counts_usage(&state));
    }

    #[test]
    fn session_still_at_the_login_window_is_inactive() {
        let states = session_states(&[session(501, true, false, false)], Some(Duration::ZERO));
        assert_eq!(state_of(&states, 501).active, Some(false));
    }

    #[test]
    fn unknown_idle_time_fails_closed() {
        let states = session_states(&[session(501, true, false, true)], None);
        let state = state_of(&states, 501);
        assert_eq!(state.idle, None);
        assert!(!crate::session::session_counts_usage(&state));
    }

    #[test]
    fn applescript_literal_escapes_quotes_and_backslashes() {
        assert_eq!(applescript_literal(r#"say "hi""#), r#""say \"hi\"""#);
        assert_eq!(applescript_literal(r"c:\path"), r#""c:\\path""#);
        assert_eq!(applescript_literal("two\nlines"), r#""two\nlines""#);
    }
}
