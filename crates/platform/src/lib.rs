//! Host-OS abstraction for the ScreenGuard agent.
//!
//! The agent's own code (usage accounting, enforcement, protocol, storage) is
//! platform-neutral and talks only to this crate. Exactly one backend compiles
//! per target:
//!
//! | | Linux | macOS |
//! |---|---|---|
//! | sessions / idle / lock state | logind over D-Bus (signals) | `ioreg` console sessions + HID idle time (polled) |
//! | lock screen | `Session.Lock()` (Cinnamon special case) | fast-user-switch to the login window |
//! | unlock | `Session.Unlock()` | **not possible** — no-op |
//! | end session | `Manager.KillSession` SIGKILL | `launchctl bootout gui/<uid>` |
//! | notifications | `org.freedesktop.Notifications` | `osascript display notification` |
//! | local users | `/etc/passwd` | `dscl . -list /Users` |
//! | supervisor | systemd | launchd |
//! | web filtering | nftables + per-UID DNS proxy | unsupported (capability withheld) |
//!
//! Anything a backend cannot do is reported through
//! [`web_filter::is_available`] / a no-op, never by failing the agent: the
//! `agent_hello` capability list already lets the server degrade gracefully.

mod session;

pub mod host;
pub mod users;

pub use session::{session_counts_usage, uid_counts_usage, SessionEvent, SessionUsageState};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{
    lock_sessions, run_helper_mode, send_desktop_notification, terminate_sessions,
    unlock_sessions, status_ipc, web_filter, SessionMonitor,
};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{
    lock_sessions, run_helper_mode, send_desktop_notification, terminate_sessions,
    unlock_sessions, status_ipc, web_filter, SessionMonitor,
};

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("the ScreenGuard agent supports Linux and macOS only");

/// Compile-time guard, never called: every backend must expose exactly the API
/// the agent is written against.
///
/// The agent crate links bundled SQLite, so it can only be compiled on the
/// target OS itself. This crate has no C dependencies, so
/// `cargo check -p platform --target aarch64-apple-darwin` type-checks the
/// macOS backend from any host — and because of this function, that check also
/// proves the backend still fits the agent.
#[allow(dead_code)]
async fn backend_api_parity(tx: tokio::sync::mpsc::Sender<SessionEvent>) -> anyhow::Result<()> {
    let ids: &[String] = &[];

    let monitor = SessionMonitor::new(tx).await?;
    monitor.run().await?;
    lock_sessions(ids).await?;
    unlock_sessions(ids).await?;
    terminate_sessions(ids).await?;
    send_desktop_notification(0, "summary", "body").await?;
    let _: Option<i32> = run_helper_mode(&[]).await;

    let handle: status_ipc::Handle = status_ipc::start(String::new()).await?;
    handle.update_uid(0, 0, "allow", "en").await;

    let _: bool = web_filter::is_available();
    let mut filter = web_filter::WebFilter::new(true);
    filter.apply(&[(0u32, Vec::<String>::new())]).await?;

    let _: String = host::hostname();
    let _: String = host::machine_id();
    let _: String = host::timezone();
    let _: Vec<String> = host::recent_logs();
    let _: Option<std::time::Duration> = host::watchdog_interval();
    host::notify_ready();
    host::notify_status("starting");
    host::notify_watchdog();
    host::notify_stopping();
    host::self_update()?;

    let _: Vec<common::models::LocalUser> = users::scan_local_users(0)?;
    Ok(())
}
