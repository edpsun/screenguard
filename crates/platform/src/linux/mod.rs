//! Linux backend: logind over D-Bus for sessions and locking, the freedesktop
//! notification spec for messages, nftables + a per-UID DNS proxy for web
//! filtering.

mod dns_proxy;
mod nftables;
pub mod status_ipc;
pub mod web_filter;

use crate::session::{SessionEvent, SessionUsageState};
use anyhow::{Context, Result};
use futures_util::StreamExt;
use std::collections::HashMap;
use tokio::sync::mpsc;
use zbus::{Connection, proxy};

/// Internal per-user helper modes.
///
/// Both notifications and the Cinnamon screensaver can only be driven from a
/// connection whose peer credentials are the target user's, so the agent
/// re-executes itself under that uid with the session bus in the environment.
/// Returns `Some(exit_code)` when this process was such a re-execution and must
/// exit instead of starting the agent.
pub async fn run_helper_mode(args: &[String]) -> Option<i32> {
    match args.get(1).map(String::as_str) {
        Some("--lock-cinnamon") => Some(lock_cinnamon_as_current_user().await),
        Some("--notify") => {
            let summary = args.get(2).map(String::as_str).unwrap_or("");
            let body = args.get(3).map(String::as_str).unwrap_or("");
            if let Err(e) = notify_as_current_user(summary, body).await {
                tracing::warn!("Notification failed: {e}");
            }
            Some(0)
        }
        _ => None,
    }
}

#[proxy(
    interface = "org.freedesktop.login1.Manager",
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1"
)]
trait Login1Manager {
    #[zbus(signal)]
    fn session_new(&self, session_id: String, object_path: zbus::zvariant::OwnedObjectPath) -> Result<()>;

    #[zbus(signal)]
    fn session_removed(&self, session_id: String, object_path: zbus::zvariant::OwnedObjectPath) -> Result<()>;

    #[zbus(signal)]
    fn prepare_for_sleep(&self, start: bool) -> Result<()>;

    fn list_sessions(
        &self,
    ) -> zbus::Result<Vec<(String, u32, String, String, zbus::zvariant::OwnedObjectPath)>>;

    fn kill_session(&self, session_id: &str, who: &str, signal_number: i32) -> zbus::Result<()>;
}

#[proxy(
    interface = "org.freedesktop.login1.Session",
    default_service = "org.freedesktop.login1"
)]
trait Login1Session {
    #[zbus(property)]
    fn user(&self) -> zbus::Result<(u32, zbus::zvariant::OwnedObjectPath)>;

    #[zbus(property)]
    fn idle_hint(&self) -> zbus::Result<bool>;

    #[zbus(property)]
    fn active(&self) -> zbus::Result<bool>;

    #[zbus(property)]
    fn locked_hint(&self) -> zbus::Result<bool>;

    #[zbus(property, name = "Type")]
    fn session_type(&self) -> zbus::Result<String>;

    #[zbus(property)]
    fn desktop(&self) -> zbus::Result<String>;

    fn lock(&self) -> zbus::Result<()>;

    fn unlock(&self) -> zbus::Result<()>;

    fn terminate(&self) -> zbus::Result<()>;
}

#[proxy(
    interface = "org.cinnamon.ScreenSaver",
    default_service = "org.cinnamon.ScreenSaver",
    default_path = "/org/cinnamon/ScreenSaver"
)]
trait CinnamonScreenSaver {
    fn lock(&self, message: &str) -> zbus::Result<()>;
    fn get_active(&self) -> zbus::Result<bool>;
}

pub struct SessionMonitor {
    conn: Connection,
    tx: mpsc::Sender<SessionEvent>,
}

impl SessionMonitor {
    pub async fn new(tx: mpsc::Sender<SessionEvent>) -> Result<Self> {
        let conn = Connection::system().await?;
        Ok(Self { conn, tx })
    }

    pub async fn run(self) -> Result<()> {
        let manager = Login1ManagerProxy::new(&self.conn).await?;
        let mut session_uids = HashMap::new();

        // Emit events for graphical sessions already present at startup.
        // TTY/SSH sessions are excluded — they are never idle and must not count as screen time.
        if let Ok(sessions) = manager.list_sessions().await {
            let mut graphical = Vec::new();
            for (session_id, uid, _user, _seat, path) in sessions {
                if !self.is_graphical_session(&path).await {
                    continue;
                }
                graphical.push((session_id, uid, path));
            }

            // Snapshot first so heartbeat can reconcile DB before processing any SessionStarted.
            let _ = self.tx.send(SessionEvent::StartupSnapshot {
                sessions: graphical.iter().map(|(sid, uid, _)| (*uid, sid.clone())).collect(),
            }).await;

            for (session_id, uid, path) in graphical {
                session_uids.insert(session_id.clone(), uid);
                let state = self.get_session_state(&path, uid, &session_id).await;
                let _ = self.tx.send(SessionEvent::SessionStarted {
                    uid,
                    session_id: session_id.clone(),
                }).await;
                let _ = self.tx.send(SessionEvent::StateChanged {
                    uid,
                    session_id: session_id.clone(),
                    state,
                }).await;
                let tx = self.tx.clone();
                let conn = self.conn.clone();
                tokio::spawn(async move {
                    let _ = watch_session_state(conn, path, uid, session_id, tx).await;
                });
            }
        }

        let mut new_stream = manager.receive_session_new().await?;
        let mut removed_stream = manager.receive_session_removed().await?;
        let mut sleep_stream = manager.receive_prepare_for_sleep().await?;

        loop {
            tokio::select! {
                Some(signal) = new_stream.next() => {
                    let args = signal.args()?;
                    let session_id = args.session_id.to_string();
                    let path = args.object_path.clone();
                    let uid = self.get_session_uid(&path).await.unwrap_or(0);
                    if uid > 0 && self.is_graphical_session(&path).await {
                        tracing::info!("Session started: uid={uid} session={session_id}");
                        session_uids.insert(session_id.clone(), uid);
                        let state = self.get_session_state(&path, uid, &session_id).await;
                        let _ = self.tx.send(SessionEvent::SessionStarted {
                            uid,
                            session_id: session_id.clone(),
                        }).await;
                        let tx = self.tx.clone();
                        let conn = self.conn.clone();
                        let sid = session_id.clone();
                        let p = path.clone();
                        tokio::spawn(async move {
                            let _ = watch_session_state(conn, p, uid, sid, tx).await;
                        });
                        let _ = self.tx.send(SessionEvent::StateChanged {
                            uid,
                            session_id,
                            state,
                        }).await;
                    }
                }
                Some(signal) = removed_stream.next() => {
                    let args = signal.args()?;
                    let session_id = args.session_id.to_string();
                    let path = args.object_path.clone();
                    let uid = match session_uids.remove(&session_id) {
                        Some(uid) => uid,
                        None => self.get_session_uid(&path).await.unwrap_or(0),
                    };
                    tracing::info!("Session ended: uid={uid} session={session_id}");
                    let _ = self.tx.send(SessionEvent::SessionEnded { uid, session_id }).await;
                }
                Some(signal) = sleep_stream.next() => {
                    let args = signal.args()?;
                    let _ = self.tx.send(SessionEvent::PrepareForSleep {
                        suspend: args.start,
                    }).await;
                }
            }
        }
    }

    async fn get_session_uid(&self, path: &zbus::zvariant::OwnedObjectPath) -> Result<u32> {
        let session = Login1SessionProxy::builder(&self.conn)
            .path(path.as_ref())?
            .build()
            .await?;
        let (uid, _) = session.user().await?;
        Ok(uid)
    }

    async fn get_session_state(
        &self,
        path: &zbus::zvariant::OwnedObjectPath,
        uid: u32,
        session_id: &str,
    ) -> SessionUsageState {
        let Ok(builder) = Login1SessionProxy::builder(&self.conn).path(path.as_ref()) else {
            tracing::warn!("Cannot monitor state for uid={uid} session={session_id}: invalid object path");
            return SessionUsageState::default();
        };
        let Ok(session) = builder.build().await else {
            tracing::warn!("Cannot monitor state for uid={uid} session={session_id}: proxy unavailable");
            return SessionUsageState::default();
        };
        read_session_state(&session, uid, session_id).await
    }

    /// Returns true only for graphical sessions (x11 or wayland).
    /// TTY, SSH, and other non-graphical sessions are never counted as screen time.
    async fn is_graphical_session(&self, path: &zbus::zvariant::OwnedObjectPath) -> bool {
        let Ok(session) = Login1SessionProxy::builder(&self.conn)
            .path(path.as_ref())
            .and_then(|b| Ok(b))
        else {
            return false;
        };
        let Ok(session) = session.build().await else { return false; };
        matches!(
            session.session_type().await.as_deref(),
            Ok("x11") | Ok("wayland") | Ok("mir")
        )
    }
}

async fn watch_session_state(
    conn: Connection,
    path: zbus::zvariant::OwnedObjectPath,
    uid: u32,
    session_id: String,
    tx: mpsc::Sender<SessionEvent>,
) -> Result<()> {
    let session = Login1SessionProxy::builder(&conn)
        .path(path.as_ref())?
        .build()
        .await?;

    let mut active_stream = session.receive_active_changed().await;
    let mut locked_stream = session.receive_locked_hint_changed().await;
    let mut idle_stream = session.receive_idle_hint_changed().await;
    let state = read_session_state(&session, uid, &session_id).await;
    let _ = tx.send(SessionEvent::StateChanged {
        uid,
        session_id: session_id.clone(),
        state,
    }).await;
    loop {
        tokio::select! {
            Some(_) = active_stream.next() => {}
            Some(_) = locked_stream.next() => {}
            Some(_) = idle_stream.next() => {}
            else => break,
        }
        let state = read_session_state(&session, uid, &session_id).await;
        let _ = tx.send(SessionEvent::StateChanged {
            uid,
            session_id: session_id.clone(),
            state,
        }).await;
    }
    Ok(())
}

async fn read_session_state(
    session: &Login1SessionProxy<'_>,
    uid: u32,
    session_id: &str,
) -> SessionUsageState {
    let active = session.active().await.map_err(|e| {
        tracing::warn!("Cannot read Active for uid={uid} session={session_id}: {e}");
        e
    }).ok();
    let locked = session.locked_hint().await.map_err(|e| {
        tracing::warn!("Cannot read LockedHint for uid={uid} session={session_id}: {e}");
        e
    }).ok();
    let idle = session.idle_hint().await.map_err(|e| {
        tracing::warn!("Cannot read IdleHint for uid={uid} session={session_id}: {e}");
        e
    }).ok();
    SessionUsageState { active, locked, idle }
}

/// Lock all sessions. Cinnamon on X11 does not respond to logind Session.Lock(), so for
/// sessions explicitly identified as Cinnamon we call org.cinnamon.ScreenSaver.Lock() via
/// a subprocess running as the target user, with logind as fallback if that fails.
pub async fn lock_sessions(session_ids: &[String]) -> Result<()> {
    let conn = Connection::system().await?;
    let manager = Login1ManagerProxy::new(&conn).await?;
    let sessions = manager.list_sessions().await?;

    for (sid, uid, _user, _seat, path) in &sessions {
        if !session_ids.contains(sid) {
            continue;
        }
        let Ok(session) = Login1SessionProxy::builder(&conn)
            .path(path.as_ref())?
            .build()
            .await
        else {
            tracing::warn!("Cannot build session proxy for uid={uid} session={sid}");
            continue;
        };

        let desktop = session.desktop().await.unwrap_or_default();
        if is_cinnamon(&desktop) {
            if try_cinnamon_lock(*uid).await {
                tracing::info!("Cinnamon lock verified for uid={uid} session={sid}");
                continue;
            }
            tracing::warn!(
                "Cinnamon lock unconfirmed for uid={uid} session={sid}; falling back to logind"
            );
        }

        let _ = session.lock().await;
        tracing::info!("logind Session.Lock() sent for uid={uid} session={sid}");
    }
    Ok(())
}

/// Returns true only for sessions explicitly identified as running Cinnamon.
/// Empty or unrecognised desktop strings return false so non-Cinnamon sessions
/// always go straight to the logind path.
fn is_cinnamon(desktop: &str) -> bool {
    !desktop.is_empty()
        && desktop.split([':', ';']).any(|part| {
            matches!(
                part.trim().to_ascii_lowercase().as_str(),
                "cinnamon" | "x-cinnamon" | "cinnamon2d" | "x-cinnamon2d"
            )
        })
}

/// Spawns the agent binary as the target user to call org.cinnamon.ScreenSaver.Lock()
/// on their session bus. Returns true if the screensaver confirmed active (exit 0).
async fn try_cinnamon_lock(uid: u32) -> bool {
    let socket = format!("/run/user/{uid}/bus");
    if !std::path::Path::new(&socket).exists() {
        return false;
    }
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("Cannot locate agent binary for Cinnamon lock: {e}");
            return false;
        }
    };
    let gid = lookup_gid_for_uid(uid).unwrap_or(uid);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::process::Command::new(exe)
            .arg("--lock-cinnamon")
            .env_clear()
            .env("DBUS_SESSION_BUS_ADDRESS", format!("unix:path=/run/user/{uid}/bus"))
            .env("XDG_RUNTIME_DIR", format!("/run/user/{uid}"))
            .uid(uid)
            .gid(gid)
            .kill_on_drop(true)
            .status(),
    )
    .await;
    matches!(result, Ok(Ok(s)) if s.code() == Some(0))
}

/// Called when the agent binary is invoked with `--lock-cinnamon` as the target user.
/// Connects to the user session bus, requests Cinnamon lock, and verifies it activated.
/// Exit 0 = locked and confirmed; exit 1 = unavailable or unconfirmed.
async fn lock_cinnamon_as_current_user() -> i32 {
    let conn = match Connection::session().await {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!("Cannot connect to session bus for Cinnamon lock: {e}");
            return 1;
        }
    };
    let proxy = match CinnamonScreenSaverProxy::new(&conn).await {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!("Cannot create Cinnamon ScreenSaver proxy: {e}");
            return 1;
        }
    };
    if let Err(e) = proxy.lock("ScreenGuard").await {
        tracing::debug!("Cinnamon ScreenSaver.Lock failed: {e}");
        return 1;
    }
    // Poll GetActive briefly — the screensaver takes a moment to report active.
    for i in 0..5usize {
        match proxy.get_active().await {
            Ok(true) => return 0,
            Ok(false) => {}
            Err(e) => {
                tracing::debug!("Cinnamon ScreenSaver.GetActive failed: {e}");
                return 1;
            }
        }
        if i < 4 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
    tracing::debug!("Cinnamon lock sent but GetActive returned false after 5 checks");
    1
}

/// Unlock all sessions in the given list via DBus.
/// Called when enforcement is lifted (e.g. admin grants more time).
pub async fn unlock_sessions(session_ids: &[String]) -> Result<()> {
    let conn = Connection::system().await?;
    let manager = Login1ManagerProxy::new(&conn).await?;
    let sessions = manager.list_sessions().await?;

    for (sid, _uid, _user, _seat, path) in &sessions {
        if session_ids.contains(sid)
            && let Ok(session) = Login1SessionProxy::builder(&conn)
                .path(path.as_ref())?
                .build()
                .await
            {
                let _ = session.unlock().await;
            }
    }
    tracing::info!("Unlocked {} session(s): {:?}", session_ids.len(), session_ids);
    Ok(())
}

/// Terminate all sessions in the given list via DBus.
/// Uses Manager.KillSession with SIGKILL so that lock-screen daemons (kscreenlocker,
/// swaylock, etc.) that resist SIGTERM are forcefully removed.
pub async fn terminate_sessions(session_ids: &[String]) -> Result<()> {
    let conn = Connection::system().await?;
    let manager = Login1ManagerProxy::new(&conn).await?;

    for sid in session_ids {
        match manager.kill_session(sid, "all", 9).await {
            Ok(()) => tracing::info!("Sent SIGKILL to session {sid}"),
            Err(e) => tracing::warn!("kill_session failed for {sid}: {e}"),
        }
    }
    tracing::info!("Terminated {} session(s): {:?}", session_ids.len(), session_ids);
    Ok(())
}

/// Send a desktop notification to a user by spawning the agent binary as that user.
/// This avoids the D-Bus peer-credential rejection that occurs when root connects directly
/// to a user's session bus socket.
pub async fn send_desktop_notification(uid: u32, summary: &str, body: &str) -> Result<()> {
    let socket = format!("/run/user/{uid}/bus");
    if !std::path::Path::new(&socket).exists() {
        tracing::debug!("No session bus for uid={uid}, skipping notification");
        return Ok(());
    }

    let exe = std::env::current_exe().context("Cannot determine agent executable path")?;
    let gid = lookup_gid_for_uid(uid).unwrap_or(uid);
    let summary = summary.to_string();
    let body = body.to_string();

    tokio::task::spawn_blocking(move || {
        use std::os::unix::process::CommandExt;
        let result = std::process::Command::new(&exe)
            .arg("--notify")
            .arg(&summary)
            .arg(&body)
            .env_clear()
            .env("DBUS_SESSION_BUS_ADDRESS", format!("unix:path=/run/user/{uid}/bus"))
            .env("XDG_RUNTIME_DIR", format!("/run/user/{uid}"))
            .uid(uid)
            .gid(gid)
            .spawn();
        if let Err(e) = result {
            tracing::warn!("Failed to spawn notification subprocess for uid={uid}: {e}");
        }
    })
    .await?;

    Ok(())
}

/// Called when the agent binary is invoked with `--notify`.
/// At this point the process is already running as the target user, so the session
/// bus connection uses the correct peer credentials.
async fn notify_as_current_user(summary: &str, body: &str) -> Result<()> {
    let conn = zbus::Connection::session().await?;
    let proxy = NotificationsProxy::new(&conn).await?;
    let hints: HashMap<&str, zbus::zvariant::Value<'_>> = HashMap::new();
    let _ = proxy
        .notify("ScreenGuard", 0, "dialog-information", summary, body, &[], hints, 5000)
        .await;
    Ok(())
}

fn lookup_gid_for_uid(uid: u32) -> Option<u32> {
    let content = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in content.lines() {
        let mut fields = line.split(':');
        let _name = fields.next()?;
        let _pass = fields.next()?;
        let uid_str = fields.next()?;
        let gid_str = fields.next()?;
        if uid_str.parse::<u32>().ok() == Some(uid) {
            return gid_str.parse().ok();
        }
    }
    None
}

#[proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications"
)]
trait Notifications {
    #[allow(clippy::too_many_arguments)]
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: &[&str],
        hints: HashMap<&str, zbus::zvariant::Value<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;
}

#[cfg(test)]
mod tests {
    use super::is_cinnamon;

    #[test]
    fn is_cinnamon_recognises_cinnamon_desktops() {
        assert!(is_cinnamon("cinnamon"));
        assert!(is_cinnamon("X-Cinnamon"));
        assert!(is_cinnamon("cinnamon2d"));
        assert!(is_cinnamon("x-cinnamon2d"));
        assert!(is_cinnamon("GNOME:X-Cinnamon"));
    }

    #[test]
    fn is_cinnamon_rejects_non_cinnamon_and_unknown() {
        assert!(!is_cinnamon(""));
        assert!(!is_cinnamon("GNOME"));
        assert!(!is_cinnamon("KDE"));
        assert!(!is_cinnamon("XFCE"));
        assert!(!is_cinnamon("Hyprland"));
    }
}
