# 0003 — macOS agent

- **Status:** Implemented, **untested on hardware** (2026-10-10). Linux
  behaviour unchanged and still covered by its tests.
- **Date:** 2026-10-10
- **Target:** macOS 14+ on Apple silicon (M1–M4); the Intel build is produced
  but not exercised.

> The protocol did not change. A macOS agent speaks exactly the same
> `agent_hello` / `heartbeat` / `usage_sync` uplink and accepts exactly the
> same `ServerMessage` set as a Linux one, so no server or web-UI change is
> needed. What it cannot do, it withholds from the `capabilities` list that
> already existed for web filtering.

---

## Context

The agent was Linux-only, but only in its edges. Of ~5,700 lines, ~3,300
(storage, protocol, pairing, enforcement arithmetic, i18n, the DNS proxy) never
touched the OS; the Linux-specific part was logind, nftables, systemd and
`/etc/passwd`.

## Decision

**A separate `crates/platform` crate holds everything OS-specific**, with one
backend compiled per target (`src/linux`, `src/macos`). The agent crate itself
carries no `cfg` except the mDNS module, and calls `platform::…` where it used
to call `crate::dbus::…`.

Two things drove a crate rather than a module:

1. It has no C dependencies, so the macOS backend can be type-checked from a
   Linux workstation with
   `cargo check -p platform --target aarch64-apple-darwin`. The agent crate
   cannot: bundled SQLite needs the macOS SDK.
2. `backend_api_parity()` in `lib.rs` is a never-called function that exercises
   the whole public surface, so the above check also proves the macOS backend
   still fits what the agent calls.

## Mapping

| Concern | Linux | macOS |
|---|---|---|
| sessions, idle, lock state | logind D-Bus signals | `ioreg -n Root` → `IOConsoleUsers`, polled every 5 s |
| idle time | logind `IdleHint` | `IOHIDSystem.HIDIdleTime`, > 5 min counts as idle |
| lock | `Session.Lock()` (Cinnamon fallback) | `CGSession -suspend` → screen saver → display sleep, each verified |
| unlock | `Session.Unlock()` | **impossible** — no-op |
| end session | `Manager.KillSession` SIGKILL | `launchctl bootout gui/<uid>` |
| notifications | `org.freedesktop.Notifications` | `osascript display notification` via `launchctl asuser` |
| local users | `/etc/passwd` | `dscl . -list /Users` |
| hostname / machine id | `/proc/sys/kernel/hostname`, `/etc/machine-id` | `scutil --get ComputerName`, `IOPlatformUUID` |
| timezone | `/etc/timezone`, `/etc/localtime`, `timedatectl` | `/etc/localtime`, `systemsetup -gettimezone` |
| supervisor | systemd unit, sd_notify, watchdog | LaunchDaemon, `KeepAlive`; notifications are no-ops |
| `fetch_logs` | `journalctl -u screenguard-agent` | tail `/var/log/screenguard-agent.log` |
| self-update | `systemd-run` + `install.sh --update` | unsupported; re-run `install-macos.sh` |
| web filtering | nftables + per-UID DNS proxy | **unsupported**, capability withheld |

### Why `ioreg` and not CoreGraphics

`CGSessionCopyCurrentDictionary` describes only the *calling* process's
session, and the `com.apple.screenIsLocked` notification is delivered per user
session — neither is reachable from a root daemon. `IOConsoleUsers` on the
IOKit registry root is maintained by the window server, covers every session
including ones parked by fast user switching, and root reads it with no privacy
(TCC) prompt. It is parsed from `ioreg -a` XML rather than through FFI to keep
the crate pure Rust and therefore checkable from Linux.

### Why polling

macOS has no logind equivalent that pushes session changes to a daemon. The
5-second poll is two `ioreg` invocations, and usage accounting is unaffected:
the agent credits time on its own heartbeat tick, not on events.

Machine sleep needs no handling. `send_heartbeat` caps each tick's credit at
`heartbeat_interval` (`.min(interval_secs)`), so a wake after eight hours
asleep can over-count by at most one interval.

### Why the lock mechanism is a chain

macOS has no supported "lock this session" API. `CGSession -suspend` is the
best behaviour — it demands the password regardless of the user's screen-saver
settings and leaves their apps running, which is what `preserve_tasks_on_lock`
promises — but it lives at an undocumented path that may not survive a macOS
release. So each mechanism is attempted, verified against the registry, and the
one that worked is logged, making a field failure diagnosable from `fetch_logs`
alone.

## Consequences

- **Unlock is not possible.** When the server grants time back, a locked macOS
  user logs in again themselves. Linux pulls them straight through.
- **Notifications are attributed to Script Editor** and are silently dropped if
  the user denied that app. No enforcement depends on a notification arriving.
- **Enforcement assumes the managed account is a Standard user.** An
  administrator can `launchctl bootout` the daemon. The installer warns when the
  console user is an admin. (The Linux agent has the same root-versus-user
  premise; macOS just makes the first account an admin by default.)
- **Idle time is machine-wide**, so with fast user switching a background
  session is reported idle. For screen time that is the right answer.
- **No web filtering.** `pf` cannot match the owning user on redirect rules for
  locally generated traffic, so per-user DNS filtering needs a NetworkExtension
  DNS proxy — a signed system extension, deliberately out of scope. The server
  already hides the feature for devices that do not advertise the capability.

## Deliberately not done

- **mDNS discovery.** The macOS agent must be told its server
  (`--server-url` or `--cloud-account`); `discovery::resolve_server_url`
  returns a clear error otherwise. `mdns-sd` is not even built for macOS.
- **Code signing / notarisation.** Binaries fetched with `curl` are not
  quarantined, so Gatekeeper does not block them. A Developer ID would mainly
  buy a stable code identity for notification permission, and is a separate
  decision.
- **A tray / menu-bar app.** `status_ipc` is a no-op handle on macOS.

## Verification status

Done on Linux: `cargo test -p agent -p platform -p common` (68 tests), and the
Linux half of the refactor is behaviour-preserving — all pre-existing tests
moved with their code.

Done for macOS without a Mac: `cargo check -p platform --target
aarch64-apple-darwin` passes clean, which type-checks the whole backend and the
parity guard. Session-state translation, `ioreg` plist parsing and AppleScript
quoting have unit tests that run on macOS.

**Still to verify on hardware** (M4 Mac mini), in order:

0. `./agent --probe` — prints every host fact the backend reads (users,
   sessions, idle time, machine id, timezone, which lock mechanisms exist) and
   exits non-zero if any of it is unreadable. Needs neither root nor a pairing,
   so it answers steps 1–2 on its own and is the first thing to run.
1. `dscl . -list /Users UniqueID` picks up the managed account.
2. `ioreg -n Root -d1 -a` contains `IOConsoleUsers` with the keys this parses,
   and `CGSSessionScreenIsLocked` appears when the screen is locked.
3. Usage accrues while the user is active and stops when locked or idle.
4. Which lock mechanism wins — specifically whether `CGSession` still exists at
   its path on this macOS version. The agent logs the one that worked.
5. `launchctl bootout gui/<uid>` ends the session after the grace period.
6. The notification actually appears.
