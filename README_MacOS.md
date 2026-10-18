# ScreenGuard agent on macOS

The macOS agent is a managed-machine agent only — the server and web UI stay on
Linux. It speaks the same protocol as the Linux agent, so a Mac shows up in the
web UI and the mobile app like any other device. Design notes, the Linux↔macOS
mapping and the open verification list live in
[docs/0003-macos-agent.md](docs/0003-macos-agent.md).

**Requirements**

- macOS 14 or newer, Apple silicon or Intel
- Xcode command line tools if you build locally: `xcode-select --install`
- A reachable ScreenGuard server URL or a cloud account — there is **no mDNS
  discovery on macOS**, so the agent has to be told where its server is
- The account you intend to manage should be a **Standard** (non-admin) user —
  see [Enforcement only holds against a Standard account](#enforcement-only-holds-against-a-standard-account)

---

## Install from a local build

Build the agent, check what it can see on this machine, then install it as a
LaunchDaemon:

```bash
cargo build --release -p agent

# Prints every host fact the backend reads — users, sessions, idle time,
# machine id, timezone, which lock mechanisms exist. Needs neither root nor a
# pairing, and exits non-zero if anything the agent depends on is unreadable.
./target/release/agent --probe

sudo ./install-macos.sh --from target/release/agent \
  --server-url ws://192.168.1.100:8765/ws
```

Use `--cloud-account you@example.com` in place of `--server-url` to pair against
the hosted server at [screenguard.cc](https://screenguard.cc).

The machine then shows as *pending* on the server; approve it there and it is
managed.

### `--from` is currently not optional

Without `--from`, the installer downloads the published release. The latest
release (0.10.12) predates three macOS fixes that are in the working tree but
not yet released:

- pairing derived the machine id and hostname itself instead of asking the
  platform backend, so a Mac paired under one identity and said hello under
  another — the server answered *Unknown agent* and dropped the socket. The
  agent paired successfully and then never connected.
- `IOConsoleUsers` on macOS 26 spells the login flag `kCGSessionLoginDoneKey`
  with one `S`. Read as absent, every session looks like it is still at the
  login window, so no usage ever accrued.
- a session returning from the lock screen while its uid is still blocked is
  now re-locked off the local session event, instead of waiting up to one
  heartbeat interval.

Until a release carries these, every macOS install has to come from a local
build.

## Trying it before installing the daemon

Running the binary directly in a terminal is the quickest way to watch a first
pairing. Point it at a scratch database so it does not touch the daemon's:

```bash
mkdir -p /tmp/screenguard-test
PARENTAL_AGENT_DB=/tmp/screenguard-test/agent.db \
  ./target/release/agent --server-url ws://192.168.1.100:8765/ws
```

It prints a pairing code; approve the request on the server.

### Carrying that pairing into the daemon

The daemon reads `/var/lib/screenguard/agent.db`. Copy the scratch database
there before installing and the existing pairing is reused, so you do not
approve a second request:

```bash
sudo mkdir -p /var/lib/screenguard
sudo cp /tmp/screenguard-test/agent.db /var/lib/screenguard/agent.db
```

Stop the manual agent (Ctrl-C) first. Skipping the copy is harmless — the
daemon simply pairs fresh and you approve once more. Either way it lands on the
same device record on the server, because the machine id is the stable
`IOPlatformUUID`.

## What the installer sets up

| Path | Purpose |
|---|---|
| `/usr/local/bin/screenguard-agent` | the binary, a **copy** of what you built |
| `/etc/screenguard/agent.toml` | `server_url` or `cloud_account` |
| `/var/lib/screenguard/agent.db` | pairing, auth token, usage |
| `/Library/LaunchDaemons/org.screenguard.agent.plist` | the daemon |
| `/var/log/screenguard-agent.log` | stdout+stderr, and what `fetch_logs` returns |
| `/etc/newsyslog.d/screenguard.conf` | log rotation, 5 × 1 MB gzipped |

The plist sets `RunAtLoad` and `KeepAlive`, so the agent starts at boot before
anyone logs in and launchd restarts it if it is killed. It carries no
command-line flags on purpose: the server address lives in `agent.toml`, so
`launchctl kickstart` can never lose it.

## Day to day

```bash
tail -f /var/log/screenguard-agent.log                      # logs
sudo launchctl print system/org.screenguard.agent           # daemon state
sudo launchctl kickstart -k system/org.screenguard.agent    # restart
sudo ./install-macos.sh --uninstall                         # remove everything
```

Editing `/etc/screenguard/agent.toml` takes effect on the next `kickstart`.

After a reboot the log should go straight to *Agent ready* with no pairing
code — that is the check that the daemon came back clean.

**After a rebuild**, re-run the installer (or `sudo install -m 755
target/release/agent /usr/local/bin/screenguard-agent && sudo launchctl
kickstart -k system/org.screenguard.agent`). The daemon runs its own copy of
the binary, so rebuilding alone changes nothing.

## Enforcement only holds against a Standard account

This matters more than any of the service setup. An administrator can run

```bash
sudo launchctl bootout system/org.screenguard.agent
```

and the enforcement is simply gone — `KeepAlive` does not help against root.
So manage a **Standard** account (System Settings → Users & Groups), not the
admin account you installed from. The installer prints this warning itself when
the logged-in user is an admin.

This is the same root-versus-user premise the Linux agent rests on; macOS just
makes the first account an admin by default.

## Differences from the Linux agent

| | Linux | macOS |
|---|---|---|
| Lock | locks the session, unlocks again when time is granted | switches to the login window; **cannot** unlock — the user logs back in |
| Session preservation | supported | supported (apps keep running behind the login window) |
| Logout after grace period | supported | supported |
| Notifications | native | AppleScript, so macOS attributes them to *Script Editor*; nothing appears if the user denied that app permission |
| Web content filtering | nftables + per-user DNS proxy | **not available** — the server hides the feature for the device |
| Server auto-discovery | mDNS | not available, `--server-url` / `--cloud-account` required |
| Remote update from the web UI | supported | not supported; re-run `install-macos.sh` |
| Session/idle source | logind D-Bus signals | `ioreg` polled every 5 s |

No enforcement path depends on a notification arriving.

## Troubleshooting

**Pairs, then never connects.** The machine id used at pairing differs from the
one in `agent_hello` — the old release's bug. Install from a local build.

**Usage never accrues.** Sessions are being read as still at the login window.
Run `./target/release/agent --probe` and check `login_done=true` for the logged
in uid; if it is false while someone is clearly logged in, the `IOConsoleUsers`
key spelling on this macOS version is not one of the ones handled.

**Lock does nothing.** The backend tries `CGSession -suspend`, then the screen
saver, then display sleep, verifying each against the registry, and logs which
one worked. `CGSession` lives at an undocumented path that a macOS release can
move, so the log line is the thing to read.

**Daemon will not start.** `launchctl print system/org.screenguard.agent` and
the tail of `/var/log/screenguard-agent.log`; the installer also fails loudly
if the agent is not running two seconds after bootstrap.
