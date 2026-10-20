# sefko: specification

Status: approved; implemented (M1–M4)
Date: 2026-10-20

sefko is a per-user agent that keeps 1Password secrets in memory and serves
them over a Unix socket. It does for API tokens what ssh-agent does for keys:
1Password is asked once, and every later request is answered from memory, with
no prompt.

## 1. Problem

SSH and Git signing now use a Secure Enclave key and no longer prompt. The
GitHub API token (`GH_TOKEN`) still does. It is read from 1Password with
`op read`:

- by the `gh` wrapper in nix-config (`gh-1password`, `modules/shared/packages/core.nix`), on every call where `GH_TOKEN`/`GITHUB_TOKEN` is unset
- by the fish functions `claude`, `codex` and `pi`, at agent start
- indirectly by vesnik (`GH_TOKEN` → `GITHUB_TOKEN` → `gh auth token`), `just release` in mailerlite (`gh release create`), scripts and coding agents

Each call outside an agent session can prompt. Touch ID is unavailable because
the MacBook runs in clamshell mode, so every prompt means typing a password or
using a watch.

### Hard constraints

- MailerLite policy: no local gh auth (`gh auth login`, hosts.yml, Keychain), and no token files on disk, plaintext or encrypted. 1Password is the source of truth.
- The GitHub API accepts tokens only, so an SSH key cannot replace the token.
- The Secure Enclave holds only P-256 keys. Encrypting the token to it (age-plugin-se) was rejected.
- No Touch ID per use.
- Shell aliases don't reach subprocesses, so integration must be via executables or environment.

## 2. Goals and non-goals

Goals
- At most one 1Password prompt per secret per week in normal use, plus one after each system sleep.
- Nothing secret written to disk, ever: no cache files, no logs containing values, no core dumps.
- Drop-in for existing callers: `gh`, vesnik, `just release` and the agent fish functions need no per-tool changes beyond the nix-config wrapper and functions.
- Generic over any allowlisted `op://` reference. GitHub is the first secret, not a special case.

Non-goals
- Protecting secrets from processes running as the same user while the agent holds them (see the threat model).
- Linux support in v1. The code keeps platform parts behind interfaces so a systemd user unit and logind sleep hook can be added later.
- Replacing `op` for writes or for ad-hoc vault browsing.
- Distribution beyond the Nix flake (no Homebrew tap in v1).

## 3. Threat model

Protects against
- **Secrets at rest.** Values exist only in the agent's locked memory and in the environments of processes that asked for them. A stolen disk, a Time Machine backup or a dotfiles leak contains no token.
- **Other local users.** The socket directory is 0700 and every connection is checked with `getpeereid`. Connections from any other uid are refused, including root via a different uid path (root can read memory anyway; see below).
- **Arbitrary vault reads through the agent.** Only aliases listed in the config can be fetched. A malicious same-user process can obtain the allowlisted secrets but cannot use sefko as a prompt-free oracle for the rest of the Private vault.
- **Accidental leakage.** Values are never logged, never put in error messages, never in `status` output, and never in core dumps (`RLIMIT_CORE=0`).
- **Stale tokens after sleep.** System sleep wipes everything.

Does not protect against (accepted trade-offs)
- **Same-user processes while the agent is loaded.** Any process running as the user can connect and request an allowlisted secret without confirmation, including a compromised package install script or a misbehaving coding agent. ssh-agent without `-c` makes the same trade-off. Mitigations: the allowlist, the audit log (§9), `sefko lock`, and the 7-day cap.
- **Screen lock.** By choice, locking the screen does not wipe. A process left running while you are away can still get the token.
- **Root, or anyone who can read the agent's memory.**
- **Secrets already handed out.** Once a value is in a process's environment (for example a Claude session started with `GH_TOKEN`), sefko cannot revoke it. Rotation at GitHub is the only revocation.
- **A compromised `op` binary or 1Password app.**

## 4. Architecture

```
 gh wrapper ─┐
 fish fns ───┤   sefko get/exec/env/validate   ┌──────────────── sefko agent (launchd) ─────────────┐
 scripts ────┼──────── Unix socket ───────────▶│ peer check → allowlist → cache ──miss──▶ op read   │
 vesnik (via gh auth token → wrapper)          │   locked pages, TTL 7d     singleflight, 60s       │
             │                                 │ IOKit sleep hook → wipe all                        │
             │                                 │ os_log audit (alias, pid, exe, hit/miss)           │
             └── daemon down → direct op read ─┴────────────────────────────────────────────────────┘
```

A single Go binary, `sefko`, acts as both agent (`sefko agent`) and client
(every other subcommand). It uses cgo for IOKit power notifications, `os_log`
and `proc_pidpath`. Platform code lives in `internal/platform` behind
interfaces (`SleepNotifier`, `Logger`, `PeerInspector`), with macOS in
build-tagged `_darwin` files and fail-closed stubs elsewhere.

### Components

- **Config loader.** Reads `~/.config/sefko/config.toml` (rendered by Home Manager; it holds refs only, never values). It reloads on SIGHUP and when the file changes, without restarting. An entry whose `ref` or `account` changed is wiped; unchanged entries keep their cached value.
- **Cache.** Maps alias → entry `{value: lockedBuffer, fetchedAt, lastUsed, hits}`.
- **Fetcher.** Runs `op read --account <account> --no-newline <ref>` using the absolute `op` path from config, with a 60 s timeout. Concurrent misses for one alias share one fetch (singleflight). Failures are never cached.
- **Validator.** Optional per secret. Makes an HTTP request with the value and treats 2xx as valid and 401 as invalid. Anything else, including 403 and network errors, is *unknown* and never triggers a refresh. At most one validation per alias per 60 s; within that window the last result is reused. After a 401 refresh the remembered result is *unknown*, because the new value has not been checked, so a quick retry cannot cause a second refresh.
- **Sleep watcher.** `IORegisterForSystemPower`. On `kIOMessageSystemWillSleep` it wipes all entries, then acknowledges the message. Display sleep and screen lock are ignored. As a backstop, a wall-clock gap of more than 5 minutes against the monotonic clock between ticks (checked every 30 s) is treated as a missed sleep and also wipes.
- **Server.** Unix socket listener. One request per connection, 5 s read deadline.

## 5. Configuration

`~/.config/sefko/config.toml`, generated by the Home Manager module:

```toml
op_path = "/nix/store/…-1password-cli/bin/op"
ttl = "168h"            # absolute, from fetch time
fetch_timeout = "60s"

[secrets.github]
ref = "op://Private/GitHub Personal Access Token/token"
account = "my.1password.eu"
env = "GH_TOKEN"

[secrets.github.validate]
url = "https://api.github.com/user"
header = "Authorization"
format = "Bearer {}"      # {} is replaced by the value, in memory only
```

Rules
- Alias: `[a-z0-9][a-z0-9_-]{0,63}`.
- `ref` must start with `op://`. `account` is required, because sefko never relies on op's default account.
- `env` is optional; it is the default variable name for `exec` and `env`.
- `ttl` is global in v1. A per-secret `ttl` is a possible later addition (§14).
- If the config is invalid, the agent keeps the last good config and logs an error. A first start with an invalid config exits non-zero.

## 6. Socket and protocol

- Path: `$SEFKO_SOCK` if set, otherwise `~/.local/state/sefko/agent.sock`. The directory is created 0700 by the agent, and the agent refuses to start if the directory is owned by another uid or has looser permissions. The socket is 0600.
- Stale sockets: on start the agent tries to connect to an existing socket. If that succeeds, another agent is running and it exits 1. Otherwise it unlinks the socket and binds.
- Peer check: `getpeereid()`. A uid other than the agent's own gets the connection closed without a response, and the refusal is logged. The requesting pid (`LOCAL_PEERPID`) and executable (`proc_pidpath`) are captured for the audit log.
- Framing: one request line of JSON and one response line of JSON, then close. The request is at most 4 KiB.

Requests

```json
{"v":1,"op":"get","name":"github"}
{"v":1,"op":"refresh","name":"github"}          // drop + fetch
{"v":1,"op":"validate","name":"github"}         // see §8
{"v":1,"op":"lock"}                              // wipe all
{"v":1,"op":"status"}
{"v":1,"op":"names"}                             // allowlisted aliases + env names
```

Responses

```json
{"ok":true,"value":"…"}                                   // get, refresh
{"ok":true,"result":"valid|invalid-refreshed|unknown"}    // validate
{"ok":true,"status":{…}}                                  // no values, ever
{"ok":false,"code":"not_allowed|op_failed|op_timeout|bad_request|version","message":"…"}
```

`message` for `op_failed` carries op's stderr, trimmed to 1 KiB, after checking
that it does not contain the cached value (defence in depth).

## 7. CLI

All commands are fish-friendly and write values only to stdout.

| Command | Behaviour |
| --- | --- |
| `sefko agent` | Run the agent in the foreground (launchd runs this). |
| `sefko get <alias>` | Print the value with no trailing newline. If the agent is unreachable, run `op read` directly using the config entry and warn on stderr. |
| `sefko exec [<alias>…] [--env NAME=alias]… -- cmd args…` | Set each alias's default `env` (or the overrides) and `exec` the command. Applies the same fallback as `get`. |
| `sefko env <alias>…` | Print `set -gx NAME 'value';` lines for fish (`--shell posix` prints `export`). |
| `sefko refresh <alias>` | Drop the entry and fetch again (may prompt). |
| `sefko validate <alias>` | Exit 0 valid, 10 invalid and refreshed, 11 unknown (or no validator configured), 1 error. |
| `sefko lock` | Wipe everything. |
| `sefko status` | Agent pid, uptime, config path, and per alias: cached yes/no, fetched at, expires at, hits, last requester. Recent requests (last 50, in memory). `--json` gives machine-readable output. |

Exit codes: 0 ok, 1 error, 2 usage, 3 not allowlisted, 4 op failed or timed
out, plus 10 and 11 for `validate`.

## 8. Expiry, lock and refresh rules

| Event | Effect |
| --- | --- |
| Fetch | Entry valid for `ttl` (7 days) from fetch time. Use does not extend it. |
| TTL reached | Wiped by a timer; the next `get` fetches again. |
| System sleep (`WillSleep`, or a detected clock gap) | Wipe all. |
| Screen lock, display sleep, clamshell with an external display | No effect. |
| `sefko lock` | Wipe all. |
| `sefko refresh <alias>` | Wipe that entry, then fetch. |
| `sefko validate <alias>` returns invalid (401) | Wipe that entry, fetch, exit 10. |
| Config change to that entry's `ref`/`account` | Wipe that entry. |
| Agent restart (reboot, upgrade, crash) | Everything is gone (memory only). |

Rotating the token in 1Password is detected lazily: the old token still works
until it is revoked at GitHub, and the first 401 after that triggers
`validate`, which refreshes. Nothing polls 1Password.

When 1Password is locked or the app is closed, `op read` either shows the
1Password unlock dialog (password or Apple Watch, since Touch ID is out) or
fails. The client waits up to `fetch_timeout`. On failure it exits 4 with op's
message, and nothing is cached.

## 9. Memory hygiene and logging

- Values live in `mmap`'d anonymous pages outside the Go heap, `mlock`ed (best effort; a failure is logged once) and zeroed with `explicit_bzero` semantics when wiped. The pipe buffer that read op's output is zeroed after copying.
- The response path writes from the locked buffer straight to the socket. JSON encoding of the value is hand-rolled into a scratch buffer that is zeroed afterwards.
- `setrlimit(RLIMIT_CORE, 0)` and `ptrace(PT_DENY_ATTACH)` at agent start.
- The client zeroes its copy before exit where practical (`get` writes and exits). `exec` necessarily hands the value to the child's environment.
- Audit: `os_log` under subsystem `io.nkl.sefko`, category `audit`, with alias, pid, executable path, result (hit/miss/fetch/denied/error) and latency, but never the value. Read with:
  `log stream --predicate 'subsystem == "io.nkl.sefko"' --info`

## 10. nix-darwin / Home Manager integration

The flake (`github:nklmilojevic/sefko`) exposes:
- `packages.<darwin>.gh`: gh wrapped with `nix/gh-wrapper.sh` (§11), so nix-config can use it instead of maintaining its own copy
- `packages.aarch64-darwin.default` (`buildGoModule` with cgo, `CGO_ENABLED=1`, frameworks `IOKit` and `CoreFoundation`)
- `homeManagerModules.default`
- `devShells.default`: go, gopls, golangci-lint, just, gotestsum. Never mise.

Home Manager module:

```nix
programs.sefko = {
  enable = true;
  package = inputs.sefko.packages.${system}.default;   # default
  opPackage = pkgs._1password-cli;                     # default
  ttl = "168h";
  secrets.github = {
    ref = "op://Private/GitHub Personal Access Token/token";
    account = "my.1password.eu";
    env = "GH_TOKEN";
    validate = {
      url = "https://api.github.com/user";
      header = "Authorization";
      format = "Bearer {}";
    };
  };
};
```

The module:
- writes `xdg.configFile."sefko/config.toml"`
- defines `launchd.agents.sefko` with `ProgramArguments = [ "${pkg}/bin/sefko" "agent" "--config" <config> "--socket" ~/.local/state/sefko/agent.sock ]` (explicit paths, because launchd's environment differs from the shell's), `RunAtLoad`, `KeepAlive.SuccessfulExit = false`, `ProcessType = "Interactive"` and no `StandardOutPath` (logging goes to `os_log`)
- adds the package to `home.packages`
- sends SIGHUP on activation when only the config changed (via `launchctl kill HUP gui/$UID/org.nix-community.home.sefko`), so a config-only `darwin-rebuild switch` keeps the cache. A binary change restarts the agent, which costs one prompt.

## 11. Changes to nix-config (described, not applied here)

1. **Flake input:** `sefko.url = "github:nklmilojevic/sefko";` and import `sefko.homeManagerModules.default` in the Darwin Home Manager config, with the `programs.sefko` block above.

2. **`gh` wrapper** (`modules/shared/packages/core.nix`, `gh-1password`). Either replace `gh-1password` with `inputs.sefko.packages.${system}.gh`, or keep it and replace the `op read` line with the same logic:

   ```sh
   #!/bin/sh
   if [ -n "${GH_TOKEN:-}" ] || [ -n "${GITHUB_TOKEN:-}" ]; then
     exec gh "$@"                       # token came from elsewhere; don't touch it
   fi
   GH_TOKEN=$(sefko get github) || exit 1   # sefko falls back to op read itself
   export GH_TOKEN
   gh "$@"; rc=$?
   [ "$rc" -eq 0 ] && exit 0
   sefko validate github >/dev/null 2>&1
   if [ $? -eq 10 ]; then
     if [ -t 0 ]; then
       GH_TOKEN=$(sefko get github) || exit "$rc"
       exec gh "$@"                     # retry once with the fresh token
     fi
     echo "sefko: GitHub token was invalid and has been refreshed; re-run the command" >&2
   fi
   exit "$rc"
   ```

   The retry happens only when stdin is a terminal, because piped stdin (`gh api --input -`) was already consumed by the first attempt. A 401 means the first attempt changed nothing on GitHub, so retrying is safe.

   The wrapper depends on the sefko package by absolute store path, like it does on `gh` today, rather than on `$PATH`.

3. **Fish functions** `claude`, `codex`, `pi` (`modules/shared/programs/fish/default.nix`): replace
   `set -lx GH_TOKEN (op read --account my.1password.eu "op://Private/GitHub Personal Access Token/token")`
   with
   `set -lx GH_TOKEN (sefko get github)`

   A token in an agent's env is not refreshed during the session. Sessions are much shorter than a week, so this is acceptable; on a 401, restart the session or run `sefko refresh github`.

4. **No change needed** for vesnik (`gh auth token` with no env goes through the wrapper, and with env set prints the env token) or for `just release` (calls `gh`).

## 12. Testing strategy

No real 1Password and no real GitHub in any automated test.

- **Fake `op`:** the test binary re-execs itself as `op` (`TestMain` checks `SEFKO_FAKE_OP=1`). Its behaviour is set through env: the value to print, a delay, an exit code, a stderr message, and a counter (an atomic file in `t.TempDir()`) to assert how many times it was called. The config's `op_path` points at it.
- **Agent tests (in-process):** start the agent against a temp socket dir under `t.TempDir()` (kept short for the 104-byte `sun_path` limit), with an injected clock and sleep notifier.
  - first `get` fetches; second `get` is served from cache (fake op called once)
  - 20 concurrent `get`s on a miss → one fetch (singleflight)
  - TTL expiry with the fake clock → refetch
  - sleep event and clock-gap event → wipe
  - `lock`, `refresh`, config reload (same ref keeps the entry; a changed ref wipes it), invalid reload keeps the old config
  - op failure, op timeout → error codes, nothing cached
  - non-allowlisted alias → `not_allowed`, and op is never called
  - status and logs never contain the value (assert on captured audit sink and status JSON)
- **Validator:** `httptest.Server` returning 200, 401, 403, 500, timeout → valid, invalid-refreshed, unknown, unknown, unknown; rate limit honoured.
- **Peer check:** unit-test the decision function with injected uids; the integration test covers the same-uid path.
- **Socket safety:** refuses a dir with mode 0755 or a foreign owner; stale socket replaced; a live agent detected.
- **Client:** `get` falls back to fake op when no agent is listening; `exec` env mapping and overrides; `env` quoting for fish (values containing `'` and `\`).
- **Memory:** wipe zeroes the locked buffer (read back through an unsafe test hook).
- **Wrapper script:** a bats-free Go test runs the wrapper with fake `gh` and fake `sefko` executables to cover the success, 401→refresh→retry, non-TTY no-retry and env-preset paths.
- **Nix:** `nix flake check` builds the package, runs `go test ./...`, and evaluates the HM module with a sample config (rendered TOML matches a golden file).
- `just test`, `just lint`, `just build`, `just check` (flake check).

## 13. Milestones

- **M0, spike (manual, you):** confirm that `op read` started from a launchd user agent shows the 1Password approval dialog and succeeds in clamshell mode, and find how long op's app-integration authorization lasts for a long-running parent. This decides whether the design holds; if launchd-spawned op can't authorize, fall back to fetching in the client (`sefko get` runs op in the terminal and hands the value to the agent).
- **M1, core:** agent and client for `get`, `status`, `lock` and `refresh`, with socket, peer check, allowlist config, fake-op test harness and fallback to direct op.
- **M2, lifetime:** TTL, IOKit sleep wipe and clock-gap backstop, locked memory, `RLIMIT_CORE`/`PT_DENY_ATTACH`, os_log audit, config hot reload.
- **M3, ergonomics:** `exec`, `env`, `validate` with rate limiting.
- **M4, packaging:** flake package, HM module with launchd agent and SIGHUP-on-activation, dev shell, justfile, `nix flake check`.
- **M5, adoption:** apply §11 to nix-config, then live with it for a week and review the audit log for unexpected requesters.

## 14. Decisions and trade-offs

| Decision | Chosen | Rejected and why |
| --- | --- | --- |
| Scope | Generic `op://` broker with an alias allowlist | Any ref (a prompt-free oracle for the whole vault); GitHub-only (rewrite for restic/HASS) |
| Naming secrets | Aliases defined in Nix config | Raw refs at call sites (duplication) |
| Expiry | 7-day absolute TTL, wipe on system sleep | Wipe on screen lock (too many prompts, by user choice); idle TTL (adds prompts for little gain); following the 1Password lock (no reliable signal) |
| Rotation detection | Client-triggered `validate` on gh failure | Polling 1Password (prompts); parsing gh stderr (breaks the TTY) |
| Fetch location | Agent runs `op read`, client waits ≤60 s | Client fetches and hands to agent (kept as the M0 fallback) |
| Agents (Claude etc.) | Env var resolved via `sefko get` at start | Socket-only (needs sefko support in every tool) |
| Daemon down | `sefko get` falls back to `op read` | Hard failure |
| Audit | macOS unified log | Log file (rotation); none |
| Platform | macOS only, Linux-ready interfaces | Linux in v1 |
| Distribution | Nix flake only, public repo, personal tool | Homebrew tap (cgo, single user) |
| Name | sefko ("little safe") | kljucar, cuvar |

## 15. Open questions

- M0 result: does op's app integration authorize a launchd-spawned `op`, and for how long? This decides where the fetch runs.
- Per-secret TTL and wipe-on-sleep overrides, for example restic with 1 day. Deferred until a second secret is added.
- If MailerLite colleagues ever want this, the policy owner should review §3 first.
