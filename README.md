# sefko

sefko keeps 1Password secrets in memory and gives them to your tools without a new prompt each time.
It does for API tokens what `ssh-agent` does for SSH keys.

sefko is for macOS.
The name is Serbian for "small safe".

## The problem

Some tools need a token, for example `gh` needs `GH_TOKEN`.
If you keep the token only in 1Password, each `op read` can show a 1Password prompt.
If Touch ID is not available, you must type your password or use your Apple Watch each time.

sefko asks 1Password one time.
Then it keeps the value in memory and gives it to each tool that asks.

## How sefko works

1. A launchd agent (`sefko agent`) starts when you log in.
2. A tool asks the agent for a secret by its alias, for example `sefko get github`.
3. If the agent does not have the value, it runs `op read`.
   1Password shows one approval dialog.
4. The agent keeps the value in locked memory.
   It gives the value to the subsequent requests without a prompt.
5. The agent removes the value after 7 days, when the Mac goes to sleep, or when you run `sefko lock`.

The agent writes no secret to disk.
It does not write secrets to logs or to the `status` output.

## Security

### What sefko protects

- **Secrets on disk.** No value goes to a file, a cache, a log, or a core dump.
- **Other users.** The socket is in a directory that only you can open.
  The agent examines the user ID of each connection.
  It closes connections from all other users.
- **Other vault items.** The agent reads only the aliases in its configuration and in the projects that you trust.
  A process cannot use sefko to read other items from your vault.
- **Changes to a project file.** The agent reads only the copy of `.sefko.toml` that you trusted.
  If the file in the repository changes, nothing changes until you trust it again.
- **Old values after sleep.** The agent removes all values before the Mac goes to sleep.

### What sefko does not protect

- **Processes that run as your user.** Each such process can ask for a secret in the allowlist.
  sefko does not ask you to confirm.
  `ssh-agent` without the `-c` option has the same limit.
- **A locked screen.** sefko keeps the values when you lock the screen.
- **The root user.** The root user can read the memory of the agent.
- **Values that a tool already has.** If a process has a token in its environment, sefko cannot remove it.
  To cancel a token, revoke it in the service that issued it.

To find unexpected requests, examine the audit log (see [Logs](#logs)).

## Install

Use Nix with Home Manager, or use Homebrew.

### Install with Nix

1. Add the flake input:

   ```nix
   sefko = {
     url = "github:nklmilojevic/sefko";
     inputs.nixpkgs.follows = "nixpkgs";
     inputs.home-manager.follows = "home-manager";
   };
   ```

2. Import the module into your Home Manager configuration:

   ```nix
   imports = [ inputs.sefko.homeManagerModules.default ];
   ```

3. Add your secrets:

   ```nix
   programs.sefko = {
     enable = true;
     secrets.github = {
       ref = "op://Private/GitHub Personal Access Token/token";
       account = "my.1password.eu";
       env = "GH_TOKEN";
       validate.url = "https://api.github.com/user";
     };
   };
   ```

4. Apply the configuration:

   ```fish
   darwin-rebuild switch --flake .
   ```

5. Make sure that the agent runs:

   ```fish
   launchctl print gui/(id -u)/org.nix-community.home.sefko | grep state
   ```

   The output must show `state = running`.

> **Note:** Nix does not see files that are not in Git.
> If you add a new module file, run `git add` on it before you apply the configuration.

### Install with Homebrew

1. Install sefko:

   ```fish
   brew install --cask nklmilojevic/sefko/sefko
   ```

   You can also download a binary from the [releases](https://github.com/nklmilojevic/sefko/releases).

2. Write the configuration in `~/.config/sefko/config.toml`:

   ```toml
   [secrets.github]
   ref = "op://Private/GitHub Personal Access Token/token"
   account = "my.1password.eu"
   env = "GH_TOKEN"

   [secrets.github.validate]
   url = "https://api.github.com/user"
   header = "Authorization"
   format = "Bearer {}"
   ```

   The agent finds `op` in `/opt/homebrew/bin`, `/usr/local/bin`, and the system directories.
   If `op` is in a different directory, set `op_path = "/path/to/op"` at the top of the file.

3. Start the agent:

   ```fish
   sefko service install
   ```

   This command writes `~/Library/LaunchAgents/io.nkl.sefko.plist` and starts the agent.
   To stop the agent and remove the file, run `sefko service uninstall`.

4. Make sure that the agent runs:

   ```fish
   launchctl print gui/(id -u)/io.nkl.sefko | grep state
   ```

### Options

| Option | Default | Description |
| --- | --- | --- |
| `enable` | `false` | Installs sefko and starts the agent. |
| `package` | sefko from this flake | The sefko package. |
| `opPackage` | `pkgs._1password-cli` | The package that has the `op` command. |
| `ttl` | `"168h"` | The time that the agent keeps a value. The time starts when the agent reads the value. |
| `fetchTimeout` | `"60s"` | The maximum time to wait for your approval in 1Password. |
| `secrets.<alias>.ref` | (required) | The 1Password reference. It must start with `op://`. |
| `secrets.<alias>.account` | (required) | The 1Password account. |
| `secrets.<alias>.env` | `null` | The default variable name for `sefko exec` and `sefko env`. |
| `secrets.<alias>.validate` | `null` | An HTTP check for the secret. See [Validate a secret](#validate-a-secret). |
| `wrappers.<program>.package` | (required) | The package that has the program. See [Wrap a command](#wrap-a-command). |
| `wrappers.<program>.secret` | (required) | The alias of the token. |
| `wrappers.<program>.program` | `<program>` | The program in the `bin` directory of the package. |
| `wrappers.<program>.var` | `null` | The variable for the token. If it is `null`, the wrapper uses the `env` of the secret. |
| `wrappers.<program>.bypassEnv` | `[ ]` | More variables. If one of them is set, the wrapper does not use sefko. |
| `wrappers.<program>.retry` | `true` | Runs the program again after sefko reads a new token. |

The module writes the configuration to `~/.config/sefko/config.toml`.
This file contains only references, not values.
When you change only the configuration, the agent reads the new file in less than 5 seconds.
It keeps the values that did not change.

## Commands

| Command | Function |
| --- | --- |
| `sefko get <alias>` | Writes the value to standard output, with no newline at the end. |
| `sefko exec <alias>... -- <command>` | Starts the command with the secrets in its environment. |
| `sefko env <alias>...` | Writes `set -gx` commands for fish. Use `--shell posix` for `export` commands. |
| `sefko wrap <alias> -- <command>` | Starts the command with the secret. If the token is not valid, it reads a new token. See [Wrap a command](#wrap-a-command). |
| `sefko refresh <alias>` | Removes the value and reads it again from 1Password. |
| `sefko validate <alias>` | Does the HTTP check. If the service rejects the value, it reads the value again. |
| `sefko lock` | Removes all values. |
| `sefko status` | Shows the agent, the values in memory, and the last 50 requests. Use `--json` for JSON output. |
| `sefko trust [file]` | Adds the secrets of a project file to the allowlist. See [Share secrets with a project](#share-secrets-with-a-project). |
| `sefko untrust [project]` | Removes the secrets of a project from the allowlist and from memory. |
| `sefko agent` | Starts the agent. launchd uses this command. |
| `sefko service install` | Writes a launchd agent and starts it. Use it only without the Home Manager module. |
| `sefko service uninstall` | Stops the launchd agent and removes it. |

### Examples

Start a command with a token:

```fish
sefko exec github -- just release
```

Set a different variable name:

```fish
sefko exec --env GITHUB_TOKEN=github -- ./deploy.sh
```

Put a token in the current fish session:

```fish
sefko env github | source
```

### If the agent does not run

`get`, `exec`, and `env` still work.
They run `op read` directly and show this warning:

```
sefko: agent not reachable, reading from 1Password directly
```

In this condition, 1Password can show a prompt for each call.
The commands `refresh`, `validate`, `lock`, and `status` need the agent.
If the agent does not run, they stop with exit code 1.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The command is successful. For `validate`: the service accepts the value. |
| 1 | An error occurred, or the agent does not run. |
| 2 | The command line is not correct. |
| 3 | The alias is not in the allowlist. |
| 4 | 1Password did not give the value, or the time to approve stopped. |
| 10 | `validate` only: the service rejected the value, and the agent read a new value. |
| 11 | `validate` only: the result is not known, or the secret has no check. |

## Validate a secret

If you change a token in 1Password, the agent continues to use the old value.
It uses the old value until the old value expires.
A validator lets a tool find this problem.

The validator sends one HTTP GET request with the secret in a header:

```nix
validate = {
  url = "https://api.github.com/user";
  header = "Authorization";   # default
  format = "Bearer {}";       # default; {} is the secret
};
```

The result of the check is one of these:

- **2xx:** The value is valid.
- **401:** The value is not valid.
  The agent reads a new value from 1Password.
- **All other results,** and network errors: The result is not known.
  The agent keeps the value.

The agent does the check a maximum of one time each minute for each alias.
The URL must use HTTPS.
Plain HTTP is permitted only for `localhost`.

## Wrap a command

`sefko wrap` makes a command get its token from sefko each time that it starts:

```fish
sefko wrap github --bypass GITHUB_TOKEN -- gh pr list
```

The wrapper does these steps:

1. If the variable of the token is set, it runs the command with that value.
   The variable is the `env` of the secret, or the `--var` value.
   The variables that you give with `--bypass` have the same effect.
2. If not, it gets the token from sefko and runs the command.
3. If the command fails, it runs `sefko validate` on the alias.
4. If the token was not valid, sefko reads a new token.
   If standard input is a terminal, the wrapper runs the command again one time.
   If not, it tells you to run the command again.
   The first command possibly read all of standard input.

The wrapper gives the exit code of the command.
If the command can be dangerous to run two times, use `--no-retry`.
The wrapper works only for tools that read the token from a variable.

### Wrap a command with Home Manager

The module can install wrapped programs:

```nix
programs.sefko.wrappers = {
  gh = { package = pkgs.gh; secret = "github"; bypassEnv = [ "GITHUB_TOKEN" ]; };
  glab = { package = pkgs.glab; secret = "gitlab"; };
};
```

Each wrapper has the full package, with the man pages and the completions.
It has a higher priority than the same package without the wrapper.
The secret must be in `programs.sefko.secrets`.

Without the module, use the flake function:

```nix
inputs.sefko.lib.mkWrapper pkgs { package = pkgs.glab; secret = "gitlab"; }
```

The flake also supplies a `gh` package that is wrapped with the `github` secret:

```nix
home.packages = [ inputs.sefko.packages.${pkgs.stdenv.hostPlatform.system}.gh ];
```

### Wrap a command without Nix

Put a script with the name of the program before the real program in `PATH`.
For example, `~/.local/bin/gh`:

```sh
#!/bin/sh
exec sefko wrap github --bypass GITHUB_TOKEN -- /opt/homebrew/bin/gh "$@"
```

## Share secrets with a project

A repository can list the secrets that its tools need in a `.sefko.toml` file:

```toml
project = "acme"
account = "team.1password.com"   # default for each secret

[secrets.app-key]
ref = "op://Dev/App/APP_KEY"
env = "APP_KEY"

[secrets.github-token]
ref = "op://Dev/GitHub token/token"
env = "GITHUB_TOKEN"

[secrets.github-token.validate]
url = "https://api.github.com/user"
header = "Authorization"
format = "Bearer {}"
```

The file can contain only `project`, `account` and `secrets`.
Each secret has the same keys as in `config.toml`.

1. Read the file, then trust it:

   ```fish
   sefko trust
   ```

   sefko finds the nearest `.sefko.toml` in the current directory or a parent directory.
   It copies the file to `~/.config/sefko/projects/<project>.toml` and shows the secrets that it added.

2. Start a command with all the secrets of the project:

   ```fish
   sefko exec --project -- just up
   ```

   `--project` adds each secret that has an `env` value.
   It also works with `sefko env`.

The name of a project secret is `<project>/<alias>`, for example `sefko get acme/app-key`.
A project cannot replace one of your own aliases, because your aliases cannot contain `/`.

If the file in the repository changes, `exec --project` stops with exit code 3.
Read the change, then run `sefko trust` again.
`sefko trust --check` gives exit code 0 only if the file is trusted and did not change.
A script can use it to decide whether to use sefko:

```sh
if command -v sefko >/dev/null && sefko trust --check 2>/dev/null; then
  exec sefko exec --project -- varlock run -- "$@"
fi
exec varlock run -- "$@"
```

To remove the secrets of a project, run `sefko untrust`.

## Logs

The agent writes to the macOS unified log, subsystem `io.nkl.sefko`.
Each request has an audit line with the alias, the process ID, the program path, and the result.
The audit line never contains the value.

To see the log as it occurs:

```fish
log stream --predicate 'subsystem == "io.nkl.sefko"' --info
```

To see the last hour:

```fish
log show --last 1h --info --predicate 'subsystem == "io.nkl.sefko"'
```

## Troubleshooting

| Problem | Action |
| --- | --- |
| `state = spawn scheduled` | launchd starts the agent again after a short time. Wait 10 seconds, then examine the state again. If the problem continues, examine the log. |
| The agent stops immediately | Run `sefko agent --log-stderr` in a terminal and read the error. |
| `... has mode 755; it must be 0700` | Run `chmod 700 ~/.local/state/sefko`. |
| `another sefko agent is already running` | Stop the other agent. Only one agent can use the socket. |
| `not_allowed` | Add the alias to `programs.sefko.secrets` and apply the configuration. For a project secret, run `sefko trust`. |
| `op_timeout` | Approve the 1Password dialog in less than `fetchTimeout`. Make sure that 1Password is open. |
| `gh` says `Bad credentials` | Run `sefko refresh github`. |

## Development

All tools come from the Nix dev shell.

```fish
nix develop
just            # show the tasks
just check      # lint, tidy check, and tests
just nix-check  # build the package and examine the Home Manager module
```

### Release

Run `vesnik release`.
vesnik makes the tag and the GitHub release.
Then the release workflow attaches the macOS binaries and updates the Homebrew cask in `nklmilojevic/homebrew-sefko`.
The workflow does not use Nix, because binaries from the Nix toolchain link to files in `/nix/store`.

The tests do not use real 1Password.
The test binary operates as a fake `op` command.

## License

MIT. See [LICENSE](LICENSE).
