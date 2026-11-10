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
| `sefko exec <alias>... -- <command>` | Starts the command with the secrets in its environment. Use `--project` or `--if-trusted` to add the secrets of a project. |
| `sefko env <alias>...` | Writes `set -gx` commands for fish. Use `--shell posix` for `export` commands. |
| `sefko wrap <alias> -- <command>` | Starts the command with the secret. If the token is not valid, it reads a new token. See [Wrap a command](#wrap-a-command). |
| `sefko refresh <alias>` | Removes the value and reads it again from 1Password. |
| `sefko validate <alias>` | Does the HTTP check. If the service rejects the value, it reads the value again. |
| `sefko lock` | Removes all values. |
| `sefko status` | Shows the agent, the values in memory, and the last 50 requests. Use `--json` for JSON output. |
| `sefko trust [file]` | Adds the secrets of a project file or a varlock schema to the allowlist. See [Share secrets with a project](#share-secrets-with-a-project). |
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

### Use the secrets of a varlock schema

If a repository uses [varlock](https://varlock.dev), sefko can read the secrets from its `.env.schema`.
The repository does not need a `.sefko.toml`.

`varlock run` reads each `op()` value from 1Password each time that it starts, so 1Password can show a prompt each time.
If a variable is already in the environment, varlock uses that value and does not read 1Password.
sefko puts the values in the environment from its memory.

1. Read the schema, then trust it:

   ```fish
   sefko trust
   ```

   If a directory has no `.sefko.toml`, sefko uses the nearest `.env.schema`.
   It adds each `KEY=op("op://...")` item of an `@initOp(allowAppAuth=true, account=...)` instance.
   The alias of the item is the name of the variable in lowercase, for example `app_key`.
   The name of the project is the name of the repository and a hash of its path, for example `myapp-1a2b3c4d/app_key`.
   All worktrees of a repository use one project and one cache.
   sefko accepts only a worktree that the repository registered (`git worktree add`).
   Another clone of the repository is another project, so you must trust it separately.
   If you move the repository, trust it again.

   sefko does not add these items, and it shows them in the output under `left to varlock`:

   - An `op()` call in an expression, for example `if($BRANCH, op("..."))`.
   - A reference with a variable in it, or a one-time password.
   - An `op()` call with `allowMissing=true`.
   - An instance without `allowAppAuth=true`, without a fixed `account`, or with `connectHost`.
   - An instance with a `token` that is not a variable, for example `token="ops_..."`.

   varlock reads these items from 1Password as before.
   If sefko can serve no item of the schema, `sefko trust` lists the items and trusts nothing.

2. Start varlock through sefko:

   ```fish
   sefko exec --if-trusted -- varlock run -- docker compose up
   ```

   To make this occur each time that you run `varlock`, wrap varlock. See [Wrap varlock](#wrap-varlock).

sefko does not set a variable if:

- The variable is already in the environment.
- The variable is in `.env` or `.env.local` next to the schema, or in the files of the current environment (`@currentEnv`).
  varlock gives the environment a higher priority than these files, so a value from sefko would hide your own value.
  sefko finds the current environment as varlock does: in the environment, then in `.env.local`, `.env` and the schema.
  If sefko cannot tell the environment, it uses all `.env.*` files.
- The item is from an `@initOp(token=$OP_TOKEN, ...)` instance, and `OP_TOKEN` has a value in the environment, the schema, or a local `.env` file.
  varlock then reads the item with the service account, which can have different access than you have.
- sefko cannot read the item, for example because you do not have access to it.
  sefko shows a warning, and varlock reads the item.

If a branch adds or changes an `op()` item, run `sefko trust` again.
sefko adds the new items to the project and keeps the items of the other worktrees.
If two worktrees use different items for one variable, sefko keeps both, and each worktree gets its own item.
A change to other lines of the schema has no effect on the trust.

### Wrap varlock

`sefko exec --if-trusted` never stops the command:

- If there is no trusted project, it starts the command without changes.
  If the project is not trusted, or if it changed, it shows a note.
- If the agent does not run, it starts the command without the secrets.
  It does not read from 1Password directly, because that can show one prompt for each secret.

Thus a wrapper can always use it.
For this reason, `--if-trusted` takes no aliases and no `--env`.

`--if-trusted` uses a `.env.schema` only if varlock loads it.
varlock loads the schema in the working directory, or the schema that `varlock.loadPath` in `package.json` specifies (a directory or the `.env.schema` file).
varlock does not look in parent directories.
In a different directory, sefko starts the command without changes.

The flake has a function that wraps varlock:

```nix
sefko.lib.mkVarlock pkgs { package = varlock; }
```

The wrapper finds `sefko` in `PATH` when it starts.
If `sefko` is not installed, or if its version does not have `--if-trusted`, the wrapper starts varlock without changes.
It also starts varlock without changes if you use `--path`, because varlock then loads a different schema.
Thus you can put the wrapper in a dev shell that all the team uses.

> **Note:** A dev shell puts its `varlock` before the `varlock` from Home Manager in `PATH`.
> If a repository gets varlock from its dev shell, wrap varlock in that dev shell.

Without Nix, put a script with the name `varlock` before the real program in `PATH`:

```sh
#!/bin/sh
real=/opt/homebrew/bin/varlock
for arg in "$@"; do
  case $arg in
    --) break ;;
    -p* | --path | --path=*) exec "$real" "$@" ;;
  esac
done
if command -v sefko >/dev/null; then
  exec sefko exec --if-trusted -- "$real" "$@"
fi
exec "$real" "$@"
```

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
