# Changelog

## v0.4.0 - 2026-11-10

This release fixes how sefko checks schema trust. Repositories trusted with v0.3.0 must be trusted again.

### Fixes

- `--if-trusted` now uses the schema that varlock loads and rejects `--env` and aliases. Schema project names now include a hash of the repository path, so repositories with the same name do not share trust.

## v0.3.0 - 2026-11-10

This release lets sefko serve 1Password secrets from a `.env.schema` file to varlock. varlock gets the values from sefko memory, so it does not call 1Password on each run.

### New features

- `sefko trust` now reads `.env.schema` when a directory has no `.sefko.toml`, so varlock projects need no extra file. Use `sefko exec --if-trusted` or `sefko.lib.mkVarlock` to run varlock through sefko.

## v0.2.0 - 2026-10-23

This release lets a repository declare the secrets its tools need. It also installs shell completions with the Nix package.

### New features

- A repository can list its secrets in a `.sefko.toml` file. Each developer runs `sefko trust` once to use them. The `exec --project` and `env --project` commands add these secrets to the environment.
- The Nix package now installs completions for bash, fish and zsh. Before, the package did not install them.

## v0.1.1 - 2026-10-20

This release does not change how sefko works. It changes how this repository gets dependency updates.

### Other changes

- Renovate now runs on this repository. Renovate opens dependency update pull requests for the project.
- Renovate Go pull requests now update the `vendorHash` in `package.nix` automatically. Before, the Nix build failed until a maintainer fixed the hash by hand.

## v0.1.0 - 2026-10-20

This release lets any CLI use a sefko secret. It also adds macOS binaries and a Homebrew cask.

### New features

- Run `sefko wrap <alias> -- cmd` to give any CLI its secret, with one retry after a token refresh. Install sefko with Homebrew on macOS, or run the agent with `sefko service install`.
