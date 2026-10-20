# Changelog

## v0.1.0 - 2026-10-20

This release lets any CLI use a sefko secret. It also adds macOS binaries and a Homebrew cask.

### New features

- Run `sefko wrap <alias> -- cmd` to give any CLI its secret, with one retry after a token refresh. Install sefko with Homebrew on macOS, or run the agent with `sefko service install`.
