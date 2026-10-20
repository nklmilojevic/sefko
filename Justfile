set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# Run inside `nix develop` (or direnv), which provides every tool.

default:
    @just --list

# Lint, tidy-check and test: what CI runs.
check: lint tidy-check test

# Run golangci-lint.
lint:
    golangci-lint run

# Format Go and Nix code in place.
fmt:
    golangci-lint fmt
    nixpkgs-fmt flake.nix package.nix nix

# Run the tests with the race detector.
test:
    test -z "$(gofmt -l .)" || { gofmt -l .; exit 1; }
    go test -race ./...

# Fail when go.mod or go.sum are not tidy.
tidy-check:
    go mod tidy
    git diff --exit-code go.mod go.sum

# Build the binary into ./bin.
build:
    go build -o bin/sefko ./cmd/sefko

# Run the agent in the foreground against a config, logging to stderr.
run-agent config="~/.config/sefko/config.toml":
    go run ./cmd/sefko agent --log-stderr --config {{config}}

# Build the Nix packages, run their tests and check the Home Manager module.
nix-check:
    nix flake check --print-build-logs

# Validate the GoReleaser configuration. Releases run in CI with `vesnik release`.
release-check:
    goreleaser check
