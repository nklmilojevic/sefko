package opread

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nklmilojevic/sefko/internal/fakeop"
)

func TestMain(m *testing.M) {
	fakeop.Main()
	os.Exit(m.Run())
}

func TestReadPassesAccountAndRef(t *testing.T) {
	f := fakeop.Setup(t)
	v, err := Read(context.Background(), f.Path, Auth{Account: "acc.example"}, "op://V/I/f")
	if err != nil {
		t.Fatal(err)
	}
	if string(v) != "value-of:op://V/I/f" {
		t.Fatalf("got %q", v)
	}
	if calls := f.Calls(); len(calls) != 1 || calls[0] != "acc.example op://V/I/f" {
		t.Fatalf("calls: %q", calls)
	}
}

func TestReadServiceAccountTokenFile(t *testing.T) {
	f := fakeop.Setup(t)
	t.Setenv("OP_CONNECT_HOST", "https://stale.example")
	t.Setenv("OP_CONNECT_TOKEN", "stale")
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("ops_test_token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := Read(context.Background(), f.Path, Auth{Account: "ignored.example", TokenFile: tokenFile}, "op://Studio/GitHub/token")
	if err != nil {
		t.Fatal(err)
	}
	if string(v) != "value-of:op://Studio/GitHub/token" {
		t.Fatalf("got %q", v)
	}
	if calls := f.Calls(); len(calls) != 1 || calls[0] != "sa:ops_test_token op://Studio/GitHub/token" {
		t.Fatalf("calls: %q", calls)
	}
}

func TestReadServiceAccountTokenFileChecks(t *testing.T) {
	f := fakeop.Setup(t)
	dir := t.TempDir()

	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(loose, []byte("ops_tok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(context.Background(), f.Path, Auth{TokenFile: loose}, "op://V/I/f"); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("loose mode: %v", err)
	}

	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte(" \n "), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(context.Background(), f.Path, Auth{TokenFile: empty}, "op://V/I/f"); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty file: %v", err)
	}

	if _, err := Read(context.Background(), f.Path, Auth{TokenFile: dir}, "op://V/I/f"); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory: %v", err)
	}

	if _, err := Read(context.Background(), f.Path, Auth{TokenFile: filepath.Join(dir, "missing")}, "op://V/I/f"); err == nil {
		t.Fatal("missing file accepted")
	}

	if calls := f.Calls(); len(calls) != 0 {
		t.Fatalf("op called despite invalid token file: %q", calls)
	}
}

func TestReadFailureRedactsServiceAccountToken(t *testing.T) {
	f := fakeop.Setup(t)
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("ops_super_secret"), 0o400); err != nil {
		t.Fatal(err)
	}
	f.SetExit(1, "failed with ops_super_secret in error")
	_, err := Read(context.Background(), f.Path, Auth{TokenFile: tokenFile}, "op://x/y/z")
	if err == nil || strings.Contains(err.Error(), "ops_super_secret") {
		t.Fatalf("token leaked in error: %v", err)
	}
}

func TestReadFailureCarriesStderr(t *testing.T) {
	f := fakeop.Setup(t)
	f.SetExit(1, "[ERROR] account is locked")
	_, err := Read(context.Background(), f.Path, Auth{Account: "a"}, "op://x/y/z")
	var oe *Error
	if !errors.As(err, &oe) || !strings.Contains(oe.Stderr, "account is locked") {
		t.Fatalf("got %v", err)
	}
}

func TestReadTimeout(t *testing.T) {
	f := fakeop.Setup(t)
	f.SetDelay(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := Read(ctx, f.Path, Auth{Account: "a"}, "op://x/y/z"); !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v", err)
	}
}

func TestReadRejectsEmptyValue(t *testing.T) {
	f := fakeop.Setup(t)
	f.SetValue("\n")
	if _, err := Read(context.Background(), f.Path, Auth{Account: "a"}, "op://x/y/z"); err == nil {
		t.Fatal("expected error for empty value")
	}
}

func TestReadRejectsOversizedValue(t *testing.T) {
	f := fakeop.Setup(t)
	f.SetValue(strings.Repeat("x", MaxValue+10))
	_, err := Read(context.Background(), f.Path, Auth{Account: "a"}, "op://x/y/z")
	var oe *Error
	if !errors.As(err, &oe) || !strings.Contains(oe.Error(), "larger than") {
		t.Fatalf("got %v", err)
	}
}

func TestReadAcceptsLargeValue(t *testing.T) {
	f := fakeop.Setup(t)
	want := strings.Repeat("y", 40<<10)
	f.SetValue(want)
	got, err := Read(context.Background(), f.Path, Auth{Account: "a"}, "op://x/y/z")
	if err != nil || string(got) != want {
		t.Fatalf("len %d, err %v", len(got), err)
	}
}

func TestTrimStderrRedactsValue(t *testing.T) {
	if got := trimStderr([]byte("oops ghp_123 leaked"), []byte("ghp_123")); strings.Contains(got, "ghp_123") {
		t.Fatal(got)
	}
	if got := trimStderr([]byte("oops ops_456 leaked"), nil, []byte("ops_456")); strings.Contains(got, "ops_456") {
		t.Fatal(got)
	}
	long := strings.Repeat("x", 3000)
	if got := trimStderr([]byte(long)); len(got) > maxStderr+4 {
		t.Fatalf("not trimmed: %d", len(got))
	}
}
