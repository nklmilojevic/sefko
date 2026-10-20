package opread

import (
	"context"
	"errors"
	"os"
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
	v, err := Read(context.Background(), f.Path, "acc.example", "op://V/I/f")
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

func TestReadFailureCarriesStderr(t *testing.T) {
	f := fakeop.Setup(t)
	f.SetExit(1, "[ERROR] account is locked")
	_, err := Read(context.Background(), f.Path, "a", "op://x/y/z")
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
	if _, err := Read(ctx, f.Path, "a", "op://x/y/z"); !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v", err)
	}
}

func TestReadRejectsEmptyValue(t *testing.T) {
	f := fakeop.Setup(t)
	f.SetValue("\n")
	if _, err := Read(context.Background(), f.Path, "a", "op://x/y/z"); err == nil {
		t.Fatal("expected error for empty value")
	}
}

func TestReadRejectsOversizedValue(t *testing.T) {
	f := fakeop.Setup(t)
	f.SetValue(strings.Repeat("x", MaxValue+10))
	_, err := Read(context.Background(), f.Path, "a", "op://x/y/z")
	var oe *Error
	if !errors.As(err, &oe) || !strings.Contains(oe.Error(), "larger than") {
		t.Fatalf("got %v", err)
	}
}

func TestReadAcceptsLargeValue(t *testing.T) {
	f := fakeop.Setup(t)
	want := strings.Repeat("y", 40<<10)
	f.SetValue(want)
	got, err := Read(context.Background(), f.Path, "a", "op://x/y/z")
	if err != nil || string(got) != want {
		t.Fatalf("len %d, err %v", len(got), err)
	}
}

func TestTrimStderrRedactsValue(t *testing.T) {
	if got := trimStderr([]byte("oops ghp_123 leaked"), []byte("ghp_123")); strings.Contains(got, "ghp_123") {
		t.Fatal(got)
	}
	long := strings.Repeat("x", 3000)
	if got := trimStderr([]byte(long), nil); len(got) > maxStderr+4 {
		t.Fatalf("not trimmed: %d", len(got))
	}
}
