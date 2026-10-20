//go:build darwin

package platform

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestPeerSameProcess(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "skp")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "s"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := net.Dial("unix", filepath.Join(dir, "s"))
		if err == nil {
			defer func() { _ = c.Close() }()
			_, _ = c.Read(make([]byte, 1))
		}
	}()
	c, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	p, err := NativePeers().Peer(c)
	if err != nil {
		t.Fatal(err)
	}
	if p.UID != os.Getuid() || p.PID != os.Getpid() {
		t.Fatalf("peer %+v, want uid %d pid %d", p, os.Getuid(), os.Getpid())
	}
	exe, _ := os.Executable()
	got, want := NativePeers().ExePath(p.PID), exe
	if r, err := filepath.EvalSymlinks(want); err == nil {
		want = r
	}
	if r, err := filepath.EvalSymlinks(got); err == nil {
		got = r
	}
	if got != want {
		t.Fatalf("exe %q, want %q", got, want)
	}
	if NativePeers().ExePath(-1) != "" {
		t.Fatal("bad pid should give empty path")
	}
}

func TestSleepNotifierStartsAndStops(t *testing.T) {
	stop, err := nativeSleep{}.Start(func() {})
	if err != nil {
		// Build sandboxes may not reach IOKit's power management.
		t.Skipf("power notifications unavailable: %v", err)
	}
	if _, err := (nativeSleep{}).Start(func() {}); err == nil {
		t.Fatal("second start should fail")
	}
	stop()
	stop2, err := nativeSleep{}.Start(func() {})
	if err != nil {
		t.Fatalf("restart after stop: %v", err)
	}
	stop2()
}

func TestLoggerDoesNotCrash(t *testing.T) {
	l := nativeLogger()
	l.Audit("op=test result=ok")
	l.Info("test info")
	l.Error("test error")
}
