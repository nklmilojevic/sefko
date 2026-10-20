//go:build !darwin

package platform

import (
	"errors"
	"net"
	"os"
	"syscall"
)

var errUnsupported = errors.New("not supported on this platform yet")

type nativePeer struct{}

// Peer refuses everything until a platform implementation exists, so the
// agent fails closed.
func (nativePeer) Peer(*net.UnixConn) (Peer, error) { return Peer{}, errUnsupported }
func (nativePeer) ExePath(int) string               { return "" }

type nativeSleep = NoSleep

func nativeLogger() Logger { return &WriterLogger{W: os.Stderr} }

func disableCoreDumps() error {
	return syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})
}

func denyAttach() error { return nil }
