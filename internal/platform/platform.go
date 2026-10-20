// Package platform isolates the OS-specific parts of the agent: peer
// credentials, power notifications, logging and process hardening. macOS is
// implemented; other systems get stubs so the rest of the code stays portable.
package platform

import (
	"fmt"
	"io"
	"net"
	"sync"
)

// Peer identifies the process on the other end of a Unix socket.
type Peer struct {
	UID int
	PID int
}

// PeerInspector reads peer credentials from a connection.
type PeerInspector interface {
	Peer(c *net.UnixConn) (Peer, error)
	ExePath(pid int) string
}

// SleepNotifier calls onSleep before the system sleeps. Start returns a
// function that stops notifications.
type SleepNotifier interface {
	Start(onSleep func()) (stop func(), err error)
}

// Logger receives audit lines and operational messages. Implementations must
// never be handed secret values; callers guarantee that.
type Logger interface {
	Audit(msg string)
	Info(msg string)
	Error(msg string)
}

// WriterLogger writes every line to w. It is used in tests and when running
// the agent in the foreground on systems without a native log.
type WriterLogger struct {
	mu sync.Mutex
	W  io.Writer
}

func (l *WriterLogger) Audit(msg string) { l.write("audit", msg) }
func (l *WriterLogger) Info(msg string)  { l.write("info", msg) }
func (l *WriterLogger) Error(msg string) { l.write("error", msg) }

func (l *WriterLogger) write(level, msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = fmt.Fprintf(l.W, "%s %s\n", level, msg)
}

// NoSleep never fires.
type NoSleep struct{}

func (NoSleep) Start(func()) (func(), error) { return func() {}, nil }

// Default returns the native implementations for this OS.
func Default() (PeerInspector, SleepNotifier, Logger) {
	return nativePeer{}, nativeSleep{}, nativeLogger()
}

// Harden disables core dumps and, on macOS, debugger attachment. Errors are
// returned so the agent can log them; none of them is fatal.
func Harden() []error {
	var errs []error
	if err := disableCoreDumps(); err != nil {
		errs = append(errs, fmt.Errorf("disable core dumps: %w", err))
	}
	if err := denyAttach(); err != nil {
		errs = append(errs, fmt.Errorf("deny debugger attach: %w", err))
	}
	return errs
}

// NativePeers returns the peer inspector for this OS.
func NativePeers() PeerInspector { return nativePeer{} }
