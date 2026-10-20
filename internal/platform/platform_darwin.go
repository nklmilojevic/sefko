//go:build darwin

package platform

/*
#cgo LDFLAGS: -framework IOKit -framework CoreFoundation
#include <stdlib.h>
#include <libproc.h>

void sefko_log_init(void);
void sefko_log(int level, const char *msg);
int  sefko_power_register(void);
void sefko_power_run(void);
void sefko_power_stop(void);
*/
import "C"

import (
	"errors"
	"net"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

type nativePeer struct{}

func (nativePeer) Peer(c *net.UnixConn) (Peer, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var p Peer
	var opErr error
	err = raw.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if e != nil {
			opErr = e
			return
		}
		p.UID = int(cred.Uid)
		pid, e := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		if e == nil {
			p.PID = pid
		}
	})
	if err != nil {
		return Peer{}, err
	}
	return p, opErr
}

func (nativePeer) ExePath(pid int) string {
	if pid <= 0 {
		return ""
	}
	buf := make([]byte, C.PROC_PIDPATHINFO_MAXSIZE)
	n := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if n <= 0 {
		return ""
	}
	return string(buf[:n])
}

type oslogLogger struct{}

const (
	levelAudit = iota
	levelInfo
	levelError
)

var logOnce sync.Once

func nativeLogger() Logger {
	logOnce.Do(func() { C.sefko_log_init() })
	return oslogLogger{}
}

func (oslogLogger) Audit(msg string) { oslog(levelAudit, msg) }
func (oslogLogger) Info(msg string)  { oslog(levelInfo, msg) }
func (oslogLogger) Error(msg string) { oslog(levelError, msg) }

func oslog(level int, msg string) {
	cs := C.CString(msg)
	defer C.free(unsafe.Pointer(cs))
	C.sefko_log(C.int(level), cs)
}

// The IOKit callback runs on the run-loop thread and calls back into Go.
var (
	sleepMu      sync.Mutex
	sleepHandler func()
)

//export sefkoGoWillSleep
func sefkoGoWillSleep() {
	sleepMu.Lock()
	h := sleepHandler
	sleepMu.Unlock()
	if h != nil {
		h()
	}
}

type nativeSleep struct{}

func (nativeSleep) Start(onSleep func()) (func(), error) {
	sleepMu.Lock()
	if sleepHandler != nil {
		sleepMu.Unlock()
		return nil, errors.New("sleep notifier already started")
	}
	sleepHandler = onSleep
	sleepMu.Unlock()

	ready := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		runtime.LockOSThread()
		if C.sefko_power_register() != 0 {
			ready <- errors.New("IORegisterForSystemPower failed")
			return
		}
		ready <- nil
		C.sefko_power_run()
	}()
	if err := <-ready; err != nil {
		sleepMu.Lock()
		sleepHandler = nil
		sleepMu.Unlock()
		return nil, err
	}
	return func() {
		C.sefko_power_stop()
		<-finished
		sleepMu.Lock()
		sleepHandler = nil
		sleepMu.Unlock()
	}, nil
}

func disableCoreDumps() error {
	return unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}

func denyAttach() error { return unix.PtraceDenyAttach() }

// IsTerminal reports whether fd is a terminal.
func IsTerminal(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	return err == nil
}
