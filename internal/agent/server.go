package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/nklmilojevic/sefko/internal/opread"
	"github.com/nklmilojevic/sefko/internal/protocol"
)

const (
	ioTimeout   = 5 * time.Second
	resultError = "error"
)

// ErrAlreadyRunning means another agent answers on the socket.
var ErrAlreadyRunning = errors.New("another sefko agent is already running")

// Listen prepares the socket directory and binds the socket. The directory
// must be owned by the current user and closed to everyone else.
func Listen(path string) (*net.UnixListener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := checkDir(dir); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			_ = c.Close()
			return nil, ErrAlreadyRunning
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	old := syscall.Umask(0o077)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	ln.SetUnlinkOnClose(true)
	return ln, nil
}

func checkDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot read owner", dir)
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is owned by uid %d, not %d", dir, st.Uid, os.Getuid())
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s has mode %o; it must be 0700", dir, fi.Mode().Perm())
	}
	return nil
}

// Serve accepts connections until ctx is done, then wipes every secret.
func (a *Agent) Serve(ctx context.Context, ln *net.UnixListener) error {
	stopSleep, err := a.opts.Sleep.Start(func() { a.WipeAll("system sleep") })
	if err != nil {
		a.opts.Log.Error("sleep notifications unavailable: " + err.Error())
		stopSleep = func() {}
	}
	defer stopSleep()

	loopCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go a.loop(loopCtx)
	go func() {
		<-loopCtx.Done()
		_ = ln.Close()
	}()

	a.opts.Log.Info(fmt.Sprintf("listening on %s (pid %d)", ln.Addr(), os.Getpid()))
	var wg sync.WaitGroup
	defer func() {
		wg.Wait()
		a.WipeAll("shutdown")
	}()
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Go(func() { a.serveConn(c) })
	}
}

func (a *Agent) loop(ctx context.Context) {
	tick := time.NewTicker(a.opts.TickInterval)
	defer tick.Stop()
	poll := time.NewTicker(a.opts.ReloadInterval)
	defer poll.Stop()
	prev := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			now := time.Now()
			if gapExceeded(now.Round(0).Sub(prev.Round(0)), now.Sub(prev)) {
				a.WipeAll("clock gap (missed sleep notification)")
			}
			prev = now
			a.Sweep()
		case <-poll.C:
			_ = a.Reload()
		}
	}
}

func allowPeer(peerUID, ownUID int) bool { return peerUID == ownUID }

func (a *Agent) serveConn(c *net.UnixConn) {
	defer func() { _ = c.Close() }()
	start := time.Now()
	ev := protocol.Event{Time: a.now()}

	peer, err := a.opts.Peers.Peer(c)
	if err != nil || !allowPeer(peer.UID, a.uid) {
		ev.PID, ev.Result = peer.PID, "denied"
		ev.Detail = fmt.Sprintf("peer uid %d", peer.UID)
		if err != nil {
			ev.Detail = "peer credentials: " + err.Error()
		}
		a.audit(ev)
		return
	}
	ev.PID = peer.PID
	ev.Exe = a.opts.Peers.ExePath(peer.PID)
	requester := fmt.Sprintf("%s[%d]", filepath.Base(cmpOr(ev.Exe, "?")), peer.PID)

	_ = c.SetReadDeadline(time.Now().Add(ioTimeout))
	req, err := readRequest(c)
	if err != nil {
		ev.Result, ev.Detail = resultError, err.Error()
		a.audit(ev)
		a.reply(c, failure(protocol.CodeBadRequest, err.Error()))
		return
	}
	ev.Op, ev.Name = req.Op, req.Name
	defer func() {
		ev.LatencyMS = time.Since(start).Milliseconds()
		a.audit(ev)
	}()
	if req.V != protocol.Version {
		ev.Result = resultError
		a.reply(c, failure(protocol.CodeVersion, fmt.Sprintf("agent speaks v%d, client sent v%d", protocol.Version, req.V)))
		return
	}

	switch req.Op {
	case protocol.OpGet, protocol.OpRefresh:
		if !a.allowed(req.Name) {
			ev.Result = "denied"
			a.reply(c, failure(protocol.CodeNotAllowed, fmt.Sprintf("%q is not in the allowlist", req.Name)))
			return
		}
		if req.Op == protocol.OpRefresh {
			a.drop(req.Name)
		}
		out, fetched, err := a.encodedValue(req.Name, requester)
		if err != nil {
			ev.Result, ev.Detail = resultError, err.Error()
			a.reply(c, errorResponse(err))
			return
		}
		ev.Result = "hit"
		if fetched {
			ev.Result = "fetch"
		}
		_ = c.SetWriteDeadline(time.Now().Add(ioTimeout))
		_, _ = c.Write(out.Bytes())
		out.Free()
	case protocol.OpValidate:
		result, err := a.validate(req.Name, requester)
		if err != nil {
			ev.Result, ev.Detail = resultError, err.Error()
			a.reply(c, errorResponse(err))
			return
		}
		ev.Result = result
		a.reply(c, &protocol.Response{OK: true, Result: result})
	case protocol.OpLock:
		a.WipeAll("lock requested by " + requester)
		ev.Result = "ok"
		a.reply(c, &protocol.Response{OK: true})
	case protocol.OpStatus:
		ev.Result = "ok"
		a.reply(c, &protocol.Response{OK: true, Status: a.status()})
	case protocol.OpReload:
		if err := a.Reload(); err != nil {
			ev.Result, ev.Detail = resultError, err.Error()
			a.reply(c, failure(protocol.CodeConfig, err.Error()))
			return
		}
		ev.Result = "ok"
		a.reply(c, &protocol.Response{OK: true})
	case protocol.OpNames:
		ev.Result = "ok"
		a.reply(c, &protocol.Response{OK: true, Names: a.names()})
	default:
		ev.Result = resultError
		a.reply(c, failure(protocol.CodeBadRequest, fmt.Sprintf("unknown op %q", req.Op)))
	}
}

func readRequest(c io.Reader) (*protocol.Request, error) {
	r := bufio.NewReader(io.LimitReader(c, protocol.MaxRequestSize+1))
	line, err := r.ReadBytes('\n')
	if len(line) > protocol.MaxRequestSize {
		return nil, errors.New("request too large")
	}
	// A final line without a newline is accepted.
	if err != nil && (!errors.Is(err, io.EOF) || len(line) == 0) {
		return nil, fmt.Errorf("read request: %w", err)
	}
	var req protocol.Request
	if err := json.Unmarshal(line, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}
	return &req, nil
}

func (a *Agent) reply(c *net.UnixConn, r *protocol.Response) {
	b, err := json.Marshal(r)
	if err != nil {
		a.opts.Log.Error("encode response: " + err.Error())
		return
	}
	_ = c.SetWriteDeadline(time.Now().Add(ioTimeout))
	_, _ = c.Write(append(b, '\n'))
}

func failure(code, msg string) *protocol.Response {
	return &protocol.Response{Code: code, Message: msg}
}

func errorResponse(err error) *protocol.Response {
	var oe *opread.Error
	switch {
	case errors.Is(err, errNotAllowed):
		return failure(protocol.CodeNotAllowed, err.Error())
	case errors.Is(err, opread.ErrTimeout):
		return failure(protocol.CodeOpTimeout, err.Error())
	case errors.As(err, &oe):
		return failure(protocol.CodeOpFailed, oe.Error())
	case errors.Is(err, errWiped):
		return failure(protocol.CodeOpFailed, err.Error())
	default:
		return failure(protocol.CodeInternal, err.Error())
	}
}
