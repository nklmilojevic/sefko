// Package opread runs `op read` for a single reference.
package opread

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

const maxStderr = 1 << 10

// ErrTimeout means op did not finish before the context deadline, usually
// because nobody approved the 1Password dialog.
var ErrTimeout = errors.New("timed out waiting for 1Password")

// Error carries op's exit status and trimmed stderr.
type Error struct {
	Err    error
	Stderr string
}

func (e *Error) Error() string {
	if e.Stderr != "" {
		return "op read failed: " + e.Stderr
	}
	return "op read failed: " + e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

// MaxValue is the largest secret Read accepts.
const MaxValue = 64 << 10

// Read returns the value of ref. The caller owns the returned slice and should
// zero it once copied.
func Read(ctx context.Context, opPath, account, ref string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, opPath, "read", "--account", account, "--no-newline", ref)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, &Error{Err: err}
	}
	// Read straight from the pipe into one fixed buffer, so the value is never
	// copied through io.Copy's scratch space or a growing bytes.Buffer.
	buf := make([]byte, MaxValue+1)
	n := 0
	for n < len(buf) {
		m, rerr := pipe.Read(buf[n:])
		n += m
		if rerr != nil {
			break
		}
	}
	tooLarge := n > MaxValue
	if tooLarge {
		_ = cmd.Process.Kill()
	}
	err = cmd.Wait()
	out := buf[:n]
	if ctx.Err() == context.DeadlineExceeded {
		clear(buf)
		return nil, ErrTimeout
	}
	if tooLarge {
		clear(buf)
		return nil, &Error{Err: fmt.Errorf("value larger than %d bytes", MaxValue)}
	}
	if err != nil {
		msg := trimStderr(stderr.Bytes(), out)
		clear(buf)
		return nil, &Error{Err: err, Stderr: msg}
	}
	// op prints no newline with --no-newline, but older versions ignored it.
	for len(out) > 0 && (out[len(out)-1] == '\n' || out[len(out)-1] == '\r') {
		out[len(out)-1] = 0
		out = out[:len(out)-1]
	}
	if len(out) == 0 {
		return nil, &Error{Err: errors.New("empty value"), Stderr: trimStderr(stderr.Bytes(), nil)}
	}
	return out, nil
}

// trimStderr shortens op's stderr and redacts it entirely if it somehow
// contains the value.
func trimStderr(stderr, value []byte) string {
	if len(value) > 0 && bytes.Contains(stderr, value) {
		return "(op output redacted: it contained the secret)"
	}
	s := strings.TrimSpace(string(stderr))
	if len(s) > maxStderr {
		s = s[:maxStderr] + "…"
	}
	return s
}

// Describe turns a Read error into a one-line message for users.
func Describe(err error) string {
	var oe *Error
	if errors.As(err, &oe) {
		return oe.Error()
	}
	return fmt.Sprint(err)
}
