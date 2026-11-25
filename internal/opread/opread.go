// Package opread runs `op read` for a single reference.
package opread

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

const (
	maxStderr      = 1 << 10
	envToken       = "OP_SERVICE_ACCOUNT_TOKEN"
	envConnectHost = "OP_CONNECT_HOST"
	envConnectTok  = "OP_CONNECT_TOKEN"
)

// Auth selects how op authenticates. When TokenFile is set, op runs with
// OP_SERVICE_ACCOUNT_TOKEN from that file and no --account flag.
type Auth struct {
	Account   string
	TokenFile string
}

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
func Read(ctx context.Context, opPath string, auth Auth, ref string) ([]byte, error) {
	var (
		cmd      *exec.Cmd
		rawToken []byte
		token    []byte
	)
	if auth.TokenFile != "" {
		var err error
		rawToken, token, err = readTokenFile(auth.TokenFile)
		if err != nil {
			return nil, &Error{Err: err}
		}
		defer clear(rawToken)
		cmd = exec.CommandContext(ctx, opPath, "read", "--no-newline", ref)
		cmd.Env = withServiceAccountEnv(os.Environ(), string(token))
	} else {
		cmd = exec.CommandContext(ctx, opPath, "read", "--account", auth.Account, "--no-newline", ref)
	}

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
		msg := trimStderr(stderr.Bytes(), out, token)
		clear(buf)
		return nil, &Error{Err: err, Stderr: msg}
	}
	// op prints no newline with --no-newline, but older versions ignored it.
	for len(out) > 0 && (out[len(out)-1] == '\n' || out[len(out)-1] == '\r') {
		out[len(out)-1] = 0
		out = out[:len(out)-1]
	}
	if len(out) == 0 {
		return nil, &Error{Err: errors.New("empty value"), Stderr: trimStderr(stderr.Bytes(), nil, token)}
	}
	return out, nil
}

// readTokenFile reads a 1Password service account token after checking that
// the target file is a regular file owned by the current user and closed to
// group and others. It returns both the backing slice (for zeroing) and the
// trimmed token slice.
func readTokenFile(path string) (raw, token []byte, err error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s is not a regular file", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, nil, fmt.Errorf("%s: cannot read owner", path)
	}
	if int(st.Uid) != os.Getuid() {
		return nil, nil, fmt.Errorf("%s is owned by uid %d, not %d", path, st.Uid, os.Getuid())
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, nil, fmt.Errorf("%s has mode %o; it must not be accessible by group or others (use 0600)", path, fi.Mode().Perm())
	}
	if fi.Size() > MaxValue {
		return nil, nil, fmt.Errorf("%s is larger than %d bytes", path, MaxValue)
	}
	raw, err = os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	token = bytes.TrimSpace(raw)
	if len(token) == 0 {
		clear(raw)
		return nil, nil, fmt.Errorf("%s is empty", path)
	}
	return raw, token, nil
}

// withServiceAccountEnv replaces any existing 1Password service-account or
// Connect variables with token, so the child op process uses only this token.
func withServiceAccountEnv(base []string, token string) []string {
	out := make([]string, 0, len(base)+1)
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		if k == envToken || k == envConnectHost || k == envConnectTok {
			continue
		}
		out = append(out, kv)
	}
	return append(out, envToken+"="+token)
}

// trimStderr shortens op's stderr and redacts it entirely if it somehow
// contains any secret.
func trimStderr(stderr []byte, secrets ...[]byte) string {
	for _, secret := range secrets {
		if len(secret) > 0 && bytes.Contains(stderr, secret) {
			return "(op output redacted: it contained the secret)"
		}
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
