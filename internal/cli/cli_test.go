package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nklmilojevic/sefko/internal/agent"
	"github.com/nklmilojevic/sefko/internal/fakeop"
	"github.com/nklmilojevic/sefko/internal/platform"
)

func TestMain(m *testing.M) {
	fakeop.Main()
	os.Exit(m.Run())
}

type env struct {
	t    *testing.T
	op   *fakeop.Fake
	cfg  string
	sock string
	tty  bool
	ctl  [][]string
	exec struct {
		path string
		argv []string
		env  []string
	}
}

// setup writes a config with the github and plain secrets plus extra, and
// starts an agent for it when withAgent is set.
func setup(t *testing.T, withAgent bool, extra ...string) *env {
	t.Helper()
	e := &env{t: t, op: fakeop.Setup(t)}
	base := os.TempDir()
	if len(base) > 60 {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "sk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	e.cfg = filepath.Join(dir, "config.toml")
	e.sock = filepath.Join(dir, "s", "agent.sock")
	cfg := fmt.Sprintf(`op_path = %q

[secrets.github]
ref = "op://Private/GitHub/token"
account = "acc.example"
env = "GH_TOKEN"

[secrets.plain]
ref = "op://Private/Plain/password"
account = "acc.example"
`, e.op.Path) + strings.Join(extra, "\n")
	if err := os.WriteFile(e.cfg, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if withAgent {
		a, err := agent.New(agent.Options{
			ConfigPath: e.cfg,
			Peers:      platform.NativePeers(),
			Sleep:      platform.NoSleep{},
			Log:        &platform.WriterLogger{W: io.Discard},
		})
		if err != nil {
			t.Fatal(err)
		}
		ln, err := agent.Listen(e.sock)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { _ = a.Serve(ctx, ln); close(done) }()
		t.Cleanup(func() { cancel(); <-done })
	}
	return e
}

func (e *env) run(args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	full := append([]string{"--socket", e.sock, "--config", e.cfg}, args...)
	code = Execute("test", full, IO{
		Stdout: &out,
		Stderr: &errb,
		Exec: func(path string, argv, env []string) error {
			e.exec.path, e.exec.argv, e.exec.env = path, argv, env
			return nil
		},
		StdinIsTerminal: func() bool { return e.tty },
		Launchctl: func(args ...string) error {
			e.ctl = append(e.ctl, args)
			return nil
		},
	})
	return code, out.String(), errb.String()
}

func lookup(env []string, key string) string {
	for _, kv := range env {
		if k, v, _ := strings.Cut(kv, "="); k == key {
			return v
		}
	}
	return ""
}

func TestGetThroughAgent(t *testing.T) {
	e := setup(t, true)
	for range 2 {
		code, out, errOut := e.run("get", "github")
		if code != 0 || out != "value-of:op://Private/GitHub/token" || errOut != "" {
			t.Fatalf("code=%d out=%q err=%q", code, out, errOut)
		}
	}
	if n := len(e.op.Calls()); n != 1 {
		t.Fatalf("calls: %d", n)
	}
}

func TestGetFallsBackWhenAgentDown(t *testing.T) {
	e := setup(t, false)
	code, out, errOut := e.run("get", "github")
	if code != 0 || out != "value-of:op://Private/GitHub/token" || !strings.Contains(errOut, "reading from 1Password directly") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errOut)
	}
	if code, _, _ := e.run("get", "nope"); code != ExitNotAllowed {
		t.Fatalf("not allowed fallback: %d", code)
	}
	e.op.SetExit(1, "[ERROR] locked")
	if code, _, errOut := e.run("get", "github"); code != ExitOpFailed || !strings.Contains(errOut, "locked") {
		t.Fatalf("op failure fallback: %d %q", code, errOut)
	}
}

func TestGetErrorsThroughAgent(t *testing.T) {
	e := setup(t, true)
	if code, _, _ := e.run("get", "nope"); code != ExitNotAllowed {
		t.Fatalf("not allowed: %d", code)
	}
	e.op.SetExit(1, "[ERROR] locked")
	if code, _, _ := e.run("get", "github"); code != ExitOpFailed {
		t.Fatalf("op failed: %d", code)
	}
}

func TestExec(t *testing.T) {
	for _, withAgent := range []bool{true, false} {
		e := setup(t, withAgent)
		t.Setenv("GH_TOKEN", "stale")
		code, _, errOut := e.run("exec", "github", "--env", "PLAIN_PW=plain", "--", "sh", "-c", "true")
		if code != 0 {
			t.Fatalf("agent=%v code=%d err=%q", withAgent, code, errOut)
		}
		if v := lookup(e.exec.env, "GH_TOKEN"); v != "value-of:op://Private/GitHub/token" {
			t.Fatalf("agent=%v GH_TOKEN=%q", withAgent, v)
		}
		if v := lookup(e.exec.env, "PLAIN_PW"); v != "value-of:op://Private/Plain/password" {
			t.Fatalf("agent=%v PLAIN_PW=%q", withAgent, v)
		}
		if n := strings.Count(strings.Join(e.exec.env, "\n"), "GH_TOKEN="); n != 1 {
			t.Fatalf("GH_TOKEN appears %d times", n)
		}
		if !strings.HasSuffix(e.exec.path, "/sh") || strings.Join(e.exec.argv, " ") != "sh -c true" {
			t.Fatalf("exec %q %q", e.exec.path, e.exec.argv)
		}
	}
}

func TestExecUsageErrors(t *testing.T) {
	e := setup(t, true)
	cases := map[string][]string{
		"no dash":        {"exec", "github"},
		"no command":     {"exec", "github", "--"},
		"no env default": {"exec", "plain", "--", "true"},
		"bad override":   {"exec", "--env", "X", "--", "true"},
		"nothing":        {"exec", "--", "true"},
		"duplicate env":  {"exec", "github", "--env", "GH_TOKEN=plain", "--", "true"},
	}
	for name, args := range cases {
		if code, _, _ := e.run(args...); code != ExitUsage {
			t.Errorf("%s: code %d", name, code)
		}
	}
	if code, _, _ := e.run("exec", "nope", "--", "true"); code != ExitNotAllowed {
		t.Errorf("unknown alias: %d", code)
	}
}

func TestExecChecksCommandBeforeFetching(t *testing.T) {
	e := setup(t, true)
	if code, _, _ := e.run("exec", "github", "--", "definitely-not-a-command-sefko"); code != ExitError {
		t.Fatalf("code %d", code)
	}
	if calls := e.op.Calls(); len(calls) != 0 {
		t.Fatalf("fetched secrets for a missing command: %q", calls)
	}
}

func TestPrintable(t *testing.T) {
	if printable("github") != "github" {
		t.Fatal("plain name changed")
	}
	if got := printable("x\x1b[2Jy\nz"); strings.ContainsAny(got, "\x1b\n") {
		t.Fatalf("control characters survived: %q", got)
	}
}

func TestEnvQuoting(t *testing.T) {
	e := setup(t, true)
	tricky := `it's a \ "test" $HOME`
	e.op.SetValue(tricky)

	code, out, _ := e.run("env", "github")
	if code != 0 || !strings.HasPrefix(out, "set -gx GH_TOKEN '") {
		t.Fatalf("fish: %d %q", code, out)
	}
	if fish, err := exec.LookPath("fish"); err == nil {
		got, err := exec.Command(fish, "--no-config", "-c", out+"printf %s $GH_TOKEN").Output()
		if err != nil || string(got) != tricky {
			t.Fatalf("fish evaluated %q (%v)", got, err)
		}
	}

	code, out, _ = e.run("env", "--shell", "posix", "--env", "X=github")
	if code != 0 {
		t.Fatal(code)
	}
	got, err := exec.Command("/bin/sh", "-c", out+`printf %s "$X"`).Output()
	if err != nil || string(got) != tricky {
		t.Fatalf("sh evaluated %q (%v)", got, err)
	}

	if code, _, _ := e.run("env", "--shell", "csh", "github"); code != ExitUsage {
		t.Fatal("bad shell accepted")
	}
}

func TestAgentOnlyCommandsFailWhenDown(t *testing.T) {
	e := setup(t, false)
	for _, args := range [][]string{{"refresh", "github"}, {"validate", "github"}, {"lock"}, {"status"}} {
		code, _, errOut := e.run(args...)
		if code != ExitError || !strings.Contains(errOut, "not running") {
			t.Errorf("%v: %d %q", args, code, errOut)
		}
	}
}

func TestAgentCommands(t *testing.T) {
	e := setup(t, true)
	if code, _, _ := e.run("refresh", "github"); code != 0 {
		t.Fatal("refresh", code)
	}
	if code, out, _ := e.run("validate", "github"); code != ExitUnknown || strings.TrimSpace(out) != "unknown" {
		t.Fatalf("validate without validator: %d %q", code, out)
	}
	code, out, _ := e.run("status")
	if code != 0 || !strings.Contains(out, "github") || !strings.Contains(out, "true") {
		t.Fatalf("status: %d %q", code, out)
	}
	if strings.Contains(out, "value-of") {
		t.Fatal("status leaked a value")
	}
	if code, out, _ := e.run("status", "--json"); code != 0 || !strings.Contains(out, `"entries"`) {
		t.Fatalf("status json: %d %q", code, out)
	}
	if code, _, _ := e.run("lock"); code != 0 {
		t.Fatal("lock", code)
	}
	if _, out, _ := e.run("status", "--json"); strings.Contains(out, `"cached": true`) {
		t.Fatal("lock did not wipe")
	}
}

func TestVersion(t *testing.T) {
	e := setup(t, false)
	if code, out, _ := e.run("--version"); code != 0 || !strings.Contains(out, "test") {
		t.Fatalf("%d %q", code, out)
	}
}
