package cli

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeTool logs the token it saw. It fails with 1 for the token "bad", with 3
// for "broken", and kills itself for "die".
const fakeTool = `#!/bin/sh
echo "$TOOL_TOKEN $*" >> "$STATE/tool.log"
[ -t 0 ] || cat > /dev/null
case "$TOOL_TOKEN" in
  bad) echo "HTTP 401: Bad credentials" >&2; exit 1 ;;
  broken) exit 3 ;;
  die) kill -TERM $$ ;;
esac
exit 0
`

type wrapWorld struct {
	*env
	state  string
	tool   string
	probes atomic.Int32
}

// newWrapWorld serves the token from a file. The validator rejects "bad" and
// swaps it for "good", like 1Password holding a rotated token.
func newWrapWorld(t *testing.T, token string, withAgent bool) *wrapWorld {
	t.Helper()
	w := &wrapWorld{state: t.TempDir()}
	tokenFile := filepath.Join(w.state, "token")
	write := func(p, body string, mode os.FileMode) {
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(tokenFile, token, 0o600)
	w.tool = filepath.Join(w.state, "tool")
	write(w.tool, fakeTool, 0o755)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.probes.Add(1)
		if r.Header.Get("Authorization") == "Bearer bad" {
			write(tokenFile, "good", 0o600)
			rw.WriteHeader(http.StatusUnauthorized)
		}
	}))
	t.Cleanup(srv.Close)
	extra := fmt.Sprintf(`
[secrets.tool]
ref = "op://Private/Tool/token"
account = "acc.example"
env = "TOOL_TOKEN"

[secrets.tool.validate]
url = %q
header = "Authorization"
format = "Bearer {}"
`, srv.URL)
	w.env = setup(t, withAgent, extra)
	w.op.SetValueFile(tokenFile)
	t.Setenv("STATE", w.state)
	t.Setenv("TOOL_TOKEN", "")
	t.Setenv("TOOL_ALT", "")
	return w
}

func (w *wrapWorld) toolLog() []string {
	b, err := os.ReadFile(filepath.Join(w.state, "tool.log"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		w.t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func (w *wrapWorld) wrap(args ...string) (int, string, string) {
	return w.run(append([]string{"wrap", "tool", "--bypass", "TOOL_ALT", "--"}, append([]string{w.tool}, args...)...)...)
}

func TestWrapGoodToken(t *testing.T) {
	w := newWrapWorld(t, "good", true)
	if code, _, errOut := w.wrap("pr", "list"); code != 0 {
		t.Fatalf("%d %q", code, errOut)
	}
	if got := w.toolLog(); len(got) != 1 || got[0] != "good pr list" {
		t.Fatalf("tool calls: %q", got)
	}
	if w.exec.path != "" || w.probes.Load() != 0 {
		t.Fatalf("exec %q, probes %d", w.exec.path, w.probes.Load())
	}
}

func TestWrapPresetVariableBypassesSefko(t *testing.T) {
	for _, v := range []string{"TOOL_TOKEN", "TOOL_ALT"} {
		w := newWrapWorld(t, "good", true)
		t.Setenv(v, "from-env")
		if code, _, errOut := w.wrap("api", "user"); code != 0 {
			t.Fatalf("%s: %d %q", v, code, errOut)
		}
		if w.exec.path != w.tool || strings.Join(w.exec.argv[1:], " ") != "api user" {
			t.Fatalf("%s: exec %q %q", v, w.exec.path, w.exec.argv)
		}
		if lookup(w.exec.env, v) != "from-env" || len(w.op.Calls()) != 0 {
			t.Fatalf("%s: env %q, op calls %q", v, lookup(w.exec.env, v), w.op.Calls())
		}
	}
}

func TestWrapBadTokenWithoutTerminalRefreshesButDoesNotRetry(t *testing.T) {
	w := newWrapWorld(t, "bad", true)
	code, _, errOut := w.wrap("api", "--input", "-")
	if code != 1 || !strings.Contains(errOut, "re-run the command") {
		t.Fatalf("%d %q", code, errOut)
	}
	if got := w.toolLog(); len(got) != 1 || w.exec.path != "" {
		t.Fatalf("tool calls %q, exec %q", got, w.exec.path)
	}
	if code, out, _ := w.run("get", "tool"); code != 0 || out != "good" {
		t.Fatalf("token not refreshed: %d %q", code, out)
	}
}

func TestWrapBadTokenWithTerminalRetriesOnce(t *testing.T) {
	w := newWrapWorld(t, "bad", true)
	w.tty = true
	if code, _, errOut := w.wrap("release", "create", "v1"); code != 0 {
		t.Fatalf("%d %q", code, errOut)
	}
	if got := w.toolLog(); len(got) != 1 || got[0] != "bad release create v1" {
		t.Fatalf("tool calls: %q", got)
	}
	if w.exec.path != w.tool || lookup(w.exec.env, "TOOL_TOKEN") != "good" {
		t.Fatalf("retry exec %q with %q", w.exec.path, lookup(w.exec.env, "TOOL_TOKEN"))
	}
}

func TestWrapNoRetry(t *testing.T) {
	w := newWrapWorld(t, "bad", true)
	w.tty = true
	code, _, errOut := w.run("wrap", "tool", "--no-retry", "--", w.tool, "apply")
	if code != 1 || !strings.Contains(errOut, "re-run the command") || w.exec.path != "" {
		t.Fatalf("%d %q exec %q", code, errOut, w.exec.path)
	}
}

func TestWrapOtherFailureKeepsExitCode(t *testing.T) {
	w := newWrapWorld(t, "broken", true)
	w.tty = true
	code, _, errOut := w.wrap("pr", "view")
	if code != 3 || strings.Contains(errOut, "refreshed") || w.exec.path != "" {
		t.Fatalf("%d %q exec %q", code, errOut, w.exec.path)
	}
	if w.probes.Load() != 1 {
		t.Fatalf("probes: %d", w.probes.Load())
	}
}

func TestWrapKilledBySignalSkipsValidate(t *testing.T) {
	w := newWrapWorld(t, "die", true)
	if code, _, _ := w.wrap("watch"); code != 128+15 {
		t.Fatalf("code %d", code)
	}
	if w.probes.Load() != 0 {
		t.Fatalf("probes: %d", w.probes.Load())
	}
}

func TestWrapAgentDown(t *testing.T) {
	w := newWrapWorld(t, "bad", false)
	w.tty = true
	code, _, errOut := w.wrap("pr", "list")
	if code != 1 || !strings.Contains(errOut, "reading from 1Password directly") || w.exec.path != "" {
		t.Fatalf("%d %q exec %q", code, errOut, w.exec.path)
	}
	if got := w.toolLog(); len(got) != 1 || got[0] != "bad pr list" {
		t.Fatalf("tool calls: %q", got)
	}
}

func TestWrapVar(t *testing.T) {
	w := newWrapWorld(t, "good", true)
	t.Setenv("PLAIN_PW", "")
	code, _, errOut := w.run("wrap", "plain", "--var", "PLAIN_PW", "--", "sh", "-c", `echo "$PLAIN_PW" > "$STATE/tool.log"`)
	if code != 0 {
		t.Fatalf("%d %q", code, errOut)
	}
	if got := w.toolLog(); len(got) != 1 || got[0] != "good" {
		t.Fatalf("tool saw %q", got)
	}
}

func TestWrapUsageErrors(t *testing.T) {
	w := newWrapWorld(t, "good", true)
	cases := map[string][]string{
		"no dash":        {"wrap", "tool"},
		"no command":     {"wrap", "tool", "--"},
		"no alias":       {"wrap", "--", "true"},
		"two aliases":    {"wrap", "tool", "plain", "--", "true"},
		"no env default": {"wrap", "plain", "--", "true"},
	}
	for name, args := range cases {
		if code, _, _ := w.run(args...); code != ExitUsage {
			t.Errorf("%s: code %d", name, code)
		}
	}
	if code, _, _ := w.run("wrap", "nope", "--", "true"); code != ExitNotAllowed {
		t.Errorf("unknown alias: %d", code)
	}
	if code, _, _ := w.run("wrap", "tool", "--", "definitely-not-a-command-sefko"); code != ExitError {
		t.Errorf("missing command: %d", code)
	}
	if calls := w.op.Calls(); len(calls) != 0 {
		t.Fatalf("fetched secrets on a usage error: %q", calls)
	}
}
