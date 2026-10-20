// Package ghwrapper tests nix/gh-wrapper.sh with fake gh and sefko
// executables.
package ghwrapper

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeGh logs the token it saw and fails with a 401 for the token "bad" or
// with a plain error for "broken".
const fakeGh = `#!/bin/sh
echo "$GH_TOKEN $*" >> "$STATE/gh.log"
[ -t 0 ] || cat > /dev/null
case "$GH_TOKEN" in
  bad) echo "HTTP 401: Bad credentials" >&2; exit 1 ;;
  broken) exit 1 ;;
esac
exit 0
`

// fakeSefko serves the token from $STATE/token. validate swaps a bad token
// for a good one and exits 10, like the agent after a 401.
const fakeSefko = `#!/bin/sh
echo "$*" >> "$STATE/sefko.log"
case "$1" in
  get)
    [ -f "$STATE/get-fails" ] && exit 4
    cat "$STATE/token" ;;
  validate)
    if [ "$(cat "$STATE/token")" = bad ]; then echo good > "$STATE/token"; echo invalid-refreshed; exit 10; fi
    echo valid; exit 0 ;;
esac
`

type world struct {
	t       *testing.T
	state   string
	wrapper string
}

func newWorld(t *testing.T, token string) *world {
	t.Helper()
	dir := t.TempDir()
	w := &world{t: t, state: dir}
	write := func(name, body string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	gh := write("gh", fakeGh, 0o755)
	sefko := write("sefko", fakeSefko, 0o755)
	write("token", token, 0o600)
	tmpl, err := os.ReadFile("../../nix/gh-wrapper.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := strings.NewReplacer("@gh@", gh, "@sefko@", sefko).Replace(string(tmpl))
	w.wrapper = write("gh-wrapper", script, 0o755)
	return w
}

func (w *world) log(name string) []string {
	b, err := os.ReadFile(filepath.Join(w.state, name))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		w.t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func (w *world) env(extra ...string) []string {
	env := make([]string, 0, 2+len(extra))
	env = append(env, "STATE="+w.state, "PATH=/usr/bin:/bin")
	return append(env, extra...)
}

// run executes the wrapper with stdin from /dev/null (not a terminal).
func (w *world) run(extra []string, args ...string) (int, string) {
	cmd := exec.Command(w.wrapper, args...)
	cmd.Env = w.env(extra...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		w.t.Fatal(err)
	}
	return code, string(out)
}

func TestPresetTokenBypassesSefko(t *testing.T) {
	for _, v := range []string{"GH_TOKEN=from-env", "GITHUB_TOKEN=from-env"} {
		w := newWorld(t, "good")
		if code, out := w.run([]string{v}, "api", "user"); code != 0 {
			t.Fatalf("%s: %d %s", v, code, out)
		}
		if w.log("sefko.log") != nil {
			t.Fatalf("%s: sefko was called", v)
		}
	}
}

func TestGoodToken(t *testing.T) {
	w := newWorld(t, "good")
	if code, out := w.run(nil, "pr", "list"); code != 0 {
		t.Fatalf("%d %s", code, out)
	}
	if got := w.log("gh.log"); len(got) != 1 || got[0] != "good pr list" {
		t.Fatalf("gh calls: %q", got)
	}
	if got := w.log("sefko.log"); len(got) != 1 || got[0] != "get github" {
		t.Fatalf("sefko calls: %q", got)
	}
}

func TestBadTokenWithoutTerminalRefreshesButDoesNotRetry(t *testing.T) {
	w := newWorld(t, "bad")
	code, out := w.run(nil, "api", "--input", "-")
	if code != 1 || !strings.Contains(out, "re-run the command") {
		t.Fatalf("%d %s", code, out)
	}
	if got := w.log("gh.log"); len(got) != 1 {
		t.Fatalf("gh calls: %q", got)
	}
	if got := w.log("sefko.log"); strings.Join(got, ",") != "get github,validate github" {
		t.Fatalf("sefko calls: %q", got)
	}
}

func TestBadTokenWithTerminalRetriesOnce(t *testing.T) {
	if _, err := os.Stat("/usr/bin/script"); err != nil {
		t.Skip("script(1) not available to provide a terminal")
	}
	w := newWorld(t, "bad")
	cmd := exec.Command("/usr/bin/script", "-q", "/dev/null", w.wrapper, "release", "create", "v1")
	cmd.Env = w.env()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	got := w.log("gh.log")
	if len(got) != 2 || got[0] != "bad release create v1" || got[1] != "good release create v1" {
		t.Fatalf("gh calls: %q", got)
	}
}

func TestOtherFailureDoesNotRetry(t *testing.T) {
	w := newWorld(t, "broken")
	if code, out := w.run(nil, "pr", "view"); code != 1 || strings.Contains(out, "refreshed") {
		t.Fatalf("%d %s", code, out)
	}
	if got := w.log("gh.log"); len(got) != 1 {
		t.Fatalf("gh calls: %q", got)
	}
}

func TestSefkoFailureStopsBeforeGh(t *testing.T) {
	w := newWorld(t, "good")
	if err := os.WriteFile(filepath.Join(w.state, "get-fails"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _ := w.run(nil, "pr", "list"); code != 1 {
		t.Fatalf("code %d", code)
	}
	if w.log("gh.log") != nil {
		t.Fatal("gh ran without a token")
	}
}
