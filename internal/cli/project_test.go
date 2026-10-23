package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nklmilojevic/sefko/internal/config"
)

const projectTOML = `project = "acme"
account = "team.example"

[secrets.app-key]
ref = "op://Dev/App/APP_KEY"
env = "APP_KEY"

[secrets.db]
ref = "op://Shared/Database/password"
env = "DB_PASSWORD"

[secrets.no-env]
ref = "op://Shared/Other/password"
`

// repo writes a project file into a new directory and moves into a
// subdirectory of it, so the commands must look upward for the file.
func repo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, config.ProjectFile)
	if err := os.WriteFile(path, []byte(projectTOML), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "app", "src")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(sub)
	return path
}

func TestTrustLifecycle(t *testing.T) {
	e := setup(t, true)
	path := repo(t)

	if code, _, _ := e.run("trust", "--check"); code != ExitNotAllowed {
		t.Fatalf("untrusted check: %d", code)
	}
	code, _, errOut := e.run("exec", "--project", "--", "true")
	if code != ExitNotAllowed || !strings.Contains(errOut, "sefko trust") {
		t.Fatalf("untrusted exec: %d %q", code, errOut)
	}
	if calls := e.op.Calls(); len(calls) != 0 {
		t.Fatalf("fetched secrets of an untrusted project: %q", calls)
	}

	code, out, errOut := e.run("trust")
	if code != 0 || !strings.Contains(out, "acme/app-key") || !strings.Contains(out, "op://Shared/Database/password") {
		t.Fatalf("trust: %d %q %q", code, out, errOut)
	}
	trusted := config.TrustedPath(e.cfg, "acme")
	for p, want := range map[string]os.FileMode{trusted: 0o600, filepath.Dir(trusted): 0o700} {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != want {
			t.Fatalf("%s: %v %v", p, fi.Mode(), err)
		}
	}
	if code, _, _ := e.run("trust", "--check"); code != 0 {
		t.Fatalf("trusted check: %d", code)
	}

	code, _, errOut = e.run("exec", "-p", "--", "true")
	if code != 0 {
		t.Fatalf("exec: %d %q", code, errOut)
	}
	if v := lookup(e.exec.env, "APP_KEY"); v != "value-of:op://Dev/App/APP_KEY" {
		t.Fatalf("APP_KEY=%q", v)
	}
	if v := lookup(e.exec.env, "DB_PASSWORD"); v != "value-of:op://Shared/Database/password" {
		t.Fatalf("DB_PASSWORD=%q", v)
	}
	if code, out, _ := e.run("get", "acme/no-env"); code != 0 || out != "value-of:op://Shared/Other/password" {
		t.Fatalf("get: %d %q", code, out)
	}

	// The repository changes a ref: nothing is served until it is trusted again.
	changed := strings.Replace(projectTOML, "op://Dev/App/APP_KEY", "op://Private/Something/else", 1)
	if err := os.WriteFile(path, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := len(e.op.Calls())
	if code, _, _ := e.run("trust", "--check"); code != ExitNotAllowed {
		t.Fatalf("changed check: %d", code)
	}
	code, _, errOut = e.run("exec", "--project", "--", "true")
	if code != ExitNotAllowed || !strings.Contains(errOut, "changed since you trusted it") {
		t.Fatalf("changed exec: %d %q", code, errOut)
	}
	if n := len(e.op.Calls()); n != calls {
		t.Fatal("fetched secrets for a changed project file")
	}

	if code, _, _ := e.run("untrust"); code != 0 {
		t.Fatalf("untrust: %d", code)
	}
	if _, err := os.Stat(trusted); !os.IsNotExist(err) {
		t.Fatalf("trusted copy still there: %v", err)
	}
	if code, _, _ := e.run("get", "acme/app-key"); code != ExitNotAllowed {
		t.Fatalf("get after untrust: %d", code)
	}
	if code, _, _ := e.run("untrust", "acme"); code != ExitError {
		t.Fatalf("second untrust: %d", code)
	}
}

func TestProjectWithoutAgent(t *testing.T) {
	e := setup(t, false)
	repo(t)
	if code, _, errOut := e.run("trust"); code != 0 {
		t.Fatalf("trust: %d %q", code, errOut)
	}
	code, out, errOut := e.run("env", "--project", "--shell", "posix")
	if code != 0 || !strings.Contains(errOut, "not reachable") {
		t.Fatalf("env: %d %q", code, errOut)
	}
	if !strings.Contains(out, "export APP_KEY='value-of:op://Dev/App/APP_KEY';") || strings.Contains(out, "no-env") {
		t.Fatalf("env output: %q", out)
	}
}

func TestTrustErrors(t *testing.T) {
	e := setup(t, true)
	t.Chdir(t.TempDir())
	if code, _, errOut := e.run("trust"); code != ExitError || !strings.Contains(errOut, config.ProjectFile) {
		t.Fatalf("no project file: %d %q", code, errOut)
	}
	bad := filepath.Join(t.TempDir(), "bad.toml")
	if err := os.WriteFile(bad, []byte("project = \"x\"\nop_path = \"/tmp/evil-op\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := e.run("trust", bad); code != ExitError {
		t.Fatalf("invalid project trusted: %d", code)
	}
	if code, _, _ := e.run("untrust", "../config"); code != ExitUsage {
		t.Fatalf("path in project name: %d", code)
	}
	if _, err := os.Stat(e.cfg); err != nil {
		t.Fatalf("config touched: %v", err)
	}
}
