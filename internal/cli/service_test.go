package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestServiceInstallAndUninstall(t *testing.T) {
	e := setup(t, false)
	home := t.TempDir()
	t.Setenv("HOME", home)
	p := filepath.Join(home, "Library", "LaunchAgents", "io.nkl.sefko.plist")
	domain := "gui/" + strconv.Itoa(os.Getuid())

	if code, _, errOut := e.run("service", "install"); code != 0 {
		t.Fatalf("%d %q", code, errOut)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<string>agent</string>", "<string>" + e.cfg + "</string>", "<string>" + e.sock + "</string>", "/opt/homebrew/bin"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("plist lacks %q:\n%s", want, b)
		}
	}
	if lint, err := exec.LookPath("plutil"); err == nil {
		if out, err := exec.Command(lint, "-lint", p).CombinedOutput(); err != nil {
			t.Fatalf("plutil: %s", out)
		}
	}
	if len(e.ctl) != 2 || e.ctl[1][0] != "bootstrap" || e.ctl[1][1] != domain || e.ctl[1][2] != p {
		t.Fatalf("launchctl calls: %q", e.ctl)
	}

	e.ctl = nil
	if code, _, errOut := e.run("service", "uninstall"); code != 0 {
		t.Fatalf("%d %q", code, errOut)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("plist still there: %v", err)
	}
	if len(e.ctl) != 1 || strings.Join(e.ctl[0], " ") != "bootout "+domain+"/io.nkl.sefko" {
		t.Fatalf("launchctl calls: %q", e.ctl)
	}
	if code, _, _ := e.run("service", "uninstall"); code != 0 {
		t.Fatal("uninstall is not idempotent")
	}
}

func TestPlistEscapesPaths(t *testing.T) {
	if got := string(plist("/a&b/sefko", "/c<d", "/s")); !strings.Contains(got, "/a&amp;b/sefko") || !strings.Contains(got, "/c&lt;d") {
		t.Fatal(got)
	}
}
