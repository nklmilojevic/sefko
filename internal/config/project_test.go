package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleProject = `
project = "acme"
account = "team.1password.com"

[secrets.app-key]
ref = "op://Dev/App/APP_KEY"
env = "APP_KEY"

[secrets.github-token]
ref = "op://Dev/GitHub token/token"
account = "other.1password.com"
env = "GITHUB_TOKEN"

[secrets.github-token.validate]
url = "https://api.github.com/user"
header = "Authorization"
format = "Bearer {}"
`

func TestParseProject(t *testing.T) {
	p, err := ParseProject([]byte(sampleProject))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(p.Aliases(), ","); got != "app-key,github-token" {
		t.Fatalf("aliases: %s", got)
	}
	if a := p.Secrets["app-key"].Account; a != "team.1password.com" {
		t.Fatalf("default account not applied: %q", a)
	}
	if a := p.Secrets["github-token"].Account; a != "other.1password.com" {
		t.Fatalf("own account replaced: %q", a)
	}
	if n := p.QualifiedName("app-key"); n != "acme/app-key" {
		t.Fatal(n)
	}
}

func TestParseProjectInvalid(t *testing.T) {
	cases := map[string]string{
		"no name":      "[secrets.a]\nref = \"op://x\"\naccount = \"a\"\n",
		"bad name":     "project = \"../x\"\n[secrets.a]\nref = \"op://x\"\naccount = \"a\"\n",
		"no secrets":   "project = \"p\"\n",
		"no account":   "project = \"p\"\n[secrets.a]\nref = \"op://x\"\n",
		"bad ref":      "project = \"p\"\naccount = \"a\"\n[secrets.a]\nref = \"x\"\n",
		"global key":   "project = \"p\"\nop_path = \"/tmp/op\"\naccount = \"a\"\n[secrets.a]\nref = \"op://x\"\n",
		"insecure url": "project = \"p\"\naccount = \"a\"\n[secrets.a]\nref = \"op://x\"\n[secrets.a.validate]\nurl = \"http://example.com\"\nheader = \"H\"\n",
	}
	for name, in := range cases {
		if _, err := ParseProject([]byte(in)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestProjectEqual(t *testing.T) {
	a, _ := ParseProject([]byte(sampleProject))
	b, _ := ParseProject([]byte("# a comment\n" + sampleProject))
	if !a.Equal(b) {
		t.Fatal("a comment changed the meaning")
	}
	c, _ := ParseProject([]byte(strings.Replace(sampleProject, "APP_KEY\"\nenv", "APP_KEY2\"\nenv", 1)))
	if a.Equal(c) {
		t.Fatal("a changed ref compared equal")
	}
	d, _ := ParseProject([]byte(strings.Replace(sampleProject, "https://api.github.com/user", "https://evil.example/", 1)))
	if a.Equal(d) {
		t.Fatal("a changed validator compared equal")
	}
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFilesMergeTrustedProjects(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	writeFile(t, cfgPath, "[secrets.github]\nref = \"op://Private/GitHub/token\"\naccount = \"me\"\n")

	f, err := ReadFiles(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	before := f.Sum

	writeFile(t, TrustedPath(cfgPath, "acme"), sampleProject)
	writeFile(t, TrustedPath(cfgPath, "wrong-name"), sampleProject)
	writeFile(t, TrustedPath(cfgPath, "broken"), "[[[")
	writeFile(t, filepath.Join(ProjectsDir(cfgPath), "notes.txt"), "ignored")

	f, err = ReadFiles(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if f.Sum == before {
		t.Fatal("adding a project did not change the sum")
	}
	cfg, warnings, err := f.Parse()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.Names(), ","); got != "acme/app-key,acme/github-token,github" {
		t.Fatalf("names: %s", got)
	}
	if len(warnings) != 2 {
		t.Fatalf("want warnings for broken.toml and wrong-name.toml, got %v", warnings)
	}
}

func TestFilesConfigErrorIsFatal(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	writeFile(t, cfgPath, "[[[")
	f, err := ReadFiles(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.Parse(); err == nil {
		t.Fatal("invalid config accepted")
	}
}

func TestFindProject(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ProjectFile), sampleProject)
	deep := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := FindProject(deep)
	if err != nil || got != filepath.Join(root, ProjectFile) {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := FindProject(t.TempDir()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("want ErrNotExist, got %v", err)
	}
}
