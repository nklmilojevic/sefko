package config

import (
	"strings"
	"testing"
	"time"
)

const sample = `
op_path = "/bin/op"
ttl = "168h"
fetch_timeout = "60s"

[secrets.github]
ref = "op://Private/GitHub Personal Access Token/token"
account = "my.1password.eu"
env = "GH_TOKEN"

[secrets.github.validate]
url = "https://api.github.com/user"
header = "Authorization"
format = "Bearer {}"

[secrets.restic]
ref = "op://Private/restic/password"
account = "my.1password.eu"
`

func TestParseSample(t *testing.T) {
	c, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if c.OpPath != "/bin/op" || c.TTLDuration() != 168*time.Hour || c.FetchTimeoutDuration() != time.Minute {
		t.Fatalf("globals: %+v", c)
	}
	gh := c.Secrets["github"]
	if gh.Env != "GH_TOKEN" || gh.Validate == nil || gh.Validate.HeaderValue([]byte("abc")) != "Bearer abc" {
		t.Fatalf("github: %+v", gh)
	}
	if got := c.Names(); strings.Join(got, ",") != "github,restic" {
		t.Fatalf("names: %v", got)
	}
}

func TestDefaults(t *testing.T) {
	c, err := Parse([]byte("[secrets.a]\nref = \"op://x/y/z\"\naccount = \"acc\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.OpPath != "op" || c.TTLDuration() != DefaultTTL || c.FetchTimeoutDuration() != DefaultFetchTimeout {
		t.Fatalf("defaults: %+v", c)
	}
}

func TestInvalid(t *testing.T) {
	cases := map[string]string{
		"bad alias":       "[secrets.Bad]\nref = \"op://x\"\naccount = \"a\"\n",
		"bad ref":         "[secrets.a]\nref = \"x\"\naccount = \"a\"\n",
		"no account":      "[secrets.a]\nref = \"op://x\"\n",
		"bad env":         "[secrets.a]\nref = \"op://x\"\naccount = \"a\"\nenv = \"1X\"\n",
		"unknown key":     "colour = \"red\"\n",
		"bad duration":    "ttl = \"forever\"\n",
		"negative ttl":    "ttl = \"-1h\"\n",
		"validate url":    "[secrets.a]\nref = \"op://x\"\naccount = \"a\"\n[secrets.a.validate]\nurl = \"ftp://x\"\nheader = \"H\"\n",
		"validate http":   "[secrets.a]\nref = \"op://x\"\naccount = \"a\"\n[secrets.a.validate]\nurl = \"http://api.github.com/user\"\nheader = \"H\"\n",
		"validate fmt":    "[secrets.a]\nref = \"op://x\"\naccount = \"a\"\n[secrets.a.validate]\nurl = \"https://x\"\nheader = \"H\"\nformat = \"Bearer\"\n",
		"no header":       "[secrets.a]\nref = \"op://x\"\naccount = \"a\"\n[secrets.a.validate]\nurl = \"https://x\"\n",
		"not toml at all": "[[[",
	}
	for name, in := range cases {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestValidateAllowsLoopbackHTTP(t *testing.T) {
	for _, u := range []string{"http://127.0.0.1:8080/x", "http://localhost/x", "http://[::1]/x"} {
		in := "[secrets.a]\nref = \"op://x\"\naccount = \"a\"\n[secrets.a.validate]\nurl = \"" + u + "\"\nheader = \"H\"\n"
		if _, err := Parse([]byte(in)); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
}

func TestSameSource(t *testing.T) {
	a := Secret{Ref: "op://a", Account: "x", Env: "A"}
	if !a.SameSource(Secret{Ref: "op://a", Account: "x", Env: "B"}) {
		t.Error("env change should keep the source")
	}
	if a.SameSource(Secret{Ref: "op://b", Account: "x"}) || a.SameSource(Secret{Ref: "op://a", Account: "y"}) {
		t.Error("ref or account change should change the source")
	}
}

func TestDefaultPath(t *testing.T) {
	t.Setenv("SEFKO_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", "/cfg")
	if got := DefaultPath(); got != "/cfg/sefko/config.toml" {
		t.Fatal(got)
	}
	t.Setenv("SEFKO_CONFIG", "/x.toml")
	if got := DefaultPath(); got != "/x.toml" {
		t.Fatal(got)
	}
}
