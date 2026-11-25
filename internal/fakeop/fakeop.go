// Package fakeop turns a test binary into a stand-in for the 1Password CLI,
// so no test ever talks to real 1Password.
//
// Call Main from TestMain. When the binary is started with SEFKO_FAKE_OP=1 it
// behaves like `op read --account A --no-newline REF` and exits.
package fakeop

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	envMode    = "SEFKO_FAKE_OP"
	envValue   = "SEFKO_FAKE_OP_VALUE"
	envFile    = "SEFKO_FAKE_OP_VALUE_FILE"
	envDelay   = "SEFKO_FAKE_OP_DELAY"
	envExit    = "SEFKO_FAKE_OP_EXIT"
	envStderr  = "SEFKO_FAKE_OP_STDERR"
	envCounter = "SEFKO_FAKE_OP_COUNTER"
	envFailRef = "SEFKO_FAKE_OP_FAIL_REF"
)

// Main runs the fake if requested. It returns only when the process is not a
// fake op invocation.
func Main() {
	if os.Getenv(envMode) != "1" {
		return
	}
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	var caller, ref string
	switch {
	case len(args) == 5 && args[0] == "read" && args[1] == "--account" && args[3] == "--no-newline":
		if os.Getenv("OP_SERVICE_ACCOUNT_TOKEN") != "" {
			fmt.Fprintln(os.Stderr, "fake op: --account cannot be used with OP_SERVICE_ACCOUNT_TOKEN")
			return 2
		}
		caller, ref = args[2], args[4]
	case len(args) == 3 && args[0] == "read" && args[1] == "--no-newline":
		tok := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
		if tok == "" {
			fmt.Fprintln(os.Stderr, "fake op: missing OP_SERVICE_ACCOUNT_TOKEN")
			return 2
		}
		if os.Getenv("OP_CONNECT_HOST") != "" || os.Getenv("OP_CONNECT_TOKEN") != "" {
			fmt.Fprintln(os.Stderr, "fake op: OP_CONNECT_* must not be set with OP_SERVICE_ACCOUNT_TOKEN")
			return 2
		}
		caller, ref = "sa:"+tok, args[2]
	default:
		fmt.Fprintf(os.Stderr, "fake op: unexpected args %q\n", args)
		return 2
	}
	if p := os.Getenv(envCounter); p != "" {
		f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = f.WriteString(caller + " " + ref + "\n")
			_ = f.Close()
		}
	}
	if d, err := time.ParseDuration(os.Getenv(envDelay)); err == nil {
		time.Sleep(d)
	}
	if msg := os.Getenv(envStderr); msg != "" {
		fmt.Fprintln(os.Stderr, msg)
	}
	if bad := os.Getenv(envFailRef); bad != "" && strings.Contains(ref, bad) {
		fmt.Fprintf(os.Stderr, "[ERROR] %q isn't an item in this vault\n", ref)
		return 1
	}
	if code, err := strconv.Atoi(os.Getenv(envExit)); err == nil && code != 0 {
		return code
	}
	value := "value-of:" + ref
	if v := os.Getenv(envValue); v != "" {
		value = v
	}
	if p := os.Getenv(envFile); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		value = strings.TrimSpace(string(b))
	}
	fmt.Print(value)
	return 0
}

// Fake configures the environment so that executing Path behaves as op.
type Fake struct {
	t       testing.TB
	Path    string
	counter string
}

// Setup enables fake mode for child processes of the test. Tests using it
// cannot run in parallel because it sets environment variables.
func Setup(t testing.TB) *Fake {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f := &Fake{t: t, Path: exe, counter: t.TempDir() + "/calls"}
	t.Setenv(envMode, "1")
	t.Setenv(envCounter, f.counter)
	for _, k := range []string{
		envValue, envFile, envDelay, envExit, envStderr, envFailRef,
		"OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_HOST", "OP_CONNECT_TOKEN",
	} {
		t.Setenv(k, "")
	}
	return f
}

func (f *Fake) SetValue(v string)        { f.t.Setenv(envValue, v) }
func (f *Fake) SetValueFile(p string)    { f.t.Setenv(envFile, p) }
func (f *Fake) SetDelay(d time.Duration) { f.t.Setenv(envDelay, d.String()) }

// FailRef makes every reference that contains s fail as a missing item.
func (f *Fake) FailRef(s string) { f.t.Setenv(envFailRef, s) }

func (f *Fake) SetExit(code int, msg string) {
	f.t.Setenv(envExit, strconv.Itoa(code))
	f.t.Setenv(envStderr, msg)
}

// Calls returns the "account ref" lines of every invocation so far.
func (f *Fake) Calls() []string {
	b, err := os.ReadFile(f.counter)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}
