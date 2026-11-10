// Package cli implements the sefko command line.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/nklmilojevic/sefko/internal/agent"
	"github.com/nklmilojevic/sefko/internal/client"
	"github.com/nklmilojevic/sefko/internal/config"
	"github.com/nklmilojevic/sefko/internal/opread"
	"github.com/nklmilojevic/sefko/internal/platform"
	"github.com/nklmilojevic/sefko/internal/protocol"
)

// Exit codes.
const (
	ExitOK          = 0
	ExitError       = 1
	ExitUsage       = 2
	ExitNotAllowed  = 3
	ExitOpFailed    = 4
	ExitInvalid     = 10
	ExitUnknown     = 11
	envSocket       = "SEFKO_SOCK"
	fallbackWarning = "sefko: agent not reachable, reading from 1Password directly"
)

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *exitError) Unwrap() error { return e.err }

func exit(code int, err error) error { return &exitError{code: code, err: err} }

// IO lets tests capture output and replace process exec.
type IO struct {
	Stdout io.Writer
	Stderr io.Writer
	// Exec replaces the current process; tests substitute it.
	Exec func(path string, argv, env []string) error
	// StdinIsTerminal decides whether wrap may run a command again.
	StdinIsTerminal func() bool
	// Launchctl runs /bin/launchctl; tests substitute it.
	Launchctl func(args ...string) error
}

type app struct {
	io         IO
	socket     string
	configPath string
}

// Execute runs the CLI and returns the process exit code.
func Execute(version string, args []string, stdio IO) int {
	if stdio.Exec == nil {
		stdio.Exec = syscall.Exec
	}
	if stdio.Launchctl == nil {
		stdio.Launchctl = runLaunchctl
	}
	if stdio.StdinIsTerminal == nil {
		stdio.StdinIsTerminal = func() bool { return platform.IsTerminal(int(os.Stdin.Fd())) }
	}
	a := &app{io: stdio}
	root := a.root(version)
	root.SetArgs(args)
	root.SetOut(stdio.Stdout)
	root.SetErr(stdio.Stderr)
	err := root.Execute()
	if err == nil {
		return ExitOK
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if ee.err != nil {
			_, _ = fmt.Fprintln(stdio.Stderr, "sefko:", ee.err)
		}
		return ee.code
	}
	_, _ = fmt.Fprintln(stdio.Stderr, "sefko:", err)
	return ExitUsage
}

func (a *app) root(version string) *cobra.Command {
	root := &cobra.Command{
		Use:           "sefko",
		Short:         "Keep 1Password secrets in memory and serve them over a Unix socket",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&a.socket, "socket", protocol.DefaultSocketPath(), "agent socket path (env "+envSocket+")")
	root.PersistentFlags().StringVar(&a.configPath, "config", config.DefaultPath(), "config file (env SEFKO_CONFIG)")
	root.AddCommand(
		a.agentCmd(),
		a.getCmd(),
		a.execCmd(),
		a.envCmd(),
		a.wrapCmd(),
		a.refreshCmd(),
		a.validateCmd(),
		a.lockCmd(),
		a.statusCmd(),
		a.trustCmd(),
		a.untrustCmd(),
		a.serviceCmd(),
	)
	return root
}

func (a *app) client() *client.Client { return client.New(a.socket) }

func (a *app) agentCmd() *cobra.Command {
	var logStderr bool
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Run the agent in the foreground (launchd runs this)",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			// Catch SIGHUP first: its default action would kill the agent.
			hup := make(chan os.Signal, 1)
			signal.Notify(hup, syscall.SIGHUP)
			defer signal.Stop(hup)
			syscall.Umask(0o077)
			peers, sleep, log := platform.Default()
			if logStderr {
				log = &platform.WriterLogger{W: a.io.Stderr}
			}
			for _, err := range platform.Harden() {
				log.Error(err.Error())
			}
			ag, err := agent.New(agent.Options{ConfigPath: a.configPath, Peers: peers, Sleep: sleep, Log: log})
			if err != nil {
				return exit(ExitError, err)
			}
			ln, err := agent.Listen(a.socket)
			if err != nil {
				return exit(ExitError, err)
			}
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			go func() {
				for range hup {
					_ = ag.Reload()
				}
			}()
			if err := ag.Serve(ctx, ln); err != nil {
				return exit(ExitError, err)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&logStderr, "log-stderr", false, "log to stderr instead of the unified log")
	return cmd
}

// value asks the agent for name and falls back to op when the agent is down.
func (a *app) value(name string) (string, error) {
	v, err := a.client().Get(name)
	if err == nil {
		return v, nil
	}
	if !errors.Is(err, client.ErrUnreachable) {
		return "", classify(err)
	}
	_, _ = fmt.Fprintln(a.io.Stderr, fallbackWarning)
	cfg, cerr := config.Load(a.configPath)
	if cerr != nil {
		return "", exit(ExitError, fmt.Errorf("%v; and loading config for the fallback failed: %w", err, cerr))
	}
	sec, ok := cfg.Secrets[name]
	if !ok {
		return "", exit(ExitNotAllowed, fmt.Errorf("%q is not in the allowlist (%s)", name, a.configPath))
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.FetchTimeoutDuration())
	defer cancel()
	raw, rerr := opread.Read(ctx, cfg.OpPath, sec.Account, sec.Ref)
	if rerr != nil {
		return "", exit(ExitOpFailed, rerr)
	}
	v = string(raw)
	clear(raw)
	return v, nil
}

// classify maps agent errors to exit codes.
func classify(err error) error {
	var pe *protocol.Error
	if errors.As(err, &pe) {
		switch pe.Code {
		case protocol.CodeNotAllowed:
			return exit(ExitNotAllowed, err)
		case protocol.CodeOpFailed, protocol.CodeOpTimeout:
			return exit(ExitOpFailed, err)
		}
	}
	return exit(ExitError, err)
}

func (a *app) getCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <alias>",
		Short: "Print a secret (no trailing newline)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			v, err := a.value(args[0])
			if err != nil {
				return err
			}
			_, err = io.WriteString(a.io.Stdout, v)
			return err
		},
	}
}

// envNames maps aliases to their default variable names, asking the agent
// first and the local config when the agent is down.
func (a *app) envNames() (map[string]string, error) {
	out := map[string]string{}
	names, err := a.client().Names()
	if err == nil {
		for _, n := range names {
			out[n.Name] = n.Env
		}
		return out, nil
	}
	if !errors.Is(err, client.ErrUnreachable) {
		return nil, classify(err)
	}
	cfg, cerr := config.Load(a.configPath)
	if cerr != nil {
		return nil, exit(ExitError, cerr)
	}
	for name, s := range cfg.Secrets {
		out[name] = s.Env
	}
	return out, nil
}

type binding struct {
	env, alias string
	// optional leaves env unset when the secret cannot be read, so that
	// the command (varlock) can resolve it itself.
	optional bool
	// agentOnly never reads from 1Password directly when the agent is down.
	agentOnly bool
}

// projectMode is how exec and env use the nearest project file.
type projectMode int

const (
	noProject projectMode = iota
	withProject
	ifTrusted
)

// bindings resolves positional aliases (using their default env names),
// --env NAME=alias overrides and the nearest project file.
func (a *app) bindings(aliases, overrides []string, project projectMode) ([]binding, error) {
	var out []binding
	for _, o := range overrides {
		env, alias, ok := strings.Cut(o, "=")
		if !ok || env == "" || alias == "" {
			return nil, exit(ExitUsage, fmt.Errorf("--env %q: want NAME=alias", o))
		}
		out = append(out, binding{env: env, alias: alias})
	}
	switch project {
	case withProject:
		bs, err := a.projectBindings()
		if err != nil {
			return nil, err
		}
		out = append(out, bs...)
	case ifTrusted:
		out = append(out, a.optionalProjectBindings()...)
	}
	if len(aliases) > 0 {
		names, err := a.envNames()
		if err != nil {
			return nil, err
		}
		for _, alias := range aliases {
			env, ok := names[alias]
			if !ok {
				return nil, exit(ExitNotAllowed, fmt.Errorf("%q is not in the allowlist", alias))
			}
			if env == "" {
				return nil, exit(ExitUsage, fmt.Errorf("%q has no default env name; use --env NAME=%s", alias, alias))
			}
			out = append(out, binding{env: env, alias: alias})
		}
	}
	if len(out) == 0 && project == noProject {
		return nil, exit(ExitUsage, errors.New("name at least one alias"))
	}
	seen := map[string]string{}
	for _, b := range out {
		if prev, dup := seen[b.env]; dup {
			return nil, exit(ExitUsage, fmt.Errorf("%s is bound to both %s and %s", b.env, prev, b.alias))
		}
		seen[b.env] = b.alias
	}
	return out, nil
}

// resolve reads every binding. An optional binding that fails is left out
// with a note. When the failure is not about that one item (the agent is
// down, nobody approved 1Password), the other optional bindings are left
// out too, because they would fail the same way, one timeout at a time.
func (a *app) resolve(bs []binding) (map[string]string, error) {
	vals := map[string]string{}
	skipped, giveUp := 0, false
	for _, b := range bs {
		if b.optional && giveUp {
			skipped++
			continue
		}
		v, err := a.lookup(b)
		if err == nil {
			vals[b.env] = v
			continue
		}
		if !b.optional {
			return nil, err
		}
		_, _ = fmt.Fprintf(a.io.Stderr, "sefko: %s is not set: %v\n", b.env, err)
		giveUp = !itemError(err)
	}
	if skipped > 0 {
		_, _ = fmt.Fprintf(a.io.Stderr, "sefko: %d more variables are not set\n", skipped)
	}
	return vals, nil
}

func (a *app) lookup(b binding) (string, error) {
	if !b.agentOnly {
		return a.value(b.alias)
	}
	v, err := a.client().Get(b.alias)
	if err != nil {
		return "", classify(err)
	}
	return v, nil
}

// itemError reports whether err is about one 1Password item (for example
// one the user cannot read) rather than about the agent or 1Password itself.
func itemError(err error) bool {
	var pe *protocol.Error
	if errors.As(err, &pe) {
		return pe.Code == protocol.CodeOpFailed
	}
	var oe *opread.Error
	return errors.As(err, &oe)
}

func (a *app) execCmd() *cobra.Command {
	var overrides []string
	var project, optional bool
	cmd := &cobra.Command{
		Use:   "exec [alias...] [--env NAME=alias]... [--project | --if-trusted] -- command [args...]",
		Short: "Run a command with secrets in its environment",
		Long: "exec runs the command with the named secrets in its environment.\n\n" +
			"--project adds every secret of the nearest trusted project file. --if-trusted\n" +
			"does the same, but never stops the command: without a trusted project it\n" +
			"runs the command unchanged, and it leaves out a secret it cannot read. It\n" +
			"does not read from 1Password directly when the agent is down. Use it in a\n" +
			"wrapper, for example around varlock.",
		RunE: func(cmd *cobra.Command, args []string) error {
			dash := cmd.ArgsLenAtDash()
			if dash < 0 || dash == len(args) {
				return exit(ExitUsage, errors.New("missing -- command"))
			}
			argv := args[dash:]
			// Check the command first so a typo doesn't cost a 1Password prompt.
			path, err := exec.LookPath(argv[0])
			if err != nil {
				return exit(ExitError, err)
			}
			mode := noProject
			switch {
			case project && optional:
				return exit(ExitUsage, errors.New("use --project or --if-trusted, not both"))
			case project:
				mode = withProject
			case optional:
				mode = ifTrusted
			}
			bs, err := a.bindings(args[:dash], overrides, mode)
			if err != nil {
				return err
			}
			vals, err := a.resolve(bs)
			if err != nil {
				return err
			}
			return a.exec(path, argv, mergeEnv(os.Environ(), vals))
		},
	}
	cmd.Flags().StringArrayVar(&overrides, "env", nil, "set NAME to the value of alias (repeatable)")
	cmd.Flags().BoolVarP(&project, "project", "p", false, "add every secret of the nearest trusted "+projectFiles)
	cmd.Flags().BoolVar(&optional, "if-trusted", false, "like --project, but run the command unchanged when the project is not trusted")
	return cmd
}

func mergeEnv(env []string, vals map[string]string) []string {
	out := make([]string, 0, len(env)+len(vals))
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if _, replaced := vals[k]; !replaced {
			out = append(out, kv)
		}
	}
	for k, v := range vals {
		out = append(out, k+"="+v)
	}
	return out
}

func (a *app) envCmd() *cobra.Command {
	var shell string
	var overrides []string
	var project bool
	cmd := &cobra.Command{
		Use:   "env [alias...] [--project]",
		Short: "Print shell commands that export secrets",
		RunE: func(_ *cobra.Command, args []string) error {
			if shell != "fish" && shell != "posix" {
				return exit(ExitUsage, fmt.Errorf("--shell must be fish or posix, not %q", shell))
			}
			mode := noProject
			if project {
				mode = withProject
			}
			bs, err := a.bindings(args, overrides, mode)
			if err != nil {
				return err
			}
			vals, err := a.resolve(bs)
			if err != nil {
				return err
			}
			for _, b := range bs {
				if _, ok := vals[b.env]; !ok {
					continue
				}
				var line string
				if shell == "fish" {
					line = fmt.Sprintf("set -gx %s %s;\n", b.env, fishQuote(vals[b.env]))
				} else {
					line = fmt.Sprintf("export %s=%s;\n", b.env, posixQuote(vals[b.env]))
				}
				if _, err := io.WriteString(a.io.Stdout, line); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&shell, "shell", "fish", "fish or posix")
	cmd.Flags().StringArrayVar(&overrides, "env", nil, "export NAME with the value of alias (repeatable)")
	cmd.Flags().BoolVarP(&project, "project", "p", false, "add every secret of the nearest trusted "+projectFiles)
	return cmd
}

const projectFiles = config.ProjectFile + " or " + config.SchemaFile

func fishQuote(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}

func posixQuote(s string) string {
	return "'" + strings.ReplaceAll(s, `'`, `'\''`) + "'"
}

func (a *app) agentOnly(err error) error {
	if errors.Is(err, client.ErrUnreachable) {
		return exit(ExitError, err)
	}
	return classify(err)
}

func (a *app) refreshCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "refresh <alias>",
		Short: "Drop a cached secret and fetch it again",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if _, err := a.client().Refresh(args[0]); err != nil {
				return a.agentOnly(err)
			}
			_, _ = fmt.Fprintf(a.io.Stderr, "sefko: refreshed %s\n", args[0])
			return nil
		},
	}
}

func (a *app) validateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <alias>",
		Short: "Check a secret against its validator; refresh it if rejected",
		Long: "Exit codes: 0 valid, 10 invalid and refreshed, 11 unknown or no validator, " +
			"1 error, 3 not allowlisted, 4 1Password failed.",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			r, err := a.client().Validate(args[0])
			if err != nil {
				return a.agentOnly(err)
			}
			_, _ = fmt.Fprintln(a.io.Stdout, r)
			switch r {
			case protocol.ResultValid:
				return nil
			case protocol.ResultInvalidRefreshed:
				return exit(ExitInvalid, nil)
			default:
				return exit(ExitUnknown, nil)
			}
		},
	}
}

func (a *app) lockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Wipe every cached secret",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if err := a.client().Lock(); err != nil {
				return a.agentOnly(err)
			}
			_, _ = fmt.Fprintln(a.io.Stderr, "sefko: locked")
			return nil
		},
	}
}

func (a *app) statusCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the agent, cached entries and recent requests",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			st, err := a.client().Status()
			if err != nil {
				return a.agentOnly(err)
			}
			if asJSON {
				enc := json.NewEncoder(a.io.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(st)
			}
			printStatus(a.io.Stdout, st)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output")
	return cmd
}

func printStatus(w io.Writer, st *protocol.Status) {
	_, _ = fmt.Fprintf(w, "agent    pid %d, up %s\nconfig   %s\nttl      %s\nmlock    %v\n\n",
		st.PID, time.Since(st.Started).Round(time.Second), st.ConfigPath, st.TTL, st.MemLocked)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tCACHED\tEXPIRES\tHITS\tLAST REQUESTER")
	for _, e := range st.Entries {
		expires := "-"
		if e.ExpiresAt != nil {
			expires = e.ExpiresAt.Local().Format("Mon 02 Jan 15:04")
		}
		_, _ = fmt.Fprintf(tw, "%s\t%v\t%s\t%d\t%s\n", e.Name, e.Cached, expires, e.Hits, cmpOr(e.LastRequester, "-"))
	}
	_ = tw.Flush()
	if len(st.Recent) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "\nrecent requests")
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, ev := range st.Recent {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s[%d]\n",
			ev.Time.Local().Format("15:04:05"), printable(ev.Op), printable(cmpOr(ev.Name, "-")), ev.Result, printable(cmpOr(ev.Exe, "?")), ev.PID)
	}
	_ = tw.Flush()
}

// printable quotes s if it contains anything a terminal might interpret.
// Names in recent requests come from peers and may be hostile.
func printable(s string) string {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return strconv.Quote(s)
		}
	}
	return s
}

func cmpOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
