package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/nklmilojevic/sefko/internal/protocol"
)

func (a *app) wrapCmd() *cobra.Command {
	var varName string
	var bypass []string
	var noRetry bool
	cmd := &cobra.Command{
		Use:   "wrap <alias> [--var NAME] [--bypass NAME]... [--no-retry] -- command [args...]",
		Short: "Run a command with a secret, and refresh the secret if the command fails because of it",
		Long: "wrap runs the command with the secret in NAME (the alias's env by default).\n" +
			"If NAME or a --bypass variable is already set, it runs the command unchanged.\n" +
			"If the command fails, it runs validate. When the secret was rejected and\n" +
			"refreshed, it runs the command again one time if stdin is a terminal,\n" +
			"because piped stdin was already read. Use --no-retry for commands that are\n" +
			"not safe to run twice.",
		RunE: func(cmd *cobra.Command, args []string) error {
			dash := cmd.ArgsLenAtDash()
			if dash != 1 || dash == len(args) {
				return exit(ExitUsage, errors.New("want: wrap <alias> -- command [args...]"))
			}
			alias, argv := args[0], args[dash:]
			path, err := exec.LookPath(argv[0])
			if err != nil {
				return exit(ExitError, err)
			}
			if varName == "" {
				names, err := a.envNames()
				if err != nil {
					return err
				}
				env, ok := names[alias]
				if !ok {
					return exit(ExitNotAllowed, fmt.Errorf("%q is not in the allowlist", alias))
				}
				if env == "" {
					return exit(ExitUsage, fmt.Errorf("%q has no default env name; use --var NAME", alias))
				}
				varName = env
			}
			for _, name := range append([]string{varName}, bypass...) {
				if os.Getenv(name) != "" {
					return a.exec(path, argv, os.Environ())
				}
			}
			v, err := a.value(alias)
			if err != nil {
				return err
			}
			rc, signaled, err := a.runChild(path, argv, mergeEnv(os.Environ(), map[string]string{varName: v}))
			if err != nil {
				return exit(ExitError, fmt.Errorf("run %s: %w", argv[0], err))
			}
			if rc == 0 {
				return nil
			}
			if signaled {
				return exit(rc, nil)
			}
			r, err := a.client().Validate(alias)
			if err != nil || r != protocol.ResultInvalidRefreshed {
				return exit(rc, nil)
			}
			if !noRetry && a.io.StdinIsTerminal() {
				if v, err = a.value(alias); err != nil {
					return exit(rc, nil)
				}
				return a.exec(path, argv, mergeEnv(os.Environ(), map[string]string{varName: v}))
			}
			_, _ = fmt.Fprintf(a.io.Stderr, "sefko: %s was rejected and has been refreshed; re-run the command\n", alias)
			return exit(rc, nil)
		},
	}
	cmd.Flags().StringVar(&varName, "var", "", "variable that carries the secret (default: the alias's env)")
	cmd.Flags().StringArrayVar(&bypass, "bypass", nil, "if this variable is set, run the command without sefko (repeatable)")
	cmd.Flags().BoolVar(&noRetry, "no-retry", false, "never run the command a second time")
	return cmd
}

func (a *app) exec(path string, argv, env []string) error {
	if err := a.io.Exec(path, argv, env); err != nil {
		return exit(ExitError, fmt.Errorf("exec %s: %w", argv[0], err))
	}
	return nil
}

// runChild runs the command and waits for it. The terminal sends SIGINT and
// SIGQUIT to the child as well, so sefko only outlives them; it passes SIGTERM
// and SIGHUP on. A child killed by a signal gives 128+signal, like a shell.
func (a *app) runChild(path string, argv, env []string) (rc int, signaled bool, err error) {
	c := &exec.Cmd{Path: path, Args: argv, Env: env, Stdin: os.Stdin, Stdout: a.io.Stdout, Stderr: a.io.Stderr}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	if err := c.Start(); err != nil {
		return 0, false, err
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case s := <-sigs:
				if s == syscall.SIGTERM || s == syscall.SIGHUP {
					_ = c.Process.Signal(s)
				}
			case <-done:
				return
			}
		}
	}()
	err = c.Wait()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return 0, false, err
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal()), true, nil
	}
	return ee.ExitCode(), false, nil
}
