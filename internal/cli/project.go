package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/nklmilojevic/sefko/internal/client"
	"github.com/nklmilojevic/sefko/internal/config"
)

// projectFile returns arg as an absolute path, or the nearest .sefko.toml
// above the working directory.
func projectFile(arg string) (string, error) {
	if arg != "" {
		return filepath.Abs(arg)
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return config.FindProject(wd)
}

// checkTrusted fails with ExitNotAllowed unless the trusted copy of p allows
// exactly what the project file at path declares.
func (a *app) checkTrusted(path string, p *config.Project) error {
	t, err := config.LoadProject(config.TrustedPath(a.configPath, p.Name))
	if errors.Is(err, fs.ErrNotExist) {
		return exit(ExitNotAllowed, fmt.Errorf("project %s is not trusted; review %s and run `sefko trust`", p.Name, path))
	}
	if err != nil || !t.Equal(p) {
		return exit(ExitNotAllowed, fmt.Errorf("%s changed since you trusted it; review it and run `sefko trust`", path))
	}
	return nil
}

// projectBindings binds every secret with an env name in the nearest
// project file, after checking that the file is still the trusted one.
func (a *app) projectBindings() ([]binding, error) {
	path, err := projectFile("")
	if err != nil {
		return nil, exit(ExitError, err)
	}
	p, err := config.LoadProject(path)
	if err != nil {
		return nil, exit(ExitError, err)
	}
	if err := a.checkTrusted(path, p); err != nil {
		return nil, err
	}
	var out []binding
	for _, alias := range p.Aliases() {
		if env := p.Secrets[alias].Env; env != "" {
			out = append(out, binding{env, p.QualifiedName(alias)})
		}
	}
	return out, nil
}

// reloadAgent makes a running agent see a trust change now instead of at its
// next poll. A stopped agent reads the files when it starts.
func (a *app) reloadAgent() {
	if err := a.client().Reload(); err != nil && !errors.Is(err, client.ErrUnreachable) {
		_, _ = fmt.Fprintln(a.io.Stderr, "sefko: the agent did not reload:", err)
	}
}

func (a *app) trustCmd() *cobra.Command {
	var check bool
	cmd := &cobra.Command{
		Use:   "trust [file]",
		Short: "Allow the secrets that a project's " + config.ProjectFile + " lists",
		Long: "Copies the project file (default: the nearest " + config.ProjectFile + " above the working directory)\n" +
			"into the allowlist. Its secrets are then available as <project>/<alias>.\n" +
			"A later change to the file has no effect until you trust it again.\n\n" +
			"With --check, exit 0 if the file is trusted and unchanged, 3 if not.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			path, err := projectFile(firstArg(args))
			if err != nil {
				return exit(ExitError, err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return exit(ExitError, err)
			}
			p, err := config.ParseProject(data)
			if err != nil {
				return exit(ExitError, fmt.Errorf("%s: %w", path, err))
			}
			if check {
				return a.checkTrusted(path, p)
			}
			if err := writeFileAtomic(config.TrustedPath(a.configPath, p.Name), data); err != nil {
				return exit(ExitError, err)
			}
			a.reloadAgent()
			_, _ = fmt.Fprintf(a.io.Stdout, "trusted %s from %s\n\n", printable(p.Name), printable(path))
			tw := tabwriter.NewWriter(a.io.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "NAME\tENV\tACCOUNT\tREF\tVALIDATES WITH")
			for _, alias := range p.Aliases() {
				s := p.Secrets[alias]
				validate := "-"
				if s.Validate != nil {
					validate = s.Validate.URL
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", p.QualifiedName(alias), cmpOr(s.Env, "-"),
					printable(s.Account), printable(s.Ref), printable(validate))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "only report whether the file is trusted and unchanged")
	return cmd
}

func (a *app) untrustCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "untrust [project]",
		Short: "Remove a project's secrets from the allowlist and from memory",
		Long:  "Without a name, untrusts the project of the nearest " + config.ProjectFile + ".",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := firstArg(args)
			if name == "" {
				path, err := projectFile("")
				if err != nil {
					return exit(ExitError, err)
				}
				p, err := config.LoadProject(path)
				if err != nil {
					return exit(ExitError, err)
				}
				name = p.Name
			}
			if !config.ValidName(name) {
				return exit(ExitUsage, fmt.Errorf("%q is not a project name", name))
			}
			err := os.Remove(config.TrustedPath(a.configPath, name))
			if errors.Is(err, fs.ErrNotExist) {
				return exit(ExitError, fmt.Errorf("project %s is not trusted", name))
			}
			if err != nil {
				return exit(ExitError, err)
			}
			a.reloadAgent()
			_, _ = fmt.Fprintf(a.io.Stderr, "sefko: untrusted %s\n", name)
			return nil
		},
	}
}

// writeFileAtomic replaces path in one step, so the agent never reads a
// partly written file.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".trust-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func firstArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}
