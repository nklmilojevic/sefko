package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/nklmilojevic/sefko/internal/client"
	"github.com/nklmilojevic/sefko/internal/config"
)

// projectFile returns arg as an absolute path, or the nearest .sefko.toml or
// .env.schema above the working directory.
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
// exactly what the project file at path declares. For a varlock schema it is
// enough that the trusted copy allows every secret of the schema: the
// worktrees of a repository share one project, and their branches can
// declare different secrets.
func (a *app) checkTrusted(path string, p *config.Project) error {
	t, err := config.LoadProject(config.TrustedPath(a.configPath, p.Name))
	if errors.Is(err, fs.ErrNotExist) {
		return exit(ExitNotAllowed, fmt.Errorf("project %s is not trusted; review %s and run `sefko trust`", p.Name, path))
	}
	ok := err == nil && t.Equal(p)
	if err == nil && config.IsSchema(path) {
		ok = t.Covers(p)
	}
	if !ok {
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
	p, _, err := config.ReadProjectFile(path)
	if err != nil {
		return nil, exit(ExitError, err)
	}
	if err := a.checkTrusted(path, p); err != nil {
		return nil, err
	}
	return projectEnv(path, p), nil
}

// optionalProjectBindings is projectBindings for --if-trusted. A missing
// project gives no bindings. An unreadable, untrusted or changed one gives a
// note and no bindings, so the command runs as it would without sefko.
func (a *app) optionalProjectBindings() []binding {
	path, err := projectFile("")
	if err != nil {
		return nil
	}
	p, _, err := config.ReadProjectFile(path)
	if err == nil {
		err = a.checkTrusted(path, p)
	}
	if err != nil {
		_, _ = fmt.Fprintln(a.io.Stderr, "sefko:", err)
		return nil
	}
	bs := projectEnv(path, p)
	for i := range bs {
		bs[i].optional, bs[i].agentOnly = true, true
	}
	return bs
}

// projectEnv binds the secrets of p that have an env name. For a varlock
// schema it leaves out the variables that varlock takes from the environment
// or a local .env file, because a value from sefko would replace them, and it
// marks the rest optional: varlock resolves a variable that sefko cannot.
func projectEnv(path string, p *config.Project) []binding {
	schema := config.IsSchema(path)
	var skip map[string]bool
	if schema {
		skip = config.SchemaOverrides(path, os.LookupEnv)
	}
	var out []binding
	for _, alias := range p.Aliases() {
		env := p.Secrets[alias].Env
		if env == "" || skip[env] {
			continue
		}
		if _, set := os.LookupEnv(env); schema && set {
			continue
		}
		out = append(out, binding{env: env, alias: p.QualifiedName(alias), optional: schema})
	}
	return out
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
		Short: "Allow the secrets that a project's " + config.ProjectFile + " or varlock " + config.SchemaFile + " lists",
		Long: "Copies the project file (default: the nearest " + config.ProjectFile + " or " + config.SchemaFile + "\n" +
			"above the working directory) into the allowlist. Its secrets are then available\n" +
			"as <project>/<alias>. A later change to the file has no effect until you trust it again.\n\n" +
			"From a varlock " + config.SchemaFile + ", sefko takes each KEY=op(\"op://...\") item of an\n" +
			"@initOp(allowAppAuth=true, account=...) instance. The project is named after the\n" +
			"repository, and the alias of KEY is key in lower case. sefko lists the items it\n" +
			"leaves to varlock.\n\n" +
			"With --check, exit 0 if the file is trusted and unchanged, 3 if not.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			path, err := projectFile(firstArg(args))
			if err != nil {
				return exit(ExitError, err)
			}
			p, notes, err := config.ReadProjectFile(path)
			if err != nil {
				return exit(ExitError, err)
			}
			if check {
				return a.checkTrusted(path, p)
			}
			trustedPath := config.TrustedPath(a.configPath, p.Name)
			own := p
			var others []string
			if config.IsSchema(path) {
				if t, err := config.LoadProject(trustedPath); err == nil && t.Name == p.Name {
					merged := t.Merge(p)
					for _, alias := range merged.Aliases() {
						if _, mine := own.Secrets[alias]; !mine {
							others = append(others, merged.QualifiedName(alias))
						}
					}
					p = merged
				}
			}
			data, err := trustedCopy(path, p)
			if err != nil {
				return exit(ExitError, err)
			}
			if err := writeFileAtomic(trustedPath, data); err != nil {
				return exit(ExitError, err)
			}
			a.reloadAgent()
			_, _ = fmt.Fprintf(a.io.Stdout, "trusted %s from %s\n\n", printable(p.Name), printable(path))
			tw := tabwriter.NewWriter(a.io.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "NAME\tENV\tACCOUNT\tREF\tVALIDATES WITH")
			for _, alias := range own.Aliases() {
				s := own.Secrets[alias]
				validate := "-"
				if s.Validate != nil {
					validate = s.Validate.URL
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", own.QualifiedName(alias), cmpOr(s.Env, "-"),
					printable(s.Account), printable(s.Ref), printable(validate))
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			if len(others) > 0 {
				_, _ = fmt.Fprintf(a.io.Stdout, "\nkept from other checkouts of %s: %s\n", printable(p.Name), printable(strings.Join(others, ", ")))
			}
			if len(notes) > 0 {
				_, _ = fmt.Fprintln(a.io.Stdout, "\nleft to varlock")
				for _, n := range notes {
					_, _ = fmt.Fprintln(a.io.Stdout, "  "+printable(n))
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "only report whether the file is trusted and unchanged")
	return cmd
}

func (a *app) untrustCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "untrust [project]",
		Short: "Remove a project's secrets from the allowlist and from memory",
		Long:  "Without a name, untrusts the project of the nearest " + config.ProjectFile + " or " + config.SchemaFile + ".",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := firstArg(args)
			if name == "" {
				path, err := projectFile("")
				if err != nil {
					return exit(ExitError, err)
				}
				p, _, err := config.ReadProjectFile(path)
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

// trustedCopy is what trust stores: a project file as it is, or the project
// that sefko derived from a varlock schema.
func trustedCopy(path string, p *config.Project) ([]byte, error) {
	if !config.IsSchema(path) {
		return os.ReadFile(path)
	}
	data, err := p.Encode()
	if err != nil {
		return nil, err
	}
	return append([]byte("# Generated by `sefko trust` from "+printable(path)+"\n"), data...), nil
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
