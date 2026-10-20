package cli

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// serviceLabel names the launchd agent that `sefko service install` writes.
// The Home Manager module uses its own label, so the two do not collide.
const serviceLabel = "io.nkl.sefko"

// servicePath reaches op from Homebrew or the 1Password installer, because
// launchd starts agents with only the system directories in PATH.
const servicePath = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

func runLaunchctl(args ...string) error {
	out, err := exec.Command("/bin/launchctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl %s: %w: %s", args[0], err, bytes.TrimSpace(out))
	}
	return nil
}

func plistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", serviceLabel+".plist"), nil
}

func (a *app) serviceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Install or remove the launchd agent (not needed with the Home Manager module)",
	}
	domain := "gui/" + strconv.Itoa(os.Getuid())
	cmd.AddCommand(&cobra.Command{
		Use:   "install",
		Short: "Write ~/Library/LaunchAgents/" + serviceLabel + ".plist and start the agent",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			exe, err := os.Executable()
			if err != nil {
				return exit(ExitError, err)
			}
			p, err := plistPath()
			if err != nil {
				return exit(ExitError, err)
			}
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				return exit(ExitError, err)
			}
			if err := os.WriteFile(p, plist(exe, a.configPath, a.socket), 0o644); err != nil {
				return exit(ExitError, err)
			}
			// bootstrap refuses a label that is already loaded.
			_ = a.io.Launchctl("bootout", domain+"/"+serviceLabel)
			if err := a.io.Launchctl("bootstrap", domain, p); err != nil {
				return exit(ExitError, err)
			}
			_, _ = fmt.Fprintf(a.io.Stderr, "sefko: installed %s\n", p)
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "uninstall",
		Short: "Stop the agent and remove its plist",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			p, err := plistPath()
			if err != nil {
				return exit(ExitError, err)
			}
			_ = a.io.Launchctl("bootout", domain+"/"+serviceLabel)
			if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				return exit(ExitError, err)
			}
			_, _ = fmt.Fprintf(a.io.Stderr, "sefko: removed %s\n", p)
			return nil
		},
	})
	return cmd
}

func plist(exe, configPath, socket string) []byte {
	esc := func(s string) string {
		var b bytes.Buffer
		_ = xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	var args strings.Builder
	for _, s := range []string{exe, "agent", "--config", configPath, "--socket", socket} {
		args.WriteString("\t\t<string>" + esc(s) + "</string>\n")
	}
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + serviceLabel + `</string>
	<key>ProgramArguments</key>
	<array>
` + args.String() + `	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>PATH</key>
		<string>` + servicePath + `</string>
	</dict>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ProcessType</key>
	<string>Interactive</string>
</dict>
</plist>
`)
}
