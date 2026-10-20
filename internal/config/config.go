// Package config loads the sefko allowlist. The file holds 1Password
// references only, never secret values.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

const (
	DefaultTTL          = 168 * time.Hour
	DefaultFetchTimeout = 60 * time.Second
	valuePlaceholder    = "{}"
)

var (
	aliasRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	envRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// Duration is a time.Duration written as a Go duration string ("168h").
type Duration time.Duration

func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// Validate describes an HTTP request that proves a secret still works.
type Validate struct {
	URL    string `toml:"url"`
	Header string `toml:"header"`
	Format string `toml:"format"`
}

// HeaderValue renders Format with the secret in place of {}.
func (v *Validate) HeaderValue(secret []byte) string {
	return strings.Replace(v.Format, valuePlaceholder, string(secret), 1)
}

type Secret struct {
	Ref      string    `toml:"ref"`
	Account  string    `toml:"account"`
	Env      string    `toml:"env"`
	Validate *Validate `toml:"validate"`
}

// SameSource reports whether two entries read the same 1Password item, so a
// cached value fetched for one is valid for the other.
func (s Secret) SameSource(o Secret) bool {
	return s.Ref == o.Ref && s.Account == o.Account
}

type Config struct {
	OpPath       string            `toml:"op_path"`
	TTL          Duration          `toml:"ttl"`
	FetchTimeout Duration          `toml:"fetch_timeout"`
	Secrets      map[string]Secret `toml:"secrets"`
}

func (c *Config) TTLDuration() time.Duration          { return time.Duration(c.TTL) }
func (c *Config) FetchTimeoutDuration() time.Duration { return time.Duration(c.FetchTimeout) }

// Names returns the aliases in sorted order.
func (c *Config) Names() []string {
	names := make([]string, 0, len(c.Secrets))
	for n := range c.Secrets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// DefaultPath is $XDG_CONFIG_HOME/sefko/config.toml, falling back to
// ~/.config/sefko/config.toml. SEFKO_CONFIG overrides both.
func DefaultPath() string {
	if p := os.Getenv("SEFKO_CONFIG"); p != "" {
		return p
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "sefko", "config.toml")
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

func Parse(data []byte) (*Config, error) {
	var c Config
	md, err := toml.Decode(string(data), &c)
	if err != nil {
		return nil, err
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("unknown keys: %s", strings.Join(keys, ", "))
	}
	if c.OpPath == "" {
		c.OpPath = "op"
	}
	if c.TTL == 0 {
		c.TTL = Duration(DefaultTTL)
	}
	if c.FetchTimeout == 0 {
		c.FetchTimeout = Duration(DefaultFetchTimeout)
	}
	if err := c.check(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) check() error {
	if c.TTL < 0 {
		return errors.New("ttl must be positive")
	}
	if c.FetchTimeout < 0 {
		return errors.New("fetch_timeout must be positive")
	}
	for _, name := range c.Names() {
		s := c.Secrets[name]
		if !aliasRe.MatchString(name) {
			return fmt.Errorf("secret %q: alias must match %s", name, aliasRe)
		}
		if !strings.HasPrefix(s.Ref, "op://") {
			return fmt.Errorf("secret %q: ref must start with op://", name)
		}
		if s.Account == "" {
			return fmt.Errorf("secret %q: account is required", name)
		}
		if s.Env != "" && !envRe.MatchString(s.Env) {
			return fmt.Errorf("secret %q: env %q is not a valid variable name", name, s.Env)
		}
		if v := s.Validate; v != nil {
			u, err := url.Parse(v.URL)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
				return fmt.Errorf("secret %q: validate.url must be an http(s) URL", name)
			}
			if v.Header == "" {
				return fmt.Errorf("secret %q: validate.header is required", name)
			}
			if v.Format == "" {
				v.Format = valuePlaceholder
			}
			if !strings.Contains(v.Format, valuePlaceholder) {
				return fmt.Errorf("secret %q: validate.format must contain {}", name)
			}
		}
	}
	return nil
}
