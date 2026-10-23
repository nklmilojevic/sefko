package config

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
)

// ProjectFile is the file in which a repository lists the secrets its tools need.
const ProjectFile = ".sefko.toml"

// Project is a repository's list of secrets. The agent never reads the
// repository's file: it reads the copy that `sefko trust` put in ProjectsDir,
// so a change in the repository has no effect until the user trusts it again.
type Project struct {
	Name    string            `toml:"project"`
	Account string            `toml:"account"` // default for every secret
	Secrets map[string]Secret `toml:"secrets"`
}

// ValidName reports whether s can be an alias or a project name.
func ValidName(s string) bool { return aliasRe.MatchString(s) }

func ParseProject(data []byte) (*Project, error) {
	var p Project
	if err := decodeStrict(data, &p); err != nil {
		return nil, err
	}
	if !ValidName(p.Name) {
		return nil, fmt.Errorf("project %q: name must match %s", p.Name, aliasRe)
	}
	if len(p.Secrets) == 0 {
		return nil, fmt.Errorf("project %q has no secrets", p.Name)
	}
	for _, alias := range p.Aliases() {
		s := p.Secrets[alias]
		if s.Account == "" {
			s.Account = p.Account
		}
		if err := checkSecret(alias, s); err != nil {
			return nil, err
		}
		p.Secrets[alias] = s
	}
	return &p, nil
}

func LoadProject(path string) (*Project, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := ParseProject(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// Aliases returns the project's own aliases in sorted order.
func (p *Project) Aliases() []string {
	names := make([]string, 0, len(p.Secrets))
	for n := range p.Secrets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// QualifiedName is the name of a project secret in the agent: project/alias.
// An alias in config.toml cannot contain a slash, so a project can never
// replace one of the user's own secrets.
func (p *Project) QualifiedName(alias string) string { return p.Name + "/" + alias }

// Equal reports whether p and o allow the same secrets.
func (p *Project) Equal(o *Project) bool {
	return p.Name == o.Name && reflect.DeepEqual(p.Secrets, o.Secrets)
}

// ProjectsDir holds the trusted copies of project files, next to the config file.
func ProjectsDir(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "projects")
}

// TrustedPath is where the trusted copy of project name is kept.
func TrustedPath(configPath, name string) string {
	return filepath.Join(ProjectsDir(configPath), name+".toml")
}

// FindProject returns the nearest ProjectFile in dir or one of its parents.
func FindProject(dir string) (string, error) {
	for d := dir; ; {
		p := filepath.Join(d, ProjectFile)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p, nil
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", fmt.Errorf("no %s in %s or a parent directory: %w", ProjectFile, dir, fs.ErrNotExist)
		}
		d = parent
	}
}

// Files is the config file and the trusted project files as read from disk.
type Files struct {
	// Sum changes when any of the files changes, appears or disappears.
	Sum [32]byte

	path     string
	data     []byte
	projects []projectData
	warnings []error
}

type projectData struct {
	path string
	data []byte
}

// ReadFiles reads the config file and every trusted project file.
func ReadFiles(path string) (*Files, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f := &Files{path: path, data: data}
	h := sha256.New()
	hashChunk(h, []byte(path), data)
	dir := ProjectsDir(path)
	entries, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		f.warnings = append(f.warnings, err)
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".toml" {
			continue
		}
		p := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(p)
		if err != nil {
			f.warnings = append(f.warnings, err)
			continue
		}
		hashChunk(h, []byte(e.Name()), b)
		f.projects = append(f.projects, projectData{p, b})
	}
	h.Sum(f.Sum[:0])
	return f, nil
}

func hashChunk(h hash.Hash, parts ...[]byte) {
	for _, b := range parts {
		_ = binary.Write(h, binary.BigEndian, uint64(len(b)))
		h.Write(b)
	}
}

// Parse builds one Config from the config file and the trusted projects. An
// invalid config file is an error. An invalid project file is skipped and
// reported in warnings, so it cannot take the other secrets down.
func (f *Files) Parse() (*Config, []error, error) {
	cfg, err := Parse(f.data)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", f.path, err)
	}
	warnings := append([]error(nil), f.warnings...)
	if cfg.Secrets == nil {
		cfg.Secrets = map[string]Secret{}
	}
	for _, pd := range f.projects {
		p, err := ParseProject(pd.data)
		if err == nil && filepath.Base(pd.path) != p.Name+".toml" {
			err = fmt.Errorf("project %q must be in %s.toml", p.Name, p.Name)
		}
		if err != nil {
			warnings = append(warnings, fmt.Errorf("%s: %w", pd.path, err))
			continue
		}
		for _, alias := range p.Aliases() {
			cfg.Secrets[p.QualifiedName(alias)] = p.Secrets[alias]
		}
	}
	return cfg, warnings, nil
}
