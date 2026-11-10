package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// SchemaFile is the varlock schema that `sefko trust` reads when a directory
// has no ProjectFile. sefko takes the op("op://…") references from it, so a
// repository that already uses varlock needs no second list of secrets.
const SchemaFile = ".env.schema"

const defaultOpInstance = "_default"

var (
	itemRe     = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$`)
	bareWordRe = regexp.MustCompile(`^[A-Za-z0-9_.@:/+-]+$`)
	otpRe      = regexp.MustCompile(`(?i)[?&](?:attribute|attr)=(?:otp|totp)(?:&|$)`)
	envFlagRe  = regexp.MustCompile(`@(?:currentEnv|envFlag)\s*=\s*\$?([A-Za-z_][A-Za-z0-9_]*)`)
	invalidRe  = regexp.MustCompile(`[^a-z0-9_-]+`)
	refRe      = regexp.MustCompile(`^\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})$`)
)

// IsSchema reports whether path names a varlock schema rather than a ProjectFile.
func IsSchema(path string) bool { return filepath.Base(path) == SchemaFile }

// opInstance is one @initOp() of a schema. A reason means sefko cannot read
// its references the way varlock would, so it leaves them to varlock.
// tokenVar is the variable that holds a service account token: when it has a
// value, varlock reads with that token instead of the 1Password app.
type opInstance struct {
	account  string
	reason   string
	tokenVar string
}

type schemaItem struct {
	key, ref, instance, reason string
}

// ParseSchema builds a project named name from the op() items of a varlock
// schema. Items that sefko cannot serve exactly as varlock would resolve them
// are left out and described in the notes; varlock still resolves those.
func ParseSchema(name string, data []byte) (*Project, []string, error) {
	instances, items := scanSchema(data)
	p := &Project{Name: name, Secrets: map[string]Secret{}}
	var notes []string
	keys := make([]string, 0, len(items))
	for k := range items {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	owner := map[string]string{}
	for _, key := range keys {
		it := items[key]
		reason := it.reason
		inst, ok := instances[it.instance]
		switch {
		case reason != "":
		case !ok && it.instance == defaultOpInstance:
			reason = "the schema has no @initOp()"
		case !ok:
			reason = fmt.Sprintf("no @initOp(id=%s)", it.instance)
		case inst.reason != "":
			reason = inst.reason
		case !strings.HasPrefix(it.ref, "op://"):
			reason = "the reference does not start with op://"
		case otpRe.MatchString(it.ref):
			reason = "one-time passwords change every 30 seconds"
		}
		alias := aliasFor(key)
		if reason == "" && owner[alias] != "" {
			reason = fmt.Sprintf("its alias %s is already used by %s", alias, owner[alias])
		}
		if reason != "" {
			notes = append(notes, fmt.Sprintf("%s: %s; varlock resolves it", key, reason))
			continue
		}
		owner[alias] = key
		p.Secrets[alias] = Secret{Ref: it.ref, Account: inst.account, Env: key}
	}
	if len(p.Secrets) == 0 {
		// Nothing to serve is not an error: varlock resolves every item.
		return p, notes, nil
	}
	data, err := p.Encode()
	if err != nil {
		return nil, notes, err
	}
	// Parse the encoded form, so the project has the same checks and
	// defaults as the trusted copy that the agent reads.
	out, err := ParseProject(data)
	return out, notes, err
}

// Encode writes p as a project file.
func (p *Project) Encode() ([]byte, error) {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(p); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// scanSchema returns the @initOp() instances and the last definition of each
// item whose value mentions op().
func scanSchema(data []byte) (map[string]opInstance, map[string]schemaItem) {
	instances := map[string]opInstance{}
	items := map[string]schemaItem{}
	var closing string // the quote that ends the multi-line value we are in
	for line := range strings.Lines(string(data)) {
		line = strings.TrimRight(line, "\r\n")
		if closing != "" {
			if strings.Contains(line, closing) {
				closing = ""
			}
			continue
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			for _, args := range decoratorArgs(trimmed, "@initOp") {
				id, inst := parseInitOp(args)
				instances[id] = inst
			}
			continue
		}
		m := itemRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key, value := m[1], strings.TrimSpace(m[2])
		closing = openQuote(value)
		delete(items, key) // a later definition replaces an earlier one
		if !strings.Contains(value, "op(") {
			continue
		}
		items[key] = parseOpItem(key, value)
	}
	return instances, items
}

// openQuote returns the quote that a value opens without closing on its
// line, so that the following lines are part of the value.
func openQuote(v string) string {
	for _, q := range []string{`"""`, `'''`, "```"} {
		if strings.HasPrefix(v, q) {
			if strings.Contains(v[len(q):], q) {
				return ""
			}
			return q
		}
	}
	if v != "" && strings.ContainsRune(`"'`+"`", rune(v[0])) {
		if _, end, ok := quoted(v); !ok || end < 0 {
			return v[:1]
		}
	}
	return ""
}

func parseOpItem(key, value string) schemaItem {
	it := schemaItem{key: key, instance: defaultOpInstance}
	if !strings.HasPrefix(value, "op(") {
		it.reason = "op() is part of an expression"
		return it
	}
	inner, end, ok := callArgs(value, len("op"))
	if !ok {
		it.reason = "the op() call is not closed"
		return it
	}
	if rest := strings.TrimSpace(value[end:]); rest != "" && !strings.HasPrefix(rest, "#") {
		it.reason = "op() is part of an expression"
		return it
	}
	var positional []string
	for _, arg := range splitArgs(inner) {
		k, v, named := cutNamed(arg)
		if !named {
			positional = append(positional, arg)
			continue
		}
		if k == "allowMissing" && v == "false" {
			continue
		}
		it.reason = fmt.Sprintf("op() has the argument %s", k)
		return it
	}
	switch len(positional) {
	case 1:
	case 2:
		id, ok := literal(positional[0])
		if !ok {
			it.reason = "the op() instance is not a fixed value"
			return it
		}
		it.instance = id
	default:
		it.reason = "op() has an unexpected number of arguments"
		return it
	}
	ref, ok := literal(positional[len(positional)-1])
	if !ok {
		it.reason = "the reference is not a fixed value"
		return it
	}
	it.ref = ref
	return it
}

func parseInitOp(args string) (string, opInstance) {
	id := defaultOpInstance
	var inst opInstance
	appAuth := false
	for _, arg := range splitArgs(args) {
		k, v, named := cutNamed(arg)
		if !named {
			continue
		}
		switch k {
		case "id":
			if s, ok := literal(v); ok {
				id = s
			}
		case "account":
			if s, ok := literal(v); ok {
				inst.account = s
			} else {
				inst.reason = "the @initOp() account is not a fixed value"
			}
		case "allowAppAuth":
			appAuth = v == "true"
		case "token":
			if name, ok := refName(v); ok {
				inst.tokenVar = name
			} else {
				inst.reason = "the @initOp() token is not a $VARIABLE"
			}
		case "connectHost":
			inst.reason = "it reads from a 1Password Connect server"
		case "allowMissing":
			if v != "false" {
				inst.reason = "@initOp() allows missing items"
			}
		}
	}
	switch {
	case inst.reason != "":
	case !appAuth:
		inst.reason = "@initOp() does not use the 1Password app (allowAppAuth=true)"
	case inst.account == "":
		inst.reason = "@initOp() has no account"
	}
	return id, inst
}

// decoratorArgs returns the argument text of each name(...) in a comment line.
func decoratorArgs(line, name string) []string {
	var out []string
	for i := 0; ; {
		j := strings.Index(line[i:], name+"(")
		if j < 0 {
			return out
		}
		start := i + j + len(name)
		inner, end, ok := callArgs(line, start)
		if !ok {
			return out
		}
		out = append(out, inner)
		i = end
	}
}

// callArgs returns the text between the parenthesis at s[open] and the one
// that closes it, and the index after the closing one.
func callArgs(s string, open int) (string, int, bool) {
	depth := 0
	for i := open; i < len(s); i++ {
		switch c := s[i]; c {
		case '"', '\'', '`':
			_, end, ok := quoted(s[i:])
			if !ok || end < 0 {
				return "", 0, false
			}
			i += end
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return s[open+1 : i], i + 1, true
			}
		}
	}
	return "", 0, false
}

// splitArgs splits on the commas that are outside quotes and parentheses.
func splitArgs(s string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '"', '\'', '`':
			if _, end, ok := quoted(s[i:]); ok && end >= 0 {
				i += end
			}
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	if last := strings.TrimSpace(s[start:]); last != "" || len(out) > 0 {
		out = append(out, last)
	}
	return out
}

// quoted reads the string literal at the start of s. It returns the content,
// the index of the closing quote (-1 if there is none), and whether s starts
// with a quote.
func quoted(s string) (string, int, bool) {
	if s == "" || !strings.ContainsRune(`"'`+"`", rune(s[0])) {
		return "", 0, false
	}
	q := s[0]
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch {
		case s[i] == '\\' && q != '\'' && i+1 < len(s):
			i++
			b.WriteByte(s[i])
		case s[i] == q:
			return b.String(), i, true
		default:
			b.WriteByte(s[i])
		}
	}
	return "", -1, true
}

// literal returns the value of a quoted string or a bare word, and false for
// anything varlock would compute: a $reference, an expansion or a call.
func literal(s string) (string, bool) {
	if v, end, ok := quoted(s); ok {
		if end != len(s)-1 || strings.Contains(v, "$") {
			return "", false
		}
		return v, true
	}
	return s, bareWordRe.MatchString(s)
}

// refName returns NAME for $NAME or ${NAME}.
func refName(s string) (string, bool) {
	m := refRe.FindStringSubmatch(s)
	if m == nil {
		return "", false
	}
	return m[1] + m[2], true
}

func cutNamed(arg string) (string, string, bool) {
	if arg == "" || strings.ContainsRune(`"'`+"`", rune(arg[0])) {
		return "", "", false
	}
	k, v, ok := strings.Cut(arg, "=")
	if !ok || strings.ContainsAny(k, "() ") {
		return "", "", false
	}
	return strings.TrimSpace(k), strings.TrimSpace(v), true
}

// aliasFor turns a variable name into an alias: APP_KEY becomes app_key.
func aliasFor(key string) string {
	return sanitizeName(key)
}

// sanitizeName lowercases s and keeps it within the alias pattern.
func sanitizeName(s string) string {
	s = invalidRe.ReplaceAllString(strings.ToLower(s), "-")
	s = strings.TrimLeft(s, "_-")
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

// SchemaProjectName names the project of a schema after its repository, so
// every worktree of a repository shares one trusted project and one cache.
// A schema below the repository root gets its directory added to the name.
// The name ends in a hash of where the main repository is, so that another
// repository with the same name cannot use its trust.
func SchemaProjectName(schemaPath string) string {
	dir := filepath.Dir(schemaPath)
	root, repo := repoRoot(dir)
	if r, err := filepath.EvalSymlinks(repo); err == nil {
		repo = r
	}
	sum := sha256.Sum256([]byte(repo))
	suffix := "-" + hex.EncodeToString(sum[:4])
	name := sanitizeName(filepath.Base(repo))
	if rel, err := filepath.Rel(root, dir); err == nil && rel != "." {
		name = sanitizeName(name + "-" + filepath.ToSlash(rel))
	}
	name = strings.TrimRight(name, "_-")
	if name == "" {
		name = "project"
	}
	if max := 64 - len(suffix); len(name) > max {
		name = name[:max]
	}
	return name + suffix
}

// repoRoot returns the working tree that contains dir and the directory of
// the main repository. For a linked worktree the two differ. Outside a
// repository both are dir.
func repoRoot(dir string) (root, repo string) {
	for d := dir; ; {
		gitPath := filepath.Join(d, ".git")
		if fi, err := os.Stat(gitPath); err == nil {
			if fi.IsDir() {
				return d, d
			}
			return d, worktreeRepo(d, gitPath)
		}
		parent := filepath.Dir(d)
		if parent == d {
			return dir, dir
		}
		d = parent
	}
}

// worktreeRepo follows a worktree's .git file to the main repository. Any
// directory can have a .git file that points into another repository, so it
// accepts only a worktree that the repository registered: the gitdir must be
// in <repository>/.git/worktrees, and its gitdir file must point back to
// gitFile. Anything else is a repository of its own.
func worktreeRepo(root, gitFile string) string {
	data, err := os.ReadFile(gitFile)
	if err != nil {
		return root
	}
	gitDir, ok := strings.CutPrefix(strings.TrimSpace(string(data)), "gitdir:")
	if !ok {
		return root
	}
	gitDir = strings.TrimSpace(gitDir)
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(root, gitDir)
	}
	gitDir, err = filepath.EvalSymlinks(gitDir)
	if err != nil {
		return root
	}
	back, err := os.ReadFile(filepath.Join(gitDir, "gitdir"))
	if err != nil {
		return root
	}
	backlink := strings.TrimSpace(string(back))
	if !filepath.IsAbs(backlink) {
		backlink = filepath.Join(gitDir, backlink)
	}
	if !samePath(backlink, gitFile) {
		return root
	}
	b, err := os.ReadFile(filepath.Join(gitDir, "commondir"))
	if err != nil {
		return root
	}
	common := strings.TrimSpace(string(b))
	if !filepath.IsAbs(common) {
		common = filepath.Join(gitDir, common)
	}
	if !samePath(filepath.Dir(gitDir), filepath.Join(common, "worktrees")) {
		return root
	}
	common = filepath.Clean(common)
	if filepath.Base(common) == ".git" {
		return filepath.Dir(common)
	}
	return common
}

// samePath reports whether a and b name the same existing file.
func samePath(a, b string) bool {
	ra, err := filepath.EvalSymlinks(a)
	if err != nil {
		return false
	}
	rb, err := filepath.EvalSymlinks(b)
	return err == nil && ra == rb
}

// SchemaOverrides returns the variables that sefko must not set for a
// schema. These are the variables that varlock takes from somewhere other
// than the schema: the environment and the local .env files next to it.
// varlock prefers the environment to every file, so a value from sefko would
// hide a developer's own value. They also include the items of an @initOp()
// instance whose token has a value, because varlock reads those with the
// service account, which can have other access than the 1Password app.
func SchemaOverrides(schemaPath string, lookupEnv func(string) (string, bool)) map[string]bool {
	dir := filepath.Dir(schemaPath)
	schema, _ := os.ReadFile(schemaPath)
	files, envKnown := overrideFiles(dir, schema, lookupEnv)
	// The definitions in the order varlock prefers them. The files of an
	// environment that sefko cannot tell have no order: they only add.
	ordered := []map[string]value{itemValues(schema)}
	var unordered []map[string]value
	out := map[string]bool{}
	for i, f := range files {
		data, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			continue
		}
		vals := itemValues(data)
		for k := range vals {
			out[k] = true
		}
		if i < 2 || envKnown {
			ordered = append([]map[string]value{vals}, ordered...)
		} else {
			unordered = append(unordered, vals)
		}
	}
	tokenSet := func(name string) bool {
		if v, ok := lookupEnv(name); ok && v != "" {
			return true
		}
		for _, vals := range unordered {
			if v := vals[name]; v.defined && v.s != "" {
				return true
			}
		}
		for _, vals := range ordered {
			if v, ok := vals[name]; ok && v.defined {
				return v.s != ""
			}
		}
		return false
	}
	instances, items := scanSchema(schema)
	for key, it := range items {
		if inst := instances[it.instance]; inst.tokenVar != "" && tokenSet(inst.tokenVar) {
			out[key] = true
		}
	}
	return out
}

// value is the value of a .env item as varlock reads it. An item without a
// value (KEY=, KEY=undefined, KEY=# comment) is not defined: varlock then
// takes the item from the file below it. KEY="" is defined and empty.
type value struct {
	s       string
	defined bool
}

// itemValues returns the last value of each variable in a .env file, without
// its quotes or a comment. A value that sefko cannot read stays as written.
func itemValues(data []byte) map[string]value {
	out := map[string]value{}
	for line := range strings.Lines(string(data)) {
		m := itemRe.FindStringSubmatch(strings.TrimRight(line, "\r\n"))
		if m == nil {
			continue
		}
		v := strings.TrimSpace(m[2])
		if q, end, ok := quoted(v); ok && end >= 0 {
			out[m[1]] = value{s: q, defined: true}
			continue
		}
		if i := strings.IndexByte(v, '#'); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		out[m[1]] = value{s: v, defined: v != "" && v != "undefined"}
	}
	return out
}

// overrideFiles lists the files varlock loads on top of the schema, in the
// order varlock loads them, each preferred to the ones before it. Without an
// environment flag that is .env and .env.local. With one, it adds the files
// of the current environment. varlock takes the flag from the environment,
// then .env.local, .env and the schema. If sefko cannot tell which
// environment that is, it takes every .env.* file, so it never hides an
// override, and it reports false.
func overrideFiles(dir string, schema []byte, lookupEnv func(string) (string, bool)) ([]string, bool) {
	files := []string{".env", ".env.local"}
	m := envFlagRe.FindSubmatch(schema)
	if m == nil {
		return files, true
	}
	flag := string(m[1])
	env := func(v string) ([]string, bool) { return append(files, ".env."+v, ".env."+v+".local"), true }
	if v, ok := lookupEnv(flag); ok && v != "" {
		return env(v)
	}
	local, _ := os.ReadFile(filepath.Join(dir, ".env.local"))
	dotenv, _ := os.ReadFile(filepath.Join(dir, ".env"))
	for _, src := range [][]byte{local, dotenv, schema} {
		v := itemValues(src)[flag]
		if !v.defined {
			continue
		}
		if bareWordRe.MatchString(v.s) {
			return env(v.s)
		}
		break
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		n := e.Name()
		known := n == SchemaFile || n == ".env.local"
		if strings.HasPrefix(n, ".env.") && !known && !strings.Contains(n, "example") && !strings.Contains(n, "sample") {
			files = append(files, n)
		}
	}
	return files, false
}

// VarlockSchema returns the schema that varlock loads when it starts in dir
// without --path: the .env.schema in dir, or the one that varlock.loadPath in
// dir/package.json names, as a directory or as the file itself. varlock does
// not look in parent directories. It returns false when there is none, or
// when sefko cannot tell which one it is.
func VarlockSchema(dir string) (string, bool) {
	path := filepath.Join(dir, SchemaFile)
	if data, err := os.ReadFile(filepath.Join(dir, "package.json")); err == nil {
		var pkg struct {
			Varlock struct {
				LoadPath json.RawMessage `json:"loadPath"`
			} `json:"varlock"`
		}
		// varlock ignores a package.json that it cannot parse.
		if json.Unmarshal(data, &pkg) == nil && len(pkg.Varlock.LoadPath) > 0 && string(pkg.Varlock.LoadPath) != "null" {
			var one string
			if err := json.Unmarshal(pkg.Varlock.LoadPath, &one); err != nil {
				var many []string
				if json.Unmarshal(pkg.Varlock.LoadPath, &many) != nil || len(many) != 1 {
					return "", false
				}
				one = many[0]
			}
			// An empty path is the directory itself, as in varlock.
			if !filepath.IsAbs(one) {
				one = filepath.Join(dir, one)
			}
			fi, err := os.Stat(one)
			switch {
			case err != nil:
				return "", false
			case fi.IsDir():
				path = filepath.Join(one, SchemaFile)
			case IsSchema(one):
				path = filepath.Clean(one)
			default:
				return "", false
			}
		}
	}
	if fi, err := os.Stat(path); err != nil || !fi.Mode().IsRegular() {
		return "", false
	}
	return path, true
}
