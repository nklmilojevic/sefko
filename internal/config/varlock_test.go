package config

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const sampleSchema = `# Example app environment.
#
# @plugin(@varlock/1password-plugin@2.0.4)
# @initOp(allowAppAuth=true, account=team.example)
# @initOp(id=ci, token=$OP_TOKEN, account=team.example)
# @initOp(id=other, allowAppAuth=true, account="other.example")
# @initOp(id=dyn, allowAppAuth=true, account=$OP_ACCOUNT)
# @initOp(id=both, token=$OP_TOKEN, allowAppAuth=true, account=team.example)
# @initOp(id=lit, token="ops_literal", allowAppAuth=true, account=team.example)
# @defaultRequired=false @defaultSensitive=false
# ---

APP_NAME="Example"

# @sensitive @required @type=string(startsWith=base64:)
APP_KEY=op("op://Employee/App key/password")
# @sensitive
export DB_PASSWORD=op('op://Dev/Database/password') # trailing comment
SINGLE_WS = op( "op://Dev/Spaced/password" )
OTHER_TOKEN=op(other, "op://Shared/Other, with comma/credential")
CI_TOKEN=op(ci, "op://CI/Token/credential")
DYN_TOKEN=op(dyn, "op://Dev/Dyn/credential")
BOTH_TOKEN=op(both, "op://Dev/Both/credential")
LIT_TOKEN=op(lit, "op://Dev/Lit/credential")
UNKNOWN=op(nope, "op://Dev/Unknown/credential")
COND=if($BRANCH, "21", op("op://Dev/Cond/credential"))
MAYBE=op("op://Dev/Maybe/credential", allowMissing=true)
SURE=op("op://Dev/Sure/credential", allowMissing=false)
OTP=op("op://Dev/Login/one-time password?attribute=otp")
EXPANDED=op("op://${VAULT}/Item/credential")
REPLACED=op("op://Dev/Replaced/credential")
REPLACED=plain
NOTE="""
FAKE=op("op://Dev/Inside/multiline")
"""
LOWER_dup=op("op://Dev/A/credential")
lower_DUP=op("op://Dev/B/credential")
`

func TestParseSchema(t *testing.T) {
	p, notes, err := ParseSchema("example", []byte(sampleSchema))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Secret{
		"app_key":     {Ref: "op://Employee/App key/password", Account: "team.example", Env: "APP_KEY"},
		"db_password": {Ref: "op://Dev/Database/password", Account: "team.example", Env: "DB_PASSWORD"},
		"single_ws":   {Ref: "op://Dev/Spaced/password", Account: "team.example", Env: "SINGLE_WS"},
		"other_token": {Ref: "op://Shared/Other, with comma/credential", Account: "other.example", Env: "OTHER_TOKEN"},
		"both_token":  {Ref: "op://Dev/Both/credential", Account: "team.example", Env: "BOTH_TOKEN"},
		"sure":        {Ref: "op://Dev/Sure/credential", Account: "team.example", Env: "SURE"},
		"lower_dup":   {Ref: "op://Dev/A/credential", Account: "team.example", Env: "LOWER_dup"},
	}
	if !reflect.DeepEqual(p.Secrets, want) {
		t.Fatalf("secrets:\n got %+v\nwant %+v", p.Secrets, want)
	}
	if p.Name != "example" {
		t.Fatalf("name %q", p.Name)
	}
	keys := make([]string, 0, len(notes))
	for _, n := range notes {
		k, _, _ := strings.Cut(n, ":")
		keys = append(keys, k)
	}
	sort.Strings(keys)
	wantKeys := []string{"CI_TOKEN", "COND", "DYN_TOKEN", "EXPANDED", "LIT_TOKEN", "MAYBE", "OTP", "UNKNOWN", "lower_DUP"}
	if !reflect.DeepEqual(keys, wantKeys) {
		t.Fatalf("notes for %v, want %v:\n%s", keys, wantKeys, strings.Join(notes, "\n"))
	}
	for _, n := range notes {
		if !strings.HasSuffix(n, "; varlock resolves it") {
			t.Fatalf("note %q", n)
		}
	}

	// The project survives the round trip through a trusted copy.
	data, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseProject(data)
	if err != nil || !back.Equal(p) {
		t.Fatalf("round trip: %v\n%s", err, data)
	}
}

func TestParseSchemaNothingToServe(t *testing.T) {
	for name, schema := range map[string]string{
		"no initOp":     "KEY=op(\"op://Dev/Item/field\")\n",
		"no app auth":   "# @initOp(token=$T, account=a.example)\n# ---\nKEY=op(\"op://Dev/Item/field\")\n",
		"no account":    "# @initOp(allowAppAuth=true)\n# ---\nKEY=op(\"op://Dev/Item/field\")\n",
		"connect":       "# @initOp(allowAppAuth=true, account=a, connectHost=\"http://x\")\nKEY=op(\"op://V/I/f\")\n",
		"allowMissing":  "# @initOp(allowAppAuth=true, account=a.example)\nKEY=op(\"op://V/I/f\", allowMissing=true)\n",
		"no op items":   "# @initOp(allowAppAuth=true, account=a.example)\nKEY=value\n",
		"literal token": "# @initOp(token=\"ops_x\", allowAppAuth=true, account=a.example)\nKEY=op(\"op://V/I/f\")\n",
	} {
		t.Run(name, func(t *testing.T) {
			p, notes, err := ParseSchema("x", []byte(schema))
			if err != nil {
				t.Fatal(err)
			}
			if p.Name != "x" || len(p.Secrets) != 0 {
				t.Fatalf("got %+v", p)
			}
			if strings.Contains(schema, "op(") && len(notes) == 0 {
				t.Fatal("no note for the item left to varlock")
			}
		})
	}
}

func TestSchemaProjectName(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "My.Repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git", "worktrees", "wt"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(repo, SchemaFile), "")
	writeFile(t, filepath.Join(repo, "services", "api", SchemaFile), "")

	// A linked worktree: .git is a file that points into the main repository.
	wt := filepath.Join(base, "elsewhere", "feature-x")
	writeFile(t, filepath.Join(wt, ".git"), "gitdir: "+filepath.Join(repo, ".git", "worktrees", "wt")+"\n")
	writeFile(t, filepath.Join(repo, ".git", "worktrees", "wt", "commondir"), "../..\n")
	writeFile(t, filepath.Join(repo, ".git", "worktrees", "wt", "gitdir"), filepath.Join(wt, ".git")+"\n")
	writeFile(t, filepath.Join(wt, SchemaFile), "")

	// Directories with a .git file that the repository did not register.
	forged := map[string]string{
		"to the repository": filepath.Join(repo, ".git"),
		"to its worktree":   filepath.Join(repo, ".git", "worktrees", "wt"),
	}
	for label, target := range forged {
		dir := filepath.Join(base, "forged", strings.ReplaceAll(label, " ", "-"), "My.Repo")
		writeFile(t, filepath.Join(dir, ".git"), "gitdir: "+target+"\n")
		writeFile(t, filepath.Join(dir, SchemaFile), "")
		forged[label] = dir
	}

	// Another repository with the same name.
	twin := filepath.Join(base, "fork", "My.Repo")
	if err := os.MkdirAll(filepath.Join(twin, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(twin, SchemaFile), "")

	writeFile(t, filepath.Join(base, "loose", SchemaFile), "")
	long := filepath.Join(base, strings.Repeat("a", 70))
	writeFile(t, filepath.Join(long, SchemaFile), "")

	name := func(path string) string {
		t.Helper()
		n := SchemaProjectName(path)
		if !ValidName(n) {
			t.Fatalf("%s: invalid name %q", path, n)
		}
		return n
	}
	main := name(filepath.Join(repo, SchemaFile))
	for path, prefix := range map[string]string{
		filepath.Join(repo, SchemaFile):                    "my-repo-",
		filepath.Join(repo, "services", "api", SchemaFile): "my-repo-services-api-",
		filepath.Join(twin, SchemaFile):                    "my-repo-",
		filepath.Join(base, "loose", SchemaFile):           "loose-",
		filepath.Join(long, SchemaFile):                    "aaaa",
	} {
		if got := name(path); !strings.HasPrefix(got, prefix) {
			t.Errorf("%s: got %q, want the prefix %q", path, got, prefix)
		}
	}
	if got := name(filepath.Join(wt, SchemaFile)); got != main {
		t.Errorf("worktree: got %q, want %q", got, main)
	}
	if got := name(filepath.Join(twin, SchemaFile)); got == main {
		t.Errorf("another repository with the same name shares %q", got)
	}
	for label, dir := range forged {
		if got := name(filepath.Join(dir, SchemaFile)); got == main {
			t.Errorf("a .git file %s shares %q", label, got)
		}
	}
}

func TestSchemaOverrides(t *testing.T) {
	noEnv := func(string) (string, bool) { return "", false }
	keys := func(m map[string]bool) string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}

	dir := t.TempDir()
	schema := filepath.Join(dir, SchemaFile)
	writeFile(t, schema, "APP_KEY=op(\"op://V/I/f\")\n")
	writeFile(t, filepath.Join(dir, ".env"), "# mine\nAPP_KEY=local-value\nexport OTHER=1\n")
	writeFile(t, filepath.Join(dir, ".env.local"), "LOCAL_ONLY=1\n")
	writeFile(t, filepath.Join(dir, ".env.production"), "PROD_ONLY=1\n")
	if got := keys(SchemaOverrides(schema, noEnv)); got != "APP_KEY,LOCAL_ONLY,OTHER" {
		t.Fatalf("without env flag: %s", got)
	}

	// With an environment flag, the files of the current environment count.
	writeFile(t, schema, "# @currentEnv=$APP_ENV\n# ---\nAPP_ENV=production\n")
	if got := keys(SchemaOverrides(schema, noEnv)); got != "APP_KEY,LOCAL_ONLY,OTHER,PROD_ONLY" {
		t.Fatalf("static env: %s", got)
	}
	staging := func(k string) (string, bool) { return "staging", k == "APP_ENV" }
	if got := keys(SchemaOverrides(schema, staging)); got != "APP_KEY,LOCAL_ONLY,OTHER" {
		t.Fatalf("env from the process: %s", got)
	}
	// An environment sefko cannot tell: every .env.* file counts.
	writeFile(t, schema, "# @currentEnv=$APP_ENV\n# ---\nAPP_ENV=fallback($X, dev)\n")
	writeFile(t, filepath.Join(dir, ".env.example"), "EXAMPLE=1\n")
	if got := keys(SchemaOverrides(schema, noEnv)); got != "APP_KEY,LOCAL_ONLY,OTHER,PROD_ONLY" {
		t.Fatalf("unknown env: %s", got)
	}
	// varlock reads .env.local before it picks the environment, and .env.local
	// wins over the schema.
	writeFile(t, schema, "# @currentEnv=$APP_ENV\n# ---\nAPP_ENV=dev\n")
	writeFile(t, filepath.Join(dir, ".env.dev"), "DEV_ONLY=1\n")
	writeFile(t, filepath.Join(dir, ".env.local"), "LOCAL_ONLY=1\nAPP_ENV=production # mine\n")
	if got := keys(SchemaOverrides(schema, noEnv)); got != "APP_ENV,APP_KEY,LOCAL_ONLY,OTHER,PROD_ONLY" {
		t.Fatalf("env with a comment in .env.local: %s", got)
	}
	// An empty KEY= is no value: varlock takes the one below it.
	writeFile(t, filepath.Join(dir, ".env.local"), "LOCAL_ONLY=1\nAPP_ENV=\n")
	if got := keys(SchemaOverrides(schema, noEnv)); got != "APP_ENV,APP_KEY,DEV_ONLY,LOCAL_ONLY,OTHER" {
		t.Fatalf("empty env in .env.local: %s", got)
	}
	writeFile(t, filepath.Join(dir, ".env.local"), "LOCAL_ONLY=1\nAPP_ENV=$(whoami)\n")
	if got := keys(SchemaOverrides(schema, noEnv)); got != "APP_ENV,APP_KEY,DEV_ONLY,LOCAL_ONLY,OTHER,PROD_ONLY" {
		t.Fatalf("computed env in .env.local: %s", got)
	}
	writeFile(t, filepath.Join(dir, ".env.local"), "LOCAL_ONLY=1\nAPP_ENV=\"production\"\n")
	if got := keys(SchemaOverrides(schema, noEnv)); got != "APP_ENV,APP_KEY,LOCAL_ONLY,OTHER,PROD_ONLY" {
		t.Fatalf("env from .env.local: %s", got)
	}
	writeFile(t, filepath.Join(dir, ".env.local"), "LOCAL_ONLY=1\n")
	writeFile(t, filepath.Join(dir, ".env"), "APP_ENV=production\n")
	if got := keys(SchemaOverrides(schema, noEnv)); got != "APP_ENV,LOCAL_ONLY,PROD_ONLY" {
		t.Fatalf("env from .env: %s", got)
	}
}

func TestSchemaOverridesToken(t *testing.T) {
	const head = "# @initOp(token=$OP_TOKEN, allowAppAuth=true, account=a.example)\n" +
		"# @initOp(id=app, allowAppAuth=true, account=a.example)\n"
	const items = "KEY=op(\"op://V/I/f\")\nAPP=op(app, \"op://V/A/f\")\n"
	const envHead = "# @currentEnv=$APP_ENV\n" + head + "APP_ENV=prod\n"
	noEnv := func(string) (string, bool) { return "", false }
	withToken := func(k string) (string, bool) { return "ops_x", k == "OP_TOKEN" }
	emptyToken := func(k string) (string, bool) { return "", k == "OP_TOKEN" }

	for name, tc := range map[string]struct {
		schema string
		files  map[string]string
		env    func(string) (string, bool)
		want   bool
	}{
		"no token anywhere":      {head + "OP_TOKEN=\n" + items, nil, noEnv, false},
		"empty in environment":   {head + items, nil, emptyToken, false},
		"in the environment":     {head + items, nil, withToken, true},
		"in .env.local":          {head + items, map[string]string{".env.local": "OP_TOKEN=ops_x\n"}, noEnv, true},
		"no value in .env.local": {head + items, map[string]string{".env.local": "OP_TOKEN=\n"}, noEnv, false},
		"value in the schema":    {head + "OP_TOKEN=op(\"op://V/T/f\")\n" + items, nil, noEnv, true},
		"with braces in schema":  {strings.Replace(head, "$OP_TOKEN", "${OP_TOKEN}", 1) + items, nil, withToken, true},

		// The definition that varlock prefers decides; KEY= is no definition.
		"schema, cleared by .env.local":    {head + "OP_TOKEN=ops_x\n" + items, map[string]string{".env.local": "OP_TOKEN=\"\"\n"}, noEnv, false},
		"schema, KEY= in .env.local":       {head + "OP_TOKEN=ops_x\n" + items, map[string]string{".env.local": "OP_TOKEN=\n"}, noEnv, true},
		".env, cleared by .env.local":      {head + items, map[string]string{".env": "OP_TOKEN=ops_x\n", ".env.local": "OP_TOKEN=\"\"\n"}, noEnv, false},
		".env.local, cleared by .env.prod": {envHead + items, map[string]string{".env.local": "OP_TOKEN=ops_x\n", ".env.prod": "OP_TOKEN=''\n"}, noEnv, false},
		".env cleared, set by .env.local":  {head + items, map[string]string{".env": "OP_TOKEN=\"\"\n", ".env.local": "OP_TOKEN=ops_x # ci\n"}, noEnv, true},
		// An environment that sefko cannot tell: any value counts.
		"in some environment": {strings.Replace(envHead, "APP_ENV=prod", "APP_ENV=fallback($X, prod)", 1) + items,
			map[string]string{".env.staging": "OP_TOKEN=ops_x\n", ".env.local": "OP_TOKEN=\"\"\n"}, noEnv, true},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			schema := filepath.Join(dir, SchemaFile)
			writeFile(t, schema, tc.schema)
			for f, data := range tc.files {
				writeFile(t, filepath.Join(dir, f), data)
			}
			got := SchemaOverrides(schema, tc.env)
			if got["KEY"] != tc.want {
				t.Fatalf("KEY left to varlock: %v, want %v", got["KEY"], tc.want)
			}
			if got["APP"] {
				t.Fatal("an instance without a token was left to varlock")
			}
		})
	}
}

func TestVarlockSchema(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, SchemaFile), "")
	sub := filepath.Join(root, "packages", "web")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	check := func(name, pkg string, want string) {
		t.Helper()
		if pkg == "" {
			_ = os.Remove(filepath.Join(sub, "package.json"))
		} else {
			writeFile(t, filepath.Join(sub, "package.json"), pkg)
		}
		got, ok := VarlockSchema(sub)
		if got != want || ok != (want != "") {
			t.Errorf("%s: got %q %v, want %q", name, got, ok, want)
		}
	}
	check("no schema here", "", "")
	check("loadPath", `{"varlock": {"loadPath": "../../"}}`, filepath.Join(root, SchemaFile))
	check("one loadPath in a list", `{"varlock": {"loadPath": ["../.."]}}`, filepath.Join(root, SchemaFile))
	check("two loadPaths", `{"varlock": {"loadPath": ["../..", "."]}}`, "")
	check("loadPath to the schema", `{"varlock": {"loadPath": "../../.env.schema"}}`, filepath.Join(root, SchemaFile))
	writeFile(t, filepath.Join(root, ".env.prod"), "")
	check("loadPath to another file", `{"varlock": {"loadPath": "../../.env.prod"}}`, "")
	check("missing loadPath", `{"varlock": {"loadPath": "../nope"}}`, "")
	check("no varlock key", `{"name": "web"}`, "")
	writeFile(t, filepath.Join(sub, SchemaFile), "")
	check("own schema", "", filepath.Join(sub, SchemaFile))
	check("empty loadPath", `{"varlock": {"loadPath": ""}}`, filepath.Join(sub, SchemaFile))
	check("broken package.json", `{"varlock": `, filepath.Join(sub, SchemaFile))
	check("loadPath elsewhere", `{"varlock": {"loadPath": "../.."}}`, filepath.Join(root, SchemaFile))
}

func TestFindProjectSchema(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, SchemaFile), "")
	deep := filepath.Join(root, "a")
	writeFile(t, filepath.Join(deep, "b", SchemaFile), "")
	if got, err := FindProject(deep); err != nil || got != filepath.Join(root, SchemaFile) {
		t.Fatalf("got %q, %v", got, err)
	}
	writeFile(t, filepath.Join(root, ProjectFile), sampleProject)
	if got, err := FindProject(deep); err != nil || got != filepath.Join(root, ProjectFile) {
		t.Fatalf("project file must win in the same directory: %q, %v", got, err)
	}
}
