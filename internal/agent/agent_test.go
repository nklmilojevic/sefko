package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nklmilojevic/sefko/internal/client"
	"github.com/nklmilojevic/sefko/internal/fakeop"
	"github.com/nklmilojevic/sefko/internal/platform"
	"github.com/nklmilojevic/sefko/internal/protocol"
)

func TestMain(m *testing.M) {
	fakeop.Main()
	os.Exit(m.Run())
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type fakeSleep struct {
	mu sync.Mutex
	fn func()
}

func (s *fakeSleep) Start(fn func()) (func(), error) {
	s.mu.Lock()
	s.fn = fn
	s.mu.Unlock()
	return func() {}, nil
}

func (s *fakeSleep) Fire() {
	s.mu.Lock()
	fn := s.fn
	s.mu.Unlock()
	fn()
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type harness struct {
	t      *testing.T
	op     *fakeop.Fake
	agent  *Agent
	client *client.Client
	clock  *fakeClock
	sleep  *fakeSleep
	logs   *syncBuffer
	cfg    string
	sock   string
	cancel context.CancelFunc
	done   chan error
}

// shortDir keeps socket paths under the 104-byte sun_path limit.
func shortDir(t *testing.T) string {
	t.Helper()
	base := os.TempDir()
	if len(base) > 60 {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "sk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

const secretsTOML = `
[secrets.github]
ref = "op://Private/GitHub/token"
account = "acc.example"
env = "GH_TOKEN"

[secrets.restic]
ref = "op://Private/restic/password"
account = "acc.example"
`

func configText(opPath, extra string) string {
	return fmt.Sprintf("op_path = %q\n%s\n%s", opPath, extra, secretsTOML)
}

func start(t *testing.T, extra string, mutate ...func(*Options)) *harness {
	t.Helper()
	h := &harness{t: t, op: fakeop.Setup(t), clock: &fakeClock{t: time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)}, sleep: &fakeSleep{}, logs: &syncBuffer{}}
	dir := shortDir(t)
	h.cfg = filepath.Join(dir, "config.toml")
	h.writeConfig(configText(h.op.Path, extra))
	h.sock = filepath.Join(dir, "s", "agent.sock")

	opts := Options{
		ConfigPath:     h.cfg,
		Peers:          platform.NativePeers(),
		Sleep:          h.sleep,
		Log:            &platform.WriterLogger{W: h.logs},
		Now:            h.clock.Now,
		TickInterval:   time.Hour,
		ReloadInterval: time.Hour,
	}
	for _, m := range mutate {
		m(&opts)
	}
	a, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	h.agent = a
	h.client = client.New(h.sock)
	h.client.Timeout = 10 * time.Second
	h.listen()
	return h
}

func (h *harness) listen() {
	h.t.Helper()
	ln, err := Listen(h.sock)
	if err != nil {
		h.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.done = make(chan error, 1)
	go func() { h.done <- h.agent.Serve(ctx, ln) }()
	h.t.Cleanup(h.stop)
}

func (h *harness) stop() {
	if h.cancel == nil {
		return
	}
	h.cancel()
	h.cancel = nil
	select {
	case err := <-h.done:
		if err != nil {
			h.t.Errorf("serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		h.t.Error("agent did not stop")
	}
}

func (h *harness) writeConfig(s string) {
	h.t.Helper()
	if err := os.WriteFile(h.cfg, []byte(s), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) get(name string) string {
	h.t.Helper()
	v, err := h.client.Get(name)
	if err != nil {
		h.t.Fatalf("get %s: %v", name, err)
	}
	return v
}

func (h *harness) entry(name string) protocol.Entry {
	h.t.Helper()
	st, err := h.client.Status()
	if err != nil {
		h.t.Fatal(err)
	}
	for _, e := range st.Entries {
		if e.Name == name {
			return e
		}
	}
	h.t.Fatalf("no status entry for %s", name)
	return protocol.Entry{}
}

func codeOf(err error) string {
	var pe *protocol.Error
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

func TestGetFetchesOnceThenServesFromCache(t *testing.T) {
	h := start(t, "")
	for range 3 {
		if v := h.get("github"); v != "value-of:op://Private/GitHub/token" {
			t.Fatalf("got %q", v)
		}
	}
	if calls := h.op.Calls(); len(calls) != 1 || calls[0] != "acc.example op://Private/GitHub/token" {
		t.Fatalf("calls: %q", calls)
	}
	e := h.entry("github")
	if !e.Cached || e.Hits != 3 || !strings.Contains(e.LastRequester, "[") {
		t.Fatalf("entry: %+v", e)
	}
	if !strings.Contains(h.logs.String(), "result=fetch") || !strings.Contains(h.logs.String(), "result=hit") {
		t.Fatalf("audit log: %s", h.logs)
	}
}

func TestConcurrentMissesShareOneFetch(t *testing.T) {
	h := start(t, "")
	h.op.SetDelay(300 * time.Millisecond)
	var wg sync.WaitGroup
	var failures atomic.Int32
	for range 20 {
		wg.Go(func() {
			if _, err := h.client.Get("github"); err != nil {
				failures.Add(1)
			}
		})
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("%d requests failed", failures.Load())
	}
	if n := len(h.op.Calls()); n != 1 {
		t.Fatalf("expected one fetch, got %d", n)
	}
}

func TestTTLExpiry(t *testing.T) {
	h := start(t, `ttl = "1h"`)
	h.get("github")
	h.clock.Advance(59 * time.Minute)
	h.get("github")
	if n := len(h.op.Calls()); n != 1 {
		t.Fatalf("refetched before TTL: %d", n)
	}
	h.clock.Advance(time.Minute)
	h.agent.Sweep()
	if h.entry("github").Cached {
		t.Fatal("sweep kept an expired entry")
	}
	h.get("github")
	if n := len(h.op.Calls()); n != 2 {
		t.Fatalf("expected refetch after TTL, got %d calls", n)
	}
	// Use does not extend the TTL.
	h.clock.Advance(30 * time.Minute)
	h.get("github")
	h.clock.Advance(30 * time.Minute)
	h.get("github")
	if n := len(h.op.Calls()); n != 3 {
		t.Fatalf("expected absolute TTL, got %d calls", n)
	}
}

func TestSleepWipesEverything(t *testing.T) {
	h := start(t, "")
	h.get("github")
	h.get("restic")
	h.sleep.Fire()
	if h.entry("github").Cached || h.entry("restic").Cached {
		t.Fatal("sleep did not wipe")
	}
	h.get("github")
	if n := len(h.op.Calls()); n != 3 {
		t.Fatalf("expected refetch after sleep, got %d", n)
	}
}

func TestGapExceeded(t *testing.T) {
	if gapExceeded(30*time.Second, 30*time.Second) {
		t.Fatal("no gap")
	}
	if !gapExceeded(2*time.Hour, 30*time.Second) {
		t.Fatal("two hours of wall time in 30s of monotonic time is a sleep")
	}
	if gapExceeded(-time.Hour, 30*time.Second) {
		t.Fatal("clock set backwards is not a sleep")
	}
}

func TestLockAndRefresh(t *testing.T) {
	h := start(t, "")
	valueFile := filepath.Join(t.TempDir(), "v")
	if err := os.WriteFile(valueFile, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.op.SetValueFile(valueFile)
	if v := h.get("github"); v != "old" {
		t.Fatal(v)
	}
	if err := os.WriteFile(valueFile, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if v := h.get("github"); v != "old" {
		t.Fatal("cache should still hold the old value")
	}
	v, err := h.client.Refresh("github")
	if err != nil || v != "new" {
		t.Fatalf("refresh: %q %v", v, err)
	}
	if err := h.client.Lock(); err != nil {
		t.Fatal(err)
	}
	if h.entry("github").Cached {
		t.Fatal("lock did not wipe")
	}
	if n := len(h.op.Calls()); n != 2 {
		t.Fatalf("calls: %d", n)
	}
}

func TestWipeDuringFetchRetries(t *testing.T) {
	h := start(t, "")
	h.op.SetDelay(400 * time.Millisecond)
	got := make(chan string, 1)
	go func() {
		v, _ := h.client.Get("github")
		got <- v
	}()
	time.Sleep(150 * time.Millisecond)
	h.sleep.Fire()
	if v := <-got; v != "value-of:op://Private/GitHub/token" {
		t.Fatalf("got %q", v)
	}
	if n := len(h.op.Calls()); n != 2 {
		t.Fatalf("expected the wiped fetch to be discarded and redone, got %d calls", n)
	}
}

func TestReload(t *testing.T) {
	h := start(t, "")
	h.get("github")
	h.get("restic")

	h.writeConfig(strings.Replace(configText(h.op.Path, ""), "op://Private/restic/password", "op://Private/restic2/password", 1))
	if err := h.agent.Reload(); err != nil {
		t.Fatal(err)
	}
	if !h.entry("github").Cached {
		t.Fatal("unchanged entry was wiped")
	}
	if h.entry("restic").Cached {
		t.Fatal("changed entry was kept")
	}
	if v := h.get("restic"); v != "value-of:op://Private/restic2/password" {
		t.Fatalf("restic: %q", v)
	}

	h.writeConfig("this is [ not toml")
	if err := h.agent.Reload(); err == nil {
		t.Fatal("invalid config accepted")
	}
	if !h.entry("github").Cached {
		t.Fatal("invalid reload wiped the cache")
	}
	h.get("github")

	h.writeConfig(fmt.Sprintf("op_path = %q\n", h.op.Path))
	if err := h.agent.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.Get("github"); codeOf(err) != protocol.CodeNotAllowed {
		t.Fatalf("removed alias still served: %v", err)
	}
	if n := len(h.op.Calls()); n != 3 {
		t.Fatalf("calls: %d", n)
	}
}

func TestOpFailureIsNotCached(t *testing.T) {
	h := start(t, "")
	h.op.SetExit(1, "[ERROR] 1Password is locked")
	_, err := h.client.Get("github")
	if codeOf(err) != protocol.CodeOpFailed || !strings.Contains(err.Error(), "1Password is locked") {
		t.Fatalf("got %v", err)
	}
	h.op.SetExit(0, "")
	h.get("github")
	if n := len(h.op.Calls()); n != 2 {
		t.Fatalf("calls: %d", n)
	}
}

func TestOpTimeout(t *testing.T) {
	h := start(t, `fetch_timeout = "200ms"`)
	h.op.SetDelay(3 * time.Second)
	if _, err := h.client.Get("github"); codeOf(err) != protocol.CodeOpTimeout {
		t.Fatalf("got %v", err)
	}
	if h.entry("github").Cached {
		t.Fatal("timeout cached something")
	}
}

func TestNotAllowedNeverCallsOp(t *testing.T) {
	h := start(t, "")
	for _, op := range []string{protocol.OpGet, protocol.OpRefresh, protocol.OpValidate} {
		_, err := h.client.Do(protocol.Request{Op: op, Name: "op://Private/Other/secret"})
		if codeOf(err) != protocol.CodeNotAllowed {
			t.Fatalf("%s: %v", op, err)
		}
	}
	if calls := h.op.Calls(); len(calls) != 0 {
		t.Fatalf("op called: %q", calls)
	}
	if !strings.Contains(h.logs.String(), "result=denied") {
		t.Fatal("denial not audited")
	}
}

func TestOtherUIDIsRefused(t *testing.T) {
	h := start(t, "")
	h.stop()
	h.agent.uid = os.Getuid() + 1
	h.listen()
	if _, err := h.client.Get("github"); err == nil {
		t.Fatal("served a different uid")
	}
	if len(h.op.Calls()) != 0 {
		t.Fatal("op called for refused peer")
	}
	if !strings.Contains(h.logs.String(), "result=denied") {
		t.Fatal("refusal not audited")
	}
	if !allowPeer(501, 501) || allowPeer(0, 501) {
		t.Fatal("allowPeer")
	}
}

func TestBadRequests(t *testing.T) {
	h := start(t, "")
	raw := func(line string) protocol.Response {
		c, err := net.Dial("unix", h.sock)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		if _, err := c.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
		var r protocol.Response
		if err := json.NewDecoder(c).Decode(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := raw("nonsense\n"); r.Code != protocol.CodeBadRequest {
		t.Fatalf("garbage: %+v", r)
	}
	if r := raw(`{"v":9,"op":"get","name":"github"}` + "\n"); r.Code != protocol.CodeVersion {
		t.Fatalf("version: %+v", r)
	}
	if r := raw(`{"v":1,"op":"dance"}` + "\n"); r.Code != protocol.CodeBadRequest {
		t.Fatalf("unknown op: %+v", r)
	}
	if r := raw(`{"v":1,"op":"get","name":"` + strings.Repeat("a", protocol.MaxRequestSize) + "\"}\n"); r.Code != protocol.CodeBadRequest {
		t.Fatalf("oversized: %+v", r)
	}
}

func TestAuditQuotesPeerFields(t *testing.T) {
	h := start(t, "")
	_, _ = h.client.Get("x\nop=lock result=ok")
	for line := range strings.SplitSeq(h.logs.String(), "\n") {
		if strings.HasPrefix(line, "op=lock") {
			t.Fatalf("forged audit line: %q", line)
		}
	}
}

func TestInvalidConfigLoggedOnce(t *testing.T) {
	h := start(t, "")
	h.writeConfig("not [ toml")
	for range 3 {
		_ = h.agent.Reload()
	}
	if n := strings.Count(h.logs.String(), "keeping the previous config"); n != 1 {
		t.Fatalf("logged %d times", n)
	}
}

func TestNames(t *testing.T) {
	h := start(t, "")
	names, err := h.client.Names()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 || names[0] != (protocol.Name{Name: "github", Env: "GH_TOKEN"}) || names[1].Name != "restic" {
		t.Fatalf("names: %+v", names)
	}
}

type validateServer struct {
	*httptest.Server
	code    atomic.Int32
	hits    atomic.Int32
	delay   atomic.Int64
	lastHdr atomic.Value
}

func newValidateServer(t *testing.T) *validateServer {
	s := &validateServer{}
	s.code.Store(200)
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.lastHdr.Store(r.Header.Get("Authorization"))
		time.Sleep(time.Duration(s.delay.Load()))
		w.WriteHeader(int(s.code.Load()))
	}))
	t.Cleanup(s.Close)
	return s
}

func startWithValidator(t *testing.T, srv *validateServer) *harness {
	h := start(t, "", func(o *Options) {
		o.HTTPClient = &http.Client{Timeout: 300 * time.Millisecond}
	})
	h.writeConfig(configText(h.op.Path, "") + fmt.Sprintf(`
[secrets.github.validate]
url = %q
header = "Authorization"
format = "Bearer {}"
`, srv.URL))
	if err := h.agent.Reload(); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestValidate(t *testing.T) {
	srv := newValidateServer(t)
	h := startWithValidator(t, srv)

	if r, err := h.client.Validate("github"); err != nil || r != protocol.ResultValid {
		t.Fatalf("valid: %q %v", r, err)
	}
	if hdr := srv.lastHdr.Load(); hdr != "Bearer value-of:op://Private/GitHub/token" {
		t.Fatalf("header: %v", hdr)
	}
	// Rate limited: within the window the last result is reused.
	if r, _ := h.client.Validate("github"); r != protocol.ResultValid || srv.hits.Load() != 1 {
		t.Fatalf("rate limit: %q hits=%d", r, srv.hits.Load())
	}

	h.clock.Advance(2 * time.Minute)
	srv.code.Store(401)
	if r, err := h.client.Validate("github"); err != nil || r != protocol.ResultInvalidRefreshed {
		t.Fatalf("401: %q %v", r, err)
	}
	if n := len(h.op.Calls()); n != 2 {
		t.Fatalf("401 should refetch, calls=%d", n)
	}
	// After a refresh the new value is unverified, so a quick retry reports unknown
	// instead of triggering another refresh.
	if r, _ := h.client.Validate("github"); r != protocol.ResultUnknown || len(h.op.Calls()) != 2 {
		t.Fatalf("after refresh: %q", r)
	}

	for _, code := range []int32{403, 500} {
		h.clock.Advance(2 * time.Minute)
		srv.code.Store(code)
		if r, _ := h.client.Validate("github"); r != protocol.ResultUnknown {
			t.Fatalf("%d: %q", code, r)
		}
	}

	h.clock.Advance(2 * time.Minute)
	srv.code.Store(200)
	srv.delay.Store(int64(time.Second))
	if r, _ := h.client.Validate("github"); r != protocol.ResultUnknown {
		t.Fatalf("timeout: %q", r)
	}

	if r, err := h.client.Validate("restic"); err != nil || r != protocol.ResultUnknown {
		t.Fatalf("no validator: %q %v", r, err)
	}
	if n := len(h.op.Calls()); n != 2 {
		t.Fatalf("calls: %d", n)
	}
}

func TestValueNeverInStatusOrLogs(t *testing.T) {
	srv := newValidateServer(t)
	h := startWithValidator(t, srv)
	h.op.SetValue("ghp_SuperSecretValue")
	h.get("github")
	_, _ = h.client.Validate("github")
	_, _ = h.client.Refresh("github")
	h.op.SetExit(1, "boom")
	_, _ = h.client.Refresh("github")
	st, err := h.client.Status()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(st)
	for name, s := range map[string]string{"status": string(b), "logs": h.logs.String()} {
		if strings.Contains(s, "SuperSecret") {
			t.Fatalf("%s leaked the value: %s", name, s)
		}
	}
}

func TestShutdownWipesAndRemovesSocket(t *testing.T) {
	h := start(t, "")
	h.get("github")
	h.stop()
	if _, err := os.Stat(h.sock); !os.IsNotExist(err) {
		t.Fatalf("socket left behind: %v", err)
	}
	if len(h.agent.entries) != 0 {
		t.Fatal("entries survived shutdown")
	}
	if _, err := h.client.Get("github"); !errors.Is(err, client.ErrUnreachable) {
		t.Fatalf("expected unreachable, got %v", err)
	}
}

func TestListenSafety(t *testing.T) {
	dir := shortDir(t)

	loose := filepath.Join(dir, "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(filepath.Join(loose, "a.sock")); err == nil || !strings.Contains(err.Error(), "0700") {
		t.Fatalf("loose dir: %v", err)
	}

	sockDir := filepath.Join(dir, "ok")
	notSock := filepath.Join(sockDir, "file")
	if err := os.Mkdir(sockDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(notSock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(notSock); err == nil {
		t.Fatal("replaced a regular file")
	}

	path := filepath.Join(sockDir, "a.sock")
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	_ = stale.Close()
	ln, err := Listen(path)
	if err != nil {
		t.Fatalf("stale socket: %v", err)
	}
	defer func() { _ = ln.Close() }()
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode: %v %v", fi.Mode(), err)
	}
	if _, err := Listen(path); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("live agent: %v", err)
	}
}
