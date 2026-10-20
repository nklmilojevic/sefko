// Package agent implements the sefko daemon: an in-memory cache of
// allowlisted 1Password secrets served over a Unix socket.
package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/nklmilojevic/sefko/internal/config"
	"github.com/nklmilojevic/sefko/internal/opread"
	"github.com/nklmilojevic/sefko/internal/platform"
	"github.com/nklmilojevic/sefko/internal/protocol"
	"github.com/nklmilojevic/sefko/internal/secmem"
)

const (
	recentSize   = 50
	gapThreshold = 5 * time.Minute
)

var (
	errNotAllowed = errors.New("not in the allowlist")
	errWiped      = errors.New("secrets were wiped while fetching; retry")
)

// ReadFunc fetches one secret from 1Password.
type ReadFunc func(ctx context.Context, opPath, account, ref string) ([]byte, error)

type Options struct {
	ConfigPath string
	Peers      platform.PeerInspector
	Sleep      platform.SleepNotifier
	Log        platform.Logger
	HTTPClient *http.Client
	Read       ReadFunc
	// Now drives TTLs and validation rate limits.
	Now func() time.Time

	TickInterval   time.Duration // TTL sweep and clock-gap check, default 30s
	ReloadInterval time.Duration // config file polling, default 2s
	ValidateEvery  time.Duration // validation rate limit, default 60s
}

type entry struct {
	buf           *secmem.Buffer
	fetchedAt     time.Time
	hits          int
	lastRequester string
}

type validation struct {
	at     time.Time
	result string
}

type Agent struct {
	opts    Options
	uid     int
	started time.Time
	group   singleflight.Group

	mu          sync.Mutex
	cfg         *config.Config
	cfgHash     [32]byte
	entries     map[string]*entry
	epoch       map[string]uint64
	globalEpoch uint64
	validations map[string]validation
	recent      []protocol.Event
	mlockFailed bool
}

// New loads the config and prepares an agent. An invalid config is fatal
// here; later reloads keep the last good config instead.
func New(opts Options) (*Agent, error) {
	if opts.Peers == nil || opts.Sleep == nil || opts.Log == nil {
		peers, sleep, log := platform.Default()
		opts.Peers = cmpOr(opts.Peers, peers)
		opts.Sleep = cmpOr(opts.Sleep, sleep)
		opts.Log = cmpOr(opts.Log, log)
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if opts.Read == nil {
		opts.Read = opread.Read
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	opts.TickInterval = cmpOr(opts.TickInterval, 30*time.Second)
	opts.ReloadInterval = cmpOr(opts.ReloadInterval, 2*time.Second)
	opts.ValidateEvery = cmpOr(opts.ValidateEvery, time.Minute)

	data, err := os.ReadFile(opts.ConfigPath)
	if err != nil {
		return nil, err
	}
	cfg, err := config.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", opts.ConfigPath, err)
	}
	return &Agent{
		opts:        opts,
		uid:         os.Getuid(),
		started:     opts.Now(),
		cfg:         cfg,
		cfgHash:     sha256.Sum256(data),
		entries:     map[string]*entry{},
		epoch:       map[string]uint64{},
		validations: map[string]validation{},
	}, nil
}

func cmpOr[T comparable](v, fallback T) T {
	var zero T
	if v == zero {
		return fallback
	}
	return v
}

func (a *Agent) now() time.Time { return a.opts.Now() }

// epochKey changes whenever the entry for name, or every entry, is wiped. A
// fetch that started under an older key must not populate the cache.
func (a *Agent) epochKey(name string) uint64 { return a.globalEpoch + a.epoch[name] }

func (a *Agent) expired(e *entry) bool {
	return !a.now().Before(e.fetchedAt.Add(a.cfg.TTLDuration()))
}

// dropLocked wipes one entry. a.mu must be held.
func (a *Agent) dropLocked(name string) {
	if e := a.entries[name]; e != nil {
		e.buf.Free()
		delete(a.entries, name)
	}
	a.epoch[name]++
	a.group.Forget(name)
}

func (a *Agent) drop(name string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.dropLocked(name)
	delete(a.validations, name)
}

// WipeAll drops every cached secret.
func (a *Agent) WipeAll(reason string) {
	a.mu.Lock()
	n := len(a.entries)
	for name, e := range a.entries {
		e.buf.Free()
		delete(a.entries, name)
	}
	a.globalEpoch++
	for _, name := range a.cfg.Names() {
		a.group.Forget(name)
	}
	clear(a.validations)
	a.mu.Unlock()
	a.opts.Log.Info(fmt.Sprintf("wiped %d secret(s): %s", n, reason))
}

// Sweep drops entries whose TTL has passed.
func (a *Agent) Sweep() {
	a.mu.Lock()
	var expired []string
	for name, e := range a.entries {
		if a.expired(e) {
			a.dropLocked(name)
			expired = append(expired, name)
		}
	}
	a.mu.Unlock()
	for _, name := range expired {
		a.opts.Log.Info("expired: " + name)
	}
}

// Reload re-reads the config file. An invalid file is logged and ignored.
// Entries whose ref or account changed, or that were removed, are wiped.
func (a *Agent) Reload() error {
	data, err := os.ReadFile(a.opts.ConfigPath)
	if err != nil {
		a.opts.Log.Error("config reload: " + err.Error())
		return err
	}
	sum := sha256.Sum256(data)
	a.mu.Lock()
	unchanged := sum == a.cfgHash
	a.mu.Unlock()
	if unchanged {
		return nil
	}
	cfg, err := config.Parse(data)
	if err != nil {
		a.opts.Log.Error(fmt.Sprintf("config reload: %v; keeping the previous config", err))
		return err
	}
	a.mu.Lock()
	for _, name := range a.cfg.Names() {
		old := a.cfg.Secrets[name]
		cur, ok := cfg.Secrets[name]
		if !ok || !cur.SameSource(old) {
			a.dropLocked(name)
		}
		delete(a.validations, name)
	}
	a.cfg = cfg
	a.cfgHash = sum
	a.mu.Unlock()
	a.opts.Log.Info("config reloaded")
	return nil
}

// fetch reads name from 1Password into the cache. Concurrent callers share one
// op invocation.
func (a *Agent) fetch(name string) error {
	_, err, _ := a.group.Do(name, func() (any, error) {
		a.mu.Lock()
		sec, ok := a.cfg.Secrets[name]
		key := a.epochKey(name)
		opPath, timeout := a.cfg.OpPath, a.cfg.FetchTimeoutDuration()
		a.mu.Unlock()
		if !ok {
			return nil, errNotAllowed
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		raw, err := a.opts.Read(ctx, opPath, sec.Account, sec.Ref)
		if err != nil {
			return nil, err
		}
		buf, err := secmem.FromBytes(raw)
		if err != nil {
			clear(raw)
			return nil, err
		}

		a.mu.Lock()
		defer a.mu.Unlock()
		cur, ok := a.cfg.Secrets[name]
		if !ok || !cur.SameSource(sec) || a.epochKey(name) != key {
			buf.Free()
			return nil, errWiped
		}
		if !buf.Locked() && !a.mlockFailed {
			a.mlockFailed = true
			a.opts.Log.Error("mlock failed; secrets may be swapped to disk")
		}
		if old := a.entries[name]; old != nil {
			old.buf.Free()
		}
		a.entries[name] = &entry{buf: buf, fetchedAt: a.now()}
		return nil, nil
	})
	return err
}

// withValue calls fn with the cached value of name, fetching it first if
// needed. fn runs under the agent lock and must not retain the slice.
func (a *Agent) withValue(name, requester string, fn func([]byte) error) (fetched bool, err error) {
	for range 3 {
		done, err := a.useCached(name, requester, fn)
		if err != nil || done {
			return fetched, err
		}
		if err := a.fetch(name); err != nil {
			if errors.Is(err, errWiped) {
				continue
			}
			return fetched, err
		}
		fetched = true
	}
	return fetched, errWiped
}

func (a *Agent) useCached(name, requester string, fn func([]byte) error) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.cfg.Secrets[name]; !ok {
		return false, errNotAllowed
	}
	e := a.entries[name]
	if e == nil {
		return false, nil
	}
	if a.expired(e) {
		a.dropLocked(name)
		return false, nil
	}
	e.hits++
	e.lastRequester = requester
	return true, fn(e.buf.Bytes())
}

// encodedValue returns a complete get response in locked memory. The caller
// must Free it.
func (a *Agent) encodedValue(name, requester string) (*secmem.Buffer, bool, error) {
	var out *secmem.Buffer
	fetched, err := a.withValue(name, requester, func(v []byte) error {
		b, err := secmem.New(protocol.MaxValueResponse(len(v)))
		if err != nil {
			return err
		}
		b.SetLen(protocol.EncodeValue(b.Raw(), v))
		out = b
		return nil
	})
	return out, fetched, err
}

func (a *Agent) allowed(name string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.cfg.Secrets[name]
	return ok
}

// validate checks the cached value against the configured endpoint. On a 401
// it refreshes the entry.
func (a *Agent) validate(name, requester string) (string, error) {
	a.mu.Lock()
	sec, ok := a.cfg.Secrets[name]
	if !ok {
		a.mu.Unlock()
		return "", errNotAllowed
	}
	if sec.Validate == nil {
		a.mu.Unlock()
		return protocol.ResultUnknown, nil
	}
	if v, ok := a.validations[name]; ok && a.now().Sub(v.at) < a.opts.ValidateEvery {
		a.mu.Unlock()
		return v.result, nil
	}
	a.mu.Unlock()

	var header string
	if _, err := a.withValue(name, requester, func(v []byte) error {
		header = sec.Validate.HeaderValue(v)
		return nil
	}); err != nil {
		return "", err
	}
	result := a.probe(sec.Validate, header)
	header = ""

	record := result
	if result == protocol.ResultInvalidRefreshed {
		a.drop(name)
		if _, err := a.withValue(name, requester, func([]byte) error { return nil }); err != nil {
			return "", err
		}
		// The fresh value has not been checked yet.
		record = protocol.ResultUnknown
	}
	a.mu.Lock()
	a.validations[name] = validation{at: a.now(), result: record}
	a.mu.Unlock()
	return result, nil
}

func (a *Agent) probe(v *config.Validate, header string) string {
	req, err := http.NewRequest(http.MethodGet, v.URL, nil)
	if err != nil {
		return protocol.ResultUnknown
	}
	req.Header.Set(v.Header, header)
	req.Header.Set("User-Agent", "sefko")
	resp, err := a.opts.HTTPClient.Do(req)
	if err != nil {
		a.opts.Log.Info("validate: request failed: " + err.Error())
		return protocol.ResultUnknown
	}
	_ = resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return protocol.ResultValid
	case resp.StatusCode == http.StatusUnauthorized:
		return protocol.ResultInvalidRefreshed
	default:
		return protocol.ResultUnknown
	}
}

func (a *Agent) status() *protocol.Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := &protocol.Status{
		PID:        os.Getpid(),
		Started:    a.started,
		ConfigPath: a.opts.ConfigPath,
		TTL:        a.cfg.TTLDuration().String(),
		MemLocked:  !a.mlockFailed,
		Recent:     append([]protocol.Event(nil), a.recent...),
	}
	for _, name := range a.cfg.Names() {
		en := protocol.Entry{Name: name, Ref: a.cfg.Secrets[name].Ref}
		if e := a.entries[name]; e != nil && !a.expired(e) {
			fetched, expires := e.fetchedAt, e.fetchedAt.Add(a.cfg.TTLDuration())
			en.Cached = true
			en.FetchedAt, en.ExpiresAt = &fetched, &expires
			en.Hits = e.hits
			en.LastRequester = e.lastRequester
		}
		s.Entries = append(s.Entries, en)
	}
	return s
}

func (a *Agent) names() []protocol.Name {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]protocol.Name, 0, len(a.cfg.Secrets))
	for _, name := range a.cfg.Names() {
		out = append(out, protocol.Name{Name: name, Env: a.cfg.Secrets[name].Env})
	}
	return out
}

func (a *Agent) audit(ev protocol.Event) {
	a.mu.Lock()
	a.recent = append(a.recent, ev)
	if len(a.recent) > recentSize {
		a.recent = a.recent[len(a.recent)-recentSize:]
	}
	a.mu.Unlock()
	a.opts.Log.Audit(fmt.Sprintf("op=%s name=%s pid=%d exe=%q result=%s latency_ms=%d detail=%q",
		ev.Op, ev.Name, ev.PID, ev.Exe, ev.Result, ev.LatencyMS, ev.Detail))
}

// gapExceeded reports whether the wall clock advanced much further than the
// monotonic clock, which on macOS stops while the system sleeps.
func gapExceeded(wall, mono time.Duration) bool {
	return wall-mono > gapThreshold
}
