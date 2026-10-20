// Package protocol defines the line-delimited JSON spoken over the agent
// socket: one request line, one response line, then close.
package protocol

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	Version        = 1
	MaxRequestSize = 4 << 10
)

// Operations.
const (
	OpGet      = "get"
	OpRefresh  = "refresh"
	OpValidate = "validate"
	OpLock     = "lock"
	OpStatus   = "status"
	OpNames    = "names"
)

// Error codes.
const (
	CodeNotAllowed = "not_allowed"
	CodeOpFailed   = "op_failed"
	CodeOpTimeout  = "op_timeout"
	CodeBadRequest = "bad_request"
	CodeVersion    = "version"
	CodeInternal   = "internal"
)

// Validation results.
const (
	ResultValid            = "valid"
	ResultInvalidRefreshed = "invalid-refreshed"
	ResultUnknown          = "unknown"
)

type Request struct {
	V    int    `json:"v"`
	Op   string `json:"op"`
	Name string `json:"name,omitempty"`
}

type Response struct {
	OK      bool    `json:"ok"`
	Value   string  `json:"value,omitempty"`
	Result  string  `json:"result,omitempty"`
	Status  *Status `json:"status,omitempty"`
	Names   []Name  `json:"names,omitempty"`
	Code    string  `json:"code,omitempty"`
	Message string  `json:"message,omitempty"`
}

// Error is a failed response returned as a Go error.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e.Message == "" {
		return e.Code
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

type Name struct {
	Name string `json:"name"`
	Env  string `json:"env,omitempty"`
}

// Status never carries secret values.
type Status struct {
	PID        int       `json:"pid"`
	Started    time.Time `json:"started"`
	ConfigPath string    `json:"config_path"`
	TTL        string    `json:"ttl"`
	MemLocked  bool      `json:"mem_locked"`
	Entries    []Entry   `json:"entries"`
	Recent     []Event   `json:"recent"`
}

type Entry struct {
	Name          string     `json:"name"`
	Ref           string     `json:"ref"`
	Cached        bool       `json:"cached"`
	FetchedAt     *time.Time `json:"fetched_at,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	Hits          int        `json:"hits"`
	LastRequester string     `json:"last_requester,omitempty"`
}

// Event is one audited request.
type Event struct {
	Time      time.Time `json:"time"`
	Op        string    `json:"op"`
	Name      string    `json:"name,omitempty"`
	PID       int       `json:"pid"`
	Exe       string    `json:"exe,omitempty"`
	Result    string    `json:"result"`
	LatencyMS int64     `json:"latency_ms"`
	Detail    string    `json:"detail,omitempty"`
}

// DefaultSocketPath is $SEFKO_SOCK or ~/.local/state/sefko/agent.sock.
func DefaultSocketPath() string {
	if p := os.Getenv("SEFKO_SOCK"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "sefko", "agent.sock")
}

const valuePrefix, valueSuffix = `{"ok":true,"value":"`, "\"}\n"

// MaxValueResponse is the worst-case size of EncodeValue's output.
func MaxValueResponse(n int) int { return len(valuePrefix) + 6*n + len(valueSuffix) }

// EncodeValue writes a complete get response for value into dst, which must
// hold MaxValueResponse(len(value)) bytes, and returns the length written.
// It exists so the value is only ever copied into memory the caller controls.
func EncodeValue(dst, value []byte) int {
	const hex = "0123456789abcdef"
	n := copy(dst, valuePrefix)
	for _, c := range value {
		switch {
		case c == '"' || c == '\\':
			dst[n], dst[n+1] = '\\', c
			n += 2
		case c < 0x20:
			n += copy(dst[n:], `\u00`)
			dst[n], dst[n+1] = hex[c>>4], hex[c&0xf]
			n += 2
		default:
			dst[n] = c
			n++
		}
	}
	n += copy(dst[n:], valueSuffix)
	return n
}
