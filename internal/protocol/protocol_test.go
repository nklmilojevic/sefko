package protocol

import (
	"encoding/json"
	"testing"
)

func TestEncodeValueRoundTrips(t *testing.T) {
	for _, v := range []string{"", "ghp_abc", `quo"te\back`, "tab\tnl\nctl\x01", "ünïcode"} {
		dst := make([]byte, MaxValueResponse(len(v)))
		n := EncodeValue(dst, []byte(v))
		var r Response
		if err := json.Unmarshal(dst[:n], &r); err != nil {
			t.Fatalf("%q: %v (%s)", v, err, dst[:n])
		}
		if !r.OK || r.Value != v {
			t.Fatalf("%q: got %+v", v, r)
		}
		if dst[n-1] != '\n' {
			t.Fatalf("%q: missing newline", v)
		}
	}
}

func TestEncodeValueWorstCaseFits(t *testing.T) {
	v := make([]byte, 64)
	dst := make([]byte, MaxValueResponse(len(v)))
	if n := EncodeValue(dst, v); n != len(dst) {
		t.Fatalf("worst case: wrote %d of %d", n, len(dst))
	}
}

func TestDefaultSocketPath(t *testing.T) {
	t.Setenv("SEFKO_SOCK", "/s.sock")
	if DefaultSocketPath() != "/s.sock" {
		t.Fatal("override ignored")
	}
}
