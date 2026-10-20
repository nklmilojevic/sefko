package secmem

import (
	"bytes"
	"testing"
)

func TestFromBytesCopiesAndZeroesSource(t *testing.T) {
	src := []byte("ghp_secret")
	b, err := FromBytes(src)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Free()
	if string(b.Bytes()) != "ghp_secret" {
		t.Fatalf("got %q", b.Bytes())
	}
	if !bytes.Equal(src, make([]byte, len(src))) {
		t.Fatalf("source not zeroed: %q", src)
	}
	if b.Cap() < pageSize {
		t.Fatalf("expected page-sized allocation, got %d", b.Cap())
	}
}

func TestWipeZeroesWholeRegion(t *testing.T) {
	b, err := FromBytes([]byte("ghp_secret"))
	if err != nil {
		t.Fatal(err)
	}
	raw := b.Raw()
	b.Wipe()
	if !bytes.Equal(raw, make([]byte, len(raw))) {
		t.Fatal("region not zeroed")
	}
	if b.Len() != 0 {
		t.Fatal("length not reset")
	}
	b.Free()
	b.Free()
}

func TestNewRejectsZero(t *testing.T) {
	if _, err := New(0); err == nil {
		t.Fatal("expected error")
	}
}
