// Package secmem holds secret bytes in anonymous mmap'd pages outside the Go
// heap, locked into RAM where the system allows it, and zeroed on release.
package secmem

import (
	"errors"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// Buffer is a fixed-size region of locked memory. The zero value is not
// usable; create one with New or FromBytes.
type Buffer struct {
	mu     sync.Mutex
	mem    []byte
	n      int
	locked bool
}

var pageSize = os.Getpagesize()

// New allocates at least size bytes. Locking failures are not fatal; check
// Locked.
func New(size int) (*Buffer, error) {
	if size <= 0 {
		return nil, errors.New("secmem: size must be positive")
	}
	alloc := (size + pageSize - 1) / pageSize * pageSize
	mem, err := unix.Mmap(-1, 0, alloc, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return nil, err
	}
	b := &Buffer{mem: mem}
	b.locked = unix.Mlock(mem) == nil
	return b, nil
}

// FromBytes copies src into a new buffer and zeroes src.
func FromBytes(src []byte) (*Buffer, error) {
	defer clear(src)
	b, err := New(max(len(src), 1))
	if err != nil {
		return nil, err
	}
	b.n = copy(b.mem, src)
	return b, nil
}

// Bytes returns the live contents. The slice is invalid after Free.
func (b *Buffer) Bytes() []byte { return b.mem[:b.n] }

// Cap returns the usable size of the buffer.
func (b *Buffer) Cap() int { return len(b.mem) }

func (b *Buffer) Len() int { return b.n }

// SetLen marks the first n bytes as content, for callers that write through
// Raw.
func (b *Buffer) SetLen(n int) { b.n = n }

// Raw exposes the whole region for writing.
func (b *Buffer) Raw() []byte { return b.mem }

func (b *Buffer) Locked() bool { return b.locked }

// Wipe zeroes the whole region.
func (b *Buffer) Wipe() {
	clear(b.mem)
	b.n = 0
}

// Free wipes, unlocks and unmaps the region. It is safe to call more than once.
func (b *Buffer) Free() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.mem == nil {
		return
	}
	b.Wipe()
	if b.locked {
		_ = unix.Munlock(b.mem)
	}
	_ = unix.Munmap(b.mem)
	b.mem = nil
}
