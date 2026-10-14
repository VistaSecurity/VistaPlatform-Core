package bundlecrypt

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

// testParams keep the KDF cheap: the format, not Argon2id's cost, is under test.
func testParams() Params {
	return Params{Time: 1, MemoryKiB: minMemoryKiB, Threads: 1, ChunkSize: minChunk}
}

func encrypt(t *testing.T, plain, pass []byte, p Params) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := NewWriter(&out, pass, p)
	if err != nil {
		t.Fatal(err)
	}
	// Uneven writes so chunk boundaries do not line up with Write calls.
	for rest := plain; len(rest) > 0; {
		n := 333
		if n > len(rest) {
			n = len(rest)
		}
		if _, err := w.Write(rest[:n]); err != nil {
			t.Fatal(err)
		}
		rest = rest[n:]
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func decrypt(enc, pass []byte) ([]byte, error) {
	r, err := NewReader(bytes.NewReader(enc), pass)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func random(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRoundTrip(t *testing.T) {
	pass := []byte("correct horse battery staple")
	c := int(minChunk)
	for _, n := range []int{0, 1, c - 1, c, c + 1, 2 * c, 3*c + 7} {
		plain := random(t, n)
		enc := encrypt(t, plain, pass, testParams())
		got, err := decrypt(enc, pass)
		if err != nil {
			t.Fatalf("size %d: %v", n, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("size %d: round trip differs", n)
		}
		if bytes.Contains(enc, plain) && n > 16 {
			t.Fatalf("size %d: plaintext visible in the bundle", n)
		}
	}
}

func TestRoundTrip_DefaultParams(t *testing.T) {
	plain := random(t, 3<<20+5)
	got, err := decrypt(encrypt(t, plain, []byte("a long enough passphrase"), DefaultParams()), []byte("a long enough passphrase"))
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("default params round trip: %v", err)
	}
}

func TestWrongPassphrase(t *testing.T) {
	enc := encrypt(t, random(t, 5000), []byte("the right passphrase"), testParams())
	if _, err := decrypt(enc, []byte("the wrong passphrase")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("err = %v, want ErrWrongPassphrase", err)
	}
}

// A bundle cut short anywhere must fail — never decrypt to a shorter bundle
// that looks complete. Cutting exactly at a chunk boundary is the case a
// naive chunked format gets wrong.
func TestTruncated(t *testing.T) {
	pass := []byte("truncation passphrase")
	c := int(minChunk)
	enc := encrypt(t, random(t, 3*c+100), pass, testParams())
	chunkOnDisk := c + tagLen
	cuts := map[string]int{
		"inside the header":         headerLen - 3,
		"after the header":          headerLen,
		"inside the first chunk":    headerLen + 10,
		"at a chunk boundary":       headerLen + chunkOnDisk,
		"at the second boundary":    headerLen + 2*chunkOnDisk,
		"one byte short of the end": len(enc) - 1,
		"inside the final tag":      len(enc) - tagLen + 2,
	}
	for name, cut := range cuts {
		_, err := decrypt(enc[:cut], pass)
		if !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s (cut at %d of %d): err = %v, want ErrCorrupt", name, cut, len(enc), err)
		}
	}
}

func TestTampered(t *testing.T) {
	pass := []byte("tamper passphrase!")
	enc := encrypt(t, random(t, 3000), pass, testParams())
	body := append([]byte(nil), enc...)
	body[headerLen+5] ^= 0x01
	if _, err := decrypt(body, pass); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("flipped ciphertext bit: err = %v, want ErrCorrupt", err)
	}
	extra := append(append([]byte(nil), enc...), 0x00)
	if _, err := decrypt(extra, pass); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("trailing byte: err = %v, want ErrCorrupt", err)
	}
	// The chunk-size field is covered by the key check's KDF inputs only
	// indirectly; it IS covered by every chunk's additional data.
	hdr := append([]byte(nil), enc...)
	hdr[len(Magic)+2+4+4+1+3] ^= 0x01 // low byte of chunk size: 1024 -> 1025
	if _, err := decrypt(hdr, pass); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tampered chunk size: err = %v, want ErrCorrupt", err)
	}
}

func TestRejectsHostileHeader(t *testing.T) {
	pass := []byte("hostile header test")
	enc := encrypt(t, []byte("x"), pass, testParams())
	h := append([]byte(nil), enc...)
	// memory field -> 0xFFFFFFFF KiB: must be refused, not allocated.
	copy(h[len(Magic)+2+4:], []byte{0xff, 0xff, 0xff, 0xff})
	if _, err := decrypt(h, pass); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if _, err := decrypt([]byte("PGDMP not a bundle at all, a plain dump......................"), pass); !errors.Is(err, ErrNotBundle) {
		t.Fatalf("plain input: err = %v, want ErrNotBundle", err)
	}
}

func TestWriterRefusesEmptyPassphrase(t *testing.T) {
	if _, err := NewWriter(io.Discard, nil, testParams()); err == nil {
		t.Fatal("empty passphrase accepted")
	}
}
