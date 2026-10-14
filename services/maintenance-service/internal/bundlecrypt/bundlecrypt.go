// Package bundlecrypt encrypts and decrypts a platform backup bundle
// (`bundle.enc`) under a passphrase (spec platform-maintenance.md D2: a bundle
// that carries the install's Secrets is never stored or served in the clear).
//
// It streams: neither direction holds the bundle in memory, so a multi-GB
// database dump costs one chunk of buffer (1 MiB by default).
//
// # Format (version 1)
//
//	header
//	  magic        8 bytes  "VSTBKUP1"
//	  version      1 byte   1
//	  kdf          1 byte   1 = Argon2id
//	  time         4 bytes  Argon2id iterations (big-endian)
//	  memory       4 bytes  Argon2id memory, KiB (big-endian)
//	  threads      1 byte   Argon2id parallelism
//	  chunk size   4 bytes  plaintext bytes per chunk (big-endian)
//	  salt        16 bytes  random, per bundle
//	  key check   16 bytes  HMAC-SHA256(macKey, "vista-backup-key-check-v1")[:16]
//	chunks, each AES-256-GCM(encKey, nonce, plaintext, aad = header)
//	  nonce = 11-byte big-endian chunk counter || 1-byte final flag
//
// Argon2id derives 64 bytes from the passphrase and salt: the first 32 are the
// AES-256 key, the last 32 key the key check. The check lets a wrong passphrase
// be reported as such before any data is read; it reveals nothing a guess at
// the passphrase could not already test against the first chunk.
//
// Every chunk is sealed with the header as additional data, so a tampered
// header (a smaller memory cost, a different chunk size) fails authentication.
// Every chunk but the last carries final = 0 and the last final = 1 (the
// STREAM construction), so a file cut short — even exactly at a chunk boundary
// — fails instead of decrypting to a silently shorter bundle. The salt is new
// for every bundle, so each bundle has its own key and a counter nonce never
// repeats under a key.
//
// The standalone decryptor is services/maintenance-service/cmd/bundle-decrypt;
// a restore does not need the platform running.
package bundlecrypt

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// Magic opens every encrypted bundle.
const Magic = "VSTBKUP1"

const (
	formatVersion = 1
	kdfArgon2id   = 1
	saltLen       = 16
	checkLen      = 16
	nonceLen      = 12
	tagLen        = 16
	// headerLen = magic + version + kdf + time + memory + threads + chunk + salt + check.
	headerLen = len(Magic) + 1 + 1 + 4 + 4 + 1 + 4 + saltLen + checkLen
	// maxChunks: an 11-byte counter cannot wrap in practice; this bound keeps
	// the arithmetic obviously safe.
	maxChunks = uint64(1) << 62
)

const keyCheckLabel = "vista-backup-key-check-v1"

// Params are the Argon2id cost and the chunk size a bundle is written with.
type Params struct {
	Time      uint32 // iterations
	MemoryKiB uint32 // memory, KiB
	Threads   uint8
	ChunkSize uint32 // plaintext bytes per chunk
}

// DefaultParams: Argon2id with 3 passes over 64 MiB (above the RFC 9106
// second recommendation's memory floor for a constrained host, which this
// service is — it runs under a 256 MiB limit), and 1 MiB chunks.
func DefaultParams() Params {
	return Params{Time: 3, MemoryKiB: 64 * 1024, Threads: 2, ChunkSize: 1 << 20}
}

// Bounds a reader accepts. A bundle is untrusted input to the decryptor: an
// absurd memory cost in its header must not make the reader allocate it.
const (
	minTime, maxTime           = 1, 16
	minMemoryKiB, maxMemoryKiB = 8 * 1024, 1024 * 1024
	minThreads, maxThreads     = 1, 16
	minChunk, maxChunk         = 1 << 10, 16 << 20
)

// MinPassphraseLen is the shortest passphrase the service accepts (the API
// refuses shorter ones; the decryptor does not, so an old bundle stays
// openable whatever the rule becomes).
const MinPassphraseLen = 12

var (
	// ErrNotBundle: the input does not start with an encrypted-bundle header.
	ErrNotBundle = errors.New("bundlecrypt: not an encrypted Vista Platform backup bundle")
	// ErrWrongPassphrase: the key check failed — wrong passphrase (or a damaged header).
	ErrWrongPassphrase = errors.New("bundlecrypt: wrong passphrase")
	// ErrCorrupt: a chunk failed authentication — the file is truncated or was modified.
	ErrCorrupt = errors.New("bundlecrypt: bundle is truncated or damaged")
	// ErrUnsupported: a header field this reader does not accept.
	ErrUnsupported = errors.New("bundlecrypt: unsupported bundle parameters")
)

func (p Params) validate() error {
	switch {
	case p.Time < minTime || p.Time > maxTime:
		return fmt.Errorf("%w: argon2id time %d", ErrUnsupported, p.Time)
	case p.MemoryKiB < minMemoryKiB || p.MemoryKiB > maxMemoryKiB:
		return fmt.Errorf("%w: argon2id memory %d KiB", ErrUnsupported, p.MemoryKiB)
	case p.Threads < minThreads || p.Threads > maxThreads:
		return fmt.Errorf("%w: argon2id threads %d", ErrUnsupported, p.Threads)
	case p.ChunkSize < minChunk || p.ChunkSize > maxChunk:
		return fmt.Errorf("%w: chunk size %d", ErrUnsupported, p.ChunkSize)
	}
	return nil
}

func deriveKeys(passphrase, salt []byte, p Params) (encKey, check []byte) {
	k := argon2.IDKey(passphrase, salt, p.Time, p.MemoryKiB, p.Threads, 64)
	mac := hmac.New(sha256.New, k[32:])
	mac.Write([]byte(keyCheckLabel))
	return k[:32], mac.Sum(nil)[:checkLen]
}

func encodeHeader(p Params, salt, check []byte) []byte {
	h := make([]byte, 0, headerLen)
	h = append(h, Magic...)
	h = append(h, formatVersion, kdfArgon2id)
	h = binary.BigEndian.AppendUint32(h, p.Time)
	h = binary.BigEndian.AppendUint32(h, p.MemoryKiB)
	h = append(h, p.Threads)
	h = binary.BigEndian.AppendUint32(h, p.ChunkSize)
	h = append(h, salt...)
	h = append(h, check...)
	return h
}

func nonceFor(counter uint64, final bool) []byte {
	n := make([]byte, nonceLen)
	// 11-byte big-endian counter: the high 3 bytes stay zero for any counter
	// below maxChunks.
	binary.BigEndian.PutUint64(n[3:11], counter)
	if final {
		n[11] = 1
	}
	return n
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Writer encrypts a stream. Close MUST be called: it seals the final chunk,
// without which the bundle does not decrypt.
type Writer struct {
	w       io.Writer
	aead    cipher.AEAD
	header  []byte
	buf     []byte
	chunk   int
	counter uint64
	closed  bool
	err     error
}

// NewWriter writes the header to w and returns a Writer that encrypts
// everything written to it.
func NewWriter(w io.Writer, passphrase []byte, p Params) (*Writer, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("bundlecrypt: empty passphrase")
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("bundlecrypt: salt: %w", err)
	}
	key, check := deriveKeys(passphrase, salt, p)
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	header := encodeHeader(p, salt, check)
	if _, err := w.Write(header); err != nil {
		return nil, fmt.Errorf("bundlecrypt: write header: %w", err)
	}
	return &Writer{w: w, aead: aead, header: header, chunk: int(p.ChunkSize), buf: make([]byte, 0, int(p.ChunkSize))}, nil
}

func (e *Writer) seal(final bool) error {
	if e.counter >= maxChunks {
		return errors.New("bundlecrypt: bundle too large")
	}
	out := e.aead.Seal(nil, nonceFor(e.counter, final), e.buf, e.header)
	e.counter++
	e.buf = e.buf[:0]
	if _, err := e.w.Write(out); err != nil {
		return fmt.Errorf("bundlecrypt: write chunk: %w", err)
	}
	return nil
}

// Write implements io.Writer. A full buffer is sealed only once more input
// arrives, because only then is it known not to be the last chunk.
func (e *Writer) Write(p []byte) (int, error) {
	if e.closed {
		return 0, errors.New("bundlecrypt: write after close")
	}
	if e.err != nil {
		return 0, e.err
	}
	n := 0
	for len(p) > 0 {
		if len(e.buf) == e.chunk {
			if err := e.seal(false); err != nil {
				e.err = err
				return n, err
			}
		}
		c := copy(e.buf[len(e.buf):e.chunk], p)
		e.buf = e.buf[:len(e.buf)+c]
		p = p[c:]
		n += c
	}
	return n, nil
}

// Close seals the final chunk (possibly empty). It does not close the
// underlying writer.
func (e *Writer) Close() error {
	if e.closed {
		return nil
	}
	e.closed = true
	if e.err != nil {
		return e.err
	}
	return e.seal(true)
}

// Reader decrypts a stream written by Writer.
type Reader struct {
	r       *bufio.Reader
	aead    cipher.AEAD
	header  []byte
	cbuf    []byte
	pbuf    []byte
	plain   []byte
	counter uint64
	done    bool
	err     error
}

// NewReader reads and checks the header, derives the key and verifies the
// passphrase. A wrong passphrase is reported here, before any data is read.
func NewReader(r io.Reader, passphrase []byte) (*Reader, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	header := make([]byte, headerLen)
	if _, err := io.ReadFull(br, header); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			if bytes.HasPrefix(header, []byte(Magic)) {
				return nil, ErrCorrupt
			}
			return nil, ErrNotBundle
		}
		return nil, err
	}
	if string(header[:len(Magic)]) != Magic {
		return nil, ErrNotBundle
	}
	off := len(Magic)
	if header[off] != formatVersion || header[off+1] != kdfArgon2id {
		return nil, fmt.Errorf("%w: version %d, kdf %d", ErrUnsupported, header[off], header[off+1])
	}
	off += 2
	p := Params{
		Time:      binary.BigEndian.Uint32(header[off:]),
		MemoryKiB: binary.BigEndian.Uint32(header[off+4:]),
		Threads:   header[off+8],
		ChunkSize: binary.BigEndian.Uint32(header[off+9:]),
	}
	off += 13
	if err := p.validate(); err != nil {
		return nil, err
	}
	salt := header[off : off+saltLen]
	stored := header[off+saltLen : off+saltLen+checkLen]
	key, check := deriveKeys(passphrase, salt, p)
	if !hmac.Equal(stored, check) {
		return nil, ErrWrongPassphrase
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return &Reader{r: br, aead: aead, header: header, cbuf: make([]byte, int(p.ChunkSize)+tagLen), pbuf: make([]byte, 0, int(p.ChunkSize))}, nil
}

func (d *Reader) next() error {
	n, err := io.ReadFull(d.r, d.cbuf)
	final := false
	switch {
	case err == nil:
		// A full chunk: it is the last one only if nothing follows.
		if _, perr := d.r.Peek(1); errors.Is(perr, io.EOF) {
			final = true
		} else if perr != nil {
			return perr
		}
	case errors.Is(err, io.ErrUnexpectedEOF):
		final = true // a short chunk can only be the last
	case errors.Is(err, io.EOF):
		// Nothing after the previous chunk, which was not sealed final: cut
		// short exactly at a chunk boundary (or no chunk at all).
		return ErrCorrupt
	default:
		return err
	}
	if n < tagLen {
		return ErrCorrupt
	}
	plain, oerr := d.aead.Open(d.pbuf[:0], nonceFor(d.counter, final), d.cbuf[:n], d.header)
	if oerr != nil {
		return ErrCorrupt
	}
	d.counter++
	d.plain = plain
	d.done = final
	return nil
}

// Read implements io.Reader. It returns io.EOF only after the final chunk
// authenticated; anything short of that is ErrCorrupt.
func (d *Reader) Read(p []byte) (int, error) {
	for len(d.plain) == 0 {
		if d.err != nil {
			return 0, d.err
		}
		if d.done {
			return 0, io.EOF
		}
		if err := d.next(); err != nil {
			d.err = err
			return 0, err
		}
	}
	n := copy(p, d.plain)
	d.plain = d.plain[n:]
	return n, nil
}
