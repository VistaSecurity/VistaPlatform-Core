package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/bundlecrypt"
)

func writeBundle(t *testing.T, dir string, plain, pass []byte) string {
	t.Helper()
	p := filepath.Join(dir, "bundle.enc")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	w, err := bundlecrypt.NewWriter(f, pass, bundlecrypt.Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1, ChunkSize: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDecryptFile(t *testing.T) {
	dir := t.TempDir()
	plain := bytes.Repeat([]byte("tar bytes "), 500)
	in := writeBundle(t, dir, plain, []byte("decrypt tool passphrase"))
	out := filepath.Join(dir, "bundle.tar")
	if err := decryptFile(in, out, []byte("decrypt tool passphrase")); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got, plain) {
		t.Fatal("decrypted output differs")
	}
	if err := decryptFile(in, out, []byte("decrypt tool passphrase")); err == nil {
		t.Fatal("overwrote an existing output")
	}
}

// A failed decrypt leaves no output and no .partial behind.
func TestDecryptFile_FailureLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	in := writeBundle(t, dir, bytes.Repeat([]byte("x"), 5000), []byte("the right passphrase"))
	out := filepath.Join(dir, "bundle.tar")
	if err := decryptFile(in, out, []byte("the wrong passphrase")); !errors.Is(err, bundlecrypt.ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	raw, _ := os.ReadFile(in)
	if err := os.WriteFile(in, raw[:len(raw)-40], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := decryptFile(in, out, []byte("the right passphrase")); !errors.Is(err, bundlecrypt.ErrCorrupt) {
		t.Fatalf("truncated: %v", err)
	}
	for _, p := range []string{out, out + ".partial"} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("%s left behind after a failed decrypt", p)
		}
	}
}
