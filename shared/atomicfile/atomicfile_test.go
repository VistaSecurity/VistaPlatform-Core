package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func noTemps(t *testing.T, dir string) {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("leftover temp file %s", e.Name())
		}
	}
}

func TestWriteReplacesAtomicallyAndSetsMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "client.key")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Write(p, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "new" {
		t.Fatalf("content = %q", b)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(p)
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %#o, want 0600", st.Mode().Perm())
		}
	}
	noTemps(t, dir)
}

// A failure on the second file must leave the first exactly as it was: the
// cert/key pair is never mismatched.
func TestWriteAllRollsBackOnFailure(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "client.crt")
	key := filepath.Join(dir, "client.key")
	if err := os.WriteFile(cert, []byte("old-cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	// key path is a non-empty directory, so renaming a file over it fails.
	if err := os.MkdirAll(filepath.Join(key, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := WriteAll([]File{
		{Path: cert, Data: []byte("new-cert"), Perm: 0o644},
		{Path: key, Data: []byte("new-key"), Perm: 0o600},
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	b, _ := os.ReadFile(cert)
	if string(b) != "old-cert" {
		t.Fatalf("cert = %q, want old-cert (not rolled back)", b)
	}
	noTemps(t, dir)
}

func TestWriteAllFailsBeforeTouchingAnythingWhenDirMissing(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "client.crt")
	_ = os.WriteFile(cert, []byte("old"), 0o644)
	err := WriteAll([]File{
		{Path: cert, Data: []byte("new"), Perm: 0o644},
		{Path: filepath.Join(dir, "missing", "client.key"), Data: []byte("k"), Perm: 0o600},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	b, _ := os.ReadFile(cert)
	if string(b) != "old" {
		t.Fatalf("cert modified despite failure: %q", b)
	}
	noTemps(t, dir)
}
