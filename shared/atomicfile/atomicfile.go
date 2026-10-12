// Package atomicfile writes files so a crash, a full disk or a permission
// failure never leaves a half-written or mismatched file behind.
//
// The collector binaries (sensor, device agent) use it for their mTLS
// identity and config: a certificate that no longer matches its key, or a
// truncated config, locks the collector out of the platform until a person
// re-enrols it. It is CGO-free and platform-agnostic.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// File is one file to write.
type File struct {
	Path string
	Data []byte
	Perm os.FileMode
}

// Write writes a single file atomically: the data goes to a temp file in the
// same directory, is synced, given perm, and renamed over path. Chmod is
// explicit because a rename over an existing file keeps the new file's mode,
// but umask would otherwise loosen or tighten the temp file's mode.
func Write(path string, data []byte, perm os.FileMode) error {
	return WriteAll([]File{{Path: path, Data: data, Perm: perm}})
}

// WriteAll writes several files as a unit: every temp file is written and
// synced first, then renamed into place. If any step fails the temp files are
// removed and the files already renamed are restored to their previous
// contents (or removed if they did not exist), so a certificate and its key
// are never left mismatched by a failure this process can observe.
func WriteAll(files []File) error {
	temps := make([]string, len(files))
	cleanup := func() {
		for _, t := range temps {
			if t != "" {
				_ = os.Remove(t)
			}
		}
	}
	for i, f := range files {
		tmp, err := writeTemp(f)
		if err != nil {
			cleanup()
			return err
		}
		temps[i] = tmp
	}

	type previous struct {
		data   []byte
		perm   os.FileMode
		exists bool
	}
	prev := make([]previous, len(files))
	for i, f := range files {
		if st, err := os.Stat(f.Path); err == nil {
			if b, rerr := os.ReadFile(f.Path); rerr == nil {
				prev[i] = previous{data: b, perm: st.Mode().Perm(), exists: true}
			}
		}
	}

	for i, f := range files {
		if err := os.Rename(temps[i], f.Path); err != nil {
			_ = os.Remove(temps[i])
			temps[i] = ""
			// Roll back files already replaced.
			for j := 0; j < i; j++ {
				if prev[j].exists {
					_ = restore(files[j].Path, prev[j].data, prev[j].perm)
				} else {
					_ = os.Remove(files[j].Path)
				}
				temps[j] = ""
			}
			for k := i; k < len(temps); k++ {
				if temps[k] != "" {
					_ = os.Remove(temps[k])
				}
			}
			return fmt.Errorf("replace %s: %w", f.Path, err)
		}
		temps[i] = ""
	}
	return nil
}

func restore(path string, data []byte, perm os.FileMode) error {
	tmp, err := writeTemp(File{Path: path, Data: data, Perm: perm})
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func writeTemp(f File) (string, error) {
	dir := filepath.Dir(f.Path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(f.Path)+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("create temp file for %s: %w", f.Path, err)
	}
	name := tmp.Name()
	fail := func(err error) (string, error) {
		_ = tmp.Close()
		_ = os.Remove(name)
		return "", fmt.Errorf("write %s: %w", f.Path, err)
	}
	if _, err := tmp.Write(f.Data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return "", fmt.Errorf("write %s: %w", f.Path, err)
	}
	if err := os.Chmod(name, f.Perm); err != nil {
		_ = os.Remove(name)
		return "", fmt.Errorf("chmod %s: %w", f.Path, err)
	}
	return name, nil
}
