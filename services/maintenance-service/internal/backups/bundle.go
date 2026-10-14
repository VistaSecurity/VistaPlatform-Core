package backups

import (
	"archive/tar"
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/bundlecrypt"
)

// pgDumpMagic opens every pg_dump custom-format (-Fc) archive.
const pgDumpMagic = "PGDMP"

// PackInput is what goes into one bundle.
type PackInput struct {
	Dir      string   // the backup's directory on the volume (holds database.dump)
	Manifest Manifest // written as manifest.json, first in the tar
	// Secrets is secrets.yaml, or nil. It is streamed into the tar from
	// memory and never written to disk.
	Secrets []byte
	// Passphrase encrypts the bundle (bundle.enc). Required when Secrets is
	// set; without it the bundle is a plain bundle.tar.
	Passphrase []byte
	Params     bundlecrypt.Params
	Now        time.Time
}

// PackResult is the bundle written.
type PackResult struct {
	Name string // FileBundleTar or FileBundleEnc
	Size int64
}

// ReadDumpVersion reads the `pg_dump --version` line the Job wrote.
func ReadDumpVersion(dir string) string {
	raw, err := os.ReadFile(filepath.Join(dir, FilePgDumpVersion))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// ReadSchemaRow reads the schema_migration_status row the Job wrote, or JSON
// null when the Job found none.
func ReadSchemaRow(dir string) json.RawMessage {
	raw, err := os.ReadFile(filepath.Join(dir, FileSchema))
	raw = bytes.TrimSpace(raw)
	if err != nil || len(raw) == 0 || !json.Valid(raw) {
		return json.RawMessage("null")
	}
	return json.RawMessage(raw)
}

// checkDump refuses a dump that is missing, empty or not a custom-format
// archive: a Job that "succeeded" without writing one must not become a
// ready backup.
func checkDump(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("the database dump is missing: %w", err)
	}
	defer func() { _ = f.Close() }()
	head := make([]byte, len(pgDumpMagic))
	if _, err := io.ReadFull(f, head); err != nil || string(head) != pgDumpMagic {
		return 0, errors.New("the database dump is not a pg_dump custom-format archive")
	}
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

// Pack writes the bundle into in.Dir (via a .partial file renamed on
// success) and removes the plaintext pieces. Nothing is held in memory but
// one chunk of the stream and the (small) manifest and secrets.
func Pack(in PackInput) (res PackResult, err error) {
	if len(in.Secrets) > 0 && len(in.Passphrase) == 0 {
		return PackResult{}, errors.New("refusing to write the install's Secrets without a passphrase")
	}
	dumpPath := filepath.Join(in.Dir, FileDump)
	dumpSize, err := checkDump(dumpPath)
	if err != nil {
		return PackResult{}, err
	}
	manifest, err := json.MarshalIndent(in.Manifest, "", "  ")
	if err != nil {
		return PackResult{}, err
	}
	manifest = append(manifest, '\n')

	name := FileBundleTar
	if len(in.Passphrase) > 0 {
		name = FileBundleEnc
	}
	final := filepath.Join(in.Dir, name)
	partial := final + ".partial"
	f, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return PackResult{}, err
	}
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(partial)
		}
	}()

	buffered := bufio.NewWriterSize(f, 1<<20)
	var sink io.Writer = buffered
	var enc *bundlecrypt.Writer
	if len(in.Passphrase) > 0 {
		params := in.Params
		if params == (bundlecrypt.Params{}) {
			params = bundlecrypt.DefaultParams()
		}
		if enc, err = bundlecrypt.NewWriter(buffered, in.Passphrase, params); err != nil {
			return PackResult{}, err
		}
		sink = enc
	}
	tw := tar.NewWriter(sink)
	mtime := in.Now.UTC()
	if mtime.IsZero() {
		mtime = time.Now().UTC()
	}
	add := func(name string, size int64, body io.Reader) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: size, ModTime: mtime, Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
			return err
		}
		n, err := io.Copy(tw, body)
		if err == nil && n != size {
			err = fmt.Errorf("%s: wrote %d of %d bytes", name, n, size)
		}
		return err
	}
	if err = add(FileManifest, int64(len(manifest)), bytes.NewReader(manifest)); err != nil {
		return PackResult{}, err
	}
	if len(in.Secrets) > 0 {
		if err = add(FileSecrets, int64(len(in.Secrets)), bytes.NewReader(in.Secrets)); err != nil {
			return PackResult{}, err
		}
	}
	dump, err := os.Open(dumpPath)
	if err != nil {
		return PackResult{}, err
	}
	err = add(FileDump, dumpSize, dump)
	_ = dump.Close()
	if err != nil {
		return PackResult{}, err
	}
	if err = tw.Close(); err != nil {
		return PackResult{}, err
	}
	if enc != nil {
		if err = enc.Close(); err != nil {
			return PackResult{}, err
		}
	}
	if err = buffered.Flush(); err != nil {
		return PackResult{}, err
	}
	if err = f.Sync(); err != nil {
		return PackResult{}, err
	}
	st, err := f.Stat()
	if err != nil {
		return PackResult{}, err
	}
	if err = f.Close(); err != nil {
		return PackResult{}, err
	}
	if err = os.Rename(partial, final); err != nil {
		return PackResult{}, err
	}
	// The plaintext pieces go once the bundle is complete. For an encrypted
	// bundle this is the point: the dump would otherwise sit beside it in the
	// clear.
	for _, p := range []string{FileDump, FilePgDumpVersion, FileSchema} {
		if rmErr := os.Remove(filepath.Join(in.Dir, p)); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			return PackResult{}, fmt.Errorf("remove %s after packing: %w", p, rmErr)
		}
	}
	return PackResult{Name: name, Size: st.Size()}, nil
}
