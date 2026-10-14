// bundle-decrypt opens an encrypted Vista Platform backup bundle (bundle.enc)
// with its passphrase and writes the tar inside it, so a restore does not need
// the platform running. See README.md next to this file.
//
//	bundle-decrypt -in bundle.enc -out bundle.tar
//
// The passphrase is read from the VISTA_BACKUP_PASSPHRASE environment variable
// when it is set, otherwise from the terminal without echo. It is never a flag:
// a flag would put it in the shell history and the process list.
//
// The output is written to <out>.partial and renamed only after the whole
// bundle authenticated, so an interrupted or failed run never leaves a
// complete-looking tar behind.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/bundlecrypt"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "bundle-decrypt:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin *os.File, stderr io.Writer) error {
	fs := flag.NewFlagSet("bundle-decrypt", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("in", "", "encrypted bundle to read (bundle.enc, or the downloaded vista-platform-backup-*.enc)")
	out := fs.String("out", "", "tar file to write (must not exist)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" || *out == "" {
		fs.Usage()
		return errors.New("-in and -out are required")
	}
	pass, err := readPassphrase(stdin, stderr)
	if err != nil {
		return err
	}
	return decryptFile(*in, *out, pass)
}

func readPassphrase(stdin *os.File, stderr io.Writer) ([]byte, error) {
	if p, ok := os.LookupEnv("VISTA_BACKUP_PASSPHRASE"); ok {
		if p == "" {
			return nil, errors.New("VISTA_BACKUP_PASSPHRASE is set but empty")
		}
		return []byte(p), nil
	}
	if term.IsTerminal(int(stdin.Fd())) {
		_, _ = fmt.Fprint(stderr, "Backup passphrase: ")
		p, err := term.ReadPassword(int(stdin.Fd()))
		_, _ = fmt.Fprintln(stderr)
		if err != nil {
			return nil, fmt.Errorf("read passphrase: %w", err)
		}
		return p, nil
	}
	// Piped: the first line of stdin.
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return nil, errors.New("no passphrase given (set VISTA_BACKUP_PASSPHRASE or type it at the prompt)")
	}
	return []byte(line), nil
}

// decryptFile decrypts in to out via out.partial, renaming only on success.
func decryptFile(inPath, outPath string, pass []byte) (err error) {
	if _, statErr := os.Stat(outPath); statErr == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite it", outPath)
	}
	src, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()

	r, err := bundlecrypt.NewReader(src, pass)
	if err != nil {
		return err
	}
	partial := outPath + ".partial"
	dst, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = dst.Close()
			_ = os.Remove(partial)
		}
	}()
	if _, err = io.Copy(dst, r); err != nil {
		return err
	}
	if err = dst.Sync(); err != nil {
		return err
	}
	if err = dst.Close(); err != nil {
		return err
	}
	return os.Rename(partial, outPath)
}
