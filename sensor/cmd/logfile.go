package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// sensorLogFileName is the sensor's log under <dataPath>/logs. The installers
// point operators at it, so renaming it means changing install-sensor.ps1 too.
const sensorLogFileName = "sensor.log"

// sensorLogMaxBytes caps sensor.log before it rotates to sensor.log.1. One
// backup is kept, so the log never holds more than twice this on disk. A
// verbose sensor logs every discovery, and a service runs for months.
const sensorLogMaxBytes = 10 << 20

// rotatingLogFile is an append-only log file that moves itself to <path>.1
// once it would exceed maxBytes, replacing the previous backup.
type rotatingLogFile struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	file     *os.File
	size     int64
}

func openRotatingLogFile(path string, maxBytes int64) (*rotatingLogFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	r := &rotatingLogFile{path: path, maxBytes: maxBytes}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *rotatingLogFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	r.file, r.size = f, info.Size()
	return nil
}

// Write appends p, rotating first if p would take the file past maxBytes. A
// write is never split across the two files.
func (r *rotatingLogFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size > 0 && r.size+int64(len(p)) > r.maxBytes {
		r.rotate()
	}
	if r.file == nil {
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	n, err := r.file.Write(p)
	r.size += int64(n)
	return n, err
}

// rotate moves the current file to <path>.1. If the move fails (on Windows,
// a reader without delete sharing holds the file open) the sensor keeps
// appending to the current file and tries again on a later write — losing log
// lines over a rotation would be worse than an oversized file.
func (r *rotatingLogFile) rotate() {
	if r.file != nil {
		_ = r.file.Close()
		r.file = nil
	}
	backup := r.path + ".1"
	// Windows will not rename over an existing file.
	if err := os.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return
	}
	_ = os.Rename(r.path, backup)
	// open() runs in Write, and re-reads the size: 0 after a rotation, the
	// current size if the rename failed.
}

func (r *rotatingLogFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return nil
	}
	err := r.file.Close()
	r.file = nil
	return err
}

// teeLogToFile adds <dataPath>/logs/sensor.log to the standard logger's
// outputs, alongside the in-memory ring (and stderr when alsoStderr). The ring
// already holds what was logged before the data path was known, so those
// lines are copied into the file first.
func teeLogToFile(dataPath string, alsoStderr bool) (string, error) {
	if strings.TrimSpace(dataPath) == "" {
		return "", fmt.Errorf("no data path configured")
	}
	path := filepath.Join(dataPath, "logs", sensorLogFileName)
	f, err := openRotatingLogFile(path, sensorLogMaxBytes)
	if err != nil {
		return "", err
	}
	if earlier := logRing.tail(0); len(earlier) > 0 {
		if _, err := f.Write([]byte(strings.Join(earlier, "\n") + "\n")); err != nil {
			_ = f.Close()
			return "", err
		}
	}
	// The ring first: io.MultiWriter abandons a write at the first failing
	// writer, and a full disk must not also empty export_logs.
	writers := []io.Writer{logRing, f}
	if alsoStderr {
		writers = append(writers, os.Stderr)
	}
	log.SetOutput(io.MultiWriter(writers...))
	return path, nil
}
