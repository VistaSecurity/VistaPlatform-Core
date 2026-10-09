package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotatingLogFile_RotatesToOneBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "sensor.log")
	f, err := openRotatingLogFile(path, 20)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	for _, line := range []string{"first-0123456\n", "second-012345\n", "third-0123456\n"} {
		if _, err := f.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}

	current, _ := os.ReadFile(path)
	backup, _ := os.ReadFile(path + ".1")
	if string(current) != "third-0123456\n" {
		t.Fatalf("current file = %q, want only the newest line", current)
	}
	// One backup is kept: the oldest line is gone, so the log is bounded.
	if string(backup) != "second-012345\n" {
		t.Fatalf("backup = %q, want the previous file", backup)
	}
}

func TestRotatingLogFile_AppendsToAnExistingLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sensor.log")
	if err := os.WriteFile(path, []byte("from the last run\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := openRotatingLogFile(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("this run\n")); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	got, _ := os.ReadFile(path)
	if string(got) != "from the last run\nthis run\n" {
		t.Fatalf("log = %q: a restart must not truncate the previous run's log", got)
	}
}

func TestRotatingLogFile_CountsTheExistingSizeTowardsTheCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sensor.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 15)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := openRotatingLogFile(path, 20)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write([]byte("next run\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("a log already near the cap was not rotated on its first write: %v", err)
	}
}

func TestRotatingLogFile_OversizedWriteIsNotSplit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sensor.log")
	f, err := openRotatingLogFile(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	long := strings.Repeat("y", 50) + "\n"
	if _, err := f.Write([]byte(long)); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != long {
		t.Fatalf("log = %q, want the whole line in one file", got)
	}
}

// teeLogToFile is what gives a Windows service a log at all: stderr goes
// nowhere there. The file must start with what was logged before the data
// path was known, keep the in-memory ring fed (export_logs), and receive
// everything after.
func TestTeeLogToFile_BackfillsTheRingAndKeepsItFed(t *testing.T) {
	savedRing, savedOut, savedFlags := logRing, log.Writer(), log.Flags()
	t.Cleanup(func() {
		logRing = savedRing
		log.SetOutput(savedOut)
		log.SetFlags(savedFlags)
	})
	logRing = newLogRingBuffer(100)
	log.SetFlags(0)
	log.SetOutput(logRing)

	log.Println("before the config was loaded")

	dataPath := t.TempDir()
	path, err := teeLogToFile(dataPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dataPath, "logs", "sensor.log"); path != want {
		t.Fatalf("log path = %q, want %q (the installer points operators there)", path, want)
	}

	log.Println("after")

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "before the config was loaded\nafter\n" {
		t.Fatalf("log file = %q", got)
	}
	if tail := logRing.tail(0); len(tail) != 2 || tail[1] != "after" {
		t.Fatalf("ring = %q: export_logs must still see new lines", tail)
	}
}

func TestTeeLogToFile_RequiresADataPath(t *testing.T) {
	savedOut := log.Writer()
	t.Cleanup(func() { log.SetOutput(savedOut) })
	var buf bytes.Buffer
	log.SetOutput(&buf)
	if _, err := teeLogToFile("  ", false); err == nil {
		t.Fatal("expected an error for an empty data path")
	}
	if log.Writer() != &buf {
		t.Fatal("a failed tee must leave the logger's output alone")
	}
}
