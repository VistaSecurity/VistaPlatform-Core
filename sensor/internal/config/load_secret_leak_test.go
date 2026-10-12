package config

import (
	"bytes"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadFromFile_NeverPrintsRegistrationKey guards against echoing the raw
// config file (which holds the registration key) to stdout or the log.
func TestLoadFromFile_NeverPrintsRegistrationKey(t *testing.T) {
	const secret = "regkey-SUPER-SECRET-0123456789abcdef"
	path := filepath.Join(t.TempDir(), "sensor.yaml")
	body := "controlPlaneUrl: https://example.invalid\nsensorId: s1\nregistrationKey: " + secret + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	var logBuf bytes.Buffer
	oldLog, oldFlags := log.Writer(), log.Flags()
	log.SetOutput(&logBuf)
	defer func() { log.SetOutput(oldLog); log.SetFlags(oldFlags) }()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()

	_, loadErr := LoadFromFile(path)

	_ = w.Close()
	os.Stdout = oldStdout
	stdout := <-done
	if loadErr != nil {
		t.Logf("LoadFromFile returned %v (output is still checked)", loadErr)
	}

	for name, out := range map[string]string{"stdout": stdout, "log": logBuf.String()} {
		if strings.Contains(out, secret) {
			t.Errorf("%s leaked the registration key: %q", name, out)
		}
	}
	if !strings.Contains(logBuf.String(), "registrationKey=(set, ") {
		t.Errorf("expected masked summary in log, got %q", logBuf.String())
	}
}
