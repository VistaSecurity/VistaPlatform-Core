package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfig_NoFileFallsBackToEnvironment(t *testing.T) {
	cfg, err := loadConfig("")
	if err != nil || cfg == nil {
		t.Fatalf("loadConfig(\"\") = %v, %v; want defaults and no error", cfg, err)
	}
}

func TestLoadConfig_ValidFileIsLoaded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(path, []byte("controlPlaneUrl: https://platform.example.test\nsensorId: 11111111-1111-1111-1111-111111111111\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("valid file: %v", err)
	}
	if got := cfg.ControlPlaneURL; got != "https://platform.example.test" {
		t.Fatalf("platform URL = %q; the file was not applied", got)
	}
}

func TestLoadConfig_MalformedFileIsAnErrorNamingThePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(path, []byte("controlPlaneUrl: https://x\nbroken line without colon\n  - [unclosed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err == nil {
		t.Fatalf("malformed file must be an error, got config %+v", cfg)
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error %q does not name the path %q", err, path)
	}
}

func TestLoadConfig_MissingExplicitFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.yaml")
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("missing explicit file: err = %v; want an error naming %q", err, path)
	}
}
