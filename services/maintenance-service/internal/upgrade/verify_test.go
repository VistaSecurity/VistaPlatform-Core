package upgrade

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeCosign writes a script standing in for the cosign binary: it records
// its arguments and the docker config it was given, and exits with code.
func fakeCosign(t *testing.T, code int) (bin, record string) {
	t.Helper()
	dir := t.TempDir()
	record = filepath.Join(dir, "record")
	bin = filepath.Join(dir, "cosign")
	script := "#!/bin/sh\n" +
		"echo \"$@\" > " + record + "\n" +
		"if [ -n \"$DOCKER_CONFIG\" ]; then cat \"$DOCKER_CONFIG/config.json\" >> " + record + "; fi\n" +
		"echo \"HOME=$HOME\" >> " + record + "\n" +
		"echo 'Error: no matching signatures: none of the expected identities matched' >&2\n" +
		"exit " + map[int]string{0: "0", 1: "1"}[code] + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin, record
}

func TestCosign_ArgumentsCredentialsAndFailure(t *testing.T) {
	bin, record := fakeCosign(t, 0)
	c := Cosign{Binary: bin, IdentityRegexp: `^https://github\.com/VistaSecurity/.*$`, TempDir: t.TempDir(),
		DockerConfig: func(context.Context) []byte { return []byte(`{"auths":{"ghcr.io":{"auth":"dTpw"}}}`) }}
	if err := c.Verify(context.Background(), "ghcr.io/vistasecurity/vistaplatform:4.6.0"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(record)
	got := string(raw)
	for _, want := range []string{
		"verify ghcr.io/vistasecurity/vistaplatform:4.6.0",
		`--certificate-identity-regexp ^https://github\.com/VistaSecurity/.*$`,
		"--certificate-oidc-issuer https://token.actions.githubusercontent.com",
		`"ghcr.io":{"auth":"dTpw"}`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("cosign invocation lacks %q:\n%s", want, got)
		}
	}
	// The per-call HOME (and the credential in it) is removed afterwards.
	home := strings.TrimPrefix(strings.TrimSpace(got[strings.LastIndex(got, "HOME="):]), "HOME=")
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Errorf("per-call HOME %s left behind", home)
	}

	bin, _ = fakeCosign(t, 1)
	c.Binary = bin
	err := c.Verify(context.Background(), "ghcr.io/vistasecurity/vistaplatform:4.6.0")
	if err == nil || !strings.Contains(err.Error(), "none of the expected identities matched") {
		t.Fatalf("failure not surfaced: %v", err)
	}
}
