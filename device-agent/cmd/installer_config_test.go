package main

// scripts/install-device-agent.sh writes the agent's config and relies on the
// agent to enroll itself. Two hand-offs have to line up, and neither side's own
// tests see the other:
//
//  1. The config the installer writes must leave the agent UNENROLLED, with a
//     key, the platform URL and a data path inside the install directory —
//     the directory the service user owns, not the agent's root-owned default.
//  2. The installer decides enrollment succeeded — and, on a re-run, that the
//     host is already enrolled with this key — by reading agent_id and
//     registration_key back out of the file the agent rewrites
//     (saveConfigFile). If its parse drifts from what the writer emits, every
//     successful install reports failure and every re-run discards a working
//     enrollment.
//
// This drives the installer's own text through bash and the agent's real
// loader and writer.

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
)

const deviceAgentInstaller = "../../scripts/install-device-agent.sh"

func installerSection(t *testing.T, script, start, end string) string {
	t.Helper()
	lines := strings.Split(script, "\n")
	startRe, endRe := regexp.MustCompile(start), regexp.MustCompile(end)
	for i, line := range lines {
		if !startRe.MatchString(line) {
			continue
		}
		for j := i + 1; j < len(lines); j++ {
			if endRe.MatchString(lines[j]) {
				return strings.Join(lines[i:j+1], "\n")
			}
		}
	}
	t.Fatalf("installer section %q … %q not found in %s", start, end, deviceAgentInstaller)
	return ""
}

func runInstallerBash(t *testing.T, script string, env ...string) string {
	t.Helper()
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash failed: %v\n%s", err, out)
	}
	return string(out)
}

func TestInstallerConfig_AgentEnrollsItselfAndInstallerSeesIt(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	raw, err := os.ReadFile(deviceAgentInstaller)
	if err != nil {
		t.Fatalf("read installer: %v", err)
	}
	script := string(raw)
	heredoc := installerSection(t, script, `cat > "\$CONFIG_FILE" << EOF`, `^EOF$`)
	readConfigValue := installerSection(t, script, `^read_config_value\(\) \{`, `^\}`)

	installDir := t.TempDir()
	cfgPath := filepath.Join(installDir, "device-agent.yaml")
	runInstallerBash(t, "CONFIG_FILE="+cfgPath+"\n"+heredoc,
		"CONTROL_PLANE_URL=https://control.example.test",
		"REGISTRATION_KEY=REG-0123456789abcdef",
		"INSTALL_DIR="+installDir,
	)

	// Hand-off 1.
	cfg, err := config.LoadFromFile(cfgPath)
	if err != nil {
		t.Fatalf("agent cannot load the installer's config: %v", err)
	}
	if cfg.AgentID != "" {
		t.Fatalf("the installer's config names an agent (%q) — the agent would never enroll", cfg.AgentID)
	}
	if cfg.RegistrationKey != "REG-0123456789abcdef" || cfg.PlatformURL != "https://control.example.test" {
		t.Fatalf("key/url = %q/%q", cfg.RegistrationKey, cfg.PlatformURL)
	}
	if want := filepath.Join(installDir, "data"); cfg.DataPath != want {
		t.Fatalf("DataPath = %q, want %q — inside the install directory the service user owns", cfg.DataPath, want)
	}
	if err := checkEnrollmentWritable(cfg.DataPath, cfgPath); err != nil {
		t.Fatalf("the agent would refuse to enroll with the installer's layout: %v", err)
	}

	// Hand-off 2: the agent records its enrollment the way main does.
	const id = "3f2b8c1e-9a7d-4e65-b0c4-2d1e8f7a6b59"
	cfg.AgentID = id
	if err := saveConfigFile(cfgPath, cfg); err != nil {
		t.Fatalf("saveConfigFile: %v", err)
	}
	read := func(key string) string {
		return strings.TrimSpace(runInstallerBash(t, readConfigValue+"\nread_config_value "+key+" "+cfgPath))
	}
	if got := read("agent_id"); got != id {
		t.Fatalf("installer read agent_id %q from the enrolled config, want %q — a successful install would be reported as a failure", got, id)
	}
	if got := read("registration_key"); got != "REG-0123456789abcdef" {
		t.Fatalf("installer read registration_key %q — a re-run would discard a working enrollment", got)
	}
}
