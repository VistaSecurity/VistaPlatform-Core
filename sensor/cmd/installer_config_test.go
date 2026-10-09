package main

// scripts/install-sensor.sh writes the sensor's config and then relies on the
// sensor to register itself. Two hand-offs have to line up, and neither side's
// own tests see the other:
//
//  1. The config the installer writes must leave the sensor UNREGISTERED with a
//     usable key and name, so the binary enrols on first start. The installer
//     once registered with curl itself and wrote the sensor's name as sensorId;
//     the binary, holding no UUID, retried a key the installer had already
//     spent — forever — while the console showed a sensor stuck at the
//     installer's hardcoded "1.0.0" that had never heartbeated.
//  2. The installer decides registration succeeded — and, on a re-run, that the
//     host is already enrolled with this key — by reading sensorId and
//     registrationKey back out of the file the sensor rewrites
//     (saveConfigFile). If its parse drifts from what the writer emits, every
//     successful install reports failure and every re-run discards a working
//     enrolment.
//
// This drives the installer's own text through bash and the sensor's real
// loader and writer.

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
)

const installerPath = "../../scripts/install-sensor.sh"

// installerSection returns the text of the installer between the first line
// matching start and the first following line matching end (both inclusive).
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
	t.Fatalf("installer section %q … %q not found in %s", start, end, installerPath)
	return ""
}

// installerLine returns the first installer line matching re.
func installerLine(t *testing.T, script, re string) string {
	t.Helper()
	for _, line := range strings.Split(script, "\n") {
		if regexp.MustCompile(re).MatchString(line) {
			return line
		}
	}
	t.Fatalf("installer line %q not found in %s", re, installerPath)
	return ""
}

func runBash(t *testing.T, script string, env ...string) string {
	t.Helper()
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash failed: %v\n%s", err, out)
	}
	return string(out)
}

func TestInstallerConfig_SensorEnrolsItselfAndInstallerSeesIt(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	raw, err := os.ReadFile(installerPath)
	if err != nil {
		t.Fatalf("read installer: %v", err)
	}
	script := string(raw)

	yamlQuote := installerSection(t, script, `^\s*yaml_quote\(\) \{`, `^\s*\}$`)
	ifaces := installerSection(t, script, `^\s*INTERFACES_YAML=""`, `^\s*done$`)
	heredoc := installerSection(t, script, `cat > "\$CONFIG_FILE" << EOF`, `^EOF$`)
	readConfigValue := installerSection(t, script, `^read_config_value\(\) \{`, `^\}`)
	readID := installerLine(t, script, `^\s*current_id=\$\(read_config_value sensorId `)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sensor-config.yaml")
	const name = `dc-1 "edge" sensor`
	runBash(t, yamlQuote+"\n"+ifaces+"\nCONFIG_FILE="+cfgPath+"\n"+heredoc,
		"SENSOR_NAME="+name,
		"CONTROL_PLANE_URL=https://control.example.test",
		"REGISTRATION_KEY=REG-0123456789abcdef",
		"INTERFACES=eth0, eth1",
		"INSTALL_DIR="+dir,
	)

	// Hand-off 1: what the binary makes of the installer's config.
	cfg, err := config.LoadFromFile(cfgPath)
	if err != nil {
		t.Fatalf("sensor cannot load the installer's config: %v", err)
	}
	if isRegistered(cfg) {
		t.Fatal("the installer's config reads as already registered — the sensor would never enrol")
	}
	if cfg.RegistrationKey != "REG-0123456789abcdef" {
		t.Errorf("RegistrationKey = %q — the sensor has no key to enrol with", cfg.RegistrationKey)
	}
	if cfg.Name != name {
		t.Errorf("Name = %q, want %q — the sensor would register under the wrong name", cfg.Name, name)
	}
	if cfg.ControlPlaneURL != "https://control.example.test" {
		t.Errorf("ControlPlaneURL = %q", cfg.ControlPlaneURL)
	}
	if strings.Join(cfg.Capture.Interfaces, ",") != "eth0,eth1" {
		t.Errorf("Interfaces = %q, want [eth0 eth1]", cfg.Capture.Interfaces)
	}
	if cfg.Storage.DataPath != dir+"/data" {
		t.Errorf("DataPath = %q, want %q", cfg.Storage.DataPath, dir+"/data")
	}
	if cfg.Security.ClientCertPath != "" || cfg.Security.ClientKeyPath != "" {
		t.Errorf("the installer wrote certificate paths (%q, %q) — the sensor obtains its own certificate and records where",
			cfg.Security.ClientCertPath, cfg.Security.ClientKeyPath)
	}

	// Hand-off 2: the sensor records a successful registration the way
	// register() does, and the installer's success check must read it back.
	const id = "3f2b8c1e-9a7d-4e65-b0c4-2d1e8f7a6b59"
	cfg.SensorID = id
	cfg.Security.ClientCertPath = filepath.Join(dir, "data", "certs", "client.crt")
	cfg.Security.ClientKeyPath = filepath.Join(dir, "data", "certs", "client.key")
	cfg.Security.ServerCACertPath = filepath.Join(dir, "data", "certs", "server-ca.crt")
	s := &Sensor{config: cfg, configPath: cfgPath}
	if err := s.saveConfigFile(); err != nil {
		t.Fatalf("saveConfigFile: %v", err)
	}
	got := strings.TrimSpace(runBash(t, readConfigValue+"\nCONFIG_FILE="+cfgPath+"\n"+readID+"\nprintf '%s' \"$current_id\""))
	if got != id {
		t.Fatalf("installer read sensorId %q from the registered config, want %q — a successful install would be reported as a failure", got, id)
	}

	// Re-running the install with the same key must recognise the enrolment it
	// would otherwise destroy: that check reads the key back from the file the
	// sensor rewrote.
	key := strings.TrimSpace(runBash(t, readConfigValue+"\nread_config_value registrationKey "+cfgPath))
	if key != "REG-0123456789abcdef" {
		t.Fatalf("installer read registrationKey %q from the registered config — a re-run would discard a working enrolment", key)
	}
}
