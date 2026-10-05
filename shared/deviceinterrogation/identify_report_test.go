package deviceinterrogation

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The report is the whole of what an agent-routed Add device sends home
// ( slice B), so its JSON keys ARE the allowlist. A field added to it is
// a field that can carry vendor data off a customer network; this pins the
// set so adding one is a decision a reviewer sees, and none of them may be
// credential-shaped.
func TestIdentificationReport_KeysAreTheAllowlist(t *testing.T) {
	full := IdentificationReport{
		Vendor: "v", Model: "m", SerialNumber: "s", FirmwareVersion: "f", OSVersion: "o",
		Hostname: "h", IPAddress: "192.0.2.10", MACAddress: "00:00:5e:00:53:01",
		TargetHost: "192.0.2.10", TargetPort: 443, SSHHostKeyFingerprint: "SHA256:x", SSHHostKeyType: "ssh-ed25519",
	}
	blob, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	_ = json.Unmarshal(blob, &m)
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := []string{"firmware_version", "hostname", "ip_address", "mac_address", "model", "os_version",
		"serial_number", "ssh_host_key_fingerprint", "ssh_host_key_type", "target_host", "target_port", "vendor"}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("report keys = %v, want exactly %v", keys, want)
	}
	for _, k := range keys {
		for _, bad := range []string{"password", "secret", "token", "psk", "private", "credential", "api_key"} {
			if strings.Contains(k, bad) {
				t.Errorf("report key %q is credential-shaped", k)
			}
		}
	}
}

// What the platform RECEIVES is scrubbed again: an agent binary is not a
// boundary the platform owns. A private key smuggled into a model string, a
// target carrying userinfo, an oversize field and an impossible port are all
// cleaned by Sanitized.
func TestIdentificationReport_SanitizedScrubsRelayedValues(t *testing.T) {
	pem := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----"
	in := &IdentificationReport{
		Model:      "FortiGate " + pem,
		TargetHost: "https://admin:hunter2@192.0.2.10",
		Hostname:   strings.Repeat("a", 5000),
		TargetPort: 70000,
	}
	got := in.Sanitized()
	if strings.Contains(got.Model, "PRIVATE KEY") || strings.Contains(got.Model, "MIIEvQ") {
		t.Errorf("model kept the private key: %q", got.Model)
	}
	if strings.Contains(got.TargetHost, "hunter2") {
		t.Errorf("target kept its userinfo: %q", got.TargetHost)
	}
	if len(got.Hostname) > maxReportField {
		t.Errorf("hostname not bounded: %d bytes", len(got.Hostname))
	}
	if got.TargetPort != 0 {
		t.Errorf("port %d kept", got.TargetPort)
	}
	if (*IdentificationReport)(nil).Sanitized() != nil || (*IdentificationReport)(nil).IdentifiesSomething() {
		t.Error("nil report must stay nil and identify nothing")
	}
	if (&IdentificationReport{Vendor: "Fortinet"}).IdentifiesSomething() {
		t.Error("a vendor alone identifies nothing — every collector knows it before dialling")
	}
}

func TestParseAgentCapabilities(t *testing.T) {
	got := ParseAgentCapabilities(" device_discovery , ,Something_New")
	if !got[CapabilityDeviceDiscovery] || !got["something_new"] || len(got) != 2 {
		t.Fatalf("ParseAgentCapabilities = %v", got)
	}
	if len(ParseAgentCapabilities("")) != 0 {
		t.Fatal("an absent header declares nothing")
	}
	if !ParseAgentCapabilities(strings.Join(AgentCapabilities(), ","))[CapabilityDeviceDiscovery] {
		t.Fatal("this build's own declaration must parse as device_discovery")
	}
}

func TestKnownIdentifyFailure(t *testing.T) {
	for _, code := range []IdentifyFailure{IdentifyNotSupported, IdentifyInvalidTarget, IdentifyTargetDisallowed,
		IdentifyConnectionFailed, IdentifyTLSUntrusted, IdentifyAuthenticationFailed, IdentifyHostKeyMismatch,
		IdentifyUnsupportedResponse, IdentifyFailed} {
		if !KnownIdentifyFailure(string(code)) {
			t.Errorf("%q not known", code)
		}
	}
	if KnownIdentifyFailure("the device said: password=hunter2") {
		t.Error("free text accepted as a failure code")
	}
}
