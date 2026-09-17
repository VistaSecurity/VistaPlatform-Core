package services

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
)

// TestShouldProbeTLSHonoursRequestedPorts pins DISC-7: the TLS probe was hard
// gated to 443/8443/636, so a TLS service the job explicitly asked about on any
// other port produced an open-port finding with no crypto data and no error.
func TestShouldProbeTLSHonoursRequestedPorts(t *testing.T) {
	tests := []struct {
		name         string
		protocolName string
		reqProtocol  string
		port         int
		want         bool
	}{
		// Explicitly requested TLS on a non-standard port — the case that was
		// silently dropped.
		{"explicit TLS on 9443", "tcp", "TLS", 9443, true},
		{"explicit TLS on 31337", "tcp", "TLS", 31337, true},
		{"explicit HTTPS on 8081", "tcp", "https", 8081, true},
		{"explicit LDAPS on 3269", "ldaps", "ldaps", 3269, true},
		{"explicit SMTPS on 465", "smtps", "smtps", 465, true},
		{"explicit IMAPS on 993", "imaps", "imaps", 993, true},

		// Unspecified sweeps still use the well-known-port heuristic.
		{"well-known 443 with generic protocol", "tcp", "tcp", 443, true},
		{"well-known 993 with generic protocol", "tcp", "tcp", 993, true},
		{"well-known 636 with generic protocol", "tcp", "tcp", 636, true},

		// Neither explicit nor well-known: no speculative TLS handshake.
		{"generic protocol on an arbitrary port", "tcp", "tcp", 31337, false},
		{"SSH on 22", "ssh", "ssh", 22, false},

		// A finding that exists because the job asked for ANOTHER protocol
		// gets no TLS probe even on a well-known TLS port. The SSH finding on
		// 443 used to receive the TLS handshake and reach the inventory as
		// "SSH, TLS 1.3, TLS_AES_256_GCM_SHA384".
		{"SSH requested on 443", "SSH", "SSH", 443, false},
		{"SSH requested on 8443", "ssh", "ssh", 8443, false},
		{"Modbus requested on 443", "modbus", "modbus", 443, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldProbeTLS(tt.protocolName, tt.reqProtocol, tt.port); got != tt.want {
				t.Errorf("shouldProbeTLS(%q, %q, %d) = %v, want %v", tt.protocolName, tt.reqProtocol, tt.port, got, tt.want)
			}
		})
	}
}

func TestShouldProbeSSHHonoursRequestedPorts(t *testing.T) {
	tests := []struct {
		name         string
		protocolName string
		reqProtocol  string
		port         int
		want         bool
	}{
		{"explicit SSH on a non-standard port", "tcp", "SSH", 2022, true},
		{"explicit SSH on 22222", "tcp", "ssh", 22222, true},
		{"well-known 22 with generic protocol", "tcp", "tcp", 22, true},
		{"well-known 2222 with generic protocol", "tcp", "tcp", 2222, true},
		{"generic protocol on an arbitrary port", "tcp", "tcp", 9000, false},
		{"TLS on 443", "tls", "tls", 443, false},
		// The mirror of the SSH-on-443 case: a TLS finding on 22 is not
		// handed the SSH probe just because 22 is a well-known SSH port.
		{"TLS requested on 22", "TLS", "TLS", 22, false},
		{"HTTPS requested on 22", "https", "https", 22, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldProbeSSH(tt.protocolName, tt.reqProtocol, tt.port); got != tt.want {
				t.Errorf("shouldProbeSSH(%q, %q, %d) = %v, want %v", tt.protocolName, tt.reqProtocol, tt.port, got, tt.want)
			}
		})
	}
}

// TestResolveTargetIPUnresolvable pins DISC-6: an unresolvable hostname used to
// return a nil *string that every call site dereferenced unconditionally,
// panicking the job goroutine.
func TestResolveTargetIPUnresolvable(t *testing.T) {
	ps := NewPortScanner()

	// .invalid is reserved by RFC 6761 and must never resolve.
	ip, reason := ps.resolveTargetIP("nothing-here.invalid")
	if ip != "" {
		t.Errorf("ip = %q, want empty for an unresolvable target", ip)
	}
	if reason == "" {
		t.Error("want a non-empty failure reason for an unresolvable target")
	}

	if ip, reason := ps.resolveTargetIP("192.0.2.10"); ip != "192.0.2.10" || reason != "" {
		t.Errorf("resolveTargetIP(literal IP) = (%q, %q), want (192.0.2.10, \"\")", ip, reason)
	}
}

// TestParseNmapOutputSurvivesUnresolvableTarget pins that the scan path records
// a failed-resolution result instead of panicking. The port and protocol are
// chosen so no probe (TLS/SSH/OT) is attempted — the test must not touch the
// network beyond the DNS miss.
func TestParseNmapOutputSurvivesUnresolvableTarget(t *testing.T) {
	ps := NewPortScanner()

	nmapOutput := strings.Join([]string{
		"Nmap scan report for nothing-here.invalid",
		"PORT      STATE SERVICE",
		"31337/tcp open  unknown",
	}, "\n")

	findings := ps.parseNmapOutput(nmapOutput, "nothing-here.invalid", []int32{31337}, []string{"tcp"}, nil, nil)

	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 (an unresolvable target must still produce a recorded result)", len(findings))
	}
	f := findings[0]
	if f.ResolvedIP != "" {
		t.Errorf("ResolvedIP = %q, want empty", f.ResolvedIP)
	}
	if failed, _ := f.Data["dns_resolution_failed"].(bool); !failed {
		t.Errorf("Data[dns_resolution_failed] = %v, want true", f.Data["dns_resolution_failed"])
	}
	if reason, _ := f.Data["dns_resolution_error"].(string); reason == "" {
		t.Error("want a dns_resolution_error explaining the failure")
	}
}

// TestValidateNmapTargetRejectsHostPort pins the contract that makes a
// "host:port" scan target fatal: nmap is given one host and a separate -p port
// list, so a colon is an illegal character and the whole target is dropped.
// Callers must send a bare host and carry the port in the job's Ports field.
// (Addresses below are RFC 5737 documentation ranges.)
func TestValidateNmapTargetRejectsHostPort(t *testing.T) {
	rejected := []string{
		"192.0.2.10:443",
		"192.0.2.10:22",
		"host.example.com:8443",
		"[2001:db8::1]:443",
		"-oN/tmp/pwn",   // option injection
		"host;rm -rf /", // shell metacharacter
		"",
	}
	for _, target := range rejected {
		t.Run(target, func(t *testing.T) {
			if err := validateNmapTarget(target); err == nil {
				t.Errorf("validateNmapTarget(%q) = nil, want an error", target)
			}
		})
	}

	accepted := []string{"192.0.2.10", "198.51.100.7", "host.example.com", "2001:db8::1"}
	for _, target := range accepted {
		t.Run(target, func(t *testing.T) {
			if err := validateNmapTarget(target); err != nil {
				t.Errorf("validateNmapTarget(%q) = %v, want nil", target, err)
			}
		})
	}
}

// TestProbeRefutedDropsAProtocolThePortDoesNotSpeak pins the second half of the
// SSH-on-443 fix: once the SSH finding on 443 no longer receives the TLS data,
// it is an open-port row carrying only `ssh_probe_error`, and storing that
// materialises an "SSH on 443" crypto configuration with nothing in it. A
// specific request refuted by its own probe on a port it is not known on
// records no finding; the same failure on a well-known port keeps it.
func TestProbeRefutedDropsAProtocolThePortDoesNotSpeak(t *testing.T) {
	failed := func(key string) models.DiscoveryFinding {
		return models.DiscoveryFinding{Data: map[string]interface{}{key: "handshake failed"}}
	}
	ok := models.DiscoveryFinding{Data: map[string]interface{}{"ssh_host_key_type": "ssh-ed25519"}}

	tests := []struct {
		name        string
		finding     models.DiscoveryFinding
		reqProtocol string
		port        int
		want        bool
	}{
		{"SSH refuted on 443", failed("ssh_probe_error"), "SSH", 443, true},
		{"SSH refuted on 8443", failed("ssh_probe_error"), "ssh", 8443, true},
		{"TLS refuted on 22", failed("tls_probe_error"), "TLS", 22, true},
		{"HTTPS refuted on 3306", failed("tls_probe_error"), "https", 3306, true},

		// A well-known port keeps its finding: the error is the finding.
		{"SSH failed on 22", failed("ssh_probe_error"), "SSH", 22, false},
		{"TLS failed on 443", failed("tls_probe_error"), "TLS", 443, false},

		// A probe that answered is never refuted, wherever it answered.
		{"SSH answered on 443", ok, "SSH", 443, false},

		// A generic finding has no protocol to be refuted about.
		{"generic with a TLS error on 9000", failed("tls_probe_error"), "tcp", 9000, false},
		{"generic with an SSH error on 9000", failed("ssh_probe_error"), "", 9000, false},

		// Another protocol's error says nothing about this one.
		{"SSH finding carrying only a TLS error", failed("tls_probe_error"), "SSH", 443, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := probeRefuted(tt.finding, tt.reqProtocol, tt.port); got != tt.want {
				t.Errorf("probeRefuted(%v, %q, %d) = %v, want %v", tt.finding.Data, tt.reqProtocol, tt.port, got, tt.want)
			}
		})
	}
}
