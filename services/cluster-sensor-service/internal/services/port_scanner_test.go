package services

import (
	"strings"
	"testing"
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
