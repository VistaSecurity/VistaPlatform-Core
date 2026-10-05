package jobunits

// The observation → finding rules (moved here from cluster-sensor-service with
// the mapping, WP2b; unchanged).

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/certificates"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// The observation → finding rules (H13/H14, D5), one case per rule.
func TestUnitFindings_MapsEachObservationKind(t *testing.T) {
	out := shareddisc.UnitOutput{
		Host: shareddisc.HostScan{PortsRequested: 10, OpenCount: 4, Open: []int{22, 443, 502, 9000}},
		TCP: []shareddisc.Observation{
			{Port: 443, Transport: "tcp", State: "open", Protocol: "TLS", Identified: true, Result: &shareddisc.ProbeResult{
				Protocol: "TLS", TLSVersions: []string{"TLS 1.3"}, SelectedCipher: "TLS_AES_128_GCM_SHA256",
				Certificates: []certificates.CertificateInfo{{SubjectDN: "CN=a", IssuerDN: "CN=b"}},
			}},
			{Port: 22, Transport: "tcp", State: "open", Protocol: "SSH", Identified: true, ServiceHint: "ssh", Notes: "ssh-handshake-failed"},
			{Port: 502, Transport: "tcp", State: "open", ServiceHint: "modbus", Metadata: map[string]any{"ot_connect_only": true}, Notes: "ot-opt-in-not-given"},
			{Port: 9000, Transport: "tcp", State: "open", Metadata: map[string]any{"banner_len": 17}, Notes: "unidentified-banner"},
		},
		UDP: []shareddisc.Observation{
			{Port: 53, Transport: "udp", State: "open", Protocol: "DNS", Identified: true, Result: &shareddisc.ProbeResult{Protocol: "DNS", Metadata: map[string]interface{}{"dns_rcode": 0}}},
			{Port: 123, Transport: "udp", State: "open_or_filtered"},
			{Port: 161, Transport: "udp", State: "closed", Notes: "icmp-port-unreachable"},
		},
	}
	got := Findings("10.0.0.5", "", out)
	byPort := map[int]Finding{}
	for _, f := range got {
		byPort[f.Port] = f
	}
	if len(got) != 5 {
		t.Fatalf("findings = %d (%+v), want 5: four open TCP ports and the UDP service that replied", len(got), byPort)
	}
	if _, ok := byPort[123]; ok {
		t.Error("a silent UDP port (open|filtered) became a finding")
	}
	if _, ok := byPort[161]; ok {
		t.Error("a refused UDP port became a finding")
	}
	tls := byPort[443]
	if tls.Protocol != "TLS" || tls.Data["cipher_suite"] != "TLS_AES_128_GCM_SHA256" || tls.Data["version"] != "TLS 1.3" {
		t.Errorf("TLS finding = %+v", tls.Data)
	}
	if certs, ok := tls.Data["certificates"].([]map[string]interface{}); !ok || len(certs) != 1 || certs[0]["subject_dn"] != "CN=a" {
		t.Errorf("TLS finding certificates = %#v, want the canonical certificates array", tls.Data["certificates"])
	}
	if ssh := byPort[22]; ssh.Protocol != "SSH" || ssh.Data["identification_note"] != "ssh-handshake-failed" {
		t.Errorf("SSH finding = %+v", ssh)
	}
	if ot := byPort[502]; ot.Protocol != "tcp" || ot.Data["ot_connect_only"] != true || ot.Data["service_hint"] != "modbus" || ot.Data["unidentified"] != true {
		t.Errorf("connect-only OT port = %+v, want a tcp endpoint with its hint, not a Modbus measurement", ot)
	}
	unk := byPort[9000]
	if unk.Protocol != "tcp" || unk.Data["unidentified"] != true || unk.Data["banner_len"] != 17 {
		t.Errorf("unidentified port = %+v", unk)
	}
	if dns := byPort[53]; dns.Protocol != "DNS" || dns.Data["transport"] != "udp" {
		t.Errorf("UDP finding = %+v", dns)
	}
	for _, f := range got {
		if !f.Mirror || f.ResolvedIP != "10.0.0.5" || f.Hostname != "" || f.ExecutedVia != ExecutedVia {
			t.Errorf("finding on %d = %+v, want queued for inventory on the scanned address, with no hostname", f.Port, f)
		}
		for k := range f.Data {
			if strings.Contains(k, "banner") && k != "banner_len" && k != "ssh_banner" {
				t.Errorf("finding on %d carries %q", f.Port, k)
			}
		}
	}
}

// A finding's hostname is the name the person typed, and only that: a target
// given as an address (or a range) leaves it empty rather than repeating the
// address as a "name" — which identity rejected as an FQDN on every finding
// and which stopped the processor looking the real name up.
func TestUnitFindings_HostnameOnlyForANamedTarget(t *testing.T) {
	out := shareddisc.UnitOutput{
		Host: shareddisc.HostScan{PortsRequested: 1, OpenCount: 1, Open: []int{22}},
		TCP:  []shareddisc.Observation{{Port: 22, Transport: "tcp", State: "open", Protocol: "SSH", Identified: true}},
	}
	for _, tc := range []struct{ target, want string }{
		{"10.0.0.5", ""},
		{"10.0.0.0/24", ""},
		{"10.0.0.1-10.0.0.9", ""},
		{"2001:db8::5", ""},
		{"mail.example.test", "mail.example.test"},
	} {
		got := Findings("10.0.0.5", shareddisc.PlanTargetHostname(tc.target), out)
		if len(got) != 1 || got[0].Hostname != tc.want || got[0].ResolvedIP != "10.0.0.5" {
			t.Errorf("target %q: findings %+v, want one on 10.0.0.5 with hostname %q", tc.target, got, tc.want)
		}
	}
}

// H14: a host that accepted connections on almost everything is ONE finding,
// with the bounded sample, and is not queued for inventory.
func TestUnitFindings_TarpitIsOneUnqueuedFinding(t *testing.T) {
	sample := make([]int, 32)
	for i := range sample {
		sample[i] = i + 1
	}
	out := shareddisc.UnitOutput{Host: shareddisc.HostScan{PortsRequested: 65535, OpenCount: 512, Open: sample, RespondsOnAllPorts: true}}
	got := Findings("10.0.0.6", "", out)
	if len(got) != 1 {
		t.Fatalf("tarpit findings = %d, want 1", len(got))
	}
	f := got[0]
	if f.Mirror || f.Protocol != "tcp" || f.Data["responds_on_all_ports"] != true || f.Data["open_count"] != 512 || len(f.Data["open_sample"].([]int)) != 32 {
		t.Errorf("tarpit finding = %+v (mirror %v)", f.Data, f.Mirror)
	}
}

// A port that answered the ClientHello with a TLS alert is a TLS finding with
// the reason and no crypto detail — not an unidentified tcp port.
func TestUnitFindings_RefusedTLSHandshakeIsATLSFinding(t *testing.T) {
	out := shareddisc.UnitOutput{
		Host: shareddisc.HostScan{PortsRequested: 1, OpenCount: 1, Open: []int{443}},
		TCP: []shareddisc.Observation{{
			Port: 443, Transport: "tcp", State: "open", Protocol: "TLS", Identified: true, ServiceHint: "tls",
			Metadata: map[string]any{"banner_len": 0, "tls_handshake_alert": "internal error"},
			Notes:    "tls-handshake-refused",
		}},
	}
	got := Findings("10.0.0.5", "", out)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	f := got[0]
	if f.Protocol != "TLS" || f.Data["unidentified"] != false {
		t.Errorf("protocol=%q unidentified=%v, want an identified TLS finding", f.Protocol, f.Data["unidentified"])
	}
	if f.Data["identification_note"] != "tls-handshake-refused" || f.Data["tls_handshake_alert"] != "internal error" {
		t.Errorf("data = %+v, want the refusal note and the alert", f.Data)
	}
	for _, k := range []string{"version", "cipher_suite", "certificates"} {
		if _, ok := f.Data[k]; ok {
			t.Errorf("refused handshake carries %q; nothing was negotiated", k)
		}
	}
}
