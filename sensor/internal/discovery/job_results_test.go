package discovery

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

const jobID = "8a2c4e10-9b3d-4f52-8e71-0d6a9c3b1f42"

// A payload the dispatcher wrote is one the sensor runs; one nothing can run is
// refused as ErrMalformedPayload, which the command loop acknowledges as FAILED.
func TestParseDiscoveryJobCommand(t *testing.T) {
	good := &models.Command{ID: "cmd-1", Type: sensordispatch.CommandType, Payload: map[string]interface{}{
		"job_id":    jobID,
		"tenant_id": "1c9e7a05-4d2b-4a63-9f18-7e5c2b0a3d64",
		"targets":   []interface{}{"192.0.2.10", "192.0.2.11"},
		"protocols": []interface{}{"TLS", "SSH"},
		"ports":     []interface{}{float64(443), float64(22)},
		"options":   map[string]interface{}{"concurrency": float64(3), "active_scanning": true},
	}}
	job, err := ParseDiscoveryJobCommand(good)
	if err != nil {
		t.Fatalf("ParseDiscoveryJobCommand = %v", err)
	}
	if job.JobID != jobID || len(job.Targets) != 2 || len(job.Protocols) != 2 || len(job.Ports) != 2 || job.Options.Concurrency != 3 {
		t.Errorf("job = %+v", job)
	}
	if job.Options.ActiveScanning == nil || !*job.Options.ActiveScanning {
		t.Errorf("active_scanning option lost: %+v", job.Options)
	}

	bad := []struct {
		name string
		cmd  *models.Command
	}{
		{"nil command", nil},
		{"no payload", &models.Command{ID: "cmd-2"}},
		{"no job id", &models.Command{ID: "cmd-3", Payload: map[string]interface{}{"targets": []interface{}{"192.0.2.10"}}}},
		{"no targets", &models.Command{ID: "cmd-4", Payload: map[string]interface{}{"job_id": jobID}}},
		{"bad port", &models.Command{ID: "cmd-5", Payload: map[string]interface{}{"job_id": jobID, "targets": []interface{}{"192.0.2.10"}, "ports": []interface{}{float64(99999)}}}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseDiscoveryJobCommand(tc.cmd); !errors.Is(err, sensordispatch.ErrMalformedPayload) {
				t.Fatalf("err = %v, want ErrMalformedPayload", err)
			}
		})
	}
}

func sampleResponse() *models.DiscoveryJobResponse {
	notAfter := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	return &models.DiscoveryJobResponse{
		JobID:             jobID,
		Status:            "partial",
		TotalTargets:      3,
		SuccessfulTargets: 2,
		FailedTargets:     1,
		Results: []models.DiscoveryJobResult{
			{
				Target: "web.internal", Status: "success", ResolvedIP: "192.0.2.10", ResolvedIPs: []string{"192.0.2.10"},
				Findings: []models.DiscoveryFinding{{
					Protocol: "TLS", Port: 443, Confidence: 0.9,
					TLSVersions: []string{"TLS 1.3", "TLS 1.2"}, SelectedCipher: "TLS_AES_256_GCM_SHA384",
					ALPN: []string{"h2"}, CertValidationStatus: "self_signed",
					Certificates: []models.CertificateInfo{{SubjectDN: "CN=web.internal", KeySize: 2048, KeyAlgorithm: "RSA", NotAfter: notAfter, FingerprintSHA256: "abc"}},
					RawMetadata:  map[string]interface{}{"cert_has_sct": false, "ocsp_status": "unknown"},
				}},
			},
			{
				// A swept host expanded from a CIDR: the target IS the address.
				Target: "192.0.2.11", Status: "success",
				Findings: []models.DiscoveryFinding{{
					Protocol: "SSH", Port: 22, SSHProtocolVersion: "SSH-2.0", SSHSoftwareVersion: "OpenSSH_9.6p1",
					SSHKexAlgorithm: "curve25519-sha256", SSHHostKeyType: "ssh-ed25519",
				}},
			},
			{Target: "192.0.2.12", Status: "failed", ErrorCode: "no_findings"},
		},
	}
}

func TestDiscoveriesForJob_TagsActiveProvenanceAndKeepsEveryField(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	got := DiscoveriesForJob(sampleResponse(), "sensor-1", now)
	if len(got) != 2 {
		t.Fatalf("got %d discoveries, want 2 (the failed target has none)", len(got))
	}

	tls := got[0]
	if tls.DestIP != "192.0.2.10" || tls.Port != 443 || tls.Protocol != "TLS" || tls.SensorID != "sensor-1" {
		t.Errorf("tls discovery = %+v", tls)
	}
	if tls.DiscoveryMethod != sensordispatch.DiscoveryMethodActive {
		t.Errorf("discovery_method = %q, want %q — this is what gives the configuration active provenance", tls.DiscoveryMethod, sensordispatch.DiscoveryMethodActive)
	}
	if tls.Version != "TLS 1.3" || tls.CipherSuite != "TLS_AES_256_GCM_SHA384" || tls.KeySize != 2048 {
		t.Errorf("version/cipher/keysize = %q/%q/%d", tls.Version, tls.CipherSuite, tls.KeySize)
	}
	m := tls.RawMetadata
	if m[sensordispatch.MetadataJobIDKey] != jobID || m["discovery_source"] != sensordispatch.DiscoverySourceActiveScan {
		t.Errorf("job/provenance stamps = %v / %v", m["job_id"], m["discovery_source"])
	}
	if m["hostname"] != "web.internal" {
		t.Errorf("hostname = %v, want the probed name kept for the platform's identity", m["hostname"])
	}
	if m["version"] != "TLS 1.3" || m["cipher_suite"] != "TLS_AES_256_GCM_SHA384" {
		t.Errorf("version/cipher_suite in metadata = %v / %v", m["version"], m["cipher_suite"])
	}
	// Typed fields under their JSON names — the same keys the platform reads
	// from the in-cluster scanner.
	if _, ok := m["tls_versions"]; !ok {
		t.Error("tls_versions missing from metadata")
	}
	if m["cert_validation_status"] != "self_signed" {
		t.Errorf("cert_validation_status = %v", m["cert_validation_status"])
	}
	// The probe's quality flags survive — including an explicit false.
	if v, ok := m["cert_has_sct"].(bool); !ok || v {
		t.Errorf("cert_has_sct = %v, want explicit false", m["cert_has_sct"])
	}
	// The canonical certificates shape.
	certs, ok := m["certificates"].([]interface{})
	if !ok || len(certs) != 1 {
		t.Fatalf("certificates = %v", m["certificates"])
	}
	cert := certs[0].(map[string]interface{})
	if cert["subject_dn"] != "CN=web.internal" || cert["key_size"] != 2048 || cert["not_after"] != "2027-01-01T00:00:00Z" {
		t.Errorf("certificate map = %v", cert)
	}

	ssh := got[1]
	if ssh.DestIP != "192.0.2.11" || ssh.Protocol != "SSH" || ssh.Version != "SSH-2.0" || ssh.DiscoveryMethod != "active" {
		t.Errorf("ssh discovery = %+v", ssh)
	}
	if ssh.RawMetadata["ssh_kex_algorithm"] != "curve25519-sha256" || ssh.RawMetadata["ssh_host_key_type"] != "ssh-ed25519" {
		t.Errorf("ssh fields lost: %v", ssh.RawMetadata)
	}
	if _, ok := ssh.RawMetadata["hostname"]; ok {
		t.Error("an IP target must not be reported as a hostname")
	}
	if _, ok := ssh.RawMetadata["certificates"]; ok {
		t.Error("an SSH finding carries no certificates key")
	}
}

func TestDiscoveriesForJob_DropsWhatCannotBeAnchored(t *testing.T) {
	resp := &models.DiscoveryJobResponse{JobID: jobID, Results: []models.DiscoveryJobResult{
		{Target: "unresolvable.internal", Status: "failed", Findings: []models.DiscoveryFinding{{Protocol: "TLS", Port: 443}}},
		{Target: "192.0.2.10", Status: "success", Findings: []models.DiscoveryFinding{{Protocol: "", Port: 443}, {Protocol: "TLS", Port: 0}}},
	}}
	if got := DiscoveriesForJob(resp, "s", time.Now()); len(got) != 0 {
		t.Fatalf("got %d discoveries from rows with no address/protocol/port", len(got))
	}
	if got := DiscoveriesForJob(nil, "s", time.Now()); got != nil {
		t.Fatal("nil response produced discoveries")
	}
}

func TestSummarizeJob(t *testing.T) {
	resp := sampleResponse()
	c := SummarizeJob(resp, 2, 2, nil)
	if c.Status != "completed" || c.TotalTargets != 3 || c.SuccessfulTargets != 2 || c.FailedTargets != 1 || c.DiscoveriesSubmitted != 2 || c.ErrorMessage != "" {
		t.Errorf("clean completion = %+v", c)
	}
	// Results existed and none reached the platform: the job FAILED, loudly.
	c = SummarizeJob(resp, 2, 0, errors.New("submission failed with status 503"))
	if c.Status != "failed" || !strings.Contains(c.ErrorMessage, "could not be submitted") {
		t.Errorf("unsubmitted results = %+v", c)
	}
	// Some reached the platform: completed, with the shortfall named.
	c = SummarizeJob(resp, 2, 1, errors.New("batch 2 failed"))
	if c.Status != "completed" || c.DiscoveriesSubmitted != 1 || !strings.Contains(c.ErrorMessage, "some results") {
		t.Errorf("partial submission = %+v", c)
	}
	// Nothing answered and there was nothing to submit: completed, zero.
	quiet := &models.DiscoveryJobResponse{JobID: jobID, TotalTargets: 1, FailedTargets: 1}
	c = SummarizeJob(quiet, 0, 0, nil)
	if c.Status != "completed" || c.DiscoveriesSubmitted != 0 {
		t.Errorf("quiet host = %+v", c)
	}
	if c := SummarizeJob(nil, 0, 0, nil); c.Status != "failed" {
		t.Errorf("no response = %+v", c)
	}
	if err := SummarizeJob(resp, 2, 2, nil).Validate(); err != nil {
		t.Errorf("summary does not validate: %v", err)
	}
}
