package producers

// Plaintext management across SOURCES (P-08, workstream W1.6 of).
//
// `mgmt.plaintext` is written per source_ref, and an interrogation's source_ref
// is its job, so one device interrogated over SNMP v2c and later over SSH or an
// HTTPS API carries several answers about several channels. The producer used to
// take the newest answer across all of them, so a later SSH or HTTPS run
// silently resolved the plaintext-management finding SNMP v2c had raised: one
// wrong "all clear" per device still managed in the clear.
//
// Every fact here is written the way the interrogation sink writes it: the
// protocol and the plaintext answer as a PAIR under one source_ref, with the
// observation time of the run.
//
// Mutation: restore the read to `DISTINCT ON (asset_id, key) … ORDER BY
// observed_at DESC` across all sources and LaterEncryptedRunsDoNotClearSNMP goes
// red (the finding is INACTIVE after the HTTPS run). Fold telnet into its own
// channel (drop the "cli" family) and TheReportingSourceRetractsIt goes red.
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer"
)

// interrogationRun writes one interrogation's management-plane answer the way
// the sink does: mgmt.protocol and mgmt.plaintext under ONE source_ref.
func interrogationRun(t *testing.T, db *sql.DB, tenant, asset uuid.UUID, source, protocol string, plaintext bool, at time.Time) {
	t.Helper()
	value := "false"
	if plaintext {
		value = "true"
	}
	for _, f := range []struct{ key, value string }{
		{"mgmt.protocol", `"` + protocol + `"`},
		{"mgmt.plaintext", value},
	} {
		exec(t, db, `INSERT INTO asset_facts (tenant_id, asset_id, key, value, source_kind, source_ref, observed_at)
		             VALUES ($1, $2, $3, $4::jsonb, 'measured', $5, $6)`,
			tenant, asset, f.key, f.value, source, at)
	}
}

// newManagedDevice adds one asset with no management facts to the fixture.
func newManagedDevice(t *testing.T, f *configFixture, name string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	exec(t, f.owner, `INSERT INTO assets (id, tenant_id, hostname, display_name, class_key, class_path, asset_status)
	                  VALUES ($1, $2, $3, $3, 'router', 'hardware.network_device.router', 'monitoring')`,
		id, f.tenant, name)
	return id
}

func sourceRef() string { return "interrogation:" + uuid.NewString() }

func TestIntegration_ConfigurationProducer_LaterEncryptedRunsDoNotClearSNMP(t *testing.T) {
	f := newConfigFixture(t)
	ctx := context.Background()
	dev := newManagedDevice(t, f, "edge-rtr-1")
	base := time.Now().Add(-3 * time.Hour).UTC().Truncate(time.Second)

	snmp := sourceRef()
	interrogationRun(t, f.owner, f.tenant, dev, snmp, "snmpv2c", true, base)
	f.run(t, ctx)
	first := f.finding(t, findings.KindPlaintextManagement, findings.SubjectAsset, dev)
	if first == nil || first.state != producer.StateActive {
		t.Fatalf("SNMP v2c raised no ACTIVE plaintext_management finding: %v", first)
	}

	// Later, the same device is reached over an HTTPS API, then over SSH. Each
	// says ITS OWN channel is encrypted, which is true and beside the point.
	https := sourceRef()
	interrogationRun(t, f.owner, f.tenant, dev, https, "https", false, base.Add(time.Hour))
	f.run(t, ctx)
	ssh := sourceRef()
	interrogationRun(t, f.owner, f.tenant, dev, ssh, "ssh", false, base.Add(2*time.Hour))
	run := f.run(t, ctx)

	after := f.finding(t, findings.KindPlaintextManagement, findings.SubjectAsset, dev)
	if after == nil || after.state != producer.StateActive {
		t.Fatalf("the finding is %v after later HTTPS and SSH runs, want ACTIVE — a source that "+
			"knows nothing about SNMP v2c cleared a finding SNMP v2c raised (P-08)", after)
	}
	if after.id != first.id {
		t.Errorf("a new finding row %s replaced %s", after.id, first.id)
	}
	if run.Resolved != 0 {
		t.Errorf("the pass resolved %d findings; nothing about the plaintext channel changed", run.Resolved)
	}

	// What the tenant reads: which protocol is plaintext and which source saw it.
	if got := after.evidence["mgmt_protocol"]; got != "snmpv2c" {
		t.Errorf("evidence.mgmt_protocol = %v, want snmpv2c — not the newest protocol from another source", got)
	}
	if got := after.evidence["fact_source_ref"]; got != snmp {
		t.Errorf("evidence.fact_source_ref = %v, want the SNMP run %s", got, snmp)
	}
	if !strings.Contains(after.summary, "snmpv2c") {
		t.Errorf("summary %q does not name the plaintext protocol", after.summary)
	}
	pp, _ := after.evidence["plaintext_protocols"].([]any)
	if len(pp) != 1 {
		t.Fatalf("evidence.plaintext_protocols = %v, want one entry", after.evidence["plaintext_protocols"])
	}
	if e, _ := pp[0].(map[string]any); e["protocol"] != "snmpv2c" || e["source_ref"] != snmp {
		t.Errorf("plaintext_protocols[0] = %v, want snmpv2c from %s", pp[0], snmp)
	}
	enc, _ := after.evidence["encrypted_protocols"].([]any)
	var encrypted []string
	for _, e := range enc {
		m, _ := e.(map[string]any)
		p, _ := m["protocol"].(string)
		encrypted = append(encrypted, p)
	}
	if strings.Join(encrypted, ",") != "https,ssh" {
		t.Errorf("evidence.encrypted_protocols = %v, want https and ssh — the reader should see the runs "+
			"that were considered and did not clear it", encrypted)
	}
}

func TestIntegration_ConfigurationProducer_TheReportingSourceRetractsIt(t *testing.T) {
	f := newConfigFixture(t)
	ctx := context.Background()
	dev := newManagedDevice(t, f, "access-sw-7")
	base := time.Now().Add(-3 * time.Hour).UTC().Truncate(time.Second)

	// The Cisco collector reads the VTY lines: telnet accepted.
	interrogationRun(t, f.owner, f.tenant, dev, sourceRef(), "telnet", true, base)
	f.run(t, ctx)
	if got := f.finding(t, findings.KindPlaintextManagement, findings.SubjectAsset, dev); got == nil || got.state != producer.StateActive {
		t.Fatalf("telnet raised no ACTIVE finding: %v", got)
	}

	// An HTTPS run in between says nothing about telnet.
	interrogationRun(t, f.owner, f.tenant, dev, sourceRef(), "https", false, base.Add(time.Hour))
	f.run(t, ctx)
	if got := f.finding(t, findings.KindPlaintextManagement, findings.SubjectAsset, dev); got == nil || got.state != producer.StateActive {
		t.Fatalf("an HTTPS run cleared the telnet finding: %v", got)
	}

	// The same collector reads the VTY lines again: SSH only. It positively
	// assessed telnet, so its answer retracts its own.
	interrogationRun(t, f.owner, f.tenant, dev, sourceRef(), "ssh", false, base.Add(2*time.Hour))
	f.run(t, ctx)
	got := f.finding(t, findings.KindPlaintextManagement, findings.SubjectAsset, dev)
	if got == nil || got.state != producer.StateInactive {
		t.Errorf("the finding is %v after the collector that raised it reported telnet off, want INACTIVE", got)
	}
}

func TestIntegration_ConfigurationProducer_HTTPSOnlyIsAnsweredAndClean(t *testing.T) {
	f := newConfigFixture(t)
	ctx := context.Background()
	dev := newManagedDevice(t, f, "fw-edge-2")
	base := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)

	interrogationRun(t, f.owner, f.tenant, dev, sourceRef(), "https", false, base)
	interrogationRun(t, f.owner, f.tenant, dev, sourceRef(), "https", false, base.Add(time.Hour))
	run := f.run(t, ctx)

	if got := f.finding(t, findings.KindPlaintextManagement, findings.SubjectAsset, dev); got != nil {
		t.Errorf("a device only ever reported as HTTPS-managed raised %v", got)
	}
	// The fixture's switch and firewall, plus this device.
	if run.PlaintextAssessed != 3 {
		t.Errorf("PlaintextAssessed = %d, want 3 — an explicit false is an answer", run.PlaintextAssessed)
	}
	assessed := false
	for _, id := range assessedAssets(t, f.owner, f.tenant, findings.ProducerConfiguration) {
		if id == dev.String() {
			assessed = true
		}
	}
	if !assessed {
		t.Error("the HTTPS-managed device was not claimed as assessed")
	}
}

// Two plaintext channels at once are both named, and the web channel's own
// later HTTPS answer retracts HTTP without touching SNMP.
func TestIntegration_ConfigurationProducer_EveryPlaintextChannelIsNamed(t *testing.T) {
	f := newConfigFixture(t)
	ctx := context.Background()
	dev := newManagedDevice(t, f, "ctrl-1")
	base := time.Now().Add(-3 * time.Hour).UTC().Truncate(time.Second)

	interrogationRun(t, f.owner, f.tenant, dev, sourceRef(), "snmpv2c", true, base)
	interrogationRun(t, f.owner, f.tenant, dev, sourceRef(), "http", true, base.Add(time.Hour))
	f.run(t, ctx)
	got := f.finding(t, findings.KindPlaintextManagement, findings.SubjectAsset, dev)
	if got == nil || got.state != producer.StateActive {
		t.Fatalf("no ACTIVE finding: %v", got)
	}
	if got.evidence["mgmt_protocol"] != "http, snmpv2c" {
		t.Errorf("evidence.mgmt_protocol = %v, want both plaintext protocols", got.evidence["mgmt_protocol"])
	}
	if !strings.Contains(got.summary, "(http, snmpv2c)") {
		t.Errorf("summary %q does not name both plaintext protocols", got.summary)
	}

	interrogationRun(t, f.owner, f.tenant, dev, sourceRef(), "https", false, base.Add(2*time.Hour))
	f.run(t, ctx)
	got = f.finding(t, findings.KindPlaintextManagement, findings.SubjectAsset, dev)
	if got == nil || got.state != producer.StateActive {
		t.Fatalf("the finding is %v; SNMP v2c is still plaintext", got)
	}
	if got.evidence["mgmt_protocol"] != "snmpv2c" {
		t.Errorf("evidence.mgmt_protocol = %v after the controller moved to HTTPS, want snmpv2c only", got.evidence["mgmt_protocol"])
	}
}

// Expiry follows the producer's existing contract (expired_facts_integration_test.go):
// an expired answer is "stopped knowing", which neither re-asserts the finding
// nor resolves it. A current answer about ANOTHER channel does not change that.
func TestIntegration_ConfigurationProducer_ExpiredSNMPBesideCurrentHTTPSIsWithheld(t *testing.T) {
	f := newConfigFixture(t)
	ctx := context.Background()
	dev := newManagedDevice(t, f, "edge-rtr-2")
	base := time.Now().Add(-3 * time.Hour).UTC().Truncate(time.Second)

	interrogationRun(t, f.owner, f.tenant, dev, sourceRef(), "snmpv2c", true, base)
	f.run(t, ctx)
	first := f.finding(t, findings.KindPlaintextManagement, findings.SubjectAsset, dev)
	if first == nil {
		t.Fatal("no finding from SNMP v2c")
	}

	exec(t, f.owner, `UPDATE asset_facts SET expires_at = now() - interval '1 day'
	                  WHERE tenant_id = $1 AND asset_id = $2`, f.tenant, dev)
	interrogationRun(t, f.owner, f.tenant, dev, sourceRef(), "https", false, base.Add(time.Hour))
	run := f.run(t, ctx)

	if run.FactsExpired != 1 {
		t.Errorf("FactsExpired = %d, want 1", run.FactsExpired)
	}
	got := f.finding(t, findings.KindPlaintextManagement, findings.SubjectAsset, dev)
	if got == nil || got.state != producer.StateActive {
		t.Errorf("the finding is %v, want ACTIVE — the SNMP answer expired, it was not retracted", got)
	}
	if got != nil && got.occurrence != first.occurrence {
		t.Errorf("occurrence_count moved %d → %d: an expired answer was re-asserted", first.occurrence, got.occurrence)
	}
}
