package producers

// `asset_endpoints.status = 'stale'` now has a writer (the hygiene pass), and
// every OTHER producer that reads the column has to be told what the new value
// means before it starts seeing it.
//
// `stale` is not `closed`. `closed` is a host's authoritative "this socket is
// gone"; `stale` says only that nothing has looked for thirty days. A reader
// that treats them alike turns the hygiene pass's first stale marking into a
// statement it never made:
//
//   - the `configuration` producer would stop asserting its exposure findings,
//     and a producer that stops asserting SWEEPS — publishing "no longer
//     detected" on a Telnet port nobody turned off;
//   - the `drift` producer would drop the port out of the live profile and
//     raise `port_profile_changed` saying it closed — drift invented by a
//     collector going quiet rather than by anything on the host.
//
// Mutation: put either read back to `status = 'active'` and the matching test
// below goes red. Both polarities are pinned — a genuinely CLOSED endpoint must
// still resolve (configuration_producer_integration_test.go's third pass) and
// must still read as closed drift.
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer"
)

func TestIntegration_ConfigurationProducer_StaleEndpointIsNotAssessedAndDoesNotResolve(t *testing.T) {
	f := newConfigFixture(t)
	ctx := context.Background()

	first := f.run(t, ctx)
	before := f.finding(t, findings.KindPlaintextManagement, findings.SubjectEndpoint, f.telnetEP)
	if before == nil || before.state != producer.StateActive {
		t.Fatalf("no ACTIVE plaintext_management finding on the Telnet endpoint after the first pass: %v", before)
	}
	if first.EndpointsUnobserved != 0 {
		t.Errorf("run.EndpointsUnobserved = %d on a fixture whose endpoints are all active, want 0",
			first.EndpointsUnobserved)
	}

	// Nothing has observed the socket for thirty days, so the hygiene pass marks
	// it stale. Nobody said Telnet was switched off.
	exec(t, f.owner, `UPDATE asset_endpoints SET status = 'stale' WHERE id = $1 AND tenant_id = $2`,
		f.telnetEP, f.tenant)

	run := f.run(t, ctx)
	if run.EndpointsUnobserved != 1 {
		t.Errorf("run.EndpointsUnobserved = %d, want 1 — a pass that skipped an endpoint has to say so",
			run.EndpointsUnobserved)
	}
	if run.Endpoints != first.Endpoints-1 {
		t.Errorf("run.Endpoints = %d, want %d — a stale endpoint is read, not judged",
			run.Endpoints, first.Endpoints-1)
	}

	after := f.finding(t, findings.KindPlaintextManagement, findings.SubjectEndpoint, f.telnetEP)
	if after == nil {
		t.Fatal("the finding vanished entirely")
	}
	if after.occurrence != before.occurrence {
		t.Errorf("occurrence_count moved from %d to %d — the producer re-asserted a finding about "+
			"an endpoint nothing has observed", before.occurrence, after.occurrence)
	}
	if after.state != producer.StateActive {
		t.Errorf("detection_state = %q after the endpoint went stale, want ACTIVE — a socket nobody "+
			"looked at is not a socket somebody closed", after.state)
	}
}

// The drift half: a stale endpoint is still part of the asset's port profile.
//
// The window has to be LONGER than the stale threshold for the bug to be
// reachable, which is a setting a tenant can make (7–365 days) and this is the
// shape it takes: a port last seen 45 days ago is inside a 90-day window, so
// "not live" there reads as "closed inside the window" and raises a finding.
func TestIntegration_DriftProducer_StaleEndpointIsNotAClosedPort(t *testing.T) {
	f := newDriftFixture(t)
	ctx := context.Background()
	f.setBaselineDays(t, 90)

	// A port that has been on this host since long before the window and was
	// last observed 45 days ago — inside the 90-day window, outside the 30-day
	// stale threshold, so the hygiene pass has marked it stale.
	staleEP := f.addEndpoint(t, f.assetID, 8080, "tcp", "TLS", f.daysAgo(settledDays), f.daysAgo(45), "stale", nil)

	if got := f.run(t, ctx); got.Raised != 0 {
		t.Errorf("a pass over a host whose only change is one endpoint going quiet raised %d findings, want 0",
			got.Raised)
	}
	if got := f.finding(t, findings.KindPortProfileChanged, f.assetID); got != nil &&
		got.state == producer.StateActive {
		t.Errorf("port_profile_changed raised for a STALE endpoint: %v — nothing observed the socket, "+
			"which is not the same as a host reporting it closed", got.evidence)
	}

	// The polarity: a host that actually reports the socket gone IS drift.
	exec(t, f.owner, `UPDATE asset_endpoints SET status = 'closed' WHERE id = $1 AND tenant_id = $2`,
		staleEP, f.tenant)
	f.run(t, ctx)
	got := f.finding(t, findings.KindPortProfileChanged, f.assetID)
	if got == nil || got.state != producer.StateActive {
		t.Fatalf("no port_profile_changed after the host reported 8080 closed: %v", got)
	}
}
