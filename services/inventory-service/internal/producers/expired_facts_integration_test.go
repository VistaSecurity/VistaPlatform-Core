package producers

// `asset_facts.expires_at` is honoured by the two producers that judge from
// facts, and an expired fact is NOT ASSESSED — never "clean".
//
// The compliance fact shape has honoured the column since it was written
// (scope_probe.go: "an expired fact has stopped being an answer"). The
// `configuration` and `eol` producers read the same table and did not, so an
// interrogation fact with a deliberately short life went on producing findings
// forever after it stopped being true.
//
// Honouring it naively is the OTHER bug, and it is the worse one: an expired
// fact read as "absent" makes the producer stop asserting the finding, and a
// producer that stops asserting something sweeps it INACTIVE. The asset page
// then shows "no longer detected" for a condition nobody fixed and nobody
// re-measured. So each test here asserts BOTH halves — no new finding AND no
// resolve of an existing one.
//
// Mutation: delete the `withheld` seeding from either producer's write phase and
// the "still ACTIVE" assertion fails; delete the `expires_at` clause from either
// read and the "no finding" assertion fails.
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer"
)

// expireFacts pushes every fact of the given keys on one asset past its
// expiry. `expires_at` in the past is the whole point — a NULL column means
// "does not expire" and must keep behaving exactly as it did.
func expireFacts(t *testing.T, f *configFixture, assetID uuid.UUID, keys ...string) {
	t.Helper()
	for _, k := range keys {
		exec(t, f.owner, `UPDATE asset_facts SET expires_at = now() - interval '1 day'
		                  WHERE tenant_id = $1 AND asset_id = $2 AND key = $3`,
			f.tenant, assetID, k)
	}
}

func TestIntegration_ConfigurationProducer_ExpiredFactIsNotAssessedAndDoesNotResolve(t *testing.T) {
	f := newConfigFixture(t)
	ctx := context.Background()

	// Pass one, with the fact current: the switch is managed over Telnet.
	f.run(t, ctx)
	first := f.finding(t, findings.KindPlaintextManagement, findings.SubjectAsset, f.switchID)
	if first == nil || first.state != producer.StateActive {
		t.Fatalf("no ACTIVE plaintext_management finding on the switch after a pass with a live fact: %v", first)
	}

	// The interrogation's answer expires. Nothing about the device changed and
	// nobody looked again.
	expireFacts(t, f, f.switchID, "mgmt.plaintext", "mgmt.protocol")

	run := f.run(t, ctx)
	if run.FactsExpired != 1 {
		t.Errorf("run.FactsExpired = %d, want 1 — a pass that skipped an asset has to say so", run.FactsExpired)
	}
	if run.PlaintextAssessed != 1 {
		t.Errorf("run.PlaintextAssessed = %d, want 1 (the clean firewall only) — an expired fact "+
			"is not coverage", run.PlaintextAssessed)
	}

	// Half one: nothing new was raised from the expired fact.
	after := f.finding(t, findings.KindPlaintextManagement, findings.SubjectAsset, f.switchID)
	if after == nil {
		t.Fatal("the finding vanished entirely")
	}
	if after.occurrence != first.occurrence {
		t.Errorf("occurrence_count moved from %d to %d — the producer re-asserted a finding it "+
			"could not evaluate", first.occurrence, after.occurrence)
	}
	// Half two, and the one that matters: it was NOT resolved. "We stopped
	// knowing" is not "somebody turned Telnet off".
	if after.state != producer.StateActive {
		t.Errorf("detection_state = %q after the fact expired, want ACTIVE — sweeping a subject "+
			"the pass could not evaluate publishes a fix nobody made", after.state)
	}
}

// The polarity that stops the fix from being "never sweep anything": a fact
// that is simply GONE is still a resolve, because absence is an answer.
func TestIntegration_ConfigurationProducer_AbsentFactStillResolves(t *testing.T) {
	f := newConfigFixture(t)
	ctx := context.Background()

	f.run(t, ctx)
	if got := f.finding(t, findings.KindPlaintextManagement, findings.SubjectAsset, f.switchID); got == nil {
		t.Fatal("no plaintext_management finding on the switch after the first pass")
	}

	exec(t, f.owner, `DELETE FROM asset_facts WHERE tenant_id = $1 AND asset_id = $2 AND key = 'mgmt.plaintext'`,
		f.tenant, f.switchID)

	run := f.run(t, ctx)
	if run.FactsExpired != 0 {
		t.Errorf("run.FactsExpired = %d for a deleted fact, want 0 — deleted is not expired", run.FactsExpired)
	}
	got := f.finding(t, findings.KindPlaintextManagement, findings.SubjectAsset, f.switchID)
	if got == nil || got.state != producer.StateInactive {
		t.Errorf("the finding is %v after the fact was removed, want INACTIVE — a fact that is "+
			"gone is an answer, and only an EXPIRED one is a refusal to answer", got)
	}
}

// A fact that expires and is then re-measured must not churn.
//
// The whole point of withholding the subject from the sweep is that the finding
// is never resolved, so the re-measurement re-asserts the SAME row rather than
// resolving one and opening another. A resolve/reopen pair would reach the user
// as "fixed" followed by "back again" for a Telnet port that was never off, and
// `resurfaced_at` — which the Findings page renders as "this came back" — would
// be set on a finding that never went anywhere.
func TestIntegration_ConfigurationProducer_ExpiredThenReobservedDoesNotChurn(t *testing.T) {
	f := newConfigFixture(t)
	ctx := context.Background()

	f.run(t, ctx)
	first := f.finding(t, findings.KindPlaintextManagement, findings.SubjectAsset, f.switchID)
	if first == nil || first.state != producer.StateActive {
		t.Fatalf("no ACTIVE finding after the first pass: %v", first)
	}

	expireFacts(t, f, f.switchID, "mgmt.plaintext", "mgmt.protocol")
	f.run(t, ctx)

	// The device is interrogated again and says the same thing.
	exec(t, f.owner, `UPDATE asset_facts SET expires_at = now() + interval '30 days', observed_at = now()
	                  WHERE tenant_id = $1 AND asset_id = $2 AND key IN ('mgmt.plaintext', 'mgmt.protocol')`,
		f.tenant, f.switchID)

	run := f.run(t, ctx)
	if run.Resolved != 0 {
		t.Errorf("the re-measurement pass resolved %d findings; nothing went away", run.Resolved)
	}
	after := f.finding(t, findings.KindPlaintextManagement, findings.SubjectAsset, f.switchID)
	if after == nil {
		t.Fatal("the finding vanished entirely")
	}
	if after.id != first.id {
		t.Errorf("the re-measurement wrote a NEW finding row (%s, was %s) — one condition, one finding",
			after.id, first.id)
	}
	if after.state != producer.StateActive {
		t.Errorf("detection_state = %q, want ACTIVE", after.state)
	}
	if after.resurfaced {
		t.Error("resurfaced_at is set — the finding never went inactive, so nothing came back")
	}
	// Two assertions, not three: the expired pass asserted nothing.
	if after.occurrence != 2 {
		t.Errorf("occurrence_count = %d after assert / expire / assert, want 2", after.occurrence)
	}
}

// A fact with a FUTURE expires_at is current and changes nothing. Without this,
// a read that treated any non-NULL expires_at as expired would pass every other
// test here.
func TestIntegration_ConfigurationProducer_UnexpiredExpiryIsStillAnAnswer(t *testing.T) {
	f := newConfigFixture(t)
	ctx := context.Background()

	exec(t, f.owner, `UPDATE asset_facts SET expires_at = now() + interval '30 days'
	                  WHERE tenant_id = $1 AND asset_id = $2`, f.tenant, f.switchID)

	run := f.run(t, ctx)
	if run.FactsExpired != 0 {
		t.Errorf("run.FactsExpired = %d for a fact that expires in 30 days, want 0", run.FactsExpired)
	}
	got := f.finding(t, findings.KindPlaintextManagement, findings.SubjectAsset, f.switchID)
	if got == nil || got.state != producer.StateActive {
		t.Errorf("a fact with a future expiry raised %v, want an ACTIVE finding", got)
	}
}

// The same rule, in the producer that reads os.* and hw.* facts.
//
// The eol producer's finding is about a DATE it looked up from a fact. When the
// fact expires the lookup is not repeated, so the finding is neither confirmed
// nor refuted — and a sweep would refute it.
func TestIntegration_EOLProducer_ExpiredOSFactIsNotAssessedAndDoesNotResolve(t *testing.T) {
	f := newEOLFixture(t)
	ctx := context.Background()

	f.run(t, ctx)
	first := f.finding(t, findings.KindOSEndOfLife, findings.SubjectAsset, f.assetID)
	if first == nil || first.state != producer.StateActive {
		t.Fatalf("no ACTIVE os_end_of_life finding after a pass with live os.* facts: %v", first)
	}

	exec(t, f.owner, `UPDATE asset_facts SET expires_at = now() - interval '1 day'
	                  WHERE tenant_id = $1 AND asset_id = $2 AND key IN ('os.name', 'os.version')`,
		f.tenant, f.assetID)

	run := f.run(t, ctx)
	if run.FactsExpired != 1 {
		t.Errorf("run.FactsExpired = %d, want 1", run.FactsExpired)
	}
	after := f.finding(t, findings.KindOSEndOfLife, findings.SubjectAsset, f.assetID)
	if after == nil {
		t.Fatal("the finding vanished entirely")
	}
	if after.occurrence != first.occurrence {
		t.Errorf("occurrence_count moved from %d to %d — the producer re-asserted a finding it "+
			"could not evaluate", first.occurrence, after.occurrence)
	}
	if after.state != producer.StateActive {
		t.Errorf("detection_state = %q after the os facts expired, want ACTIVE", after.state)
	}
	// The SOFTWARE finding beside it is untouched: its subject is an install,
	// not a fact, and one kind's refusal to answer must not hold another kind's
	// sweep. A withheld subject is per (kind, subject), not per pass.
	if sw := f.finding(t, findings.KindSoftwareEndOfLife, findings.SubjectSoftwareInstall, f.installID); sw == nil ||
		sw.state != producer.StateActive {
		t.Errorf("the software finding is %v after the OS facts expired; it reads no facts at all", sw)
	}
}

// The polarity: the os facts simply CHANGE to something supported and the
// finding resolves as it always did.
func TestIntegration_EOLProducer_LiveFactsStillResolve(t *testing.T) {
	f := newEOLFixture(t)
	ctx := context.Background()

	f.run(t, ctx)
	if got := f.finding(t, findings.KindOSEndOfLife, findings.SubjectAsset, f.assetID); got == nil {
		t.Fatal("no os_end_of_life finding after the first pass")
	}

	exec(t, f.owner, `UPDATE asset_facts SET value = '"99.04 LTS"'
	                  WHERE tenant_id = $1 AND asset_id = $2 AND key = 'os.version'`,
		f.tenant, f.assetID)

	run := f.run(t, ctx)
	if run.FactsExpired != 0 {
		t.Errorf("run.FactsExpired = %d, want 0 — nothing expired", run.FactsExpired)
	}
	got := f.finding(t, findings.KindOSEndOfLife, findings.SubjectAsset, f.assetID)
	if got == nil || got.state != producer.StateInactive {
		t.Errorf("the finding is %v after the OS was upgraded, want INACTIVE", got)
	}
}
