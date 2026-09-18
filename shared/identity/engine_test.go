package identity_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/memory"
)

const tenant = "tenant-a"

var observedAt = time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)

func newEngine(t *testing.T, cfg identity.Config) (*identity.Engine, *memory.Repository) {
	t.Helper()
	repo := memory.New()
	cfg.Repo = repo
	e, err := identity.New(cfg)
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	return e, repo
}

func id(kind identity.Kind, value string) identity.Identifier {
	return identity.Identifier{Kind: kind, Value: value, Confidence: 1}
}

func scoped(kind identity.Kind, value, scope string) identity.Identifier {
	return identity.Identifier{Kind: kind, Value: value, Scope: scope, Confidence: 1}
}

func obs(classHint string, ids ...identity.Identifier) identity.Observation {
	return identity.Observation{
		TenantID:    tenant,
		ClassHint:   classHint,
		Identifiers: ids,
		Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "sensor", Mode: identity.ModePassive},
		ObservedAt:  observedAt,
		Confidence:  0.9,
	}
}

func mustResolve(t *testing.T, e *identity.Engine, o identity.Observation) identity.Resolution {
	t.Helper()
	res, err := e.Resolve(context.Background(), o)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return res
}

// ── outcomes ───────────────────────────────────────────────────────────────

func TestResolveCreatesWhenNothingMatches(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	res := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-1")))

	if res.Outcome != identity.OutcomeCreated {
		t.Fatalf("outcome = %s, want created", res.Outcome)
	}
	if res.Asset.ID == "" || res.Asset.TenantID != tenant {
		t.Fatalf("created asset ref = %+v", res.Asset)
	}
	if res.ClassKey != assetclass.KeyServer {
		t.Errorf("class = %q, want %q", res.ClassKey, assetclass.KeyServer)
	}
	if got := repo.Identifiers(res.Asset); len(got) != 1 || got[0].Value != "SN-1" {
		t.Errorf("identifiers = %+v, want the serial attached", got)
	}
	assertHistory(t, repo, res.Asset.ID, identity.ActionCreated)
}

func TestResolveMatchesOnSerialAndUpdates(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	first := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-1")))

	second := obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-1"), id(identity.KindMACAddress, "AA:BB:CC:DD:EE:01"))
	second.ObservedAt = observedAt.Add(time.Hour)
	second.Endpoints = []identity.EndpointObservation{{Address: "192.0.2.10", Port: 443, Transport: "tcp"}}

	res := mustResolve(t, e, second)
	if res.Outcome != identity.OutcomeMatched {
		t.Fatalf("outcome = %s, want matched", res.Outcome)
	}
	if res.Asset.ID != first.Asset.ID {
		t.Fatalf("matched %s, want the asset created first (%s)", res.Asset.ID, first.Asset.ID)
	}
	if res.DecidedBy != identity.KindSerialNumber {
		t.Errorf("decided_by = %q, want serial_number", res.DecidedBy)
	}
	if repo.AssetCount() != 1 {
		t.Errorf("a match created a second asset: %d assets exist", repo.AssetCount())
	}
	// The new identifier was attached, normalised.
	if got := repo.Identifiers(res.Asset); len(got) != 2 {
		t.Fatalf("identifiers = %+v, want the serial and the MAC", got)
	} else if got[1].Value != "aa:bb:cc:dd:ee:01" {
		t.Errorf("MAC stored as %q, want it normalised", got[1].Value)
	}
	if eps := repo.Endpoints(res.Asset); len(eps) != 1 || eps[0].Port != 443 {
		t.Errorf("endpoints = %+v, want the 443 endpoint upserted", eps)
	}
	if last := repo.LastSeen(res.Asset); !last.Equal(observedAt.Add(time.Hour)) {
		t.Errorf("last seen = %v, want it advanced to the new sighting", last)
	}
	assertHistory(t, repo, res.Asset.ID, identity.ActionCreated, identity.ActionUpdated)
}

func TestResolvePromotesLinux2OverHexLocal(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	first := obs(assetclass.KeyUnknownHost,
		scoped(identity.KindHostname, "4c6e0a87d480.local", identity.ScopeTenantDefault),
		scoped(identity.KindIPAddress, "192.168.1.68", identity.ScopeTenantDefault),
	)
	first.Hostname = "4c6e0a87d480.local"
	first.DisplayName = "4c6e0a87d480.local"
	created := mustResolve(t, e, first)
	if repo.Hostname(created.Asset) != "4c6e0a87d480.local" {
		t.Fatalf("created hostname = %q, want the first-seen hex .local", repo.Hostname(created.Asset))
	}

	second := obs(assetclass.KeyUnknownHost,
		scoped(identity.KindHostname, "linux-2", identity.ScopeTenantDefault),
		scoped(identity.KindIPAddress, "192.168.1.68", identity.ScopeTenantDefault),
	)
	second.Hostname = "linux-2"
	second.ObservedAt = observedAt.Add(time.Minute)
	matched := mustResolve(t, e, second)
	if matched.Outcome != identity.OutcomeMatched || matched.Asset.ID != created.Asset.ID {
		t.Fatalf("outcome = %s asset %s, want matched on %s", matched.Outcome, matched.Asset.ID, created.Asset.ID)
	}
	if got := repo.Hostname(matched.Asset); got != "linux-2" {
		t.Fatalf("hostname after linux-2 = %q", got)
	}
	if got := repo.DisplayName(matched.Asset); got != "linux-2" {
		t.Fatalf("display after linux-2 = %q", got)
	}

	third := first
	third.ObservedAt = observedAt.Add(2 * time.Minute)
	again := mustResolve(t, e, third)
	if got := repo.Hostname(again.Asset); got != "linux-2" {
		t.Fatalf("later hex mDNS reverted hostname to %q", got)
	}

	repo.SetNameSourceDeclared(created.Asset)
	fourth := second
	fourth.Hostname = "bobbydubs"
	fourth.ObservedAt = observedAt.Add(3 * time.Minute)
	_ = mustResolve(t, e, fourth)
	if got := repo.Hostname(created.Asset); got != "linux-2" {
		t.Fatalf("declared name was overwritten: %q", got)
	}
}

// TestResolvePrecedenceHigherKindDecides is the mutation target for the
// precedence walk: a lower-precedence kind matching the same asset must NOT
// take the decision from a higher one.
func TestResolvePrecedenceHigherKindDecides(t *testing.T) {
	e, _ := newEngine(t, identity.Config{})
	create := obs(assetclass.KeyServer,
		id(identity.KindSerialNumber, "SN-1"),
		scoped(identity.KindHostname, "host-1", "segment-1"),
	)
	first := mustResolve(t, e, create)

	// Both identifiers now point at the same asset; the serial outranks the
	// hostname, so the serial must be reported as the deciding evidence.
	res := mustResolve(t, e, create)
	if res.Outcome != identity.OutcomeMatched || res.Asset.ID != first.Asset.ID {
		t.Fatalf("outcome = %s on %s, want matched on %s", res.Outcome, res.Asset.ID, first.Asset.ID)
	}
	if res.DecidedBy != identity.KindSerialNumber {
		t.Fatalf("decided_by = %q, want serial_number: a lower-precedence kind must not override a higher one", res.DecidedBy)
	}
}

func TestResolveSerialBeatsHostnameAcrossAssets(t *testing.T) {
	// A serial pointing at A and a hostname pointing at B is a cross-kind
	// disagreement, not a silent win for the serial (ADR-0002 D3 row 3).
	e, repo := newEngine(t, identity.Config{})
	a := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-1")))
	b := mustResolve(t, e, obs(assetclass.KeyServer, scoped(identity.KindHostname, "host-1", "segment-1")))

	res := mustResolve(t, e, obs(assetclass.KeyServer,
		id(identity.KindSerialNumber, "SN-1"),
		scoped(identity.KindHostname, "host-1", "segment-1"),
	))
	if res.Outcome != identity.OutcomeConflict {
		t.Fatalf("outcome = %s, want conflict: the serial says %s and the hostname says %s", res.Outcome, a.Asset.ID, b.Asset.ID)
	}
	if len(res.Candidates) != 2 {
		t.Fatalf("candidates = %+v, want both assets", res.Candidates)
	}
	if res.Proposal.ID == "" {
		t.Error("a conflict opened no merge proposal")
	}
	// THE FLOOR. Every identifier this observation carries is already owned —
	// the serial by A, the hostname by B — so the "observation asset" the
	// engine used to create here would have carried NONE, and an asset with no
	// identifier can never be matched again: the next observation of the same
	// host makes another one, and so on at the sensor's polling rate. The
	// proposal alone is the honest record.
	if repo.AssetCount() != 2 {
		t.Errorf("%d assets exist, want 2: when EVERY identifier is already owned there is nothing "+
			"left to attach, and an asset with no identifier must never be created", repo.AssetCount())
	}
	if !res.Asset.Zero() {
		t.Errorf("resolution names asset %s; nothing was written to any asset, so the ref must be zero "+
			"— returning a candidate here invites the caller to apply context to an asset the engine did not match", res.Asset.ID)
	}
}

func TestConflictStillCreatesWhenSomethingIsLeftToAttach(t *testing.T) {
	// The other half of the floor: a conflict whose observation carries an
	// identifier nobody owns DOES become its own pending asset, because that
	// asset can be recognised again. Without this the floor would have turned
	// ADR-0002 D3's third outcome into "never create", which is a different
	// rule and loses the observation.
	e, repo := newEngine(t, identity.Config{})
	_ = mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-1")))
	_ = mustResolve(t, e, obs(assetclass.KeyServer, scoped(identity.KindHostname, "host-1", "segment-1")))

	res := mustResolve(t, e, obs(assetclass.KeyServer,
		id(identity.KindSerialNumber, "SN-1"),
		scoped(identity.KindHostname, "host-1", "segment-1"),
		id(identity.KindMACAddress, "aa:bb:cc:dd:ee:01"), // nobody's
	))
	if res.Outcome != identity.OutcomeConflict {
		t.Fatalf("outcome = %s, want conflict", res.Outcome)
	}
	if res.Asset.Zero() {
		t.Fatal("no observation asset was created, but the MAC belongs to nobody and can identify it")
	}
	if repo.AssetCount() != 3 {
		t.Errorf("%d assets exist, want 3: the observation becomes its own pending asset", repo.AssetCount())
	}
	kinds := map[identity.Kind]bool{}
	for _, i := range repo.Identifiers(res.Asset) {
		kinds[i.Kind] = true
	}
	if !kinds[identity.KindMACAddress] {
		t.Error("the new pending asset carries no MAC; the uncontested identifier is exactly what makes it findable again")
	}
	if kinds[identity.KindSerialNumber] || kinds[identity.KindHostname] {
		t.Error("the new pending asset stole a contested identifier from a candidate")
	}
}

func TestResolveConflictOnSameKindMultiMatch(t *testing.T) {
	// The unique index makes this impossible in a healthy store, which is why
	// FindByIdentifier returns a slice: a store that has lost the invariant
	// must be detectable rather than silently picking one.
	e, repo := newEngine(t, identity.Config{})
	a := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-1")))
	b := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-2")))
	repo.Corrupt(tenant, identity.Identifier{Kind: identity.KindSerialNumber, Value: "SN-1"}, b.Asset)

	res := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-1")))
	if res.Outcome != identity.OutcomeConflict {
		t.Fatalf("outcome = %s, want conflict when one identifier resolves to two assets", res.Outcome)
	}
	ids := map[string]bool{}
	for _, c := range res.Candidates {
		ids[c.Ref.ID] = true
	}
	if !ids[a.Asset.ID] || !ids[b.Asset.ID] {
		t.Errorf("candidates = %+v, want both %s and %s", res.Candidates, a.Asset.ID, b.Asset.ID)
	}
	props := repo.Proposals()
	if len(props) != 1 {
		t.Fatalf("%d proposals opened, want 1", len(props))
	}
	if props[0].AutoAccepted {
		t.Error("the proposal was auto-accepted at the default threshold")
	}
	for _, c := range props[0].Candidates {
		if len(c.MatchedIdentifiers) == 0 {
			t.Errorf("candidate %s carries no matched identifiers; a proposal with no evidence can only be rubber-stamped", c.Ref.ID)
		}
	}
	// The one identifier is owned by both corrupted rows, so nothing is left to
	// attach and nothing is created (the floor). The proposal hangs off the
	// first candidate, and so does its history entry — it is the only asset in
	// the picture.
	if !res.Asset.Zero() {
		t.Errorf("resolution names asset %s; with every identifier owned there is nothing to create", res.Asset.ID)
	}
	if repo.AssetCount() != 2 {
		t.Errorf("%d assets exist, want 2", repo.AssetCount())
	}
	assertHistory(t, repo, res.Candidates[0].Ref.ID, identity.ActionCreated, identity.ActionMergeProposed)
}

func TestResolveConflictDoesNotStealTheCandidatesIdentifiers(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	a := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-1")))
	_ = mustResolve(t, e, obs(assetclass.KeyServer, scoped(identity.KindHostname, "host-1", "segment-1")))

	res := mustResolve(t, e, obs(assetclass.KeyServer,
		id(identity.KindSerialNumber, "SN-1"),
		scoped(identity.KindHostname, "host-1", "segment-1"),
		id(identity.KindCloudResourceID, "arn:aws:ec2:1"),
	))
	if res.Outcome != identity.OutcomeConflict {
		t.Fatalf("outcome = %s, want conflict", res.Outcome)
	}
	// The serial still belongs to A.
	owner, err := repo.FindByIdentifier(context.Background(), tenant, identity.KindSerialNumber, "SN-1", "")
	if err != nil {
		t.Fatalf("FindByIdentifier: %v", err)
	}
	if len(owner) != 1 || owner[0].ID != a.Asset.ID {
		t.Fatalf("SN-1 now resolves to %+v, want it still on %s", owner, a.Asset.ID)
	}
	// The unowned identifier went onto the new pending asset; the contested
	// ones are reported as unattached rather than dropped.
	if got := repo.Identifiers(res.Asset); len(got) != 1 || got[0].Kind != identity.KindCloudResourceID {
		t.Errorf("new asset carries %+v, want only the uncontested cloud id", got)
	}
	if len(res.Unattached) != 2 {
		t.Errorf("unattached = %+v, want the serial and the hostname", res.Unattached)
	}
}

// ── scope rules ────────────────────────────────────────────────────────────

func TestHostnameWithNoSegmentTakesTheTenantDefaultScopeAndMatches(t *testing.T) {
	// ADR-0002 D3 erratum (the default scope). A hostname with no segment is
	// scoped to the TENANT, not left unscoped, so the second observation of the
	// same host in the same tenant MATCHES.
	//
	// It used to create. That is the defect this erratum exists for: a tenant
	// with no segments configured — every fresh tenant — got one new asset per
	// observation, each after the first carrying no identifier at all, because
	// the hostname belonged to the first asset and could not vote. Measured
	// before the fix: one host ingested three times became three assets.
	e, repo := newEngine(t, identity.Config{})
	first := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindHostname, "host-1")))
	if got := repo.Identifiers(first.Asset); len(got) != 1 || got[0].Scope != identity.ScopeTenantDefault {
		t.Fatalf("identifiers = %+v, want the hostname scoped to %q", got, identity.ScopeTenantDefault)
	}

	res := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindHostname, "host-1")))
	if res.Outcome != identity.OutcomeMatched || res.Asset.ID != first.Asset.ID {
		t.Fatalf("outcome = %s on %s, want matched on %s: in a tenant with no segments the default scope "+
			"is what lets a hostname decide anything at all", res.Outcome, res.Asset.ID, first.Asset.ID)
	}
	if res.DecidedBy != identity.KindHostname {
		t.Errorf("decided_by = %q, want hostname", res.DecidedBy)
	}
	if repo.AssetCount() != 1 {
		t.Errorf("%d assets, want 1: one host observed twice is one asset", repo.AssetCount())
	}
}

func TestSegmentScopedAndDefaultScopedHostnamesAreDifferentIdentifiers(t *testing.T) {
	// The default scope is a scope like any other, not a wildcard. A host
	// identified inside segment-1 and a host of the same name identified
	// nowhere in particular are two keys and two assets — which is why a tenant
	// that later CREATES segments may see merge proposals: it has just told us
	// two things it used to call one might be two, and a human settles it.
	e, repo := newEngine(t, identity.Config{})
	first := mustResolve(t, e, obs(assetclass.KeyServer, scoped(identity.KindHostname, "host-1", "segment-1")))
	res := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindHostname, "host-1")))

	if res.Outcome != identity.OutcomeCreated || res.Asset.ID == first.Asset.ID {
		t.Fatalf("outcome = %s on %s, want a new asset: the tenant-default scope is not segment-1", res.Outcome, res.Asset.ID)
	}
	// Different keys, so nothing is contested and the identifier is attached.
	if len(res.Unattached) != 0 {
		t.Errorf("unattached = %+v, want none: the default-scoped key is free", res.Unattached)
	}
	if got := repo.Identifiers(res.Asset); len(got) != 1 || got[0].Scope != identity.ScopeTenantDefault {
		t.Errorf("identifiers = %+v, want the hostname scoped to %q", got, identity.ScopeTenantDefault)
	}
}

func TestHostnameInADifferentScopeDoesNotMatch(t *testing.T) {
	e, _ := newEngine(t, identity.Config{})
	first := mustResolve(t, e, obs(assetclass.KeyServer, scoped(identity.KindHostname, "printer-2", "segment-1")))
	res := mustResolve(t, e, obs(assetclass.KeyServer, scoped(identity.KindHostname, "printer-2", "segment-2")))

	if res.Outcome != identity.OutcomeCreated || res.Asset.ID == first.Asset.ID {
		t.Fatalf("outcome = %s on %s: printer-2 in segment-2 must not be printer-2 in segment-1 (%s)",
			res.Outcome, res.Asset.ID, first.Asset.ID)
	}
}

func TestHostnameWithScopeDoesMatch(t *testing.T) {
	e, _ := newEngine(t, identity.Config{})
	first := mustResolve(t, e, obs(assetclass.KeyServer, scoped(identity.KindHostname, "host-1", "segment-1")))
	res := mustResolve(t, e, obs(assetclass.KeyServer, scoped(identity.KindHostname, "host-1", "segment-1")))

	if res.Outcome != identity.OutcomeMatched || res.Asset.ID != first.Asset.ID {
		t.Fatalf("outcome = %s on %s, want matched on %s", res.Outcome, res.Asset.ID, first.Asset.ID)
	}
	if res.DecidedBy != identity.KindHostname {
		t.Errorf("decided_by = %q, want hostname", res.DecidedBy)
	}
}

func TestIPInADynamicScopeNeverMatches(t *testing.T) {
	e, repo := newEngine(t, identity.Config{DynamicScopes: map[string]bool{"dhcp-segment": true}})
	first := mustResolve(t, e, obs(assetclass.KeyServer, scoped(identity.KindIPAddress, "192.0.2.10", "dhcp-segment")))

	res := mustResolve(t, e, obs(assetclass.KeyServer, scoped(identity.KindIPAddress, "192.0.2.10", "dhcp-segment")))
	if res.Outcome != identity.OutcomeConflict {
		t.Fatalf("outcome = %s on %s, want conflict: today's DHCP lease is tomorrow's other host, so the "+
			"IP must not MATCH — and the address is already owned, so there is nothing to create either",
			res.Outcome, res.Asset.ID)
	}
	if !res.Asset.Zero() {
		t.Fatalf("resolution names asset %s; the only identifier belongs to %s, so an asset created here "+
			"would carry none and could never be matched again", res.Asset.ID, first.Asset.ID)
	}
	if res.Proposal.ID == "" {
		t.Error("no merge proposal: a human has to say whether this is the same host on the same lease")
	}
	// The identifier still belongs to the first asset and is reported, not dropped.
	if len(res.Unattached) != 1 {
		t.Errorf("unattached = %+v, want the contested IP", res.Unattached)
	}
	if repo.AssetCount() != 1 {
		t.Errorf("%d assets, want 1", repo.AssetCount())
	}
}

func TestIPInAStaticScopeMatches(t *testing.T) {
	e, _ := newEngine(t, identity.Config{DynamicScopes: map[string]bool{"dhcp-segment": true}})
	first := mustResolve(t, e, obs(assetclass.KeyServer, scoped(identity.KindIPAddress, "192.0.2.10", "static-segment")))
	res := mustResolve(t, e, obs(assetclass.KeyServer, scoped(identity.KindIPAddress, "192.0.2.10", "static-segment")))

	if res.Outcome != identity.OutcomeMatched || res.Asset.ID != first.Asset.ID {
		t.Fatalf("outcome = %s on %s, want matched on %s", res.Outcome, res.Asset.ID, first.Asset.ID)
	}
}

// ── class precedence ───────────────────────────────────────────────────────

func TestMACOnlyObservationNeverMatchesACloudResource(t *testing.T) {
	// A cloud class drops mac_address from its precedence (ADR-0002 D3: "a
	// cloud resource never identifies by MAC"). The identifier is recorded,
	// but it cannot decide.
	e, repo := newEngine(t, identity.Config{})
	first := mustResolve(t, e, obs(assetclass.KeyCloudResource,
		id(identity.KindCloudResourceID, "arn:aws:ec2:us-east-1:1:instance/i-1"),
		id(identity.KindMACAddress, "aa:bb:cc:dd:ee:01"),
	))

	res := mustResolve(t, e, obs(assetclass.KeyCloudResource, id(identity.KindMACAddress, "aa:bb:cc:dd:ee:01")))
	if res.Outcome == identity.OutcomeMatched {
		t.Fatalf("a MAC-only observation MATCHED cloud resource %s; a cloud resource never identifies by MAC", res.Asset.ID)
	}
	// It cannot match, and the MAC is already owned by that cloud resource, so
	// there is nothing left to attach either: the floor turns this into a
	// proposal rather than an asset with no identifier.
	if res.Outcome != identity.OutcomeConflict {
		t.Fatalf("outcome = %s, want conflict", res.Outcome)
	}
	if !res.Asset.Zero() {
		t.Fatalf("resolution names asset %s; the MAC belongs to %s, so an asset created here would carry none",
			res.Asset.ID, first.Asset.ID)
	}
	if repo.AssetCount() != 1 {
		t.Errorf("%d assets, want 1", repo.AssetCount())
	}

	// The same MAC against a class that DOES identify by it matches.
	hw := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindMACAddress, "aa:bb:cc:dd:ee:02")))
	again := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindMACAddress, "aa:bb:cc:dd:ee:02")))
	if again.Outcome != identity.OutcomeMatched || again.Asset.ID != hw.Asset.ID {
		t.Fatalf("server MAC: outcome = %s on %s, want matched on %s", again.Outcome, again.Asset.ID, hw.Asset.ID)
	}
}

func TestServiceIdentifiesByNameAndNothingElse(t *testing.T) {
	// ADR-0002 D3 erratum: "services identify by (tenant, class, name),
	// realised as the `name` identifier kind". business_service lists ONLY
	// `name`, so a hostname is recorded and cannot decide — falling back to the
	// default order would give a business service an IP-address identity, which
	// is the opposite of what the registry said.
	e, repo := newEngine(t, identity.Config{})

	// A hostname cannot DECIDE a service's identity: the class lists only
	// `name`, so the hostname is recorded and never votes. The first
	// observation still creates (the hostname is unowned, so there is something
	// to attach); the SECOND cannot match on it and, with nothing left to
	// attach, becomes a proposal rather than a duplicate.
	hostOnly := obs(assetclass.KeyBusinessService, scoped(identity.KindHostname, "payments", "segment-1"))
	byHost := mustResolve(t, e, hostOnly)
	if byHost.Outcome != identity.OutcomeCreated {
		t.Fatalf("outcome = %s, want created", byHost.Outcome)
	}
	again := mustResolve(t, e, hostOnly)
	if again.Outcome != identity.OutcomeConflict || !again.Asset.Zero() {
		t.Fatalf("second hostname-only observation: outcome = %s on %s, want a conflict that creates nothing "+
			"- a hostname must not identify a service, and it is already owned", again.Outcome, again.Asset.ID)
	}
	if repo.AssetCount() != 1 {
		t.Fatalf("%d assets, want 1: a service cannot be identified by a hostname, so it must not be "+
			"duplicated by one either", repo.AssetCount())
	}

	// By name it identifies, and identifies STABLY: the second observation of
	// the same service is the same service.
	named := obs(assetclass.KeyBusinessService, scoped(identity.KindName, "Payments  API", assetclass.KeyBusinessService))
	first := mustResolve(t, e, named)
	if first.Outcome != identity.OutcomeCreated {
		t.Fatalf("outcome = %s, want created", first.Outcome)
	}
	// Normalisation: trimmed, whitespace collapsed, lowercased.
	if got := repo.Identifiers(first.Asset); len(got) != 1 || got[0].Value != "payments api" {
		t.Fatalf("identifiers = %+v, want the name folded to %q", got, "payments api")
	}
	second := mustResolve(t, e, obs(assetclass.KeyBusinessService,
		scoped(identity.KindName, "  payments   api ", assetclass.KeyBusinessService)))
	if second.Outcome != identity.OutcomeMatched || second.Asset.ID != first.Asset.ID {
		t.Fatalf("outcome = %s on %s, want matched on %s: a declared name is how a service is identified",
			second.Outcome, second.Asset.ID, first.Asset.ID)
	}
	if second.DecidedBy != identity.KindName {
		t.Errorf("decided_by = %q, want name", second.DecidedBy)
	}
}

func TestNameOnlyIdentifiesWithinItsClass(t *testing.T) {
	// The `name` scope is the class key: a business service and a technical
	// service may share a name, and the class is what says they are different
	// things. An unscoped name takes the tenant default, which is a different
	// key again.
	e, _ := newEngine(t, identity.Config{})
	biz := mustResolve(t, e, obs(assetclass.KeyBusinessService,
		scoped(identity.KindName, "payments", assetclass.KeyBusinessService)))
	tech := mustResolve(t, e, obs(assetclass.KeyTechnicalService,
		scoped(identity.KindName, "payments", assetclass.KeyTechnicalService)))

	if tech.Outcome != identity.OutcomeCreated || tech.Asset.ID == biz.Asset.ID {
		t.Fatalf("outcome = %s on %s: a technical service named `payments` is not the business service of that name (%s)",
			tech.Outcome, tech.Asset.ID, biz.Asset.ID)
	}
}

func TestTenantPrecedenceOverride(t *testing.T) {
	// ADR-0002 D3 makes the order editable per tenant, and a tenant leaf
	// subclass is not in the generated registry at all.
	calls := 0
	e, _ := newEngine(t, identity.Config{
		Precedence: func(_ context.Context, tenantID, classKey string) ([]identity.Kind, bool) {
			calls++
			if classKey == "dell_poweredge" {
				return []identity.Kind{identity.KindSerialNumber}, true
			}
			return nil, false
		},
	})
	first := mustResolve(t, e, obs("dell_poweredge", id(identity.KindSerialNumber, "SN-1")))
	res := mustResolve(t, e, obs("dell_poweredge", id(identity.KindSerialNumber, "SN-1")))

	if calls == 0 {
		t.Fatal("the precedence hook was never consulted")
	}
	if res.Outcome != identity.OutcomeMatched || res.Asset.ID != first.Asset.ID {
		t.Fatalf("outcome = %s on %s, want matched on %s", res.Outcome, res.Asset.ID, first.Asset.ID)
	}
}

func TestNoClassHintUsesTheDefaultOrder(t *testing.T) {
	e, _ := newEngine(t, identity.Config{})
	first := mustResolve(t, e, obs("", id(identity.KindSerialNumber, "SN-1")))
	if first.ClassKey != assetclass.KeyUnknownHost {
		t.Errorf("class = %q, want unknown_host", first.ClassKey)
	}
	res := mustResolve(t, e, obs("", id(identity.KindSerialNumber, "SN-1")))
	if res.Outcome != identity.OutcomeMatched || res.Asset.ID != first.Asset.ID {
		t.Fatalf("outcome = %s, want matched with the default precedence", res.Outcome)
	}
}

func TestExternalOwnershipCreatesAnExternalAsset(t *testing.T) {
	for _, ownership := range []string{identity.OwnershipExternal, identity.OwnershipThirdParty} {
		t.Run(ownership, func(t *testing.T) {
			e, repo := newEngine(t, identity.Config{})
			o := obs("", id(identity.KindFQDN, "api.stripe.com"))
			o.Network = identity.Network{Ownership: ownership, Type: "public"}
			res := mustResolve(t, e, o)
			if res.ClassKey != assetclass.KeyExternal {
				t.Fatalf("class = %q, want external", res.ClassKey)
			}
			if got := repo.ClassOf(res.Asset); got != assetclass.KeyExternal {
				t.Errorf("stored class = %q, want external", got)
			}
		})
	}

	for _, ownership := range []string{identity.OwnershipInternal, identity.OwnershipUnknown, ""} {
		t.Run("inside/"+ownership, func(t *testing.T) {
			e, _ := newEngine(t, identity.Config{})
			o := obs("", scoped(identity.KindIPAddress, "10.1.2.3", "segment-1"))
			o.Network = identity.Network{Ownership: ownership, Type: "private", SegmentID: "segment-1"}
			res := mustResolve(t, e, o)
			if res.ClassKey != assetclass.KeyUnknownHost {
				t.Fatalf("class = %q for ownership %q, want unknown_host", res.ClassKey, ownership)
			}
		})
	}
}

func TestCreatedAssetIsPendingWithNotAssessedClassConfidence(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})

	t.Run("a fallback class is not assessed", func(t *testing.T) {
		o := obs("", id(identity.KindFQDN, "host.example.com"))
		o.Confidence = 0.75
		res := mustResolve(t, e, o)
		if res.ClassKey != assetclass.KeyUnknownHost {
			t.Fatalf("class = %q, want unknown_host", res.ClassKey)
		}
		// Confidence 0 means NOT ASSESSED. Carrying the observation's 0.75
		// across would claim the class was 75% likely, which nothing measured.
		if got := repo.ClassConfidence(res.Asset); got != 0 {
			t.Errorf("class confidence = %v for a fallback class, want 0 (not assessed)", got)
		}
		sums, err := repo.LoadSummaries(context.Background(), tenant, []string{res.Asset.ID})
		if err != nil || len(sums) != 1 {
			t.Fatalf("LoadSummaries = %+v (err %v)", sums, err)
		}
		if sums[0].Status != identity.StatusPendingApproval {
			t.Errorf("status = %q, want pending_approval: the engine never approves its own creations", sums[0].Status)
		}
	})

	t.Run("a hinted class carries the observation's confidence", func(t *testing.T) {
		o := obs(assetclass.KeyFirewall, id(identity.KindSerialNumber, "SN-fw-1"))
		o.Confidence = 0.75
		res := mustResolve(t, e, o)
		if res.ClassKey != assetclass.KeyFirewall {
			t.Fatalf("class = %q, want firewall", res.ClassKey)
		}
		if got := repo.ClassConfidence(res.Asset); got != 0.75 {
			t.Errorf("class confidence = %v, want the observation's 0.75", got)
		}
	})
}

// ── the matcher seam ───────────────────────────────────────────────────────

type stubMatcher struct {
	scores map[string]float64
	calls  int
	err    error
	// explain makes the stub return an explanation, so the engine's carrying of
	// one is tested without depending on the real model's weights.
	explain bool
}

func (m *stubMatcher) Match(_ context.Context, _ seams.Observation, existing []seams.AssetSummary) ([]seams.MatchScore, error) {
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	var out []seams.MatchScore
	for _, a := range existing {
		s, ok := m.scores[a.ID]
		if !ok {
			continue
		}
		score := seams.MatchScore{
			Proposal: seams.NewProposal("test-matcher-v1", "matcher:stub", s),
			AssetID:  a.ID,
			Score:    s,
			Reason:   "stubbed",
		}
		if m.explain {
			score.Explanation = []seams.MatchFactor{
				{Feature: "id_match_singleton", Label: "a one-per-asset identifier matches", Value: 1, Weight: 3, Contribution: 3},
				{Feature: "segment_match", Label: "same network segment", Value: 1, Weight: 0.9, Contribution: 0.9},
			}
		}
		out = append(out, score)
	}
	return out, nil
}

// conflictingObservations sets up two assets and returns an observation whose
// identifiers point at both.
//
// Both assets are promoted to `monitoring`, which is what an asset a human has
// admitted to the inventory looks like. It matters because the auto-accept
// guard refuses to merge into anything still waiting in Approvals: leaving them
// pending would make every auto-accept test pass for the wrong reason, and
// TestAutoAcceptRefusesAPendingCandidate is the one that checks the refusal.
func conflictingObservations(t *testing.T, e *identity.Engine, repo *memory.Repository) (a, b identity.Resolution, o identity.Observation) {
	t.Helper()
	a = mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-1")))
	b = mustResolve(t, e, obs(assetclass.KeyServer, scoped(identity.KindHostname, "host-1", "segment-1")))
	repo.SetStatus(a.Asset, identity.StatusMonitoring)
	repo.SetStatus(b.Asset, identity.StatusMonitoring)
	o = obs(assetclass.KeyServer,
		id(identity.KindSerialNumber, "SN-1"),
		scoped(identity.KindHostname, "host-1", "segment-1"),
	)
	return a, b, o
}

func TestMatcherNeverAutoMergesAtTheDefaultThreshold(t *testing.T) {
	// The whole of ADR-0002 D5 in one test: a matcher screaming 1.0 does not
	// merge anything when the tenant has not asked for auto-accept.
	m := &stubMatcher{scores: map[string]float64{}}
	e, repo := newEngine(t, identity.Config{Matcher: m})
	a, b, o := conflictingObservations(t, e, repo)
	m.scores[a.Asset.ID] = 1.0
	m.scores[b.Asset.ID] = 0.2

	res := mustResolve(t, e, o)
	if m.calls == 0 {
		t.Error("the matcher was never consulted on a conflict")
	}
	if res.Outcome != identity.OutcomeConflict {
		t.Fatalf("outcome = %s, want conflict: a score of 1.0 must not bypass the proposal at threshold 0", res.Outcome)
	}
	if res.AutoAccepted {
		t.Fatal("auto_accepted = true at the default threshold of 0")
	}
	if res.Asset.ID == a.Asset.ID || res.Asset.ID == b.Asset.ID {
		t.Fatalf("the observation was written into a candidate (%s) instead of its own pending asset", res.Asset.ID)
	}
	props := repo.Proposals()
	if len(props) != 1 || props[0].AutoAccepted {
		t.Fatalf("proposals = %+v, want one, not auto-accepted", props)
	}
	// Ranked, though: the top-scored candidate comes first.
	if res.Candidates[0].Ref.ID != a.Asset.ID {
		t.Errorf("candidates were not ranked by score: %+v", res.Candidates)
	}
	if res.Candidates[0].Reason != "stubbed" {
		t.Errorf("the matcher's reason was dropped: %+v", res.Candidates[0])
	}
}

func TestMatcherAutoAcceptsAboveTheThreshold(t *testing.T) {
	m := &stubMatcher{scores: map[string]float64{}}
	e, repo := newEngine(t, identity.Config{Matcher: m, AutoAcceptThreshold: 0.9})
	a, b, o := conflictingObservations(t, e, repo)
	m.scores[a.Asset.ID] = 0.95
	m.scores[b.Asset.ID] = 0.10

	before := repo.AssetCount()
	res := mustResolve(t, e, o)
	if res.Outcome != identity.OutcomeMatched || !res.AutoAccepted {
		t.Fatalf("outcome = %s (auto-accepted %v), want a matched auto-accept", res.Outcome, res.AutoAccepted)
	}
	if res.Asset.ID != a.Asset.ID {
		t.Fatalf("merged into %s, want the top-scored candidate %s", res.Asset.ID, a.Asset.ID)
	}
	if repo.AssetCount() != before {
		t.Errorf("an auto-accepted merge created an asset: %d → %d", before, repo.AssetCount())
	}
	// The proposal is still opened: it is the evidence AND the executor's work
	// item, and the losing candidate is still a separate asset.
	props := repo.Proposals()
	if len(props) != 1 || !props[0].AutoAccepted {
		t.Fatalf("proposals = %+v, want one marked auto-accepted", props)
	}
	if props[0].AcceptedAssetID != a.Asset.ID || props[0].AcceptedScore != 0.95 {
		t.Errorf("proposal records %+v, want asset %s at 0.95", props[0], a.Asset.ID)
	}
	if props[0].AcceptedModelID != "test-matcher-v1" || props[0].AcceptedSourceRef != "matcher:stub" {
		t.Errorf("the matcher's provenance was not carried onto the proposal: %+v", props[0])
	}
	// The losing candidate keeps its identifier until a merge is executed.
	if got := repo.Identifiers(b.Asset); len(got) != 1 {
		t.Errorf("the losing candidate's identifiers changed: %+v", got)
	}
	assertHistory(t, repo, a.Asset.ID, identity.ActionCreated, identity.ActionMergedFrom, identity.ActionMergeProposed)
	// The merge_proposed entry is what joins this asset's history to the
	// proposal a reviewer opens. Without it the one outcome a model decided is
	// the one outcome whose history dead-ends.
	entries := repo.HistoryFor(a.Asset)
	last := entries[len(entries)-1]
	if got := last.Changes["proposal_id"]; got != res.Proposal.ID {
		t.Errorf("merge_proposed records proposal_id = %v, want %q", got, res.Proposal.ID)
	}
	if got := last.Changes["auto_accepted"]; got != true {
		t.Errorf("merge_proposed records auto_accepted = %v, want true", got)
	}
	if got := last.Changes["model_id"]; got != "test-matcher-v1" {
		t.Errorf("merge_proposed records model_id = %v, want the matcher's", got)
	}
}

func TestMatcherBelowTheThresholdStillProposes(t *testing.T) {
	m := &stubMatcher{scores: map[string]float64{}}
	e, repo := newEngine(t, identity.Config{Matcher: m, AutoAcceptThreshold: 0.9})
	a, b, o := conflictingObservations(t, e, repo)
	m.scores[a.Asset.ID] = 0.89
	m.scores[b.Asset.ID] = 0.10

	res := mustResolve(t, e, o)
	if res.Outcome != identity.OutcomeConflict || res.AutoAccepted {
		t.Fatalf("outcome = %s (auto-accepted %v) at 0.89 against a 0.9 threshold, want a conflict", res.Outcome, res.AutoAccepted)
	}
}

// ── the auto-accept guards (workstream 4.6) ────────────────────────────────

// A singleton identifier that DISAGREES is never auto-accepted, at any score.
//
// ADR-0002 D3's singleton erratum is categorical: "two ARNs are two resources
// whatever a matcher scores the pair, and the auto-accept threshold does not
// apply". This is the SECOND route to that guarantee — the matcher also caps
// its own score — and it is the load-bearing one, because it consults no score
// at all.
//
// Both polarities, in one test: the same pair, differing only in whether the
// cloud ids agree, must auto-accept one way and refuse the other. Without the
// agreeing half the guard could be "never auto-accept anything" and this would
// still pass.
func TestAutoAcceptRefusesASingletonDisagreementAtAnyScore(t *testing.T) {
	setup := func(t *testing.T, candidateARN string) (identity.Resolution, *memory.Repository) {
		t.Helper()
		m := &stubMatcher{scores: map[string]float64{}}
		e, repo := newEngine(t, identity.Config{Matcher: m, AutoAcceptThreshold: 0.5})

		// A: carries the serial AND a cloud resource id.
		a := mustResolve(t, e, obs(assetclass.KeyServer,
			id(identity.KindSerialNumber, "SN-1"),
			id(identity.KindCloudResourceID, candidateARN)))
		// B: carries the hostname, so the observation below conflicts across kinds.
		b := mustResolve(t, e, obs(assetclass.KeyServer, scoped(identity.KindHostname, "host-1", "segment-1")))
		repo.SetStatus(a.Asset, identity.StatusMonitoring)
		repo.SetStatus(b.Asset, identity.StatusMonitoring)

		m.scores[a.Asset.ID] = 1.0
		m.scores[b.Asset.ID] = 0.0

		return mustResolve(t, e, obs(assetclass.KeyServer,
			id(identity.KindSerialNumber, "SN-1"),
			id(identity.KindCloudResourceID, "arn:aws:ec2:us-east-1:1:instance/i-0aaa"),
			scoped(identity.KindHostname, "host-1", "segment-1"))), repo
	}

	t.Run("agreeing singleton auto-accepts", func(t *testing.T) {
		res, _ := setup(t, "arn:aws:ec2:us-east-1:1:instance/i-0aaa")
		if !res.AutoAccepted || res.Outcome != identity.OutcomeMatched {
			t.Fatalf("outcome = %s (auto-accepted %v); the control case must auto-accept, or the refusal below proves nothing",
				res.Outcome, res.AutoAccepted)
		}
	})

	t.Run("disagreeing singleton is refused", func(t *testing.T) {
		res, repo := setup(t, "arn:aws:ec2:us-east-1:1:instance/i-0bbb")
		if res.AutoAccepted {
			t.Fatal("a differing cloud_resource_id was auto-merged; two ARNs are two resources whatever the score")
		}
		if res.Outcome != identity.OutcomeConflict {
			t.Fatalf("outcome = %s, want conflict", res.Outcome)
		}
		for _, p := range repo.Proposals() {
			if p.AutoAccepted {
				t.Error("a proposal was recorded as auto-accepted")
			}
		}
	})
}

// Never merge into an asset a human has not yet admitted to the inventory.
//
// Approving an asset and merging two assets are two decisions, and the tenant's
// auto-accept threshold licenses only the second. Both polarities again: the
// same pair auto-accepts when both candidates are in service and is refused
// when either is still pending.
func TestAutoAcceptRefusesAPendingCandidate(t *testing.T) {
	run := func(t *testing.T, promote func(repo *memory.Repository, a, b identity.Resolution)) identity.Resolution {
		t.Helper()
		m := &stubMatcher{scores: map[string]float64{}}
		e, repo := newEngine(t, identity.Config{Matcher: m, AutoAcceptThreshold: 0.5})
		a := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-1")))
		b := mustResolve(t, e, obs(assetclass.KeyServer, scoped(identity.KindHostname, "host-1", "segment-1")))
		promote(repo, a, b)
		m.scores[a.Asset.ID] = 1.0
		m.scores[b.Asset.ID] = 0.1
		return mustResolve(t, e, obs(assetclass.KeyServer,
			id(identity.KindSerialNumber, "SN-1"),
			scoped(identity.KindHostname, "host-1", "segment-1")))
	}

	t.Run("both in service auto-accepts", func(t *testing.T) {
		res := run(t, func(repo *memory.Repository, a, b identity.Resolution) {
			repo.SetStatus(a.Asset, identity.StatusMonitoring)
			repo.SetStatus(b.Asset, identity.StatusMonitoring)
		})
		if !res.AutoAccepted {
			t.Fatal("the control case did not auto-accept, so the refusals below prove nothing")
		}
	})

	t.Run("the winner is still pending", func(t *testing.T) {
		res := run(t, func(repo *memory.Repository, _, b identity.Resolution) {
			repo.SetStatus(b.Asset, identity.StatusMonitoring)
		})
		if res.AutoAccepted {
			t.Fatal("auto-merged into an asset still waiting in Approvals")
		}
	})

	t.Run("a losing candidate is still pending", func(t *testing.T) {
		res := run(t, func(repo *memory.Repository, a, _ identity.Resolution) {
			repo.SetStatus(a.Asset, identity.StatusMonitoring)
		})
		if res.AutoAccepted {
			t.Fatal("auto-merged while a candidate was still waiting in Approvals: " +
				"the contest involves an asset nobody has admitted yet")
		}
	})
}

// A threshold outside 0..1 is refused into "never", not clamped. A stored
// setting of 1.5 means something wrote a value nobody validated, and the safe
// reading of a corrupt threshold is the one that merges nothing.
func TestWithAutoAcceptThreshold(t *testing.T) {
	m := &stubMatcher{scores: map[string]float64{}}
	base, repo := newEngine(t, identity.Config{Matcher: m})
	a, b, o := conflictingObservations(t, base, repo)
	m.scores[a.Asset.ID] = 0.95
	m.scores[b.Asset.ID] = 0.05

	for _, tc := range []struct {
		name       string
		threshold  float64
		wantAccept bool
	}{
		{"zero never accepts", 0, false},
		{"below the score accepts", 0.9, true},
		{"above the score proposes", 0.99, false},
		{"negative is refused into never", -1, false},
		{"above one is refused into never", 1.5, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Each case re-runs the same observation; the engine is per-tenant
			// by value, so this is exactly the shape the service uses.
			e := base.WithAutoAcceptThreshold(tc.threshold)
			if tc.threshold < 0 || tc.threshold > 1 {
				if got := e.AutoAcceptThreshold(); got != 0 {
					t.Fatalf("threshold %v was stored as %v, want 0", tc.threshold, got)
				}
			}
			res := mustResolve(t, e, o)
			if res.AutoAccepted != tc.wantAccept {
				t.Errorf("auto-accepted = %v at threshold %v, want %v", res.AutoAccepted, tc.threshold, tc.wantAccept)
			}
		})
	}

	// The base engine is untouched: WithAutoAcceptThreshold copies.
	if got := base.AutoAcceptThreshold(); got != 0 {
		t.Errorf("the base engine's threshold moved to %v", got)
	}
}

// The explanation and the model id reach the proposal, on every conflict — not
// only on an auto-accepted one. A proposal a human resolves should still say
// which model put the winner at the top.
func TestProposalCarriesTheMatchersProvenanceAndExplanation(t *testing.T) {
	m := &stubMatcher{scores: map[string]float64{}, explain: true}
	e, repo := newEngine(t, identity.Config{Matcher: m})
	a, b, o := conflictingObservations(t, e, repo)
	m.scores[a.Asset.ID] = 0.7
	m.scores[b.Asset.ID] = 0.2

	res := mustResolve(t, e, o)
	if res.Outcome != identity.OutcomeConflict {
		t.Fatalf("outcome = %s, want conflict", res.Outcome)
	}
	props := repo.Proposals()
	if len(props) != 1 {
		t.Fatalf("proposals = %d, want 1", len(props))
	}
	if props[0].ModelID != "test-matcher-v1" || props[0].SourceRef != "matcher:stub" {
		t.Errorf("proposal provenance = %q/%q, want the matcher's", props[0].ModelID, props[0].SourceRef)
	}
	if props[0].AutoAccepted {
		t.Error("a proposal nothing auto-accepted is marked auto-accepted")
	}
	top := props[0].Candidates[0]
	if top.Ref.ID != a.Asset.ID {
		t.Fatalf("the top candidate is %s, want the highest-scored %s", top.Ref.ID, a.Asset.ID)
	}
	if len(top.Explanation) == 0 {
		t.Fatal("the top candidate carries no explanation; a score with no working can only be rubber-stamped")
	}
	if top.Explanation[0].Label == "" || top.Explanation[0].Feature == "" {
		t.Errorf("explanation factor is unlabelled: %+v", top.Explanation[0])
	}
}

func TestMatcherFailureDoesNotFailIdentification(t *testing.T) {
	m := &stubMatcher{err: errors.New("model unavailable")}
	e, repo := newEngine(t, identity.Config{Matcher: m, AutoAcceptThreshold: 0.5})
	_, _, o := conflictingObservations(t, e, repo)

	res := mustResolve(t, e, o)
	if res.Outcome != identity.OutcomeConflict {
		t.Fatalf("outcome = %s, want conflict: a failing seam made no proposal, it did not break identification", res.Outcome)
	}
	if res.AutoAccepted {
		t.Error("a failed matcher produced an auto-accept")
	}
}

// An engine built with no Matcher gets the seam registry's DEFAULT, which is
// now the learned model (ADR-0008 D2) rather than the null one. So a conflict in
// a stock deployment arrives RANKED and EXPLAINED.
//
// And still never auto-merged: the threshold is zero and zero means never,
// whatever the model scores. That is the property this test exists for; the
// scores are incidental.
func TestUnconfiguredEngineRanksButNeverAutoAccepts(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	_, _, o := conflictingObservations(t, e, repo)
	res := mustResolve(t, e, o)
	if res.Outcome != identity.OutcomeConflict {
		t.Fatalf("outcome = %s, want conflict", res.Outcome)
	}
	if res.AutoAccepted {
		t.Fatal("the default engine auto-accepted a merge; the default threshold is zero, which means never")
	}
	if res.Proposal.ID == "" {
		t.Error("no merge proposal was opened")
	}
	scored := 0
	for _, c := range res.Candidates {
		if c.Score > 0 {
			scored++
		}
		if c.Score > 0 && len(c.Explanation) == 0 {
			t.Errorf("candidate %s carries a score with no explanation", c.Ref.ID)
		}
	}
	if scored == 0 {
		t.Error("the default matcher scored nothing; a stock deployment's proposals should arrive ranked")
	}
}

// "none" is still selectable, and selecting it leaves every candidate unscored —
// which is exactly the pre-4.6 behaviour, and the proposal is otherwise
// identical.
func TestExplicitNullMatcherLeavesEveryCandidateUnscored(t *testing.T) {
	e, repo := newEngine(t, identity.Config{Matcher: seams.NullMatcher{}})
	_, _, o := conflictingObservations(t, e, repo)
	res := mustResolve(t, e, o)
	if res.Outcome != identity.OutcomeConflict {
		t.Fatalf("outcome = %s, want conflict", res.Outcome)
	}
	if res.TopScore != 0 {
		t.Errorf("top score = %v with the null matcher, want 0", res.TopScore)
	}
	for _, c := range res.Candidates {
		if c.Score != 0 {
			t.Errorf("candidate %s scored %v with the null matcher", c.Ref.ID, c.Score)
		}
		if len(c.Explanation) != 0 {
			t.Errorf("candidate %s carries an explanation with no score", c.Ref.ID)
		}
	}
}

// ── validation ─────────────────────────────────────────────────────────────

func TestResolveRejectsAnObservationWithNoTenant(t *testing.T) {
	e, _ := newEngine(t, identity.Config{})
	o := obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-1"))
	o.TenantID = "  "
	if _, err := e.Resolve(context.Background(), o); !errors.Is(err, identity.ErrInvalidObservation) {
		t.Fatalf("err = %v, want ErrInvalidObservation", err)
	}
}

// TestResolveRejectsAScopeOnAGlobalKind is the engine-level half of the same
// guard: one serial number must never become two assets because one observer
// filled in the segment it happened to know.
func TestResolveRejectsAScopeOnAGlobalKind(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	first := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-1")))

	_, err := e.Resolve(context.Background(), obs(assetclass.KeyServer,
		scoped(identity.KindSerialNumber, "SN-1", "segment-1")))
	if !errors.Is(err, identity.ErrInvalidObservation) {
		t.Fatalf("err = %v, want ErrInvalidObservation", err)
	}
	if repo.AssetCount() != 1 {
		t.Errorf("%d assets exist, want 1 (%s): a spurious scope must not fork the identifier key",
			repo.AssetCount(), first.Asset.ID)
	}

	// And the lenient path reports it rather than creating the duplicate.
	clean, rejected := obs(assetclass.KeyServer,
		scoped(identity.KindSerialNumber, "SN-1", "segment-1"),
		scoped(identity.KindHostname, "host-1", "segment-1"),
	).Sanitize()
	if len(rejected) != 1 || rejected[0].Identifier.Kind != identity.KindSerialNumber {
		t.Fatalf("rejected = %+v, want the scoped serial", rejected)
	}
	if len(clean.Identifiers) != 1 || clean.Identifiers[0].Kind != identity.KindHostname {
		t.Errorf("sanitised identifiers = %+v, want the legitimately scoped hostname kept", clean.Identifiers)
	}
}

func TestResolveRejectsAMalformedIdentifier(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	o := obs(assetclass.KeyServer, id(identity.KindMACAddress, "not-a-mac"))
	_, err := e.Resolve(context.Background(), o)
	if !errors.Is(err, identity.ErrInvalidObservation) {
		t.Fatalf("err = %v, want ErrInvalidObservation", err)
	}
	if repo.AssetCount() != 0 {
		t.Errorf("a rejected observation created %d assets", repo.AssetCount())
	}
}

func TestSanitizeIsTheExplicitLenientPath(t *testing.T) {
	e, _ := newEngine(t, identity.Config{})
	o := obs(assetclass.KeyServer,
		id(identity.KindMACAddress, "not-a-mac"),
		id(identity.KindSerialNumber, "SN-1"),
	)
	clean, rejected := o.Sanitize()
	if len(rejected) != 1 || rejected[0].Identifier.Kind != identity.KindMACAddress {
		t.Fatalf("rejected = %+v, want the bad MAC", rejected)
	}
	if rejected[0].Err == nil {
		t.Error("a rejected identifier carries no reason")
	}
	res := mustResolve(t, e, clean)
	if res.Outcome != identity.OutcomeCreated {
		t.Fatalf("outcome = %s, want created from the sanitised observation", res.Outcome)
	}
}

func TestNewRejectsAMissingRepositoryAndABadThreshold(t *testing.T) {
	if _, err := identity.New(identity.Config{}); err == nil {
		t.Error("New with no repository returned no error")
	}
	for _, bad := range []float64{-0.1, 1.5} {
		if _, err := identity.New(identity.Config{Repo: memory.New(), AutoAcceptThreshold: bad}); err == nil {
			t.Errorf("New with threshold %v returned no error", bad)
		}
	}
}

func TestResolveIsTenantScoped(t *testing.T) {
	e, _ := newEngine(t, identity.Config{})
	mine := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-1")))

	other := obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-1"))
	other.TenantID = "tenant-b"
	res := mustResolve(t, e, other)

	if res.Outcome != identity.OutcomeCreated {
		t.Fatalf("outcome = %s, want created: another tenant's serial is not this tenant's asset", res.Outcome)
	}
	if res.Asset.ID == mine.Asset.ID {
		t.Fatal("an observation matched an asset in a different tenant")
	}
}

// ── history ────────────────────────────────────────────────────────────────

func TestHistoryCarriesProvenanceOnEveryPath(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	res := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-1")))
	mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-1")))

	entries := repo.HistoryFor(res.Asset)
	if len(entries) != 2 {
		t.Fatalf("%d history entries, want 2", len(entries))
	}
	for _, e := range entries {
		if e.Source.Kind != identity.SourceMeasured || e.Source.Ref != "sensor" {
			t.Errorf("history entry %s carries source %+v, want the observation's", e.Action, e.Source)
		}
		if e.TenantID != tenant {
			t.Errorf("history entry %s is not tenant-scoped: %+v", e.Action, e)
		}
		if e.At.IsZero() {
			t.Errorf("history entry %s has no timestamp", e.Action)
		}
		if len(e.Changes) == 0 {
			t.Errorf("history entry %s records no changes", e.Action)
		}
	}
	if got := entries[1].Changes["decided_by"]; got != string(identity.KindSerialNumber) {
		t.Errorf("the update's changes record decided_by = %v, want serial_number", got)
	}
}

func TestObservedAtDefaultsToTheClock(t *testing.T) {
	fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	e, repo := newEngine(t, identity.Config{Now: func() time.Time { return fixed }})
	o := obs(assetclass.KeyServer, id(identity.KindSerialNumber, "SN-1"))
	o.ObservedAt = time.Time{}
	res := mustResolve(t, e, o)

	if got := repo.HistoryFor(res.Asset)[0].At; !got.Equal(fixed) {
		t.Fatalf("history timestamp = %v, want the injected clock %v", got, fixed)
	}
}

// ── helpers ────────────────────────────────────────────────────────────────

func assertHistory(t *testing.T, repo *memory.Repository, assetID string, want ...identity.HistoryAction) {
	t.Helper()
	entries := repo.HistoryFor(identity.AssetRef{TenantID: tenant, ID: assetID})
	if len(entries) != len(want) {
		got := make([]identity.HistoryAction, 0, len(entries))
		for _, e := range entries {
			got = append(got, e.Action)
		}
		t.Fatalf("history for %s = %v, want %v", assetID, got, want)
	}
	for i, w := range want {
		if entries[i].Action != w {
			t.Errorf("history[%d] = %s, want %s", i, entries[i].Action, w)
		}
	}
}
