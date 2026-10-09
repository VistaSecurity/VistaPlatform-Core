package services

// The dhcp_vendor_class rule kind, end to end through the passive host-
// observation path, against a real Postgres with the shipped seed.
//
// What these pin is the WIRING of the DHCP option 60 identifier into each of the
// three places the classifier reads evidence:
//
//   - a NEW asset, classified from the observation alone
//     (hostObservationClassEvidence);
//   - an EXISTING floor asset the engine MATCHES, promoted by the passive path
//     (classOutcomeForResolution over accumulatedClassEvidence);
//   - an EXISTING floor asset nothing observes any more, promoted by the floor
//     sweep from the identifier stored in
//     `assets.metadata->'host_observation_attributes'` (storedClassEvidence).
//
// Mutation-tested (see the PR): deleting the DHCPVendorClass line in
// hostObservationClassEvidence turns the born-classified test red; deleting it
// in storedClassEvidence turns the sweep test red. The passive-match test is
// green under EITHER single deletion, by design: the match path reads the
// accumulated evidence after this observation's metadata is written, so the
// identifier reaches it both as the observation's and as the stored one.
//
// Skips without TEST_DATABASE_URL. RFC 5737 documentation addresses throughout.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// msftRuleID is the seeded `^MSFT 5\.0$` rule's id — the precondition every
// test here stands on, and what a promotion's class_source_ref must cite.
func msftRuleID(t *testing.T, db *database.DB) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.QueryRow(`SELECT id FROM classification_rules
		WHERE rule_kind = 'dhcp_vendor_class' AND pattern = '^MSFT 5\.0$' AND class_key = 'computer'`).Scan(&id); err != nil {
		t.Fatalf("precondition: the seeded MSFT 5.0 dhcp_vendor_class rule is missing (schema CHECK or seed region not applied?): %v", err)
	}
	return id
}

func dhcpObservation(t *testing.T, mac, addr, host, vendorClass string, at time.Time) *hostobs.HostObservation {
	t.Helper()
	return &hostobs.HostObservation{
		Source: hostobs.SourceDHCP, MAC: mac, Addresses: addrsFor(t, addr),
		Hostnames: []string{host}, ObservedAt: at,
		Attributes: map[string]any{"dhcp_vendor_class": vendorClass},
	}
}

// A host's first sighting is its DHCP exchange: born `computer` from the
// option 60 identifier alone, with the rule as provenance.
func TestIntegration_DHCPVendorClass_ANewAssetIsBornClassified(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	ruleID := msftRuleID(t, db)
	const host = "dhcp-born-computer"

	ho := dhcpObservation(t, macUnassigned, "192.0.2.131", host, "MSFT 5.0", time.Now().UTC().Add(-time.Minute))
	ingestObservation(t, svc, tenant, ho)

	got := floorAssetByHost(t, db, tenant, host)
	if got.class != "computer" {
		t.Errorf("class_key = %q, want computer from the MSFT 5.0 vendor class", got.class)
	}
	if got.kind != string(identity.ClassSourceRule) || got.ref != "rule:"+ruleID.String() {
		t.Errorf("class provenance = %q/%q, want rule / rule:%s", got.kind, got.ref, ruleID)
	}
}

// Born `unknown_host` from an ARP sighting that carries nothing a rule reads;
// the next frame is the host's DHCP REQUEST naming `MSFT 5.0`. The engine
// MATCHES it to the asset and the rule's `computer` is promoted off the floor,
// with a classifier history row citing the rule and nothing in Approvals.
func TestIntegration_DHCPVendorClass_PassiveMatchPromotesTheFloor(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	ruleID := msftRuleID(t, db)
	const host = "dhcp-floor-promoted"

	ingestObservation(t, svc, tenant, &hostobs.HostObservation{
		Source: hostobs.SourceARP, MAC: macUnassigned, Addresses: addrsFor(t, "192.0.2.132"),
		Hostnames: []string{host}, ObservedAt: time.Now().UTC().Add(-2 * time.Minute),
	})
	before := floorAssetByHost(t, db, tenant, host)
	if before.class != "unknown_host" {
		t.Fatalf("precondition: born %q, want unknown_host — the ARP frame carries nothing a rule reads", before.class)
	}

	ho := dhcpObservation(t, macUnassigned, "192.0.2.132", host, "MSFT 5.0", time.Now().UTC().Add(-time.Minute))
	ingestObservation(t, svc, tenant, ho)

	after := floorAssetByHost(t, db, tenant, host)
	if after.id != before.id {
		t.Fatalf("the DHCP observation resolved to another asset (%s, was %s); the fixture no longer exercises a MATCH", after.id, before.id)
	}
	if after.class != "computer" || after.kind != string(identity.ClassSourceRule) {
		t.Errorf("class = %q/%q, want computer/rule promoted from the DHCP vendor class", after.class, after.kind)
	}
	hist := classifierHistory(t, db, tenant, after.id)
	if len(hist) != 1 || hist[0].from != "unknown_host" || hist[0].to != "computer" || hist[0].ref != "rule:"+ruleID.String() {
		t.Errorf("classifier class-history rows = %+v; want exactly one unknown_host -> computer citing rule:%s", hist, ruleID)
	}
	if n := countClassProposals(t, db, tenant); n != 0 {
		t.Errorf("%d class proposals; a promotion off the floor is not a question for Approvals", n)
	}
}

// The identifier is already STORED and no new observation arrives: an asset
// left on the floor (ingested before this rule kind existed) whose
// host_observation_attributes carry `MSFT 5.0`. The sweep alone must promote
// it — which it can only do by reading the stored attribute.
func TestIntegration_DHCPVendorClass_SweepPromotesFromTheStoredAttribute(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	ruleID := msftRuleID(t, db)
	ctx := context.Background()
	const host = "dhcp-sweep-computer"

	ho := dhcpObservation(t, macUnassigned, "192.0.2.133", host, "MSFT 5.0", time.Now().UTC().Add(-time.Minute))
	ingestObservation(t, svc, tenant, ho)

	// Back onto the floor, with no class history for the move — the state of an
	// asset ingested before a rule could classify it.
	execTenant(t, db, tenant, fmt.Sprintf(`UPDATE assets SET class_key = 'unknown_host', class_path = '%s',
		class_source_kind = 'measured', class_source_ref = NULL, class_confidence = NULL
		WHERE tenant_id = $1 AND hostname = '%s'`, classPathForKey("unknown_host"), host))

	var stored string
	if err := database.WithTenantTx(ctx, db, tenant, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`SELECT COALESCE(metadata->'host_observation_attributes'->>'dhcp_vendor_class', '')
			FROM assets WHERE tenant_id = $1 AND hostname = $2`, tenant, host).Scan(&stored)
	}); err != nil {
		t.Fatal(err)
	}
	if stored != "MSFT 5.0" {
		t.Fatalf("precondition: stored dhcp_vendor_class = %q; intake no longer keeps the attribute the sweep reads", stored)
	}
	asset := floorAssetByHost(t, db, tenant, host)
	if asset.class != "unknown_host" {
		t.Fatalf("precondition: the asset is %q, not on the floor", asset.class)
	}

	res, err := svc.SweepClassFloor(ctx, tenant)
	if err != nil {
		t.Fatalf("SweepClassFloor: %v", err)
	}
	if res.Promoted != 1 {
		t.Errorf("sweep = %+v; want the one floor asset promoted from its stored DHCP vendor class", res)
	}
	got := floorAssetByHost(t, db, tenant, host)
	if got.class != "computer" || got.kind != string(identity.ClassSourceRule) {
		t.Errorf("class = %q/%q, want computer/rule", got.class, got.kind)
	}
	hist := classifierHistory(t, db, tenant, got.id)
	if len(hist) != 1 || hist[0].to != "computer" || !strings.HasSuffix(hist[0].ref, ruleID.String()) {
		t.Errorf("classifier history = %+v, want one move to computer citing rule:%s", hist, ruleID)
	}
}
