package services

// Generic-hostname MARKING on the sensor's host-observation path ( B2).
//
// A name many unrelated devices carry is still recorded — it is true — but it
// arrives at the engine marked Generic with confidence 0.3, so that a later
// reader does not take it for evidence of ONE device. What the engine does with
// the mark is a separate change; these tests pin the mark itself: which names
// get it, that the decision is made from the tenant's own data, and that a name
// which is not generic is left exactly as it was.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// identifierNamed finds the identifier of kind holding value, failing the test
// when there is none: a name that vanished is a different bug from one that was
// not marked.
func identifierNamed(t *testing.T, obs identity.Observation, kind identity.Kind, value string) identity.Identifier {
	t.Helper()
	for _, id := range obs.Identifiers {
		if id.Kind == kind && id.Value == value {
			return id
		}
	}
	t.Fatalf("no %s identifier %q in %+v", kind, value, obs.Identifiers)
	return identity.Identifier{}
}

// The static half needs no database: the dictionary and the pattern.
func TestHostObservationBuilder_MarksDefaultNamesGeneric(t *testing.T) {
	obs, err := buildHostObs(t, unscopedService(), &hostobs.HostObservation{
		Source:    hostobs.SourceDHCP,
		MAC:       "28:cf:da:11:22:33",
		Addresses: mustAddrs(t, "192.0.2.50"),
		Hostnames: []string{"iphone", "iPad-2", "xps-15", "sams-iphone"},
		FQDNs:     []string{"printer.corp.example", "printer.local", "kitchen-hub.local"},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	cases := []struct {
		kind    identity.Kind
		value   string
		generic bool
	}{
		{identity.KindHostname, "iphone", true},
		{identity.KindHostname, "ipad-2", true},
		{identity.KindHostname, "printer.local", true}, // `.local` is filed as a scoped hostname
		{identity.KindHostname, "xps-15", false},
		{identity.KindHostname, "sams-iphone", false}, // a person's name makes it identify one device
		{identity.KindHostname, "kitchen-hub.local", false},
		{identity.KindFQDN, "printer.corp.example", false}, // an FQDN is issued by the domain's owner
	}
	for _, c := range cases {
		id := identifierNamed(t, obs, c.kind, c.value)
		if id.Generic != c.generic {
			t.Errorf("%s %q: Generic = %v, want %v", c.kind, c.value, id.Generic, c.generic)
		}
		wantConfidence := 1.0
		if c.generic {
			wantConfidence = identity.GenericConfidence
		}
		if id.Confidence != wantConfidence {
			t.Errorf("%s %q: Confidence = %v, want %v", c.kind, c.value, id.Confidence, wantConfidence)
		}
	}
	// The marked names are still there: marking is not dropping.
	if identifierNamed(t, obs, identity.KindHostname, "iphone").Scope == "" {
		t.Error("the generic name lost its scope")
	}
}

// The tenant-frequency half against a real Postgres: three assets carrying a
// name that is in no dictionary make it generic for the tenant, and only that
// tenant.
func TestIntegration_HostObservation_MarksATenantFrequentNameGeneric(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	other := testdb.NewTenant(t, db.DB.DB)

	hold := func(owner uuid.UUID, name, scope string) {
		t.Helper()
		asset := seedAsset(t, db, owner, "held-"+uuid.NewString()[:8], "unknown_host", "unknown_host", "production", 0, 0)
		if _, err := db.Exec(`INSERT INTO asset_identifiers (tenant_id, asset_id, kind, value, scope, source_kind, confidence)
			VALUES ($1, $2, 'hostname', $3, $4, 'measured', 1)`, owner, asset, name, scope); err != nil {
			t.Fatalf("attach hostname: %v", err)
		}
	}
	build := func(tenantID uuid.UUID, name string) identity.Identifier {
		t.Helper()
		ho := &hostobs.HostObservation{
			Source: hostobs.SourceDHCP, MAC: "28:cf:da:44:55:66",
			Addresses: mustAddrs(t, "192.0.2.77"), Hostnames: []string{name},
		}
		ho.Finalize()
		f := hostObsFinding(t, ho, nil)
		payload, ok := hostObservationPayload(f)
		if !ok {
			t.Fatal("no readable payload")
		}
		obs, err := svc.hostObservationObservation(tenantID, f, payload)
		if err != nil {
			t.Fatalf("hostObservationObservation: %v", err)
		}
		return identifierNamed(t, obs, identity.KindHostname, name)
	}

	// Two assets: a name, not yet a pattern. (Each scenario uses its own name:
	// the count is cached per tenant and name for ten minutes.)
	hold(tenant, "hall-display", "seg-a")
	hold(tenant, "hall-display", "seg-b")
	if id := build(tenant, "hall-display"); id.Generic || id.Confidence != 1 {
		t.Fatalf("two assets carry the name: %+v, want it NOT generic and confidence 1", id)
	}

	// Three, under three different scopes: the count looks across scopes.
	hold(tenant, "lobby-display", "seg-a")
	hold(tenant, "lobby-display", "seg-b")
	hold(tenant, "lobby-display", identity.ScopeTenantDefault)
	id := build(tenant, "lobby-display")
	if !id.Generic || id.Confidence != identity.GenericConfidence {
		t.Fatalf("three assets carry the name: %+v, want Generic with confidence %v", id, identity.GenericConfidence)
	}

	// The count is the tenant's own: nobody in the other tenant has this name.
	if got := build(other, "lobby-display"); got.Generic {
		t.Errorf("another tenant's three assets made the name generic here: %+v", got)
	}

	// A name nobody else carries is untouched.
	if got := build(tenant, "one-of-a-kind"); got.Generic || got.Confidence != 1 {
		t.Errorf("an unshared name was marked: %+v", got)
	}
}

// The mark reaches storage: the engine still RECORDS the generic name (it is
// true), as an identifier of the asset it created, at the lowered confidence.
func TestIntegration_HostObservation_GenericNameIsStillRecorded(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	ho := &hostobs.HostObservation{
		Source: hostobs.SourceDHCP, MAC: "28:cf:da:aa:bb:cc", Addresses: mustAddrs(t, "192.0.2.90"),
		Hostnames: []string{"iphone"}, ObservedAt: time.Now().UTC(),
	}
	ho.Finalize()
	f := hostObsFinding(t, ho, nil)
	payload, _ := hostObservationPayload(f)
	obs, err := svc.hostObservationObservation(tenant, f, payload)
	if err != nil {
		t.Fatal(err)
	}
	repo := pgidentity.New(db.DB.DB)
	engine, err := identity.New(identity.Config{Repo: repo})
	if err != nil {
		t.Fatal(err)
	}
	var res identity.Resolution
	if err := repo.RunInTx(context.Background(), tenant.String(), func(bound *pgidentity.Repository) error {
		var rerr error
		res, rerr = engine.WithRepository(bound).Resolve(context.Background(), obs)
		return rerr
	}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	var confidence float64
	if err := db.QueryRow(`SELECT confidence FROM asset_identifiers WHERE tenant_id=$1 AND asset_id=$2 AND kind='hostname' AND value='iphone'`,
		tenant, res.Asset.ID).Scan(&confidence); err != nil {
		t.Fatalf("the generic name was not recorded as an identifier: %v", err)
	}
	if confidence != identity.GenericConfidence {
		t.Errorf("stored confidence = %v, want %v", confidence, identity.GenericConfidence)
	}
}
