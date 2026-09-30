package services

// Generic-hostname MARKING on the interrogation path ( B2): a peer a
// device told us about is measured, so a default name (`iphone`) or one the
// tenant already sees on three assets is recorded but marked Generic at
// confidence 0.3. A name an operator TYPED for a managed device is a
// statement, not an observation, and is never marked.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func peerIdentifier(t *testing.T, obs identity.Observation, kind identity.Kind, value string) identity.Identifier {
	t.Helper()
	for _, id := range obs.Identifiers {
		if id.Kind == kind && id.Value == value {
			return id
		}
	}
	t.Fatalf("no %s identifier %q in %+v", kind, value, obs.Identifiers)
	return identity.Identifier{}
}

func TestIntegration_PeerObservation_MarksGenericHostnames(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	otherTenant := testdb.NewTenant(t, db)
	sink := NewObservationSink(db)
	repo := pgidentity.New(db)
	ctx := context.Background()
	now := time.Now().UTC()

	// Three assets in the tenant already hold a name that is in no dictionary.
	for i, scope := range []string{"seg-a", "seg-b", identity.ScopeTenantDefault} {
		if _, err := repo.CreateAsset(ctx, tenant.String(), identity.NewAsset{
			ClassKey: "unknown_host", ClassSourceKind: identity.ClassSourceMeasured,
			DisplayName: "held", Status: identity.StatusPendingApproval,
			Source: identity.Source{Kind: identity.SourceMeasured, Ref: "test"},
			Identifiers: []identity.Identifier{{
				Kind: identity.KindHostname, Value: "lobby-display", Scope: scope, Confidence: 1,
				Source: identity.Source{Kind: identity.SourceMeasured, Ref: "test"}, SeenAt: now,
			}},
			FirstSeenAt: now, LastSeenAt: now,
		}); err != nil {
			t.Fatalf("seed asset %d: %v", i, err)
		}
	}

	observe := func(tenantID uuid.UUID, names ...string) identity.Observation {
		t.Helper()
		peer := di.PeerRef{DisplayName: "Some Peer"}
		peer.AddIdentifier(di.IdentifierIPAddress, "192.0.2.61")
		for _, n := range names {
			peer.AddIdentifier(di.IdentifierHostname, n)
		}
		obs, _, err := sink.peerObservation(ctx, tenantID, peer,
			identity.Source{Kind: identity.SourceMeasured, Ref: "test", Mode: identity.ModeActive}, now)
		if err != nil {
			t.Fatalf("peerObservation: %v", err)
		}
		return obs
	}

	obs := observe(tenant, "lobby-display", "iphone", "office-plotter", "printer.corp.example", "printer.local")
	cases := []struct {
		kind    identity.Kind
		value   string
		generic bool
	}{
		{identity.KindHostname, "lobby-display", true}, // tenant frequency: three assets carry it
		{identity.KindHostname, "iphone", true},        // dictionary
		{identity.KindHostname, "printer.local", true}, // `.local` names are scoped hostnames
		{identity.KindHostname, "office-plotter", false},
		{identity.KindFQDN, "printer.corp.example", false}, // an FQDN is not judged
	}
	for _, c := range cases {
		id := peerIdentifier(t, obs, c.kind, c.value)
		want := 1.0
		if c.generic {
			want = identity.GenericConfidence
		}
		if id.Generic != c.generic || id.Confidence != want {
			t.Errorf("%s %q: Generic=%v Confidence=%v, want Generic=%v Confidence=%v",
				c.kind, c.value, id.Generic, id.Confidence, c.generic, want)
		}
	}

	// The tenant-frequency signal is the tenant's own.
	if id := peerIdentifier(t, observe(otherTenant, "lobby-display"), identity.KindHostname, "lobby-display"); id.Generic {
		t.Errorf("another tenant's assets made the name generic here: %+v", id)
	}
}

// A managed device's hostname is what the operator typed for it, and is not
// marked even when it is a word every printer on earth is called.
func TestIntegration_DeviceObservation_DeclaredNameIsNeverMarkedGeneric(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	svc := NewDeviceService(raw)
	tenant := testdb.NewTenant(t, raw)

	obs, err := svc.deviceObservation(context.Background(), tenant, deviceObservationInput{
		DeviceType: "cisco_ios", Hostname: "printer", Source: declaredSource(), ObservedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("build the observation: %v", err)
	}
	id := peerIdentifier(t, obs, identity.KindHostname, "printer")
	if id.Generic || id.Confidence != 1 {
		t.Errorf("a declared name was marked: %+v, want it untouched", id)
	}
}
