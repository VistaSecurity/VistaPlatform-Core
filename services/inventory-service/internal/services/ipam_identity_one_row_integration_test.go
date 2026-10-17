package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// TestIntegration_IPAMAndIdentity_OneAddressOneRow: in the common case (one
// tenant, the global table) the IPAM API and the identity engine agree on
// what an address is. An address a person created through IPAM, then observed
// on a host, is ONE ip_addresses row — the engine adopts it onto the host's
// interface rather than writing a second — and the person can still edit it
// afterwards (the global table enforces unique addresses, so a duplicate would
// make every later edit of either row a conflict). The other order holds too:
// once the engine has filed an address, IPAM refuses a second copy of it.
//
// Mutation: drop the `OR ip.assigned_id IS NULL` adoption arm from
// upsertAddress (shared/identity/postgres/addresses.go) and the first half
// finds two rows.
func TestIntegration_IPAMAndIdentity_OneAddressOneRow(t *testing.T) {
	f := newIPAMFixture(t)
	repo := pgidentity.New(f.app)
	engine, err := identity.New(identity.Config{Repo: repo})
	if err != nil {
		t.Fatal(err)
	}
	intake, err := identity.NewIntake(repo)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	observe := func(host, mac, addr string) identity.Resolution {
		t.Helper()
		at = at.Add(time.Minute)
		obs, err := intake.Build(context.Background(), identity.Sighting{
			TenantID: f.tenant.String(), Channel: identity.ChannelAuthenticatedSession, ObservedAt: at,
			Source: identity.Source{Kind: identity.SourceMeasured, Ref: "agent:it-host", Mode: identity.ModeActive},
			Identifiers: []identity.SightedIdentifier{
				{Kind: identity.KindHostname, Value: host},
				{Kind: identity.KindMACAddress, Value: mac, Interface: "eth0"},
				{Kind: identity.KindIPAddress, Value: addr, Interface: "eth0"},
			},
		})
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		var res identity.Resolution
		if err := repo.RunInTx(context.Background(), f.tenant.String(), func(bound *pgidentity.Repository) error {
			var rerr error
			res, rerr = engine.WithRepository(bound).Resolve(context.Background(), obs)
			return rerr
		}); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		return res
	}
	rowsAt := func(addr string) (n int, onInterface int) {
		t.Helper()
		if err := f.owner.QueryRow(`
			SELECT count(*), count(*) FILTER (WHERE assigned_kind = 'interface' AND assigned_id IS NOT NULL)
			  FROM ip_addresses WHERE tenant_id = $1 AND vrf_id IS NULL AND host = $2::inet`,
			f.tenant, addr).Scan(&n, &onInterface); err != nil {
			t.Fatal(err)
		}
		return n, onInterface
	}

	// IPAM first, then the engine.
	declared := f.create(t, "ip-addresses", map[string]any{"address": "10.93.0.7/24", "dns_name": "pbx.example.test"})
	res := observe("it-ipam-first", "00:00:5e:00:93:01", "10.93.0.7")
	if res.Outcome != identity.OutcomeCreated {
		t.Fatalf("observation: outcome %s, want created", res.Outcome)
	}
	if n, on := rowsAt("10.93.0.7"); n != 1 || on != 1 {
		t.Fatalf("10.93.0.7: %d rows, %d on an interface — want the one IPAM row, adopted onto the host's interface", n, on)
	}
	if _, err := f.svc.Update(f.ctx, f.tenant, "ip-addresses", idOf(declared), []byte(`{"description":"edited after adoption"}`)); err != nil {
		t.Fatalf("editing the adopted address through IPAM: %v", err)
	}

	// The engine first, then IPAM.
	observe("it-engine-first", "00:00:5e:00:93:02", "10.93.0.8")
	if n, on := rowsAt("10.93.0.8"); n != 1 || on != 1 {
		t.Fatalf("10.93.0.8: %d rows, %d on an interface — want one, on the host's interface", n, on)
	}
	if err := f.tryCreate("ip-addresses", map[string]any{"address": "10.93.0.8/24"}); !errors.Is(err, ErrIPAMConflict) {
		t.Fatalf("IPAM create of an address the engine already filed: err = %v, want ErrIPAMConflict", err)
	}
}
