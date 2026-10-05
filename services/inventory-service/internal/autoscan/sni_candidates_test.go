package autoscan

// The names an asset offers a scan as SNI (sni_candidates.go): their order, the
// synthetic names left out, the bound, and — against a real Postgres — that they
// are read from the asset's own endpoints, identifiers and hostname.

import (
	"context"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func TestRankSNINames_OrderSyntheticAndBound(t *testing.T) {
	got := rankSNINames([]sniName{
		{"web01", sniRankShortName},
		{"host.example.test", sniRankDotted},
		{"fqdn.example.test", sniRankFQDN},
		{"seen.example.test", sniRankEndpoint},
		{"none-3", sniRankDotted},                                 // a placeholder name
		{"1f852cc2-9a96-4a7b-8a1e-0123456789ab", sniRankEndpoint}, // a UUID
		{"192-0-2-5.example.test", sniRankFQDN},                   // an address written as a name
		{"Seen.Example.Test", sniRankFQDN},                        // a duplicate by case
	})
	want := []string{"seen.example.test", "fqdn.example.test", "host.example.test"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q (best evidence first, synthetic dropped, three at most)", got, want)
	}
}

func TestMergeSNICandidates_IsBoundedAndOrdered(t *testing.T) {
	got := MergeSNICandidates([]string{"a.example.test", "b.example.test"}, []string{"b.example.test", "c.example.test", "d.example.test"})
	want := []string{"a.example.test", "b.example.test", "c.example.test"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got := MergeSNICandidates(); got != nil {
		t.Fatalf("no lists: got %q", got)
	}
}

func TestIntegration_SNICandidates_AreCollectedFromTheAssetItself(t *testing.T) {
	store, db, tenant := newStampFixture(t)
	assetID, other := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{assetID, other} {
		execOrFail(t, db, `
			INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, primary_address,
			                    last_seen_at, first_discovered_at, created_at, updated_at)
			VALUES ($1, $2, $3, 'server', 'hardware.computer.server', 'monitoring', '10.20.30.51'::inet,
			        NOW(), NOW(), NOW(), NOW())`,
			id, tenant, id.String()[:8]+".example.test")
	}
	execOrFail(t, db, `
		INSERT INTO asset_endpoints (tenant_id, asset_id, address, port, transport, protocol, sni, status)
		VALUES ($1, $2, '10.20.30.51'::inet, 443, 'tcp', 'TLS', ARRAY['seen.example.test', 'none-7'], 'active')`,
		tenant, assetID)
	execOrFail(t, db, `
		INSERT INTO asset_identifiers (tenant_id, asset_id, kind, value)
		VALUES ($1, $2, 'fqdn', 'ident.example.test'), ($1, $2, 'hostname', 'web01'), ($1, $2, 'ip_address', '10.20.30.51')`,
		tenant, assetID)

	got, err := store.SNICandidates(context.Background(), tenant, []uuid.UUID{assetID, other})
	if err != nil {
		t.Fatalf("SNICandidates: %v", err)
	}
	want := []string{"seen.example.test", "ident.example.test", assetID.String()[:8] + ".example.test"}
	if !reflect.DeepEqual(got[assetID], want) {
		t.Fatalf("names = %q, want %q: observed SNI first, then the identifier, then the hostname; the placeholder and the IP excluded, three at most", got[assetID], want)
	}
	// An asset's names are its own: the other asset sees only its hostname.
	if wantOther := []string{other.String()[:8] + ".example.test"}; !reflect.DeepEqual(got[other], wantOther) {
		t.Fatalf("the second asset got %q, want %q", got[other], wantOther)
	}
}
