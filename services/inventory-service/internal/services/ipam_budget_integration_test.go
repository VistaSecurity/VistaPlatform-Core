package services

// IPAM performance budgets (DCIM DATA_MODEL §12) on the scale fixture
// (shared/testdb/dcimfixture): at Scale1, 20,000 prefixes holding 200,000 IP
// addresses across 50 VRFs, plus one dense global /16 with 10,000 addresses
// for the available-IPs budget. DCIM_SCALE=1 selects Scale1 (make
// test-dcim-scale, nightly); otherwise the fixture's Small() shape runs.
//
// Budgets: prefix tree page < 300 ms, available IPs for a /16 < 500 ms,
// /ipam/find < 50 ms — each the median of five runs at the service (one
// transaction, the real queries, as the RLS app role). dcimfixture.AssertUnder
// records them and fails only under DCIM_BUDGETS=enforce.

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
	"github.com/vistasecurity/vistaplatform/shared/testdb/dcimfixture"
)

func ipamMedian(t *testing.T, name string, budget time.Duration, fn func() error) {
	t.Helper()
	var ds []time.Duration
	for range 5 {
		start := time.Now()
		if err := fn(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		ds = append(ds, time.Since(start))
	}
	slices.Sort(ds)
	dcimfixture.AssertUnder(t, name, ds[2], budget)
}

func TestIntegration_IPAM_Budgets(t *testing.T) {
	f := newIPAMFixture(t)
	testdb.HoldSchemaShareLock(t, f.owner)
	scale := dcimfixture.Small()
	if os.Getenv("DCIM_SCALE") == "1" {
		scale = dcimfixture.Scale1()
	}
	sum := dcimfixture.Populate(context.Background(), t, f.owner, f.tenant, scale)
	if sum.Counts["prefixes"] != scale.Prefixes() || sum.Counts["ip_addresses"] != scale.IPs() {
		t.Fatalf("fixture wrote %d prefixes / %d addresses, want %d / %d (skipped %v)",
			sum.Counts["prefixes"], sum.Counts["ip_addresses"], scale.Prefixes(), scale.IPs(), sum.Skipped)
	}
	// One dense /16 in the global table: 10,000 addresses.
	for _, q := range []string{
		`INSERT INTO prefixes (tenant_id, prefix) VALUES ($1, '172.16.0.0/16')`,
		`INSERT INTO ip_addresses (tenant_id, address)
		   SELECT $1, ('172.16.' || (g / 250) || '.' || (g % 250 + 1) || '/16')::inet FROM generate_series(0, 9999) g`,
	} {
		if _, err := f.owner.Exec(q, f.tenant); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []string{`ANALYZE prefixes`, `ANALYZE ip_addresses`, `ANALYZE prefix_utilization`, `ANALYZE vrfs`, `ANALYZE vlans`, `ANALYZE assets`} {
		if _, err := f.owner.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	var vrf, dense uuid.UUID
	if err := f.owner.QueryRow(`SELECT id FROM vrfs WHERE tenant_id = $1 AND name = $2`, f.tenant, dcimfixture.VRFName(scale.VRFs()-1)).Scan(&vrf); err != nil {
		t.Fatal(err)
	}
	if err := f.owner.QueryRow(`SELECT id FROM prefixes WHERE tenant_id = $1 AND prefix = '172.16.0.0/16'`, f.tenant).Scan(&dense); err != nil {
		t.Fatal(err)
	}
	perVRF := scale.Prefixes() / scale.VRFs()
	t.Logf("fixture: %d prefixes, %d addresses, %d VRFs (%d prefixes per VRF), populated in %v",
		scale.Prefixes(), scale.IPs()+10000, scale.VRFs(), perVRF, sum.Elapsed)

	ipamMedian(t, "ipam: prefix tree (one VRF)", 300*time.Millisecond, func() error {
		_, total, err := f.svc.PrefixTree(f.ctx, f.tenant, &vrf)
		if err == nil && total != perVRF {
			t.Fatalf("tree: %d prefixes, want %d", total, perVRF)
		}
		return err
	})
	ipamMedian(t, "ipam: available IPs for a /16 (10k used)", 500*time.Millisecond, func() error {
		d, err := f.svc.PrefixDetail(f.ctx, f.tenant, dense, PrefixDetailParams{IPLimit: 50, AvailableLimit: 50})
		if err == nil && (len(d.AvailableIPs.Addresses) != 50 || d.IPCount != 10000) {
			t.Fatalf("detail: %d listed, %d addresses", len(d.AvailableIPs.Addresses), d.IPCount)
		}
		return err
	})
	probe := netip.MustParseAddr("10.0.1.7")
	ipamMedian(t, "ipam: find in one VRF", 50*time.Millisecond, func() error {
		res, err := f.svc.FindAddress(f.ctx, f.tenant, probe, &vrf, false)
		if err == nil && len(res) != 1 {
			t.Fatalf("find: %d results", len(res))
		}
		return err
	})
	ipamMedian(t, "ipam: find across every VRF", 50*time.Millisecond, func() error {
		res, err := f.svc.FindAddress(f.ctx, f.tenant, probe, nil, true)
		if err == nil && len(res) != scale.VRFs() {
			t.Fatalf("find all: %d results, want %d", len(res), scale.VRFs())
		}
		return err
	})
	ipamMedian(t, "ipam: prefix list page (50)", 300*time.Millisecond, func() error {
		_, _, err := f.svc.List(f.ctx, f.tenant, "prefixes", IPAMListParams{Limit: 50})
		return err
	})
	// A write's synchronous utilisation refresh walks the ancestor chain.
	n := 0
	ipamMedian(t, "ipam: create an address (with refresh)", 100*time.Millisecond, func() error {
		n++
		_, err := f.svc.Create(f.ctx, f.tenant, "ip-addresses", []byte(fmt.Sprintf(`{"address":"10.0.1.%d/24","vrf_id":%q}`, 200+n, vrf)))
		return err
	})
}
