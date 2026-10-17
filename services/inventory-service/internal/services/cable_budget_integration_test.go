package services

// Cable trace budget (DCIM DATA_MODEL §12: cable trace < 100 ms on 100,000
// cables). DCIM_SCALE=1 selects Scale1 (make test-dcim-scale, nightly);
// otherwise the fixture's Small() shape runs. The trace is the median of five
// at the service — the app role, RLS in force, the real queries — from an
// interface whose path crosses two patch panels (a nine-hop path). A
// recompute of that path (what a cable write costs per origin) is recorded
// beside it.

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/cablepath"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
	"github.com/vistasecurity/vistaplatform/shared/testdb/dcimfixture"
)

func TestIntegration_Cables_TraceBudget(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	testdb.HoldSchemaShareLock(t, owner)
	scale := dcimfixture.Small()
	if os.Getenv("DCIM_SCALE") == "1" {
		scale = dcimfixture.Scale1()
	}
	ctx := context.Background()
	sum := dcimfixture.Populate(ctx, t, owner, tenant, scale)
	if sum.Counts["cables"] != scale.Cables() || len(sum.PatchedInterfaces) == 0 {
		t.Fatalf("fixture wrote %d cables (want %d), %d patched interfaces (skipped %v)",
			sum.Counts["cables"], scale.Cables(), len(sum.PatchedInterfaces), sum.Skipped)
	}
	for _, q := range []string{`ANALYZE cables`, `ANALYZE cable_terminations`, `ANALYZE cable_paths`, `ANALYZE interfaces`,
		`ANALYZE front_ports`, `ANALYZE rear_ports`, `ANALYZE assets`} {
		if _, err := owner.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	svc := NewCableService(app)
	origin := sum.PatchedInterfaces[len(sum.PatchedInterfaces)/2]
	t.Logf("fixture: %d cables, populated in %v", sum.Counts["cables"], sum.Elapsed)

	var res TraceResult
	ipamMedian(t, "cable trace (interface through two patch panels)", 100*time.Millisecond, func() error {
		var err error
		res, err = svc.Trace(ctx, tenant, dcim.ObjectKindInterface, origin)
		return err
	})
	if len(res.Paths) != 1 || !res.Paths[0].IsComplete || len(res.Paths[0].Segments) != 3 {
		t.Fatalf("the budgeted trace is not the three-cable path it should be: %+v", res.Paths)
	}
	// A pass-through port's trace (paths THROUGH it, the GIN read).
	rear := res.Paths[0].Segments[1].NearEnd[0].ID
	ipamMedian(t, "cable trace (paths through a rear port)", 100*time.Millisecond, func() error {
		r, err := svc.Trace(ctx, tenant, dcim.ObjectKindRearPort, rear)
		if err == nil && len(r.Paths) != 2 {
			t.Fatalf("rear port carries %d paths, want 2", len(r.Paths))
		}
		return err
	})
	ipamMedian(t, "cable path recompute (one origin, two panels)", 100*time.Millisecond, func() error {
		return database.WithTenantTx(ctx, app, tenant, func(tx *sql.Tx) error {
			return cablepath.Recompute(ctx, tx, tenant, []cablepath.Node{cablepath.N(dcim.ObjectKindInterface, origin)})
		})
	})
}
