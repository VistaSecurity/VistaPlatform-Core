package services

// A node's risk score means nothing without saying whether anything assessed it.
//
// A stored 0 with an empty `risk_assessed_by` is NOT ASSESSED, and the map's
// GraphML / Cytoscape export needs the flag to leave the score out instead of
// writing a 0 for both "assessed clean" and "nobody looked". Both polarities, on
// the neighbourhood and on the impact closure (they share the peer loader).
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/relationships"
)

func TestIntegration_Neighbourhood_CarriesRiskAssessed(t *testing.T) {
	svc, db, tenant := relFixture(t)
	ctx := context.Background()

	root := seedRelAsset(t, db, tenant, "root.example.test", "monitoring")
	assessed := seedRelAsset(t, db, tenant, "assessed.example.test", "monitoring")
	unassessed := seedRelAsset(t, db, tenant, "unassessed.example.test", "monitoring")
	for _, q := range []struct {
		id uuid.UUID
		by string
	}{
		{root, "{}"},
		{assessed, "{crypto}"}, // assessed clean: score 0 WITH a producer
		{unassessed, "{}"},     // nobody looked
	} {
		if _, err := db.Exec(`UPDATE assets SET risk_score = 0, risk_assessed_by = $3::text[] WHERE tenant_id = $1 AND id = $2`,
			tenant, q.id, q.by); err != nil {
			t.Fatalf("set risk on %s: %v", q.id, err)
		}
	}
	seedEdge(t, db, tenant, root, assessed, relationships.RunsOn, SourceKindMeasured, EdgeStatusActive)
	seedEdge(t, db, tenant, root, unassessed, relationships.RunsOn, SourceKindMeasured, EdgeStatusActive)

	check := func(name string, nodes []NeighbourhoodNode) {
		t.Helper()
		got := map[uuid.UUID]NeighbourhoodNode{}
		for _, n := range nodes {
			got[n.AssetID] = n
		}
		if n, ok := got[assessed]; !ok || !n.RiskAssessed {
			t.Errorf("%s: an asset with a producer in risk_assessed_by is assessed (clean); present=%v risk_assessed=%v", name, ok, n.RiskAssessed)
		}
		if n, ok := got[unassessed]; !ok || n.RiskAssessed {
			t.Errorf("%s: an asset with an empty risk_assessed_by is NOT ASSESSED; present=%v risk_assessed=%v", name, ok, n.RiskAssessed)
		}
	}

	g, err := svc.Neighbourhood(ctx, tenant, root, 1, false)
	if err != nil {
		t.Fatalf("Neighbourhood: %v", err)
	}
	check("neighbourhood", g.Nodes)

	// Impact reads the same peer decoration. `runs_on` runs root -> peer, so the
	// peers are on one side or the other depending on direction; one of the two
	// walks must reach them.
	for _, dir := range []string{ImpactUpstream, ImpactDownstream} {
		imp, err := svc.Impact(ctx, tenant, root, dir, 1)
		if err != nil {
			t.Fatalf("Impact %s: %v", dir, err)
		}
		if len(imp.Nodes) == 0 {
			continue
		}
		check("impact "+dir, imp.Nodes)
	}
}
