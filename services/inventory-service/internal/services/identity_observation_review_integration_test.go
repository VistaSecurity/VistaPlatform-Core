package services

// The Observations review table's reads and bulk decision against a
// real Postgres with the real schema and seed.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// insertObservationRow writes one identity_observations row as given. The
// fingerprint is random: these rows are inputs to the read path, not evidence
// the engine will meet again.
func insertObservationRow(t *testing.T, db *sql.DB, tenant uuid.UUID, state string, reasons []string, enrichment, sourceRef, scope string, evidence string, lastSeen time.Time) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.QueryRow(`INSERT INTO identity_observations(tenant_id,fingerprint,source_kind,source_ref,network_scope,evidence,admission_reasons,state,enrichment_reason,first_seen_at,last_seen_at)
	 VALUES($1,$2,'measured',$3,$4,$5,$6,$7,$8,$9,$9) RETURNING id`,
		tenant, uuid.NewString(), sourceRef, scope, evidence, pq.Array(reasons), state, enrichment, lastSeen).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// seedOwnerAsset inserts an asset that owns the given identifiers
// ([kind, value, scope] triples) in asset_identifiers, the table the Confirm
// refusal and the ownership-aware suggestion both read.
func seedOwnerAsset(t *testing.T, db *sql.DB, tenant uuid.UUID, hostname, status string, deleted bool, owns ...[3]string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`INSERT INTO assets(id,tenant_id,hostname,display_name,class_key,class_path,asset_status,deleted_at)
	 VALUES($1,$2,$3,$3,'server','hardware.computer.server',$4,CASE WHEN $5 THEN now() END)`, id, tenant, hostname, status, deleted); err != nil {
		t.Fatal(err)
	}
	for _, o := range owns {
		if _, err := db.Exec(`INSERT INTO asset_identifiers(tenant_id,asset_id,kind,value,scope) VALUES($1,$2,$3,$4,NULLIF($5,''))`, tenant, id, o[0], o[1], o[2]); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

// The `needs` rule exists twice — SuggestObservation in Go, observationNeedsSQL
// for filtering and counting — and this holds them in lockstep over every
// combination of the inputs either reads. A change to one without the other
// fails on the first row they disagree about, naming the inputs.
func TestIntegration_ObservationNeeds_SQLMatchesGo(t *testing.T) {
	db, tenant := getTestDBAndTenant(t)
	testdb.WithSchemaShareLock(t, db.DB.DB, func() {
		// Ownership: who owns what, for the evidences below.
		seedOwnerAsset(t, db.DB.DB, tenant, "owner-a", "monitoring", false,
			[3]string{"ip_address", "198.51.100.1", "seg"}, [3]string{"ip_address", "198.51.100.2", "seg"},
			[3]string{"ip_address", "198.51.100.5", "seg"}, [3]string{"hostname", "h5", "seg"})
		seedOwnerAsset(t, db.DB.DB, tenant, "owner-b", "monitoring", false, [3]string{"mac_address", "aa:bb:cc:00:00:02", ""})
		seedOwnerAsset(t, db.DB.DB, tenant, "owner-archived", "archived", false, [3]string{"ip_address", "198.51.100.3", "seg"})
		seedOwnerAsset(t, db.DB.DB, tenant, "owner-deleted", "monitoring", true, [3]string{"ip_address", "198.51.100.4", "seg"})
		reasonPool := []string{rDynamic, rUnplaced, rRelayed, rNameOnly, "insufficient_identity_evidence"}
		evidences := []string{
			`{"identifiers":[{"kind":"hostname","value":"printer"}]}`,
			`{"identifiers":[{"kind":"ip_address","value":"192.0.2.17"}]}`,
			`{"endpoints":[{"address":"192.0.2.18","port":443,"transport":"tcp"}]}`,
			`{"endpoints":[{"fqdn":"svc.example.test","port":443,"transport":"tcp"}]}`,
			`{"identifiers":[{"kind":"ip_address","value":"192.0.2.19"}],"endpoints":[{"address":"192.0.2.19","port":22,"transport":"tcp","protocol":"ssh"}]}`,
			`{"identifiers":[{"kind":"ip_address","value":""}],"endpoints":[]}`,
			// Owned by one active asset → link_existing.
			`{"identifiers":[{"kind":"ip_address","value":"198.51.100.1","scope":"seg"}],"endpoints":[{"address":"198.51.100.1","port":22,"transport":"tcp"}]}`,
			// The same address in another scope is a different identifier → unowned.
			`{"identifiers":[{"kind":"ip_address","value":"198.51.100.1","scope":"other"}],"endpoints":[{"address":"198.51.100.1","port":22,"transport":"tcp"}]}`,
			// Owned by two assets → needs_review.
			`{"identifiers":[{"kind":"ip_address","value":"198.51.100.2","scope":"seg"},{"kind":"mac_address","value":"aa:bb:cc:00:00:02"}],"endpoints":[{"address":"198.51.100.2","port":22,"transport":"tcp"}]}`,
			// Owned by an archived asset / a deleted asset: Link would be refused → needs_review.
			`{"identifiers":[{"kind":"ip_address","value":"198.51.100.3","scope":"seg"}],"endpoints":[{"address":"198.51.100.3","port":22,"transport":"tcp"}]}`,
			`{"identifiers":[{"kind":"ip_address","value":"198.51.100.4","scope":"seg"}],"endpoints":[{"address":"198.51.100.4","port":22,"transport":"tcp"}]}`,
			// Two identifiers, ONE owner → still link_existing (owners are distinct assets).
			`{"identifiers":[{"kind":"ip_address","value":"198.51.100.5","scope":"seg"},{"kind":"hostname","value":"h5","scope":"seg"}],"endpoints":[{"address":"198.51.100.5","port":22,"transport":"tcp"}]}`,
			// One owned identifier, one unowned → the owner still counts.
			`{"identifiers":[{"kind":"ip_address","value":"198.51.100.1","scope":"seg"},{"kind":"mac_address","value":"aa:bb:cc:00:00:99"}],"endpoints":[{"address":"198.51.100.1","port":22,"transport":"tcp"}]}`,
		}
		now := time.Now().UTC()
		var (
			states, enrichments, evs, fps []string
			reasonSets                    []string
			seen                          []time.Time
		)
		for _, state := range []string{"unresolved", "linked", "expired"} {
			for mask := 0; mask < 1<<len(reasonPool); mask++ {
				reasons := []string{}
				for i, r := range reasonPool {
					if mask&(1<<i) != 0 {
						reasons = append(reasons, r)
					}
				}
				arr, _ := pq.Array(reasons).Value()
				for _, enrichment := range []string{"", rNoCollect} {
					for _, ev := range evidences {
						for _, at := range []time.Time{now.Add(-time.Hour), now.Add(-40 * 24 * time.Hour)} {
							states, enrichments, evs, fps = append(states, state), append(enrichments, enrichment), append(evs, ev), append(fps, uuid.NewString())
							reasonSets = append(reasonSets, arr.(string))
							seen = append(seen, at)
						}
					}
				}
			}
		}
		if _, err := db.Exec(`INSERT INTO identity_observations(tenant_id,fingerprint,source_kind,source_ref,evidence,admission_reasons,state,enrichment_reason,first_seen_at,last_seen_at)
		 SELECT $1, fp, 'measured', 'sensor', ev::jsonb, rs::text[], st, en, at, at
		 FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::timestamptz[]) AS u(fp, ev, rs, st, en, at)`,
			tenant, pq.Array(fps), pq.Array(evs), pq.Array(reasonSets), pq.Array(states), pq.Array(enrichments), pq.Array(seen)); err != nil {
			t.Fatal(err)
		}
		rows, err := db.Query(`SELECT o.state,o.admission_reasons,o.enrichment_reason,o.evidence,o.last_seen_at,`+observationNeedsSQL+`
		 FROM identity_observations o WHERE o.tenant_id=$1`, tenant)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		goCounts := map[string]int{}
		n := 0
		// Go's owners come from the DECISION path's lookup (observationOwners),
		// not from the SQL under test, so a disagreement is a real one.
		ownersTx, err := db.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ownersTx.Rollback() }()
		for rows.Next() {
			var state, enrichment, sqlNeeds string
			var reasons pq.StringArray
			var raw []byte
			var last time.Time
			if err := rows.Scan(&state, &reasons, &enrichment, &raw, &last, &sqlNeeds); err != nil {
				t.Fatal(err)
			}
			var ev identity.Observation
			if err := json.Unmarshal(raw, &ev); err != nil {
				t.Fatal(err)
			}
			owners, err := observationOwners(context.Background(), ownersTx, tenant, ev)
			if err != nil {
				t.Fatal(err)
			}
			goNeeds := SuggestObservation(ObservationSuggestionInput{State: state, AdmissionReasons: reasons, EnrichmentReason: enrichment, Evidence: ev, LastSeenAt: last, Owners: owners}, time.Now().UTC()).Needs
			if goNeeds != sqlNeeds {
				t.Fatalf("Go says %s, SQL says %s for state=%s reasons=%v enrichment=%q evidence=%s last_seen=%s owners=%+v",
					goNeeds, sqlNeeds, state, []string(reasons), enrichment, raw, last, owners)
			}
			goCounts[goNeeds]++
			n++
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		if n != len(fps) {
			t.Fatalf("compared %d rows, inserted %d", n, len(fps))
		}
		for _, needs := range ObservationNeedsValues {
			if goCounts[needs] == 0 {
				t.Fatalf("the matrix never produced %s, so it proves nothing about that branch: %v", needs, goCounts)
			}
		}
		// And the filter path, which is where the SQL copy is used: filtering
		// by each needs value over every state returns exactly Go's count.
		svc := NewAssetService(db)
		for _, needs := range ObservationNeedsValues {
			page, err := svc.ListIdentityObservationsFiltered(context.Background(), tenant, ObservationListFilter{State: "all", Page: 1, PageSize: 100, Needs: []string{needs}})
			if err != nil {
				t.Fatal(err)
			}
			if page.Total != goCounts[needs] {
				t.Errorf("needs=%s: filtered total %d, Go counted %d", needs, page.Total, goCounts[needs])
			}
			for _, o := range page.Observations {
				if o.Needs != needs {
					t.Errorf("needs=%s filter returned a row the response labels %s", needs, o.Needs)
				}
			}
		}
	})
}

// Names come from the observation's OWN tenant. Tenant B's rows name tenant
// A's segment and sensor — a forged or stale reference — and must resolve to
// nothing, through the plain pool (the join's tenant predicate) and through
// the application role (RLS) alike.
func TestIntegration_ObservationReview_NamesAreTenantScoped(t *testing.T) {
	db, tenantA := getTestDBAndTenant(t)
	// Before the share lock: granting the app role LOGIN takes the schema
	// lock exclusively, and would wait forever on our own shared hold.
	app := testdb.ConnectAsAppRole(t, db.DB.DB)
	testdb.WithSchemaShareLock(t, db.DB.DB, func() {
		tenantB := testdb.NewTenant(t, db.DB.DB)
		segment := seedSegment(t, db, tenantA, "Head office LAN", "192.0.2.0/24")
		sensor := uuid.New()
		if _, err := db.Exec(`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status) VALUES($1,$2,'Head office sensor','linux','1','datacenter_host','active')`, sensor, tenantA); err != nil {
			t.Fatal(err)
		}
		ev := `{"identifiers":[{"kind":"ip_address","value":"192.0.2.17"}],"endpoints":[{"address":"192.0.2.17","port":22,"transport":"tcp","protocol":"ssh"}]}`
		now := time.Now().UTC().Add(-time.Hour)
		mine := insertObservationRow(t, db.DB.DB, tenantA, "unresolved", []string{rDynamic}, "", "sensor:"+sensor.String(), segment.String(), ev, now)
		forged := insertObservationRow(t, db.DB.DB, tenantB, "unresolved", []string{rDynamic}, "", "scan:"+sensor.String(), segment.String(), ev, now)

		for _, pool := range []struct {
			name string
			svc  *AssetService
		}{
			{"plain pool", NewAssetService(db)},
			{"application role", NewAssetService(&database.DB{DB: sqlx.NewDb(app, "postgres")})},
		} {
			t.Run(pool.name, func(t *testing.T) {
				ctx := context.Background()
				a, err := pool.svc.GetIdentityObservation(ctx, tenantA, mine)
				if err != nil {
					t.Fatal(err)
				}
				if a.NetworkName == nil || *a.NetworkName != "Head office LAN" || a.SourceName != "Head office sensor" {
					t.Fatalf("own names not resolved: network=%v source=%q", a.NetworkName, a.SourceName)
				}
				if !strings.Contains(a.SuggestedReason, "on Head office LAN (Head office sensor)") || uuidRE.MatchString(a.SuggestedReason) {
					t.Fatalf("suggested reason %q", a.SuggestedReason)
				}
				page, err := pool.svc.ListIdentityObservationsFiltered(ctx, tenantB, ObservationListFilter{State: "unresolved", Page: 1, PageSize: 50})
				if err != nil {
					t.Fatal(err)
				}
				if page.Total != 1 || page.Observations[0].ID != forged {
					t.Fatalf("tenant B page %+v", page)
				}
				b := page.Observations[0]
				if b.NetworkName != nil || b.SourceName != "Discovery scan" {
					t.Fatalf("tenant A's names leaked to tenant B: network=%v source=%q", b.NetworkName, b.SourceName)
				}
				if strings.Contains(b.SuggestedReason, "Head office") {
					t.Fatalf("tenant A's names leaked into B's reason: %q", b.SuggestedReason)
				}
				// A search for A's names finds nothing of B's.
				hit, err := pool.svc.ListIdentityObservationsFiltered(ctx, tenantB, ObservationListFilter{State: "all", Page: 1, PageSize: 50, Query: "head office"})
				if err != nil || hit.Total != 0 {
					t.Fatalf("search crossed tenants: total=%d err=%v", hit.Total, err)
				}
			})
		}
	})
}

func TestIntegration_ObservationReview_FiltersCountsSortPaging(t *testing.T) {
	db, tenant := getTestDBAndTenant(t)
	testdb.WithSchemaShareLock(t, db.DB.DB, func() {
		ctx := context.Background()
		svc := NewAssetService(db)
		office := seedSegment(t, db, tenant, "Office", "192.0.2.0/24")
		lab := seedSegment(t, db, tenant, "Lab", "198.51.100.0/24")
		sensor := uuid.New()
		if _, err := db.Exec(`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status) VALUES($1,$2,'Rack sensor','linux','1','datacenter_host','active')`, sensor, tenant); err != nil {
			t.Fatal(err)
		}
		src := "sensor:" + sensor.String()
		base := time.Now().UTC().Add(-time.Hour)
		ready := func(addr, host string) string {
			return fmt.Sprintf(`{"hostname":%q,"identifiers":[{"kind":"ip_address","value":%q}],"endpoints":[{"address":%q,"port":22,"transport":"tcp","protocol":"ssh"}]}`, host, addr, addr)
		}
		// 5 ready on Office, 2 needs-network, 1 needs-sensor (Lab), 1 noise,
		// 1 ready but DISMISSED (not counted), 1 ready but 40 days old
		// (outside the unresolved window, not counted).
		var readyIDs []uuid.UUID
		for i := 0; i < 5; i++ {
			readyIDs = append(readyIDs, insertObservationRow(t, db.DB.DB, tenant, "unresolved", []string{rDynamic}, "", src, office.String(),
				ready(fmt.Sprintf("192.0.2.%d", 10+i), fmt.Sprintf("host-%c", 'e'-i)), base.Add(time.Duration(i)*time.Minute)))
		}
		for i := 0; i < 2; i++ {
			insertObservationRow(t, db.DB.DB, tenant, "unresolved", []string{rUnplaced}, "", "scan", "", ready(fmt.Sprintf("203.0.113.%d", i+1), ""), base)
		}
		insertObservationRow(t, db.DB.DB, tenant, "unresolved", []string{rRelayed}, "", src, lab.String(), ready("198.51.100.5", "lab-printer"), base)
		insertObservationRow(t, db.DB.DB, tenant, "unresolved", []string{rNameOnly}, "", src, "", `{"identifiers":[{"kind":"hostname","value":"ghost"}]}`, base)
		insertObservationRow(t, db.DB.DB, tenant, "dismissed", []string{rDynamic}, "", src, office.String(), ready("192.0.2.90", "gone"), base)
		insertObservationRow(t, db.DB.DB, tenant, "unresolved", []string{rDynamic}, "", src, office.String(), ready("192.0.2.91", "old"), base.Add(-40*24*time.Hour))

		list := func(f ObservationListFilter) IdentityObservationPage {
			t.Helper()
			if f.State == "" {
				f.State = "unresolved"
			}
			if f.Page == 0 {
				f.Page, f.PageSize = 1, 50
			}
			page, err := svc.ListIdentityObservationsFiltered(ctx, tenant, f)
			if err != nil {
				t.Fatal(err)
			}
			return page
		}
		all := list(ObservationListFilter{})
		want := ObservationNeedsCounts{ReadyToConfirm: 5, NeedsNetwork: 2, NeedsSensor: 1, LikelyNoise: 1, All: 9}
		if all.Counts == nil || *all.Counts != want {
			t.Fatalf("counts %+v, want %+v", all.Counts, want)
		}
		if all.Total != 9 {
			t.Fatalf("unresolved total %d, want 9", all.Total)
		}
		// Counts are independent of the filter.
		narrowed := list(ObservationListFilter{Needs: []string{NeedsSensor}})
		if narrowed.Total != 1 || narrowed.Counts == nil || *narrowed.Counts != want {
			t.Fatalf("needs filter: total=%d counts=%+v", narrowed.Total, narrowed.Counts)
		}
		if two := list(ObservationListFilter{Needs: []string{NeedsNetwork, NeedsLikelyNoise}}); two.Total != 3 {
			t.Fatalf("two needs values: total=%d, want 3", two.Total)
		}
		// Paging under a filter: total stays honest, pages partition.
		p1 := list(ObservationListFilter{Needs: []string{NeedsReadyToConfirm}, Page: 1, PageSize: 2})
		p3 := list(ObservationListFilter{Needs: []string{NeedsReadyToConfirm}, Page: 3, PageSize: 2})
		if p1.Total != 5 || len(p1.Observations) != 2 || p3.Total != 5 || len(p3.Observations) != 1 {
			t.Fatalf("paging: p1 total=%d len=%d, p3 total=%d len=%d", p1.Total, len(p1.Observations), p3.Total, len(p3.Observations))
		}
		if p1.Observations[0].ID != readyIDs[4] {
			t.Fatalf("default sort is not last_seen_desc: first=%s", p1.Observations[0].ID)
		}
		if asc := list(ObservationListFilter{Needs: []string{NeedsReadyToConfirm}, Sort: "last_seen_asc"}); asc.Observations[0].ID != readyIDs[0] {
			t.Fatalf("last_seen_asc first=%s", asc.Observations[0].ID)
		}
		// host sort: host-a (readyIDs[4]) … host-e (readyIDs[0]).
		if host := list(ObservationListFilter{Needs: []string{NeedsReadyToConfirm}, Sort: "host"}); host.Observations[0].ID != readyIDs[4] || host.Observations[4].ID != readyIDs[0] {
			t.Fatalf("host sort: %s … %s", host.Observations[0].ID, host.Observations[4].ID)
		}
		if net := list(ObservationListFilter{Sort: "network"}); net.Observations[0].NetworkName == nil || *net.Observations[0].NetworkName != "Lab" {
			t.Fatalf("network sort first=%v", net.Observations[0].NetworkName)
		}
		bySort := list(ObservationListFilter{Sort: "needs"})
		order := []string{}
		for _, o := range bySort.Observations {
			if len(order) == 0 || order[len(order)-1] != o.Needs {
				order = append(order, o.Needs)
			}
		}
		if strings.Join(order, ",") != "ready_to_confirm,needs_network,needs_sensor,likely_noise" {
			t.Fatalf("needs sort grouped as %v", order)
		}
		if scoped := list(ObservationListFilter{NetworkScope: lab.String()}); scoped.Total != 1 {
			t.Fatalf("network_scope filter total=%d", scoped.Total)
		}
		if bySource := list(ObservationListFilter{Source: "scan"}); bySource.Total != 2 {
			t.Fatalf("source filter total=%d", bySource.Total)
		}
		for q, n := range map[string]int{"HOST-C": 1, "192.0.2.1": 5, "office": 5, "rack sensor": 7, "lab-printer": 1, "%": 0, "_": 0} {
			if got := list(ObservationListFilter{Query: q}); got.Total != n {
				t.Errorf("q=%q total=%d, want %d", q, got.Total, n)
			}
		}
		// The old parameters still work, and state=all reaches the rows the
		// unresolved window hides.
		if everything := list(ObservationListFilter{State: "all"}); everything.Total != 11 {
			t.Fatalf("state=all total=%d, want 11", everything.Total)
		}
		if _, err := svc.ListIdentityObservationsFiltered(ctx, tenant, ObservationListFilter{State: "unresolved", Page: 1, PageSize: 50, Sort: "bogus"}); err == nil {
			t.Fatal("an unknown sort was accepted")
		}
	})
}

func TestIntegration_ObservationBulk_MixedOutcomesAndAudit(t *testing.T) {
	db, tenant := getTestDBAndTenant(t)
	testdb.WithSchemaShareLock(t, db.DB.DB, func() {
		ctx := context.Background()
		svc := NewAssetService(db)
		actor := seedUser(t, db, tenant)
		other := testdb.NewTenant(t, db.DB.DB)
		segment := seedSegment(t, db, tenant, "Home", "192.0.2.0/24")
		if _, err := db.Exec(`INSERT INTO tenant_entitlements(tenant_id,item_id,override_value,reason)
		 SELECT $1,id,'{"quantity":1}'::jsonb,'bulk regression' FROM billable_items WHERE key='max_assets'`, tenant); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Add(-time.Hour)
		readyEv := func(addr string) string {
			return fmt.Sprintf(`{"identifiers":[{"kind":"ip_address","value":%q,"scope":%q}],"endpoints":[{"address":%q,"port":22,"transport":"tcp","protocol":"ssh"}]}`, addr, segment, addr)
		}
		first := insertObservationRow(t, db.DB.DB, tenant, "unresolved", []string{rDynamic}, "", "scan", segment.String(), readyEv("192.0.2.21"), now)
		second := insertObservationRow(t, db.DB.DB, tenant, "unresolved", []string{rDynamic}, "", "scan", segment.String(), readyEv("192.0.2.22"), now)
		notReady := insertObservationRow(t, db.DB.DB, tenant, "unresolved", []string{rRelayed}, "", "scan", segment.String(), readyEv("192.0.2.23"), now)
		conflicted := insertObservationRow(t, db.DB.DB, tenant, "conflict", []string{rDynamic}, "", "scan", segment.String(), readyEv("192.0.2.24"), now)
		foreign := insertObservationRow(t, db.DB.DB, other, "unresolved", []string{rDynamic}, "", "scan", "", readyEv("192.0.2.25"), now)

		batch, items, err := svc.BulkDecideIdentityObservations(ctx, tenant, actor, "confirm",
			[]uuid.UUID{first, second, notReady, conflicted, foreign, first}, ObservationDecisionInput{Reason: "Recognised on the home network"})
		if err != nil {
			t.Fatal(err)
		}
		if batch == uuid.Nil || len(items) != 5 {
			t.Fatalf("batch=%s items=%d, want 5 (the repeated id is decided once)", batch, len(items))
		}
		byID := map[uuid.UUID]error{}
		for _, it := range items {
			byID[it.ID] = it.Err
		}
		if byID[first] != nil {
			t.Fatalf("first confirm: %v", byID[first])
		}
		if !errors.Is(byID[second], ErrObservationAllowance) {
			t.Fatalf("second confirm past the allowance of 1: %v, want 402", byID[second])
		}
		if !errors.Is(byID[notReady], ErrObservationNotReady) {
			t.Fatalf("relayed advertisement confirmed in bulk: %v, want not_ready_to_confirm (D4)", byID[notReady])
		}
		if !errors.Is(byID[conflicted], ErrObservationNotReady) {
			t.Fatalf("conflicted observation: %v, want not_ready_to_confirm", byID[conflicted])
		}
		if !errors.Is(byID[foreign], ErrObservationNotFound) {
			t.Fatalf("another tenant's observation: %v, want not found", byID[foreign])
		}
		// The D4 refusal changed nothing, and the single endpoint still
		// confirms the same row: the rule is bulk-only.
		var state string
		if err := db.QueryRow(`SELECT state FROM identity_observations WHERE tenant_id=$1 AND id=$2`, tenant, notReady).Scan(&state); err != nil || state != "unresolved" {
			t.Fatalf("refused row changed: %s %v", state, err)
		}

		// Dismiss takes any unresolved or expired row; a conflict is the
		// single endpoint's 409.
		expired := insertObservationRow(t, db.DB.DB, tenant, "expired", []string{rNameOnly}, "", "scan", "", `{"identifiers":[{"kind":"hostname","value":"old"}]}`, now)
		dbatch, ditems, err := svc.BulkDecideIdentityObservations(ctx, tenant, actor, "dismiss", []uuid.UUID{notReady, expired, conflicted}, ObservationDecisionInput{Reason: "Not ours"})
		if err != nil {
			t.Fatal(err)
		}
		if ditems[0].Err != nil || ditems[1].Err != nil || !errors.Is(ditems[2].Err, ErrObservationChanged) {
			t.Fatalf("dismiss results: %v / %v / %v", ditems[0].Err, ditems[1].Err, ditems[2].Err)
		}

		// One audit row per decided item, each carrying its batch id.
		for _, c := range []struct {
			batch uuid.UUID
			ids   []uuid.UUID
		}{{batch, []uuid.UUID{first}}, {dbatch, []uuid.UUID{notReady, expired}}} {
			var n int
			if err := db.QueryRow(`SELECT count(*) FROM identity_observation_decisions WHERE tenant_id=$1 AND details->>'batch_id'=$2`, tenant, c.batch.String()).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != len(c.ids) {
				t.Fatalf("batch %s has %d audit rows, want %d", c.batch, n, len(c.ids))
			}
		}
		// A single decision carries no batch id.
		single := insertObservationRow(t, db.DB.DB, tenant, "unresolved", []string{rNameOnly}, "", "scan", "", `{"identifiers":[{"kind":"hostname","value":"single"}]}`, now)
		if _, err := svc.DecideIdentityObservation(ctx, tenant, single, actor, "dismissed", ObservationDecisionInput{Reason: "one"}); err != nil {
			t.Fatal(err)
		}
		var hasBatch bool
		if err := db.QueryRow(`SELECT details ? 'batch_id' FROM identity_observation_decisions WHERE tenant_id=$1 AND observation_id=$2`, tenant, single).Scan(&hasBatch); err != nil || hasBatch {
			t.Fatalf("single decision batch id: %v %v", hasBatch, err)
		}

		// Cancellation reports the rest as cancelled; nothing is skipped silently.
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		_, citems, err := svc.BulkDecideIdentityObservations(cancelled, tenant, actor, "dismiss", []uuid.UUID{second}, ObservationDecisionInput{Reason: "late"})
		if err != nil || len(citems) != 1 || !errors.Is(citems[0].Err, context.Canceled) {
			t.Fatalf("cancelled batch: %+v %v", citems, err)
		}

		if _, _, err := svc.BulkDecideIdentityObservations(ctx, tenant, actor, "relink", []uuid.UUID{second}, ObservationDecisionInput{Reason: "x"}); err == nil {
			t.Fatal("an unknown bulk action was accepted")
		}
		tooMany := make([]uuid.UUID, MaxBulkObservationDecisions+1)
		if _, _, err := svc.BulkDecideIdentityObservations(ctx, tenant, actor, "dismiss", tooMany, ObservationDecisionInput{Reason: "x"}); err == nil {
			t.Fatal("more than 200 ids accepted")
		}
	})
}
