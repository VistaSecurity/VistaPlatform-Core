package services

// The asset timeline records what CHANGED, not that something was observed
// again (asset_context.go applyAssetContext), against a real Postgres.
//
// A sensor re-states an unchanged host's context on every coalescing window:
// the same ownership, the same discovery source, and a fresh batch id. Each of
// those used to write an `updated` row, so an idle inventory accumulated
// hundreds of rows an hour whose only difference was the batch id, and the
// rows a reviewer needs (a new owner, a moved environment) were buried.
//
// The half that must NOT go quiet is held here too: a real change still
// writes exactly one row naming it, a person's edit still writes its row, and
// an import or declaration listing an asset still leaves one row per source
// the first time (`listed_by`, written by the identification engine on the
// same transaction) — a reviewer reads it as "this source vouches for the
// asset", and nothing on the context path may swallow it.
//
// MUTATION (each goes red): make applyAssetContext record unconditionally
// (skip the `moved` filter) — the repeat-observation, real-change, repeat-pull
// and listing tests fail; drop metadataProvenanceKeys from the metadata
// comparison — the repeat-observation, alternating-descriptor and real-change tests fail; make the
// gate drop every `updated` row — the real-change and repeat-pull tests fail;
// filter `created` rows by `moved` too — the repeat-observation test fails (a
// created row would lose the ownership that matched the column default); drop
// the engine's `listed_by` — the listing test fails; drop UpdateAsset's
// history write — the person-edit test fails.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db). RFC 5737 documentation addresses throughout.

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

type contextHistoryRow struct {
	Action  string
	Source  string
	Actor   *uuid.UUID
	Changes map[string]any
}

// assetTimeline reads one asset's history in append order.
func assetTimeline(t *testing.T, db *database.DB, tenant, asset uuid.UUID) []contextHistoryRow {
	t.Helper()
	rows, err := db.Query(`
		SELECT action, source, actor_user_id, changes_json::text
		  FROM asset_history WHERE tenant_id = $1 AND asset_id = $2 ORDER BY seq`, tenant, asset)
	if err != nil {
		t.Fatalf("read history: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []contextHistoryRow
	for rows.Next() {
		var r contextHistoryRow
		var raw string
		if err := rows.Scan(&r.Action, &r.Source, &r.Actor, &raw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(raw), &r.Changes); err != nil {
			t.Fatalf("decode changes %s: %v", raw, err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func countTimelineAction(rows []contextHistoryRow, action string) int {
	n := 0
	for _, r := range rows {
		if r.Action == action {
			n++
		}
	}
	return n
}

func describeTimeline(rows []contextHistoryRow) string {
	s := ""
	for i, r := range rows {
		b, _ := json.Marshal(r.Changes)
		s += fmt.Sprintf("\n  %d. %s by %s: %s", i+1, r.Action, r.Source, b)
	}
	return s
}

// hostObservationBatch is the finding a sensor forwards for one coalescing
// window: the same host, a later observation time, and the window's own batch.
func hostObservationBatch(t *testing.T, i int, attrs map[string]interface{}) IngestFinding {
	t.Helper()
	return hostObservationBatchHeardBy(t, i, attrs, []string{hostobs.SourceMDNS})
}

// hostObservationBatchHeardBy is hostObservationBatch with the collectors that
// heard the host named, for a host two of them alternate on.
func hostObservationBatchHeardBy(t *testing.T, i int, attrs map[string]interface{}, sources []string) IngestFinding {
	t.Helper()
	f := observationFinding(t, &hostobs.HostObservation{
		Source:     hostobs.SourceMDNS,
		Sources:    sources,
		MAC:        "28:cf:da:77:00:01",
		Addresses:  addrsFor(t, "192.0.2.70"),
		FQDNs:      []string{"office-speaker.local"},
		Hostnames:  []string{"office-speaker"},
		Services:   []string{"_airplay._tcp"},
		Attributes: attrs,
		ObservedAt: time.Now().UTC().Add(time.Duration(i-10) * time.Minute),
	})
	f.RawData["batch_id"] = fmt.Sprintf("batch-%d-%s", i, uuid.NewString())
	return f
}

func onlyAsset(t *testing.T, db *database.DB, tenant uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.QueryRow(`SELECT id FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL`, tenant).Scan(&id); err != nil {
		t.Fatalf("read the one asset: %v", err)
	}
	return id
}

func lastSeen(t *testing.T, db *database.DB, asset uuid.UUID) time.Time {
	t.Helper()
	var at time.Time
	if err := db.QueryRow(`SELECT last_seen_at FROM assets WHERE id = $1`, asset).Scan(&at); err != nil {
		t.Fatal(err)
	}
	return at
}

// The defect, measured: the same host observed five times, each in its own
// batch, with nothing about it changing. The first observation creates it and
// says so; the four after it refresh last-seen and write nothing.
func TestIntegration_AssetContextHistory_RepeatObservationWritesNoRow(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)

	if _, err := svc.IngestFindings(tenant, []IngestFinding{hostObservationBatch(t, 1, nil)}); err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	asset := onlyAsset(t, db, tenant)
	first := assetTimeline(t, db, tenant, asset)
	if countTimelineAction(first, string(identity.ActionCreated)) == 0 {
		t.Fatalf("the creating observation left no created row:%s", describeTimeline(first))
	}
	if n := countTimelineAction(first, string(identity.ActionUpdated)); n != 0 {
		t.Fatalf("the creating observation wrote %d updated rows:%s", n, describeTimeline(first))
	}
	// The created row carries the context the asset was born with, provenance
	// included: that is the one row where "which batch" is the record.
	var createdWithContext bool
	for _, r := range first {
		if r.Action == string(identity.ActionCreated) && r.Changes["metadata"] != nil && r.Changes["asset_ownership"] != nil {
			createdWithContext = true
		}
	}
	if !createdWithContext {
		t.Errorf("no created row names the context the asset was created with:%s", describeTimeline(first))
	}
	seenAfterFirst := lastSeen(t, db, asset)

	for i := 2; i <= 5; i++ {
		if _, err := svc.IngestFindings(tenant, []IngestFinding{hostObservationBatch(t, i, nil)}); err != nil {
			t.Fatalf("ingest %d: %v", i, err)
		}
	}
	if got := onlyAsset(t, db, tenant); got != asset {
		t.Fatalf("the repeat observations resolved to %s, want %s", got, asset)
	}
	after := assetTimeline(t, db, tenant, asset)
	if len(after) != len(first) {
		t.Errorf("four repeat observations of an unchanged host wrote %d rows, want 0:%s",
			len(after)-len(first), describeTimeline(after[len(first):]))
	}
	if n := countTimelineAction(after, string(identity.ActionCreated)); n != countTimelineAction(first, string(identity.ActionCreated)) {
		t.Errorf("created rows went from %d to %d", countTimelineAction(first, string(identity.ActionCreated)), n)
	}
	if !lastSeen(t, db, asset).After(seenAfterFirst) {
		t.Error("last_seen_at did not advance: a quiet timeline must not mean an asset that stopped being seen")
	}
	// The provenance is still STORED: the asset's metadata names the latest
	// batch, as it did before; it just is not news on the timeline.
	var batch string
	if err := db.QueryRow(`SELECT COALESCE(metadata->>'batch_id','') FROM assets WHERE id = $1`, asset).Scan(&batch); err != nil {
		t.Fatal(err)
	}
	if batch == "" || batch[:8] != "batch-5-" {
		t.Errorf("metadata.batch_id = %q, want the fifth batch's id", batch)
	}
}

// The defect found on a quiet install after 4.4.0: one host announcing two mDNS
// services (ports 7000 and 53696), heard sometimes through a reflector and
// sometimes by mDNS and ARP together. Each observation describes ITSELF, and
// the metadata merge replaces `host_observation_attributes` and
// `host_observation_sources` wholesale, so they flipped on every observation
// and each flip wrote an `updated` row (840 of 861 in six hours, one asset
// ~100 an hour). They are sighting provenance, like the batch id.
//
// MUTATION: take host_observation_attributes (or host_observation_sources) out
// of metadataProvenanceKeys — this test fails.
func TestIntegration_AssetContextHistory_AlternatingSightingDescriptorsWriteNoRow(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	observe := func(i int) {
		t.Helper()
		attrs := map[string]interface{}{"capture_interface": "eth0", "mdns_service_port": 53696}
		sources := []string{hostobs.SourceMDNS}
		if i%2 == 0 {
			attrs = map[string]interface{}{"capture_interface": "eth0", "mdns_service_port": 7000, "mdns_relayed": true}
			sources = []string{hostobs.SourceMDNS, hostobs.SourceARP}
		}
		if _, err := svc.IngestFindings(tenant, []IngestFinding{hostObservationBatchHeardBy(t, i, attrs, sources)}); err != nil {
			t.Fatalf("ingest %d: %v", i, err)
		}
	}
	observe(1)
	asset := onlyAsset(t, db, tenant)
	observe(2)
	base := len(assetTimeline(t, db, tenant, asset))

	for i := 3; i <= 8; i++ {
		observe(i)
	}
	rows := assetTimeline(t, db, tenant, asset)
	if len(rows) != base {
		t.Errorf("six alternating observations of one host wrote %d rows, want 0:%s", len(rows)-base, describeTimeline(rows[base:]))
	}

	// Still STORED: the metadata carries the latest sighting's description,
	// as before; it just is not news.
	var port float64
	var relayed bool
	if err := db.QueryRow(`
		SELECT COALESCE((metadata->'host_observation_attributes'->>'mdns_service_port')::float, 0),
		       COALESCE((metadata->'host_observation_attributes'->>'mdns_relayed')::bool, false)
		  FROM assets WHERE id = $1`, asset).Scan(&port, &relayed); err != nil {
		t.Fatal(err)
	}
	if port != 7000 || !relayed {
		t.Errorf("stored attributes = port %v relayed %v, want the eighth observation's (7000, true)", port, relayed)
	}
}

// A real change on the observation path writes exactly one row, and the row
// names what changed and nothing that did not.
func TestIntegration_AssetContextHistory_RealChangesWriteOneRowNamingThem(t *testing.T) {
	svc, db, tenant := newHostObsFixture(t)
	// `source` is what discoverySourceMetadata turns into the discovery source
	// the Approvals filters read; the rest of the finding is the same host.
	ingest := func(i int, source string) {
		t.Helper()
		f := hostObservationBatch(t, i, map[string]interface{}{"capture_interface": "eth0"})
		if source != "" {
			f.RawData["source"] = source
		}
		if _, err := svc.IngestFindings(tenant, []IngestFinding{f}); err != nil {
			t.Fatalf("ingest %d: %v", i, err)
		}
	}
	ingest(1, "")
	asset := onlyAsset(t, db, tenant)
	ingest(2, "")
	base := len(assetTimeline(t, db, tenant, asset))

	// A new discovery source is news about the asset: which collector put it
	// in front of a reviewer.
	ingest(3, "cloud_discovery")
	rows := assetTimeline(t, db, tenant, asset)
	if len(rows) != base+1 {
		t.Fatalf("a changed discovery source wrote %d rows, want 1:%s", len(rows)-base, describeTimeline(rows[base:]))
	}
	got := rows[base]
	if got.Action != string(identity.ActionUpdated) || got.Changes["metadata"] == nil {
		t.Errorf("the row does not name the metadata change: %+v", got)
	}
	if _, ok := got.Changes["asset_ownership"]; ok {
		t.Errorf("the row names asset_ownership, which did not change: %+v", got.Changes)
	}
	// The same new value again is not news.
	ingest(4, "cloud_discovery")
	if n := len(assetTimeline(t, db, tenant, asset)); n != base+1 {
		t.Errorf("re-stating the new discovery source wrote %d more rows, want 0", n-base-1)
	}

	// Ownership changed underneath (here by hand) is written again by the
	// sensor's statement. Whether it should be is not this test's question;
	// that the write is a real change the timeline has to show is.
	if _, err := db.Exec(`UPDATE assets SET asset_ownership = 'third_party' WHERE id = $1`, asset); err != nil {
		t.Fatal(err)
	}
	ingest(5, "cloud_discovery")
	rows = assetTimeline(t, db, tenant, asset)
	if len(rows) != base+2 {
		t.Fatalf("an ownership change wrote %d rows, want 1:%s", len(rows)-base-1, describeTimeline(rows[base+1:]))
	}
	got = rows[base+1]
	if got.Changes["asset_ownership"] != string(hostObservationOwnership) {
		t.Errorf("the ownership row does not name the new ownership: %+v", got.Changes)
	}
	if _, ok := got.Changes["metadata"]; ok {
		t.Errorf("the ownership row names metadata, of which only the batch id changed: %+v", got.Changes)
	}
}

// Context a system of record supplies — owner, environment — on a connection's
// repeated pulls: the first pull that lists an existing asset says so once, a
// changed owner writes one row naming only the owner, and an identical pull
// writes nothing.
func TestIntegration_AssetContextHistory_RepeatedPullsWriteOnlyChanges(t *testing.T) {
	f := newSourceFixture(t)
	tenant := f.tenant(t)
	ctx := context.Background()
	conn := identity.Source{Kind: identity.SourceImported, Ref: "cmdb:" + uuid.NewString()}

	owner, env := "ops@example.com", "production"
	pull := func(owner string) uuid.UUID {
		t.Helper()
		item := sourceHost("CTX-PULL-1", "10.63.0.11", "ctx-pull-1")
		item.Input.OwnerEmail = &owner
		item.Input.Environment = &env
		res := f.svc.ResolveAssets(ctx, tenant, conn, []SourceAssetItem{item})
		if res[0].AssetID == nil {
			t.Fatalf("pull: %+v", res[0])
		}
		return *res[0].AssetID
	}
	asset := pull(owner)
	created := assetTimeline(t, f.db, tenant, asset)
	var createdRow *contextHistoryRow
	for i := range created {
		if created[i].Action == string(identity.ActionCreated) && created[i].Changes["owner_email"] != nil {
			createdRow = &created[i]
		}
	}
	if createdRow == nil || createdRow.Changes["environment"] != env {
		t.Fatalf("the created row does not record the context the asset was created with:%s", describeTimeline(created))
	}

	pull(owner)
	pull(owner)
	base := assetTimeline(t, f.db, tenant, asset)
	for _, r := range base[len(created):] {
		if r.Changes["owner_email"] != nil || r.Changes["environment"] != nil {
			t.Errorf("an identical pull re-recorded unchanged context: %+v", r.Changes)
		}
	}

	pull("platform@example.com")
	rows := assetTimeline(t, f.db, tenant, asset)
	if len(rows) != len(base)+1 {
		t.Fatalf("a changed owner wrote %d rows, want 1:%s", len(rows)-len(base), describeTimeline(rows[len(base):]))
	}
	got := rows[len(base)]
	if got.Changes["owner_email"] != "platform@example.com" || got.Source != conn.Ref {
		t.Errorf("the row does not name the new owner and its source: %+v", got)
	}
	if _, ok := got.Changes["environment"]; ok {
		t.Errorf("the row names environment, which did not change: %+v", got.Changes)
	}

	pull("platform@example.com")
	if n := len(assetTimeline(t, f.db, tenant, asset)); n != len(rows) {
		t.Errorf("an identical pull after the change wrote %d rows, want 0", n-len(rows))
	}
}

// An import or a declaration listing an asset something else created leaves
// ONE row per source the first time — the fact the scan-consent rule and a
// reviewer both read — and nothing the second time, including when the
// listing carries context the asset already has.
func TestIntegration_AssetContextHistory_ListingIsRecordedOncePerSource(t *testing.T) {
	f := newSourceFixture(t)
	tenant := f.tenant(t)
	ctx := context.Background()
	assets := NewAssetService(f.db)
	conn := identity.Source{Kind: identity.SourceImported, Ref: "netbox:" + uuid.NewString()}

	ip, host, serial := "10.63.0.21", "ctx-list-21", "CTX-LIST-21"
	sensorRef := "sensor:" + uuid.NewString()
	sensed, _, err := assets.CreateAssetFromSource(tenant, models.AssetInput{
		ClassKey: "server", IPAddress: &ip, Hostname: &host, DisplayName: &host,
		Identifiers: []models.AssetIdentifierInput{{Kind: string(identity.KindSerialNumber), Value: serial}},
	}, identity.Source{Kind: identity.SourceMeasured, Ref: sensorRef})
	if err != nil || sensed == nil {
		t.Fatalf("sensor asset: %v", err)
	}
	asset := sensed.ID

	listedBy := func(ref string) int {
		n := 0
		for _, r := range assetTimeline(t, f.db, tenant, asset) {
			if r.Action == string(identity.ActionUpdated) && r.Changes["listed_by"] == ref {
				n++
			}
		}
		return n
	}
	env := "production"
	sheet := func() {
		t.Helper()
		item := sourceHost(serial, ip, host)
		item.Input.Environment = &env
		res := assets.BulkCreateAssets(tenant, []models.AssetInput{item.Input})
		if len(res.Results) != 1 || res.Results[0].ID == nil || *res.Results[0].ID != asset {
			t.Fatalf("the spreadsheet row did not match the sensor's asset: %+v", res.Results)
		}
	}
	pull := func() {
		t.Helper()
		item := sourceHost(serial, ip, host)
		item.Input.Environment = &env
		res := f.svc.ResolveAssets(ctx, tenant, conn, []SourceAssetItem{item})
		if res[0].AssetID == nil || *res[0].AssetID != asset {
			t.Fatalf("the pull did not match the sensor's asset: %+v", res[0])
		}
	}

	sheet()
	if n := listedBy(identity.SpreadsheetImportSourceRef); n != 1 {
		t.Fatalf("the spreadsheet's first listing left %d listed_by rows, want 1:%s", n, describeTimeline(assetTimeline(t, f.db, tenant, asset)))
	}
	afterSheet := len(assetTimeline(t, f.db, tenant, asset))
	sheet()
	if rows := assetTimeline(t, f.db, tenant, asset); len(rows) != afterSheet {
		t.Errorf("the spreadsheet listing the asset again wrote %d rows, want 0:%s", len(rows)-afterSheet, describeTimeline(rows[afterSheet:]))
	}

	pull()
	if n := listedBy(conn.Ref); n != 1 {
		t.Fatalf("the connection's first listing left %d listed_by rows, want 1:%s", n, describeTimeline(assetTimeline(t, f.db, tenant, asset)))
	}
	afterPull := len(assetTimeline(t, f.db, tenant, asset))
	pull()
	if rows := assetTimeline(t, f.db, tenant, asset); len(rows) != afterPull {
		t.Errorf("the connection listing the asset again wrote %d rows, want 0:%s", len(rows)-afterPull, describeTimeline(rows[afterPull:]))
	}

	// A sensor's sighting is not a listing, however many there are.
	for _, r := range assetTimeline(t, f.db, tenant, asset) {
		if r.Changes["listed_by"] == sensorRef {
			t.Errorf("a measured source was recorded as listing the asset: %+v", r)
		}
	}
}

// A person's edit is a change by definition and keeps its row. (It is written
// by UpdateAsset, not by the gated context writer; this pins that the gate did
// not reach it.)
func TestIntegration_AssetContextHistory_PersonEditStillWritesItsRow(t *testing.T) {
	f := newSourceFixture(t)
	tenant := f.tenant(t)
	assets := NewAssetService(f.db)

	ip, host := "10.63.0.31", "ctx-edit-31"
	created, err := assets.CreateAsset(tenant, models.AssetInput{
		ClassKey: "server", IPAddress: &ip, Hostname: &host, DisplayName: &host,
		Identifiers: []models.AssetIdentifierInput{{Kind: string(identity.KindSerialNumber), Value: "CTX-EDIT-31"}},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	before := len(assetTimeline(t, f.db, tenant, created.ID))
	owner := "owner@example.com"
	if _, _, err := assets.UpdateAsset(tenant, created.ID, models.AssetInput{OwnerEmail: &owner}, uuid.Nil); err != nil {
		t.Fatalf("update: %v", err)
	}
	rows := assetTimeline(t, f.db, tenant, created.ID)
	if len(rows) != before+1 {
		t.Fatalf("a person's edit wrote %d rows, want 1:%s", len(rows)-before, describeTimeline(rows[before:]))
	}
	if got := rows[before]; got.Action != string(identity.ActionUpdated) || got.Changes["owner_email"] != owner || got.Source != "manual" {
		t.Errorf("the edit's row does not name the owner change by a person: %+v", got)
	}
}
