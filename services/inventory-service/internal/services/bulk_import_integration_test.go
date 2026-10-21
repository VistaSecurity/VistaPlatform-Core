package services

// Bulk CSV import and export through the real services over the real schema as
// the app role (RLS on). The guard of DCIM BUILD_PLAN row 2.7 is
// TestIntegration_BulkImport_EveryKindHasATemplateAndRoundTrips: for each
// importable kind, export fixture rows from one tenant, dry-run them into a
// fresh tenant (zero errors), apply (the row counts match), export again
// (identical CSV), and re-apply (every row unchanged).
//
// Mutations that must turn it red (each tried when the row landed):
//   - drop a field from a kind's Fields → the kind's export loses the column,
//     the re-export differs (and the spec-coverage test names the column);
//   - drop a kind from bulkEngineKinds / bulkCustomKinds → the registry test
//     fails and the round trip never runs for it;
//   - make the importer skip the `update` path → the second apply is not all
//     "unchanged".

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type bulkImpFixture struct {
	owner, app *sql.DB
	svc        *BulkImportService
	ips        *IPAMService
	cat        *CatalogueService
	ifaces     *InterfaceService
	bus        *BusinessUnitService
	assets     *AssetService
	sites      *SiteService
	ctx        context.Context
}

func newBulkImpFixture(t *testing.T) *bulkImpFixture {
	t.Helper()
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	db := &database.DB{DB: sqlx.NewDb(app, "postgres")}
	f := &bulkImpFixture{
		owner: owner, app: app,
		ips: NewIPAMService(app), cat: NewCatalogueService(app), ifaces: NewInterfaceService(app),
		bus: NewBusinessUnitService(db), sites: NewSiteService(db),
		ctx: changes.WithSource(changes.WithActor(context.Background(), changes.Actor{UserID: uuid.New(), UserName: "op@example.test"}), changes.SourceUI),
	}
	f.assets = NewAssetService(db)
	f.svc = NewBulkImportService(app, BulkDeps{
		BusinessUnits: f.bus, Sites: f.sites, Assets: f.assets, Catalogue: f.cat, Interfaces: f.ifaces,
	})
	return f
}

func (f *bulkImpFixture) ipam(t *testing.T, tenant uuid.UUID, route string, body map[string]any) string {
	t.Helper()
	b, _ := bulkJSONMarshal(body)
	raw, err := f.ips.Create(f.ctx, tenant, route, b)
	if err != nil {
		t.Fatalf("create %s %s: %v", route, b, err)
	}
	return bulkJSONField(t, raw, "id")
}

func (f *bulkImpFixture) catalogue(t *testing.T, tenant uuid.UUID, route string, body map[string]any) string {
	t.Helper()
	b, _ := bulkJSONMarshal(body)
	raw, err := f.cat.Create(f.ctx, tenant, route, b)
	if err != nil {
		t.Fatalf("create %s %s: %v", route, b, err)
	}
	return bulkJSONField(t, raw, "id")
}

// seed writes at least one row of every kind into tenant.
func (f *bulkImpFixture) seed(t *testing.T, tenant uuid.UUID) {
	t.Helper()
	name := func(s string) *string { return &s }
	corp, err := f.bus.Create(f.ctx, tenant, uuid.New(), models.BusinessUnitInput{Name: name("Corporate"), Description: name("Head office")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.bus.Create(f.ctx, tenant, uuid.New(), models.BusinessUnitInput{Name: name("Finance"), ParentID: &corp.ID, ParentSet: true}); err != nil {
		t.Fatal(err)
	}
	site, err := f.sites.CreateSite(f.ctx, tenant, uuid.New(), models.SiteInput{Name: name("DC West")})
	if err != nil {
		t.Fatal(err)
	}
	floor, err := f.sites.CreateLocation(f.ctx, tenant, uuid.New(), models.LocationInput{SiteID: &site.ID, Name: name("Floor 2")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.sites.CreateLocation(f.ctx, tenant, uuid.New(), models.LocationInput{SiteID: &site.ID, ParentID: &floor.ID, Name: name("Room 201"), Facility: name("Cage 4")}); err != nil {
		t.Fatal(err)
	}

	mf := f.catalogue(t, tenant, "manufacturers", map[string]any{"name": "Acme Networks", "description": "Switches"})
	plat := f.catalogue(t, tenant, "platforms", map[string]any{"name": "AcmeOS", "manufacturer_id": mf, "end_of_support": "2029-06-30", "end_of_life": "2030-06-30"})
	parent := f.catalogue(t, tenant, "device-roles", map[string]any{"name": "Network"})
	role := f.catalogue(t, tenant, "device-roles", map[string]any{"name": "Core switch", "parent_id": parent, "color": "2196f3"})
	dt := f.catalogue(t, tenant, "device-types", map[string]any{
		"manufacturer_id": mf, "model": "AX-48", "u_height": "1", "is_full_depth": true, "weight": "7.3", "weight_unit": "kg", "default_platform_id": plat,
		"end_of_sale": "2025-10-31", "end_of_support": "2030-10-31"})

	// The asset goes in through the identity engine, as an imported one will:
	// both tenants then carry the same side effects (the observed address and
	// interface the engine writes for an asset with an IP).
	assetIn := models.AssetInput{
		ClassKey: "server", DisplayName: name("core-sw-01"), Hostname: name("core-sw-01.example.test"), IPAddress: name("192.0.2.10"),
		BusinessUnit: name("Corporate/Finance"), Description: name("Core switch"),
	}
	var buID uuid.UUID
	if err := f.owner.QueryRow(`SELECT id FROM business_units WHERE tenant_id = $1 AND name = 'Finance'`, tenant).Scan(&buID); err != nil {
		t.Fatal(err)
	}
	bid := buID.String()
	assetIn.BusinessUnit, assetIn.BusinessUnitID = nil, &bid
	asset, _, err := f.assets.CreateAssetFromSource(tenant, assetIn, identity.Source{Kind: identity.SourceImported, Ref: "test:fixture"})
	if err != nil || asset == nil {
		t.Fatalf("create asset: %v", err)
	}
	if _, _, err := f.assets.UpdateAsset(tenant, asset.ID, models.AssetInput{DisplayName: name("core-sw-01")}, uuid.New()); err != nil {
		t.Fatal(err)
	}
	patch := HardwarePatch{}
	for k, v := range map[string]string{"device_type_id": dt, "device_role_id": role, "platform_id": plat, "serial": "SN-100", "asset_tag": "A-0001",
		// The commercial lifecycle (DCIM gap 4) round-trips with the rest.
		"purchase_date": "2024-03-01", "warranty_start": "2024-03-01", "warranty_end": "2027-02-28", "purchase_cost": "4200.50",
		"purchase_currency": "EUR", "purchase_order": "PO-1001", "vendor": "Acme Resale", "support_contract": "SC-77",
		"support_contract_end": "2027-03-31", "installed_at": "2024-03-15"} {
		raw, _ := json.Marshal(v)
		patch[k] = raw
	}
	if _, err := f.cat.UpdateHardware(f.ctx, tenant, asset.ID, patch); err != nil {
		t.Fatal(err)
	}
	assetID := asset.ID
	speed := int64(1000000)
	desc := "Uplink"
	if _, err := f.ifaces.Create(f.ctx, tenant, uuid.New(), InterfaceInput{AssetID: assetID, Name: "Gi1/0/1", Type: "1000base-t", SpeedKbps: &speed, Description: &desc}); err != nil {
		t.Fatal(err)
	}

	rir := f.ipam(t, tenant, "rirs", map[string]any{"name": "Internal registry", "is_private": true})
	f.ipam(t, tenant, "aggregates", map[string]any{"prefix": "10.0.0.0/8", "rir_id": rir, "date_added": "2026-01-31"})
	vrf := f.ipam(t, tenant, "vrfs", map[string]any{"name": "blue", "rd": "65000:1", "enforce_unique": true})
	grp := f.ipam(t, tenant, "vlan-groups", map[string]any{"name": "Campus", "vid_ranges": [][2]int{{1, 99}, {200, 299}}})
	vlan := f.ipam(t, tenant, "vlans", map[string]any{"vid": 250, "name": "Users", "group_id": grp})
	f.ipam(t, tenant, "prefixes", map[string]any{"prefix": "10.10.0.0/24", "vrf_id": vrf, "vlan_id": vlan, "is_pool": true, "description": "User access"})
	f.ipam(t, tenant, "prefixes", map[string]any{"prefix": "10.20.0.0/24"})
	f.ipam(t, tenant, "ip-ranges", map[string]any{"start_address": "10.10.0.10/24", "end_address": "10.10.0.50/24", "vrf_id": vrf})
	f.ipam(t, tenant, "ip-addresses", map[string]any{"address": "10.10.0.1/24", "vrf_id": vrf, "dns_name": "gw.example.test"})
}

func (f *bulkImpFixture) export(t *testing.T, tenant uuid.UUID, kind string) (string, int) {
	t.Helper()
	cols, err := f.svc.BulkColumnNames(kind)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write(cols)
	n := 0
	if err := f.svc.Export(f.ctx, tenant, kind, BulkExportQuery{}, func(r BulkRecord) error {
		row := make([]string, len(cols))
		for i, c := range cols {
			row[i] = r[c]
		}
		n++
		return w.Write(row)
	}); err != nil {
		t.Fatalf("export %s: %v", kind, err)
	}
	w.Flush()
	return buf.String(), n
}

func (f *bulkImpFixture) imp(t *testing.T, tenant uuid.UUID, kind, body string, apply bool) *BulkPlan {
	t.Helper()
	plan, err := f.svc.Import(f.ctx, tenant, kind, strings.NewReader(body), apply)
	if err != nil {
		t.Fatalf("import %s: %v", kind, err)
	}
	return plan
}

func bulkPlanErrors(p *BulkPlan) string {
	var out []string
	for _, r := range p.Rows {
		if r.Action == BulkError {
			out = append(out, fmt.Sprintf("row %d %q: %s", r.Row, r.Key, r.Reason))
		}
	}
	return strings.Join(out, "; ")
}

func TestIntegration_BulkImport_EveryKindHasATemplateAndRoundTrips(t *testing.T) {
	f := newBulkImpFixture(t)
	src, dst := testdb.NewTenant(t, f.owner), testdb.NewTenant(t, f.owner)
	f.seed(t, src)

	for _, info := range f.svc.Kinds() {
		info := info
		t.Run(info.Kind, func(t *testing.T) {
			// Template: the header is the kind's columns, the example fills every required one.
			header, example, err := f.svc.Template(info.Kind)
			if err != nil || len(header) == 0 || len(header) != len(example) {
				t.Fatalf("template: %v %v %v", header, example, err)
			}
			for i, c := range info.Columns {
				if header[i] != c.Name {
					t.Fatalf("template header[%d] = %q, want %q", i, header[i], c.Name)
				}
				if c.Required && strings.TrimSpace(example[i]) == "" {
					t.Fatalf("required column %q has no example", c.Name)
				}
			}

			want, rows := f.export(t, src, info.Kind)
			if rows == 0 {
				t.Fatalf("the fixture has no %s row; extend seed()", info.Kind)
			}

			before, _ := f.export(t, dst, info.Kind)
			plan := f.imp(t, dst, info.Kind, want, false)
			if plan.Summary.Error != 0 {
				t.Fatalf("dry run: %s", bulkPlanErrors(plan))
			}
			if plan.Applied {
				t.Fatal("a dry run must not report applied")
			}
			// A dry run writes nothing.
			if after, _ := f.export(t, dst, info.Kind); after != before {
				t.Fatalf("dry run changed the tenant's %s rows\n--- before\n%s\n--- after\n%s", info.Kind, before, after)
			}

			plan = f.imp(t, dst, info.Kind, want, true)
			if plan.Summary.Error != 0 {
				t.Fatalf("apply: %s", bulkPlanErrors(plan))
			}
			if plan.Summary.Total != rows {
				t.Fatalf("apply planned %d rows, exported %d", plan.Summary.Total, rows)
			}
			got, gotRows := f.export(t, dst, info.Kind)
			if gotRows != rows || got != want {
				t.Fatalf("re-export differs (%d vs %d rows)\n--- source\n%s\n--- imported\n%s", rows, gotRows, want, got)
			}

			again := f.imp(t, dst, info.Kind, want, true)
			if again.Summary.Unchanged != rows {
				t.Fatalf("re-applying the same file: %+v (%s) %+v", again.Summary, bulkPlanErrors(again), again.Rows)
			}
		})
	}
}

func TestIntegration_BulkImport_FlaggedRowsThenApplyScenario(t *testing.T) {
	// The brief's acceptance walk on a kind that exists today (VLANs stand in for racks): ten rows, two
	// flagged (an unknown group and a duplicate VID), fix, apply.
	f := newBulkImpFixture(t)
	tenant := testdb.NewTenant(t, f.owner)
	f.ipam(t, tenant, "vlan-groups", map[string]any{"name": "Campus"})
	var sb strings.Builder
	sb.WriteString("vid,name,group\n")
	for i := 1; i <= 8; i++ {
		fmt.Fprintf(&sb, "%d,VLAN %d,Campus\n", i*10, i)
	}
	sb.WriteString("90,Orphan,Nowhere\n")   // unknown group
	sb.WriteString("10,Duplicate,Campus\n") // same group + vid as row 2: matches it, renames it
	plan := f.imp(t, tenant, "vlan", sb.String(), false)
	if plan.Summary.Error != 1 || plan.Summary.Create != 8 {
		t.Fatalf("plan %+v: %s", plan.Summary, bulkPlanErrors(plan))
	}
	bad := plan.Rows[8]
	if bad.Action != BulkError || !strings.Contains(bad.Reason, "Nowhere") {
		t.Fatalf("row 10: %+v", bad)
	}
	// The duplicate (group, vid) is the same VLAN, so it plans an update, not a second row.
	if plan.Rows[9].Action != BulkUpdate {
		t.Fatalf("duplicate vid: %+v", plan.Rows[9])
	}
	// Fix the file: drop the orphan row, apply.
	fixed := strings.Replace(sb.String(), "90,Orphan,Nowhere\n", "", 1)
	plan = f.imp(t, tenant, "vlan", fixed, true)
	if plan.Summary.Error != 0 {
		t.Fatal(bulkPlanErrors(plan))
	}
	var n int
	_ = f.owner.QueryRow(`SELECT count(*) FROM vlans WHERE tenant_id = $1`, tenant).Scan(&n)
	if n != 8 {
		t.Fatalf("%d vlans, want 8", n)
	}
	// Every created row says where it came from, and every change is recorded as an import.
	var imported, changesN int
	_ = f.owner.QueryRow(`SELECT count(*) FROM vlans WHERE tenant_id = $1 AND source_kind = 'imported'`, tenant).Scan(&imported)
	_ = f.owner.QueryRow(`SELECT count(*) FROM object_changes WHERE tenant_id = $1 AND object_kind = 'vlan' AND source = 'intake:import'`, tenant).Scan(&changesN)
	if imported != 8 || changesN < 8 {
		t.Fatalf("imported rows %d, import changes %d", imported, changesN)
	}
}

func TestIntegration_BulkImport_ForwardReferencesAndDryRunWritesNothing(t *testing.T) {
	f := newBulkImpFixture(t)
	tenant := testdb.NewTenant(t, f.owner)
	// The child is listed before its parent.
	csvBody := "name,parent\nFinance,Corporate\nCorporate,\n"
	plan := f.imp(t, tenant, "business_unit", csvBody, false)
	if plan.Summary.Error != 0 || plan.Summary.Create != 2 {
		t.Fatalf("bu dry run: %s %+v", bulkPlanErrors(plan), plan.Summary)
	}
	var n int
	_ = f.owner.QueryRow(`SELECT count(*) FROM business_units WHERE tenant_id = $1`, tenant).Scan(&n)
	if n != 0 {
		t.Fatalf("dry run wrote %d business units", n)
	}
	plan = f.imp(t, tenant, "business_unit", csvBody, true)
	if plan.Summary.Error != 0 {
		t.Fatal(bulkPlanErrors(plan))
	}
	_ = f.owner.QueryRow(`SELECT count(*) FROM business_units WHERE tenant_id = $1`, tenant).Scan(&n)
	if n != 2 {
		t.Fatalf("%d business units, want 2", n)
	}

	// An engine kind: a device role before its parent; a dry run leaves nothing.
	roles := "name,parent\nCore switch,Network\nNetwork,\n"
	plan = f.imp(t, tenant, "device_role", roles, false)
	if plan.Summary.Error != 0 || plan.Summary.Create != 2 {
		t.Fatalf("role dry run: %s %+v", bulkPlanErrors(plan), plan.Summary)
	}
	_ = f.owner.QueryRow(`SELECT count(*) FROM device_roles WHERE tenant_id = $1`, tenant).Scan(&n)
	if n != 0 {
		t.Fatalf("dry run wrote %d device roles", n)
	}
}

func TestIntegration_BulkImport_RowErrorsAreIsolatedAndReasoned(t *testing.T) {
	f := newBulkImpFixture(t)
	tenant := testdb.NewTenant(t, f.owner)
	body := "prefix,vrf,status\n10.1.0.0/24,,active\nnot-a-prefix,,\n10.2.0.0/24,ghost,\n10.3.0.0/24,,bogus\n10.4.0.0/24,,active\n"
	plan := f.imp(t, tenant, "prefix", body, true)
	if plan.Summary.Create != 2 || plan.Summary.Error != 3 {
		t.Fatalf("summary %+v: %s", plan.Summary, bulkPlanErrors(plan))
	}
	for i, want := range map[int]string{1: "prefix", 2: "ghost", 3: "status"} {
		r := plan.Rows[i]
		if r.Action != BulkError || !strings.Contains(strings.ToLower(r.Reason), want) {
			t.Fatalf("row %d: %+v (want a reason naming %q)", i+2, r, want)
		}
	}
	var n int
	_ = f.owner.QueryRow(`SELECT count(*) FROM prefixes WHERE tenant_id = $1`, tenant).Scan(&n)
	if n != 2 {
		t.Fatalf("%d prefixes, want the 2 valid rows", n)
	}
}

func TestIntegration_BulkImport_FileLevelErrors(t *testing.T) {
	f := newBulkImpFixture(t)
	tenant := testdb.NewTenant(t, f.owner)
	for name, c := range map[string]struct{ kind, body string }{
		"missing required column": {"vlan", "name\nUsers\n"},
		"empty":                   {"vlan", ""},
		"header only":             {"vlan", "vid,name\n"},
		"unknown kind":            {"nonsense", "a\n1\n"},
	} {
		if _, err := f.svc.Import(f.ctx, tenant, c.kind, strings.NewReader(c.body), false); err == nil {
			t.Fatalf("%s: want an error", name)
		}
	}
	// An unknown column is a warning, not a failure.
	plan := f.imp(t, tenant, "vlan", "vid,name,colour\n10,Users,red\n", false)
	if plan.Summary.Error != 0 || len(plan.Unknown) != 1 || plan.Unknown[0] != "colour" {
		t.Fatalf("%+v %v", plan.Summary, plan.Unknown)
	}
}

func TestIntegration_BulkImport_TenantIsolation(t *testing.T) {
	f := newBulkImpFixture(t)
	a, b := testdb.NewTenant(t, f.owner), testdb.NewTenant(t, f.owner)
	f.ipam(t, a, "vrfs", map[string]any{"name": "secret-vrf"})
	csv1, n := f.export(t, b, "vrf")
	if n != 0 || strings.Contains(csv1, "secret-vrf") {
		t.Fatalf("tenant B exported tenant A's VRF: %s", csv1)
	}
	// Tenant B cannot reference A's VRF from a prefix.
	plan := f.imp(t, b, "prefix", "prefix,vrf\n10.9.0.0/24,secret-vrf\n", true)
	if plan.Summary.Error != 1 {
		t.Fatalf("%+v", plan.Summary)
	}
}

// Every writable column of an engine kind's spec is either a CSV column or
// listed, with a reason, as skipped. A column the spec gains turns this red
// until someone decides.
func TestBulkImport_EngineKindsCoverTheirSpecs(t *testing.T) {
	for _, ek := range bulkEngineKinds() {
		eng := NewIPAMService(nil)
		if ek.DeviceCatalogue {
			eng = newObjectEngine(nil, catalogueSpecs())
		}
		sp, err := eng.spec(ek.Route)
		if err != nil {
			t.Fatalf("%s: %v", ek.Kind, err)
		}
		covered := map[string]bool{}
		for _, f := range ek.Fields {
			if _, ok := sp.col(f.field()); !ok {
				t.Errorf("%s: field %q is not a column of %s", ek.Kind, f.field(), sp.Table)
			}
			covered[f.field()] = true
		}
		for _, c := range sp.Cols {
			if c.Computed || covered[c.Name] || substrateSkipped[c.Name] {
				continue
			}
			if _, ok := ek.Skipped[c.Name]; !ok {
				t.Errorf("%s: column %q of %s is neither a CSV field nor Skipped", ek.Kind, c.Name, sp.Table)
			}
		}
		for _, id := range ek.Identity {
			if !covered[id] {
				t.Errorf("%s: identity column %q has no CSV field", ek.Kind, id)
			}
		}
		for _, f := range ek.Fields {
			if f.Ref != "" {
				if _, ok := bulkRefs[f.Ref]; !ok {
					t.Errorf("%s: field %q names unknown reference %q", ek.Kind, f.Name, f.Ref)
				}
			}
		}
	}
}

func TestBulkImport_ParseCSV(t *testing.T) {
	h, rows, lines, err := ParseBulkCSV(strings.NewReader("\xef\xbb\xbfName, Parent \r\nA,\r\n\r\n\"B, Inc\",A\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(h, "|") != "name|parent" || len(rows) != 2 || rows[1]["name"] != "B, Inc" || lines[1] != 4 {
		t.Fatalf("%v %v %v", h, rows, lines)
	}
}

func bulkJSONMarshal(v any) ([]byte, error) { return json.Marshal(v) }

func bulkJSONField(t *testing.T, raw []byte, field string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprint(m[field])
}

// The CSV header of every kind is a contract with every spreadsheet a customer
// has saved: a column dropped or renamed fails here, not in someone's import.
func TestBulkImport_ColumnsArePinned(t *testing.T) {
	want := map[string]string{
		"business_unit": "name,parent,slug,description,comments",
		"site":          "name,slug,operational_status,facility,time_zone,physical_address,shipping_address,latitude,longitude,description,comments",
		"location":      "site,name,parent,slug,operational_status,facility,description,comments",
		"manufacturer":  "name,slug,description",
		"device_role":   "name,slug,color,vm_role,parent,description",
		"platform":      "name,slug,manufacturer,description,end_of_sale,end_of_support,end_of_life",
		"device_type":   "manufacturer,model,slug,part_number,u_height,is_full_depth,exclude_from_utilization,subdevice_role,airflow,weight,weight_unit,default_platform,description,end_of_sale,end_of_support,end_of_life",
		"asset":         "display_name,class_key,hostname,ip_address,environment,business_unit,owner_email,support_group,device_type,device_role,platform,serial,asset_tag,description,purchase_date,warranty_start,warranty_end,purchase_cost,purchase_currency,purchase_order,vendor,support_contract,support_contract_end,installed_at,decommissioned_at",
		"interface":     "asset,name,type,label,enabled,mgmt_only,mtu,mac_address,speed_kbps,duplex,mode,description",
		"rir":           "name,slug,is_private,description",
		"aggregate":     "prefix,rir,business_unit,date_added,description",
		"vrf":           "name,rd,business_unit,enforce_unique,description",
		"vlan_group":    "name,slug,vid_ranges,business_unit,description",
		"vlan":          "vid,name,group,business_unit,status,operational_status,role,qinq_role,description",
		"prefix":        "prefix,vrf,business_unit,vlan,role,status,operational_status,is_pool,mark_utilized,network_type,environment,auto_approve_discoveries,auto_approve_sources,dhcp_managed,active_probes_disabled,sensitive,gateway_source_ref,cloud_network_ref,description",
		"ip_range":      "start_address,end_address,vrf,business_unit,operational_status,role,mark_utilized,description",
		"ip_address":    "address,vrf,business_unit,status,operational_status,role,dns_name,mac_address,last_seen_source,description",
	}
	svc := NewBulkImportService(nil, BulkDeps{})
	got := map[string]bool{}
	for _, k := range svc.Kinds() {
		got[k.Kind] = true
		cols, _ := svc.BulkColumnNames(k.Kind)
		if strings.Join(cols, ",") != want[k.Kind] {
			t.Errorf("%s columns changed:\n got %s\nwant %s", k.Kind, strings.Join(cols, ","), want[k.Kind])
		}
	}
	for k := range want {
		if !got[k] {
			t.Errorf("kind %s is no longer importable", k)
		}
	}
}
