package xbom

// Database-integration tests for the xBOM source and assembler.
//
// These exist because everything the unit tests above prove is downstream of a
// Snapshot that a fixture handed them. Nothing in that proof says the SQL that
// produces a Snapshot is correct — and the SQL is where the interesting
// failures live: seven queries over eight partitioned, RLS-policied tables,
// each with a tenant predicate that has to hold when the service connects as
// the non-owner application role. `ee/cbomattest` already found exactly this
// class of bug (correct SQL, no tenant context, zero rows, signed evidence
// asserting "no findings").
//
// They skip unless TEST_DATABASE_URL is set (see shared/testdb); CI runs them
// in the nightly backend job, locally via `make test-integration-db`.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/cbom-service/internal/cbom"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/scopes"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// seedAsset inserts one asset and returns its id.
func seedAsset(t *testing.T, owner *sql.DB, tenant uuid.UUID, classKey, classPath, name, address string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := owner.Exec(`
		INSERT INTO public.assets
			(id, tenant_id, class_key, class_path, display_name, primary_address,
			 asset_status, asset_ownership, environment, risk_score)
		VALUES ($1, $2, $3, $4, $5, $6::inet, 'monitoring', 'internal', 'production', 40)
	`, id, tenant, classKey, classPath, name, address)
	if err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	return id
}

func seedFact(t *testing.T, owner *sql.DB, tenant, asset uuid.UUID, key string, value any, sourceRef string) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal fact value: %v", err)
	}
	if _, err := owner.Exec(`
		INSERT INTO public.asset_facts (tenant_id, asset_id, key, value, source_kind, source_ref)
		VALUES ($1, $2, $3, $4::jsonb, 'measured', $5)
	`, tenant, asset, key, string(raw), sourceRef); err != nil {
		t.Fatalf("seed fact %s: %v", key, err)
	}
}

// seedProduct inserts one product in the tenant's catalogue.
//
// Separate from seedInstall because `software_products_identity_uniq` dedupes
// by purl PER TENANT: a product is catalogued once and installed many times,
// which is exactly the shape that makes an SBOM one component per product with
// several occurrences rather than one per host.
func seedProduct(t *testing.T, owner *sql.DB, tenant uuid.UUID, name, version, purl string) uuid.UUID {
	t.Helper()
	product := uuid.New()
	if _, err := owner.Exec(`
		INSERT INTO public.software_products (id, tenant_id, name, version, purl, source_kind)
		VALUES ($1, $2, $3, $4, $5, 'measured')
	`, product, tenant, name, version, purl); err != nil {
		t.Fatalf("seed product: %v", err)
	}
	return product
}

func seedInstall(t *testing.T, owner *sql.DB, tenant, asset, product uuid.UUID) {
	t.Helper()
	if _, err := owner.Exec(`
		INSERT INTO public.software_installs (tenant_id, asset_id, product_id, source_kind, status)
		VALUES ($1, $2, $3, 'measured', 'active')
	`, tenant, asset, product); err != nil {
		t.Fatalf("seed install: %v", err)
	}
}

func seedSoftware(t *testing.T, owner *sql.DB, tenant, asset uuid.UUID, name, version, purl string) uuid.UUID {
	t.Helper()
	product := seedProduct(t, owner, tenant, name, version, purl)
	seedInstall(t, owner, tenant, asset, product)
	return product
}

// TestIntegration_XBOMSource_ReadsEveryTableUnderRLS is the central one: the
// assembler running as the NON-OWNER app role must see the tenant's rows.
//
// Under `serviceRls` the services connect as that role, and a query that is
// perfectly correct but runs without `app.tenant_id` set returns zero rows
// silently — producing a signed, dated inventory artifact that says the tenant
// has nothing. That is the worst failure this service can have and it is
// invisible to every mock.
func TestIntegration_XBOMSource_ReadsEveryTableUnderRLS(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)

	server := seedAsset(t, owner, tenant, "server", "hardware.computer.server", "web-01", "192.0.2.10")
	sw := seedAsset(t, owner, tenant, "switch", "hardware.network_device.switch", "sw-01", "192.0.2.20")

	if _, err := owner.Exec(`
		INSERT INTO public.asset_identifiers (tenant_id, asset_id, kind, value, source_kind)
		VALUES ($1, $2, 'hostname', 'web-01', 'measured')
	`, tenant, server); err != nil {
		t.Fatalf("seed identifier: %v", err)
	}
	if _, err := owner.Exec(`
		INSERT INTO public.asset_endpoints (tenant_id, asset_id, address, port, transport, service_name, status)
		VALUES ($1, $2, '192.0.2.10'::inet, 443, 'tcp', 'nginx', 'active')
	`, tenant, server); err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}
	seedFact(t, owner, tenant, server, "os.name", "Ubuntu", "agent:1")
	seedFact(t, owner, tenant, server, "hw.vendor", "Dell Inc.", "agent:1")
	seedSoftware(t, owner, tenant, server, "openssl", "3.0.14", "pkg:deb/ubuntu/openssl@3.0.14")
	if _, err := owner.Exec(`
		INSERT INTO public.asset_relationships (tenant_id, from_asset_id, to_asset_id, type, source_kind, status)
		VALUES ($1, $2, $3, 'connects_to', 'measured', 'active')
	`, tenant, server, sw); err != nil {
		t.Fatalf("seed relationship: %v", err)
	}

	snap, err := NewSource(app).Load(context.Background(), tenant, []uuid.UUID{server, sw})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(snap.Assets) != 2 {
		t.Errorf("assets = %d, want 2", len(snap.Assets))
	}
	if len(snap.Identifiers) != 1 {
		t.Errorf("identifiers = %d, want 1", len(snap.Identifiers))
	}
	if len(snap.Endpoints) != 1 {
		t.Errorf("endpoints = %d, want 1", len(snap.Endpoints))
	}
	if len(snap.Facts) != 2 {
		t.Errorf("facts = %d, want 2", len(snap.Facts))
	}
	if len(snap.Software) != 1 {
		t.Errorf("software = %d, want 1", len(snap.Software))
	}
	if len(snap.Relationships) != 1 {
		t.Errorf("relationships = %d, want 1", len(snap.Relationships))
	}

	// The jsonb scalar rendering, which only a real jsonb column exercises: a
	// stored JSON string must come back WITHOUT its quotes, or every property
	// in every document carries them.
	for _, f := range snap.Facts {
		if f.Key == "os.name" && f.Value != "Ubuntu" {
			t.Errorf(`os.name = %q, want "Ubuntu" (unquoted — a jsonb string must not arrive as "\"Ubuntu\"")`, f.Value)
		}
	}
}

// TestIntegration_XBOMSource_CarriesTheClassRegistrysCycloneDXType.
//
// The WIRING, not the helper. resolveCycloneDXType is unit-tested against a
// hand-built Asset, and that proof says nothing about whether the SQL puts
// `asset_classes.cyclonedx_type` on the row — which is the half that was
// missing: a tenant leaf subclass (ADR-0002 D2, and what the NetBox connector
// creates per device role) is not in the generated registry, so without this
// column every one of them was typed `device` and listed in the HBOM as
// hardware. Delete the subselect in loadAssets and this goes red.
func TestIntegration_XBOMSource_CarriesTheClassRegistrysCycloneDXType(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)

	// A tenant leaf subclass: a runtime row under `application`, which the
	// generated registry cannot know about.
	subclass := "acme_payment_app_" + uuid.New().String()[:8]
	if _, err := owner.Exec(`
		INSERT INTO public.asset_classes
			(tenant_id, key, parent_key, path, label, cyclonedx_type, is_fixed)
		VALUES ($1, $2, 'application', 'application.' || $2, 'Payment app', 'application', false)
	`, tenant, subclass); err != nil {
		t.Fatalf("seed tenant subclass: %v", err)
	}

	custom := seedAsset(t, owner, tenant, subclass, "application."+subclass, "Payments", "192.0.2.30")
	server := seedAsset(t, owner, tenant, "server", "hardware.computer.server", "web-01", "192.0.2.10")

	snap, err := NewSource(app).Load(context.Background(), tenant, []uuid.UUID{custom, server})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	byID := map[uuid.UUID]Asset{}
	for _, a := range snap.Assets {
		byID[a.ID] = a
	}
	if got := byID[custom].CycloneDXType; got != "application" {
		t.Fatalf("tenant subclass CycloneDXType = %q, want \"application\" — the class registry's answer did not reach the row", got)
	}

	// And it decides the emitted document, which is the point of reading it.
	doc, err := BuildDocument("inventory", snap, fixtureInput())
	if err != nil {
		t.Fatalf("BuildDocument(inventory): %v", err)
	}
	for _, c := range doc.Components {
		if c.BOMRef == refAsset+custom.String() && c.Type != "application" {
			t.Errorf("the subclass asset was emitted as %q, want application", c.Type)
		}
	}
	hbom, err := BuildDocument("hbom", snap, fixtureInput())
	if err != nil {
		t.Fatalf("BuildDocument(hbom): %v", err)
	}
	for _, c := range hbom.Components {
		if c.BOMRef == refAsset+custom.String() {
			t.Error("an `application` tenant subclass was listed in the HBOM as hardware")
		}
	}
	// Positive half: the real hardware asset is still there, so a build that
	// emitted an empty HBOM would not pass.
	found := false
	for _, c := range hbom.Components {
		if c.BOMRef == refAsset+server.String() {
			found = true
		}
	}
	if !found {
		t.Error("the server is missing from the HBOM")
	}
}

// TestIntegration_XBOMSource_NeverCrossesTenants. The tenant predicate is the
// real isolation boundary, because the services connect as the table owner in
// most deployments and RLS is inert there. An asset id from another
// tenant must produce nothing, not that tenant's row.
func TestIntegration_XBOMSource_NeverCrossesTenants(t *testing.T) {
	owner := testdb.Connect(t)
	mine := testdb.NewTenant(t, owner)
	theirs := testdb.NewTenant(t, owner)

	theirAsset := seedAsset(t, owner, theirs, "server", "hardware.computer.server", "their-web", "192.0.2.50")
	seedFact(t, owner, theirs, theirAsset, "os.name", "Ubuntu", "agent:1")
	seedSoftware(t, owner, theirs, theirAsset, "openssl", "3.0.14", "pkg:deb/ubuntu/openssl@3.0.14")

	// Ask as MY tenant for THEIR asset id — the shape a guessed or leaked id
	// takes.
	snap, err := NewSource(owner).Load(context.Background(), mine, []uuid.UUID{theirAsset})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(snap.Assets) != 0 || len(snap.Facts) != 0 || len(snap.Software) != 0 {
		t.Fatalf("cross-tenant read returned assets=%d facts=%d software=%d, want all zero",
			len(snap.Assets), len(snap.Facts), len(snap.Software))
	}
}

// TestIntegration_XBOMSource_ExcludesWhatMustNotBeInEvidence.
//
// Four exclusions, each of which would put a false statement in a signed,
// dated document: a deleted asset, a closed endpoint, an expired fact (one the
// producer said it would no longer stand behind), and a removed software
// install. A `stale` install is deliberately KEPT — stale is a statement about
// our collection freshness, not about the software being gone.
func TestIntegration_XBOMSource_ExcludesWhatMustNotBeInEvidence(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)

	live := seedAsset(t, owner, tenant, "server", "hardware.computer.server", "live", "192.0.2.10")
	gone := seedAsset(t, owner, tenant, "server", "hardware.computer.server", "gone", "192.0.2.11")
	if _, err := owner.Exec(`UPDATE public.assets SET deleted_at = now() WHERE tenant_id = $1 AND id = $2`, tenant, gone); err != nil {
		t.Fatalf("soft-delete asset: %v", err)
	}

	if _, err := owner.Exec(`
		INSERT INTO public.asset_endpoints (tenant_id, asset_id, address, port, transport, status)
		VALUES ($1, $2, '192.0.2.10'::inet, 22, 'tcp', 'closed'),
		       ($1, $2, '192.0.2.10'::inet, 443, 'tcp', 'active')
	`, tenant, live); err != nil {
		t.Fatalf("seed endpoints: %v", err)
	}

	if _, err := owner.Exec(`
		INSERT INTO public.asset_facts (tenant_id, asset_id, key, value, source_kind, source_ref, expires_at)
		VALUES ($1, $2, 'os.name', '"Ubuntu"'::jsonb, 'measured', 'stale-source', now() - interval '1 day')
	`, tenant, live); err != nil {
		t.Fatalf("seed expired fact: %v", err)
	}
	seedFact(t, owner, tenant, live, "os.version", "24.04", "agent:1")

	removedProduct := seedSoftware(t, owner, tenant, live, "oldpkg", "1.0", "pkg:deb/ubuntu/oldpkg@1.0")
	if _, err := owner.Exec(`
		UPDATE public.software_installs SET status = 'removed' WHERE tenant_id = $1 AND product_id = $2
	`, tenant, removedProduct); err != nil {
		t.Fatalf("mark install removed: %v", err)
	}
	staleProduct := seedSoftware(t, owner, tenant, live, "stalepkg", "2.0", "pkg:deb/ubuntu/stalepkg@2.0")
	if _, err := owner.Exec(`
		UPDATE public.software_installs SET status = 'stale' WHERE tenant_id = $1 AND product_id = $2
	`, tenant, staleProduct); err != nil {
		t.Fatalf("mark install stale: %v", err)
	}

	snap, err := NewSource(owner).Load(context.Background(), tenant, []uuid.UUID{live, gone})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(snap.Assets) != 1 || snap.Assets[0].ID != live {
		t.Errorf("assets = %+v, want only the live one", snap.Assets)
	}
	if len(snap.Endpoints) != 1 || snap.Endpoints[0].Port != 443 {
		t.Errorf("endpoints = %+v, want only the active one", snap.Endpoints)
	}
	if len(snap.Facts) != 1 || snap.Facts[0].Key != "os.version" {
		t.Errorf("facts = %+v, want only the unexpired one", snap.Facts)
	}
	names := map[string]bool{}
	for _, si := range snap.Software {
		names[si.Name] = true
	}
	if names["oldpkg"] {
		t.Error("a removed install reached the snapshot")
	}
	if !names["stalepkg"] {
		t.Error("a stale install was dropped; stale is a freshness statement about us, not about the software being gone")
	}
}

// TestIntegration_XBOMSource_DropsPendingRelationships. A `pending` edge is a
// proposal awaiting a human (ADR-0003), and signed evidence is not the place a
// proposal becomes a fact.
func TestIntegration_XBOMSource_DropsPendingRelationships(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)

	a := seedAsset(t, owner, tenant, "server", "hardware.computer.server", "a", "192.0.2.10")
	b := seedAsset(t, owner, tenant, "server", "hardware.computer.server", "b", "192.0.2.11")
	c := seedAsset(t, owner, tenant, "server", "hardware.computer.server", "c", "192.0.2.12")

	if _, err := owner.Exec(`
		INSERT INTO public.asset_relationships (tenant_id, from_asset_id, to_asset_id, type, source_kind, status)
		VALUES ($1, $2, $3, 'connects_to', 'measured', 'active'),
		       ($1, $2, $4, 'connects_to', 'inferred', 'pending')
	`, tenant, a, b, c); err != nil {
		t.Fatalf("seed relationships: %v", err)
	}

	snap, err := NewSource(owner).Load(context.Background(), tenant, []uuid.UUID{a, b, c})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(snap.Relationships) != 1 || snap.Relationships[0].ToAssetID != b {
		t.Fatalf("relationships = %+v, want only the active edge", snap.Relationships)
	}
}

// TestIntegration_Assemble_EachKindHashesStablyOverRealRows is the end-to-end
// determinism proof: the unit test pins it over a hand-built Snapshot, this one
// pins it over rows a database returned, where the ORDER BY clauses are what
// stand between us and a hash that changes on every generation.
func TestIntegration_Assemble_EachKindHashesStablyOverRealRows(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)

	// One product, installed everywhere — the case the per-product collapse
	// exists for, and the one whose occurrence ORDER is most likely to come
	// back from Postgres differently between runs.
	product := seedProduct(t, owner, tenant, "openssl", "3.0.14", "pkg:deb/ubuntu/openssl@3.0.14")

	ids := make([]uuid.UUID, 0, 6)
	for i, class := range []string{"server", "server", "switch", "firewall", "business_service", "object_storage"} {
		path := map[string]string{
			"server":           "hardware.computer.server",
			"switch":           "hardware.network_device.switch",
			"firewall":         "hardware.network_device.firewall",
			"business_service": "service.business_service",
			"object_storage":   "cloud_resource.object_storage",
		}[class]
		id := seedAsset(t, owner, tenant, class, path, "asset", fmt.Sprintf("192.0.2.%d", i+1))
		ids = append(ids, id)
		seedFact(t, owner, tenant, id, "hw.vendor", "Vendor", "agent:1")
		seedInstall(t, owner, tenant, id, product)
	}

	scope := &scopes.Scope{ID: uuid.New(), TenantID: tenant, Name: "All", Version: 1}
	assembler := NewAssembler(NewSource(owner)).
		WithClock(fixtureTime, func() uuid.UUID { return fixtureSerial })

	for _, kind := range []cbom.ArtifactKind{cbom.KindSBOM, cbom.KindHBOM, cbom.KindInventory} {
		t.Run(string(kind), func(t *testing.T) {
			first, err := assembler.Assemble(context.Background(), kind, scope, ids)
			if err != nil {
				t.Fatalf("Assemble: %v", err)
			}
			if first.Kind != kind {
				t.Errorf("Kind = %q, want %q", first.Kind, kind)
			}
			if first.ContentHash == "" || len(first.CanonicalBytes) == 0 {
				t.Fatal("assembly produced no bytes")
			}
			for i := 0; i < 6; i++ {
				again, err := assembler.Assemble(context.Background(), kind, scope, ids)
				if err != nil {
					t.Fatalf("Assemble (repeat %d): %v", i, err)
				}
				if again.ContentHash != first.ContentHash {
					t.Fatalf("repeat %d hashed %s, first hashed %s — the SQL order is not deterministic",
						i, again.ContentHash, first.ContentHash)
				}
			}
		})
	}
}

// TestIntegration_Assemble_EmptyScopeProducesAnEmptyArtifact. A scope that
// matches nothing is a legitimate answer, and it must produce a valid, hashable
// artifact rather than an error — otherwise a tenant cannot attest to "this
// boundary is empty", which is a claim an auditor may well want.
func TestIntegration_Assemble_EmptyScopeProducesAnEmptyArtifact(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)

	scope := &scopes.Scope{ID: uuid.New(), TenantID: tenant, Name: "Empty", Version: 1}
	out, err := NewAssembler(NewSource(owner)).
		WithClock(fixtureTime, func() uuid.UUID { return fixtureSerial }).
		Assemble(context.Background(), cbom.KindInventory, scope, nil)
	if err != nil {
		t.Fatalf("Assemble on an empty scope: %v", err)
	}
	if out.ComponentCount != 0 {
		t.Errorf("ComponentCount = %d, want 0", out.ComponentCount)
	}
	// `components` must be [] and not null — the CycloneDX schema types it as
	// an array, and a null fails validation for the whole document.
	var doc struct {
		Components *[]any `json:"components"`
	}
	if err := json.Unmarshal(out.CanonicalBytes, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.Components == nil {
		t.Error("components serialised as null; the schema requires an array")
	}
}
