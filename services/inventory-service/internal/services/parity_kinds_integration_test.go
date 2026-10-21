package services

// DB-integration tests for DCIM gap 10's NetBox-parity kinds: virtual circuits
// (and their interface terminations), ASN ranges and VLAN translation
// policies. Skipped unless TEST_DATABASE_URL is set; run with
// make test-integration-db. The services run on the NON-OWNER app role, so RLS
// is in force as in production.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/query"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// vcChain builds a provider, its network, a virtual circuit type and a
// virtual circuit for the tenant.
func vcChain(t *testing.T, svc *CircuitService, tenant uuid.UUID, prov, cid string) (provider, network, typ, vc uuid.UUID) {
	t.Helper()
	ctx := ifaceActorCtx()
	provider = mustCreate(t, ctx, svc, tenant, CircuitRouteProviders, fmt.Sprintf(`{"name":%q}`, prov))
	network = mustCreate(t, ctx, svc, tenant, CircuitRouteProviderNetworks, fmt.Sprintf(`{"provider_id":%q,"name":"%s overlay"}`, provider, prov))
	typ = mustCreate(t, ctx, svc, tenant, CircuitRouteVirtualCircuitTypes, `{"name":"SD-WAN","color":"#00AA00"}`)
	vc = mustCreate(t, ctx, svc, tenant, CircuitRouteVirtualCircuits, fmt.Sprintf(`{"cid":%q,"provider_network_id":%q,"type_id":%q}`, cid, network, typ))
	return
}

// Tenant isolation: tenant B can neither read, list, patch nor hang a
// termination on tenant A's virtual circuit, and raw SQL under B's context
// stamped with A's tenant is refused by RLS.
//
// Mutation: drop the virtual_circuits / virtual_circuit_terminations
// tenant_isolation policy from the schema block → the raw cross-tenant INSERT
// is accepted and this goes red.
func TestIntegration_VirtualCircuits_RLS(t *testing.T) {
	owner, app, tenantA := ifaceFixture(t)
	tenantB := testdb.NewTenant(t, owner)
	ctx := ifaceActorCtx()
	svc := NewCircuitService(app)
	_, network, typ, vc := vcChain(t, svc, tenantA, "Overlay Co", "VC-1")

	if _, err := svc.Get(ctx, tenantB, CircuitRouteVirtualCircuits, vc); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("tenant B read tenant A's virtual circuit: %v", err)
	}
	if _, err := svc.Update(ctx, tenantB, CircuitRouteVirtualCircuits, vc, []byte(`{"description":"x"}`)); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("tenant B patched tenant A's virtual circuit: %v", err)
	}
	if rows, total, err := svc.List(ctx, tenantB, CircuitRouteVirtualCircuits, IPAMListParams{Limit: 50}); err != nil || total != 0 || len(rows) != 0 {
		t.Fatalf("tenant B lists %d virtual circuits (%v), want none", total, err)
	}
	if _, err := svc.Create(ctx, tenantB, CircuitRouteVirtualCircuits, []byte(fmt.Sprintf(`{"cid":"X","provider_network_id":%q,"type_id":%q}`, network, typ))); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("tenant B built a virtual circuit on tenant A's network: %v", err)
	}
	bAsset := ifaceSeedAsset(t, owner, tenantB, "monitoring")
	ifs := NewInterfaceService(app)
	bIf, err := ifs.Create(ctx, tenantB, uuid.Nil, InterfaceInput{AssetID: bAsset, Name: "wan0", Type: "virtual"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(ctx, tenantB, CircuitRouteVirtualCircuitTerminations, []byte(fmt.Sprintf(`{"virtual_circuit_id":%q,"interface_id":%q}`, vc, bIf.ID))); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("tenant B terminated tenant A's virtual circuit: %v", err)
	}

	testdb.EnsureRLSAppRole(t, owner)
	for _, table := range []string{"virtual_circuit_types", "virtual_circuits", "virtual_circuit_terminations", "asn_ranges",
		"vlan_translation_policies", "vlan_translation_rules"} {
		testdb.AsTenant(t, owner, tenantB, func(tx *sql.Tx) {
			var n int
			if err := tx.QueryRow(`SELECT count(*) FROM public.`+table+` WHERE tenant_id = $1`, tenantA).Scan(&n); err != nil || n != 0 {
				t.Fatalf("tenant B sees %d of tenant A's %s (%v)", n, table, err)
			}
		})
	}
	testdb.AsTenant(t, owner, tenantB, func(tx *sql.Tx) {
		_, err := tx.Exec(`INSERT INTO public.virtual_circuits (tenant_id, cid, provider_network_id, type_id) VALUES ($1, 'VC-B', $2, $3)`, tenantA, network, typ)
		if err == nil || !strings.Contains(err.Error(), "row-level security") {
			t.Fatalf("cross-tenant virtual circuit insert: %v, want a row-level security refusal", err)
		}
	})
	testdb.AsTenant(t, owner, tenantB, func(tx *sql.Tx) {
		_, err := tx.Exec(`INSERT INTO public.vlan_translation_policies (tenant_id, name) VALUES ($1, 'stolen')`, tenantA)
		if err == nil || !strings.Contains(err.Error(), "row-level security") {
			t.Fatalf("cross-tenant policy insert: %v, want a row-level security refusal", err)
		}
	})
}

// The rules: cid unique per provider network, an account must be the
// network's provider's, one termination per interface, the role set, the
// list rows the Circuits lens and the interface page read, change recording,
// and deleting the interface takes its termination.
//
// Mutation: drop virtual_circuits_identity_key → the second VC-7 on the same
// network is accepted; drop virtual_circuit_terminations_interface_key → the
// second termination on wan0 is accepted; drop the provider-account check in
// prepareVirtualCircuit → the foreign account is accepted.
func TestIntegration_VirtualCircuits_RulesAndListRows(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	svc := NewCircuitService(app)
	provider, network, typ, vc := vcChain(t, svc, tenant, "Overlay Co", "VC-7")

	if _, err := svc.Create(ctx, tenant, CircuitRouteVirtualCircuits, []byte(fmt.Sprintf(`{"cid":"VC-7","provider_network_id":%q,"type_id":%q}`, network, typ))); !errors.Is(err, ErrIPAMConflict) {
		t.Fatalf("second VC-7 on the same network: %v, want conflict", err)
	}
	other := mustCreate(t, ctx, svc, tenant, CircuitRouteProviders, `{"name":"Other Carrier"}`)
	otherNet := mustCreate(t, ctx, svc, tenant, CircuitRouteProviderNetworks, fmt.Sprintf(`{"provider_id":%q,"name":"Other core"}`, other))
	mustCreate(t, ctx, svc, tenant, CircuitRouteVirtualCircuits, fmt.Sprintf(`{"cid":"VC-7","provider_network_id":%q,"type_id":%q}`, otherNet, typ))
	foreign := mustCreate(t, ctx, svc, tenant, CircuitRouteProviderAccounts, fmt.Sprintf(`{"provider_id":%q,"account":"ACC-9"}`, other))
	if _, err := svc.Update(ctx, tenant, CircuitRouteVirtualCircuits, vc, []byte(fmt.Sprintf(`{"provider_account_id":%q}`, foreign))); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("an account of another provider: %v, want invalid", err)
	}
	own := mustCreate(t, ctx, svc, tenant, CircuitRouteProviderAccounts, fmt.Sprintf(`{"provider_id":%q,"account":"ACC-1"}`, provider))
	if _, err := svc.Update(ctx, tenant, CircuitRouteVirtualCircuits, vc, []byte(fmt.Sprintf(`{"provider_account_id":%q,"operational_status":"planned"}`, own))); err != nil {
		t.Fatalf("the network's provider's account: %v", err)
	}
	if _, err := svc.Update(ctx, tenant, CircuitRouteVirtualCircuits, vc, []byte(`{"operational_status":"broken"}`)); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("an unknown status: %v, want invalid", err)
	}

	ifs := NewInterfaceService(app)
	hub := ifaceSeedAsset(t, owner, tenant, "monitoring")
	spoke := ifaceSeedAsset(t, owner, tenant, "monitoring")
	hubIf, err := ifs.Create(ctx, tenant, uuid.Nil, InterfaceInput{AssetID: hub, Name: "wan0", Type: "virtual"})
	if err != nil {
		t.Fatal(err)
	}
	spokeIf, err := ifs.Create(ctx, tenant, uuid.Nil, InterfaceInput{AssetID: spoke, Name: "wan0", Type: "virtual"})
	if err != nil {
		t.Fatal(err)
	}
	term := mustCreate(t, ctx, svc, tenant, CircuitRouteVirtualCircuitTerminations, fmt.Sprintf(`{"virtual_circuit_id":%q,"interface_id":%q,"role":"Hub"}`, vc, hubIf.ID))
	if _, err := svc.Create(ctx, tenant, CircuitRouteVirtualCircuitTerminations, []byte(fmt.Sprintf(`{"virtual_circuit_id":%q,"interface_id":%q}`, vc, hubIf.ID))); !errors.Is(err, ErrIPAMConflict) {
		t.Fatalf("a second termination on wan0: %v, want conflict", err)
	}
	if _, err := svc.Create(ctx, tenant, CircuitRouteVirtualCircuitTerminations, []byte(fmt.Sprintf(`{"virtual_circuit_id":%q,"interface_id":%q,"role":"leaf"}`, vc, spokeIf.ID))); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("role leaf: %v, want invalid", err)
	}
	if _, err := svc.Create(ctx, tenant, CircuitRouteVirtualCircuitTerminations, []byte(fmt.Sprintf(`{"virtual_circuit_id":%q,"interface_id":%q}`, vc, uuid.New()))); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("an unknown interface: %v, want invalid", err)
	}
	spokeTerm := mustCreate(t, ctx, svc, tenant, CircuitRouteVirtualCircuitTerminations, fmt.Sprintf(`{"virtual_circuit_id":%q,"interface_id":%q,"role":"spoke"}`, vc, spokeIf.ID))

	// The Circuits lens's row: network, provider, type and both terminations.
	rows, _, err := svc.List(ctx, tenant, CircuitRouteVirtualCircuits, IPAMListParams{Filters: map[string]string{"provider_id": provider.String()}, Limit: 10})
	if err != nil || len(rows) != 1 {
		t.Fatalf("the provider's virtual circuits: %d (%v), want 1", len(rows), err)
	}
	var row struct {
		ProviderName        string `json:"provider_name"`
		ProviderNetworkName string `json:"provider_network_name"`
		TypeName            string `json:"type_name"`
		OperationalStatus   string `json:"operational_status"`
		Terminations        []struct {
			Role          string  `json:"role"`
			InterfaceName string  `json:"interface_name"`
			AssetName     *string `json:"asset_name"`
		} `json:"terminations"`
	}
	if err := json.Unmarshal(rows[0], &row); err != nil {
		t.Fatal(err)
	}
	if row.ProviderName != "Overlay Co" || row.ProviderNetworkName != "Overlay Co overlay" || row.TypeName != "SD-WAN" ||
		row.OperationalStatus != "planned" || len(row.Terminations) != 2 || row.Terminations[0].Role != "hub" || row.Terminations[0].AssetName == nil {
		t.Fatalf("virtual circuit list row %s", rows[0])
	}
	// The interface page's read: its termination with the circuit's cid.
	trows, _, err := svc.List(ctx, tenant, CircuitRouteVirtualCircuitTerminations, IPAMListParams{Filters: map[string]string{"interface_id": hubIf.ID.String()}, Limit: 5})
	if err != nil || len(trows) != 1 || !strings.Contains(strings.ReplaceAll(string(trows[0]), " ", ""), `"virtual_circuit_cid":"VC-7"`) {
		t.Fatalf("the interface's termination: %d %s (%v)", len(trows), trows, err)
	}

	// A provider network with virtual circuits cannot be deleted out from
	// under them; the type neither.
	if err := svc.Delete(ctx, tenant, CircuitRouteProviderNetworks, network); !errors.Is(err, ErrIPAMInUse) {
		t.Fatalf("deleting a network with virtual circuits: %v, want in use", err)
	}
	if err := svc.Delete(ctx, tenant, CircuitRouteVirtualCircuitTypes, typ); !errors.Is(err, ErrIPAMInUse) {
		t.Fatalf("deleting a type in use: %v, want in use", err)
	}
	// Deleting the interface takes its termination (NetBox CASCADE).
	if err := ifs.Delete(ctx, tenant, spokeIf.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Get(ctx, tenant, CircuitRouteVirtualCircuitTerminations, spokeTerm); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("the deleted interface's termination survived: %v", err)
	}

	testdb.EnsureRLSAppRole(t, owner)
	for kind, id := range map[string]uuid.UUID{"virtual_circuit": vc, "virtual_circuit_termination": term, "virtual_circuit_type": typ} {
		var recorded bool
		testdb.AsTenant(t, owner, tenant, func(tx *sql.Tx) {
			if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM object_changes WHERE object_kind = $1 AND object_id = $2 AND action = 'create')`, kind, id).Scan(&recorded); err != nil {
				t.Fatal(err)
			}
		})
		if !recorded {
			t.Fatalf("creating a %s recorded no change", kind)
		}
	}

	// The query fields (QUERY_LANGUAGE §15.10) find the hub by its circuit.
	match := func(q string) map[uuid.UUID]bool {
		t.Helper()
		c, err := query.Compile(q, "asset", query.DefaultCatalog(), query.DefaultOptionsFor(query.DefaultCatalog()))
		if err != nil {
			t.Fatalf("compile %q: %v", q, err)
		}
		out := map[uuid.UUID]bool{}
		testdb.AsTenant(t, owner, tenant, func(tx *sql.Tx) {
			rows, err := tx.Query("SELECT a.id FROM assets a WHERE a.tenant_id = '"+tenant.String()+"' AND "+c.Where, c.Args...)
			if err != nil {
				t.Fatalf("run %q: %v", q, err)
			}
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var id uuid.UUID
				if err := rows.Scan(&id); err != nil {
					t.Fatal(err)
				}
				out[id] = true
			}
		})
		return out
	}
	if got := match(`virtual_circuit = VC-7`); !got[hub] || got[spoke] || len(got) != 1 {
		t.Errorf("virtual_circuit = VC-7: %v", got)
	}
	if got := match(`virtual_circuit:sd-wan`); !got[hub] || len(got) != 1 {
		t.Errorf("virtual_circuit by type slug: %v", got)
	}
	if got := match(`virtual_circuit.provider:overlay*`); !got[hub] || len(got) != 1 {
		t.Errorf("virtual_circuit.provider: %v", got)
	}
	if got := match(`virtual_circuit.role = hub`); !got[hub] || len(got) != 1 {
		t.Errorf("virtual_circuit.role = hub: %v", got)
	}
	if got := match(`virtual_circuit.role != hub`); got[hub] || !got[spoke] {
		t.Errorf("virtual_circuit.role != hub must exclude the hub and keep an asset with none: %v", got)
	}
}

// An interface names a VLAN translation policy of its tenant; another
// tenant's policy is refused with the field named; deleting the policy
// detaches the interface (ON DELETE SET NULL), and the change is in the
// interface's record.
//
// Mutation: drop the vlan_translation_policies check in ifaceCheckIPAMRefs →
// tenant B's policy id reaches the FK and answers a 500-shaped error instead
// of the field-named 422; drop the ifaceSetTranslationPolicy call in Patch →
// the policy is never stored and the read-back check fails.
func TestIntegration_Interfaces_VLANTranslationPolicy(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	tenantB := testdb.NewTenant(t, owner)
	ctx := ifaceActorCtx()
	ipam := NewIPAMService(app)
	ifs := NewInterfaceService(app)
	asset := ifaceSeedAsset(t, owner, tenant, "monitoring")

	raw, err := ipam.Create(ctx, tenant, "vlan-translation-policies", []byte(`{"name":"customer-a"}`))
	if err != nil {
		t.Fatal(err)
	}
	pol := catID(t, raw)
	if _, err := ipam.Create(ctx, tenant, "vlan-translation-rules", []byte(fmt.Sprintf(`{"policy_id":%q,"local_vid":100,"remote_vid":4095}`, pol))); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("remote VID 4095: %v, want invalid", err)
	}
	rawB, err := ipam.Create(ctx, tenantB, "vlan-translation-policies", []byte(`{"name":"customer-b"}`))
	if err != nil {
		t.Fatal(err)
	}
	polB := catID(t, rawB)

	created, err := ifs.Create(ctx, tenant, uuid.Nil, InterfaceInput{AssetID: asset, Name: "xe-0/0/1", Type: "10gbase-x-sfpp", VLANTranslationPolicyID: &pol})
	if err != nil {
		t.Fatal(err)
	}
	if created.VLANTranslationPolicyID == nil || *created.VLANTranslationPolicyID != pol {
		t.Fatalf("create did not store the policy: %+v", created.VLANTranslationPolicyID)
	}
	if _, err := ifs.Patch(ctx, tenant, created.ID, map[string]json.RawMessage{"vlan_translation_policy_id": json.RawMessage(fmt.Sprintf("%q", polB))}); err == nil {
		t.Fatal("another tenant's policy was accepted")
	} else {
		var ve *InterfaceValidationError
		if !errors.As(err, &ve) || ve.Field != "vlan_translation_policy_id" {
			t.Fatalf("another tenant's policy: %v, want a validation error on vlan_translation_policy_id", err)
		}
	}
	got, err := ifs.Patch(ctx, tenant, created.ID, map[string]json.RawMessage{"vlan_translation_policy_id": json.RawMessage(`null`)})
	if err != nil || got.VLANTranslationPolicyID != nil {
		t.Fatalf("clearing the policy: %v %+v", err, got.VLANTranslationPolicyID)
	}
	got, err = ifs.Patch(ctx, tenant, created.ID, map[string]json.RawMessage{"vlan_translation_policy_id": json.RawMessage(fmt.Sprintf("%q", pol))})
	if err != nil || got.VLANTranslationPolicyID == nil || *got.VLANTranslationPolicyID != pol {
		t.Fatalf("setting the policy: %v %+v", err, got.VLANTranslationPolicyID)
	}
	if err := ipam.Delete(ctx, tenant, "vlan-translation-policies", pol); err != nil {
		t.Fatalf("deleting the policy: %v", err)
	}
	after, err := ifs.Get(ctx, tenant, created.ID)
	if err != nil || after.VLANTranslationPolicyID != nil {
		t.Fatalf("deleting the policy did not detach the interface: %v %+v", err, after.VLANTranslationPolicyID)
	}
}
