package services

// DB-integration tests for circuits (DCIM BUILD_PLAN row 4.1). Skipped unless
// TEST_DATABASE_URL is set; run with make test-integration-db.
//
// The service runs on the NON-OWNER app role, so RLS is in force exactly as in
// production; seed.sql's platform circuit types are present.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func mustCreate(t *testing.T, ctx context.Context, svc *CircuitService, tenant uuid.UUID, route, body string) uuid.UUID {
	t.Helper()
	raw, err := svc.Create(ctx, tenant, route, []byte(body))
	if err != nil {
		t.Fatalf("create %s %s: %v", route, body, err)
	}
	return catID(t, raw)
}

func platformCircuitType(t *testing.T, ctx context.Context, svc *CircuitService, tenant uuid.UUID, slug string) uuid.UUID {
	t.Helper()
	rows, _, err := svc.List(ctx, tenant, CircuitRouteCircuitTypes, IPAMListParams{Filters: map[string]string{"slug": slug}, Limit: 5})
	if err != nil || len(rows) != 1 {
		t.Fatalf("platform circuit type %q: %d rows (%v) — is seed.sql applied?", slug, len(rows), err)
	}
	return catID(t, rows[0])
}

// A tenant's circuits and terminations are invisible to, and unwritable by,
// another tenant — through the service and through raw SQL on the app role.
//
// Mutation: drop the circuits / circuit_terminations tenant_isolation policy
// from the schema block → the raw cross-tenant INSERT is accepted (or, with
// RLS left on and no policy, tenant A cannot read its own rows) and this goes
// red.
func TestIntegration_Circuits_RLS(t *testing.T) {
	owner, app, tenantA := ifaceFixture(t)
	tenantB := testdb.NewTenant(t, owner)
	ctx := ifaceActorCtx()
	svc := NewCircuitService(app)
	mpls := platformCircuitType(t, ctx, svc, tenantA, "mpls")

	prov := mustCreate(t, ctx, svc, tenantA, CircuitRouteProviders, `{"name":"Lumen","asns":[3356]}`)
	circ := mustCreate(t, ctx, svc, tenantA, CircuitRouteCircuits, fmt.Sprintf(`{"cid":"CKT-1","provider_id":%q,"type_id":%q,"commit_rate_kbps":100000}`, prov, mpls))
	term := mustCreate(t, ctx, svc, tenantA, CircuitRouteTerminations, fmt.Sprintf(`{"circuit_id":%q,"term_side":"a"}`, circ))

	for route, id := range map[string]uuid.UUID{CircuitRouteProviders: prov, CircuitRouteCircuits: circ, CircuitRouteTerminations: term} {
		if _, err := svc.Get(ctx, tenantA, route, id); err != nil {
			t.Fatalf("tenant A cannot read its own %s: %v", route, err)
		}
		if _, err := svc.Get(ctx, tenantB, route, id); !errors.Is(err, ErrIPAMNotFound) {
			t.Fatalf("tenant B read tenant A's %s: %v", route, err)
		}
		if _, err := svc.Update(ctx, tenantB, route, id, []byte(`{"description":"x"}`)); !errors.Is(err, ErrIPAMNotFound) {
			t.Fatalf("tenant B patched tenant A's %s: %v", route, err)
		}
	}
	rows, total, err := svc.List(ctx, tenantB, CircuitRouteCircuits, IPAMListParams{Limit: 50})
	if err != nil || total != 0 || len(rows) != 0 {
		t.Fatalf("tenant B lists %d circuits (%v), want none", total, err)
	}
	// B cannot hang a termination or a circuit off A's objects.
	if _, err := svc.Create(ctx, tenantB, CircuitRouteTerminations, []byte(fmt.Sprintf(`{"circuit_id":%q,"term_side":"Z"}`, circ))); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("tenant B terminated tenant A's circuit: %v", err)
	}
	if _, err := svc.Create(ctx, tenantB, CircuitRouteCircuits, []byte(fmt.Sprintf(`{"cid":"X","provider_id":%q,"type_id":%q}`, prov, mpls))); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("tenant B built a circuit on tenant A's provider: %v", err)
	}

	// Raw SQL on the app role: USING doubles as WITH CHECK, so a row written
	// under B's context but stamped with A's tenant is refused, and B sees none
	// of A's rows.
	testdb.EnsureRLSAppRole(t, owner)
	for _, table := range []string{"circuits", "circuit_terminations"} {
		testdb.AsTenant(t, owner, tenantB, func(tx *sql.Tx) {
			var n int
			if err := tx.QueryRow(`SELECT count(*) FROM public.`+table+` WHERE tenant_id = $1`, tenantA).Scan(&n); err != nil || n != 0 {
				t.Fatalf("tenant B sees %d of tenant A's %s (%v)", n, table, err)
			}
		})
	}
	testdb.AsTenant(t, owner, tenantB, func(tx *sql.Tx) {
		_, err := tx.Exec(`INSERT INTO public.circuit_terminations (tenant_id, circuit_id, term_side) VALUES ($1, $2, 'Z')`, tenantA, circ)
		if err == nil || !strings.Contains(err.Error(), "row-level security") {
			t.Fatalf("cross-tenant termination insert: %v, want a row-level security refusal", err)
		}
	})
	testdb.AsTenant(t, owner, tenantB, func(tx *sql.Tx) {
		_, err := tx.Exec(`INSERT INTO public.circuits (tenant_id, cid, provider_id, type_id) VALUES ($1, 'CKT-B', $2, $3)`, tenantA, prov, mpls)
		if err == nil || !strings.Contains(err.Error(), "row-level security") {
			t.Fatalf("cross-tenant circuit insert: %v, want a row-level security refusal", err)
		}
	})
}

// The rules the row exists for: a circuit's cid is unique per provider (and
// only per provider), a circuit has one A and one Z end, a platform circuit
// type is read-only, a termination's target must be the tenant's, and every
// write lands in the change log.
//
// Mutation: drop circuits_identity_key → the second CKT-7 on the same provider
// is accepted; drop circuit_terminations_side_key → the second A end is
// accepted; drop `Catalogue: true` from the circuit-types spec → the PATCH of
// MPLS answers not-found instead of read-only.
func TestIntegration_Circuits_IdentityAndTerminations(t *testing.T) {
	owner, app, tenant := ifaceFixture(t)
	ctx := ifaceActorCtx()
	svc := NewCircuitService(app)
	mpls := platformCircuitType(t, ctx, svc, tenant, "mpls")
	internet := platformCircuitType(t, ctx, svc, tenant, "internet")

	lumen := mustCreate(t, ctx, svc, tenant, CircuitRouteProviders, `{"name":"Lumen"}`)
	zayo := mustCreate(t, ctx, svc, tenant, CircuitRouteProviders, `{"name":"Zayo Group"}`)
	body := func(prov, typ uuid.UUID, cid string) string {
		return fmt.Sprintf(`{"cid":%q,"provider_id":%q,"type_id":%q}`, cid, prov, typ)
	}
	c1 := mustCreate(t, ctx, svc, tenant, CircuitRouteCircuits, body(lumen, mpls, "CKT-7"))
	if _, err := svc.Create(ctx, tenant, CircuitRouteCircuits, []byte(body(lumen, internet, "CKT-7"))); !errors.Is(err, ErrIPAMConflict) {
		t.Fatalf("second CKT-7 on the same provider: %v, want conflict", err)
	}
	mustCreate(t, ctx, svc, tenant, CircuitRouteCircuits, body(zayo, mpls, "CKT-7")) // another provider's CKT-7 is another circuit

	// An account must be the circuit's provider's.
	zacct := mustCreate(t, ctx, svc, tenant, CircuitRouteProviderAccounts, fmt.Sprintf(`{"provider_id":%q,"account":"ACC-1"}`, zayo))
	if _, err := svc.Update(ctx, tenant, CircuitRouteCircuits, c1, []byte(fmt.Sprintf(`{"provider_account_id":%q}`, zacct))); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("Lumen circuit on a Zayo account: %v, want invalid", err)
	}

	// One A, one Z.
	pn := mustCreate(t, ctx, svc, tenant, CircuitRouteProviderNetworks, fmt.Sprintf(`{"provider_id":%q,"name":"Lumen MPLS core"}`, lumen))
	mustCreate(t, ctx, svc, tenant, CircuitRouteTerminations, fmt.Sprintf(`{"circuit_id":%q,"term_side":"A","port_speed_kbps":1000000}`, c1))
	if _, err := svc.Create(ctx, tenant, CircuitRouteTerminations, []byte(fmt.Sprintf(`{"circuit_id":%q,"term_side":"A"}`, c1))); !errors.Is(err, ErrIPAMConflict) {
		t.Fatalf("second A end: %v, want conflict", err)
	}
	if _, err := svc.Create(ctx, tenant, CircuitRouteTerminations, []byte(fmt.Sprintf(`{"circuit_id":%q,"term_side":"B"}`, c1))); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("term_side B: %v, want invalid", err)
	}
	if _, err := svc.Create(ctx, tenant, CircuitRouteTerminations, []byte(fmt.Sprintf(`{"circuit_id":%q,"term_side":"Z","termination_kind":"provider_network","termination_id":%q}`, c1, uuid.New()))); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("termination on an unknown provider network: %v, want invalid", err)
	}
	mustCreate(t, ctx, svc, tenant, CircuitRouteTerminations, fmt.Sprintf(`{"circuit_id":%q,"term_side":"Z","termination_kind":"provider_network","termination_id":%q}`, c1, pn))

	// The lens's list row: provider, type, both ends with the target named.
	rows, _, err := svc.List(ctx, tenant, CircuitRouteCircuits, IPAMListParams{Filters: map[string]string{"provider_id": lumen.String()}, Limit: 10})
	if err != nil || len(rows) != 1 {
		t.Fatalf("Lumen circuits: %d (%v)", len(rows), err)
	}
	var row struct {
		ProviderName string `json:"provider_name"`
		TypeName     string `json:"type_name"`
		Terminations []struct {
			TermSide        string  `json:"term_side"`
			TerminationName *string `json:"termination_name"`
		} `json:"terminations"`
	}
	if err := json.Unmarshal(rows[0], &row); err != nil {
		t.Fatal(err)
	}
	if row.ProviderName != "Lumen" || row.TypeName != "MPLS" || len(row.Terminations) != 2 ||
		row.Terminations[1].TermSide != "Z" || row.Terminations[1].TerminationName == nil || *row.Terminations[1].TerminationName != "Lumen MPLS core" {
		t.Fatalf("circuit list row %s", rows[0])
	}
	if rows, _, err := svc.List(ctx, tenant, CircuitRouteCircuits, IPAMListParams{Filters: map[string]string{"termination_id": pn.String()}, Limit: 10}); err != nil || len(rows) != 1 {
		t.Fatalf("circuits terminating on the provider network: %d (%v), want 1", len(rows), err)
	}

	// The platform catalogue is read-only.
	if _, err := svc.Update(ctx, tenant, CircuitRouteCircuitTypes, mpls, []byte(`{"color":"000000"}`)); !errors.Is(err, ErrIPAMReadOnly) {
		t.Fatalf("PATCH of the platform MPLS type: %v, want read-only", err)
	}
	// A provider with circuits cannot be deleted out from under them.
	if err := svc.Delete(ctx, tenant, CircuitRouteProviders, lumen); !errors.Is(err, ErrIPAMInUse) {
		t.Fatalf("deleting a provider with circuits: %v, want in use", err)
	}

	// Change recording.
	var recorded bool
	testdb.EnsureRLSAppRole(t, owner)
	testdb.AsTenant(t, owner, tenant, func(tx *sql.Tx) {
		if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM object_changes WHERE object_kind = 'circuit' AND object_id = $1 AND action = 'create')`, c1).Scan(&recorded); err != nil {
			t.Fatal(err)
		}
	})
	if !recorded {
		t.Fatal("creating a circuit recorded no change")
	}
}
