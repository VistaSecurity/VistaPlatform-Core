package entitlements_test

// SetTenantOperator's unmark rule ( item 1): once the grace period under
// the licence has ended, taking a tenant out of the operator's own set is
// refused when it would put the customer count OVER max_tenants — the same
// rule a creation meets. Otherwise the flag closes the cap's last bypass: mark
// customers as the operator's own, create a tenant (admitted: under the
// licence), unmark them, repeat.
//
// Mutations (each turns a case red):
//   - drop the refusal (always write)                    → CycleAttack, RefusedPastGrace
//   - refuse without an expired clock (`in.graceStartedAt == nil ||`)
//                                                         → AllowedBeforeGraceStarts
//   - `!now.Before(ends)` → `true` (ignore the clock's end)
//                                                         → AllowedDuringGrace
//   - `in.current+1 >= *in.licensed` (refuse AT the licence)
//                                                         → AllowedBackToTheLicensedNumber
//   - check any false write (drop `marked &&`)            → MarkAlwaysAllowed (unmarked tenant)
//   - apply the rule on a non-MSP licence                 → NotCappedOffMSP
//
// Scratch database (capHarness). Skips without TEST_DATABASE_URL.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/entitlements"
)

// operatorTenant inserts a live tenant marked as the operator's own.
func (h *capHarness) operatorTenant(t *testing.T) uuid.UUID {
	t.Helper()
	id := uuid.New()
	mustExec(t, h.owner, `INSERT INTO tenants (id, name, slug, is_operator) VALUES ($1, 'op', $2, true)`, id, "op-"+id.String())
	return id
}

func (h *capHarness) setOperator(t *testing.T, id uuid.UUID, flag bool, now time.Time) error {
	t.Helper()
	found, err := entitlements.SetTenantOperator(context.Background(), h.bypass, id, flag, now)
	if err == nil && !found {
		t.Fatalf("SetTenantOperator(%s): tenant not found", id)
	}
	return err
}

func (h *capHarness) isOperator(t *testing.T, id uuid.UUID) bool {
	t.Helper()
	var flag bool
	if err := h.owner.QueryRow(`SELECT is_operator FROM tenants WHERE id = $1`, id).Scan(&flag); err != nil {
		t.Fatal(err)
	}
	return flag
}

func mustRefuseUnmark(t *testing.T, h *capHarness, id uuid.UUID, now time.Time) {
	t.Helper()
	err := h.setOperator(t, id, false, now)
	refusal, ok := entitlements.IsOperatorUnmarkRefused(err)
	if !ok {
		t.Fatalf("unmark: err = %v, want an OperatorUnmarkRefusedError", err)
	}
	if refusal.After <= refusal.Licensed {
		t.Errorf("refusal = %+v, want After over Licensed", refusal)
	}
	if !h.isOperator(t, id) {
		t.Fatal("a refused unmark was written")
	}
}

// Over the licence past grace: the unmark is refused and nothing is written.
func TestIntegration_OperatorUnmark_RefusedPastGrace(t *testing.T) {
	h := newCapHarness(t)
	now := time.Now().Truncate(time.Microsecond)
	h.licence(t, "msp", ptr(1), ptr(2), now.Add(365*24*time.Hour))
	own := h.operatorTenant(t)
	h.mustCreate(t, now, entitlements.TenantCapUnder) // base+1: at the licence
	h.mustCreate(t, now, entitlements.TenantCapGrace) // base+2: over, clock starts
	later := now.Add(3 * 24 * time.Hour)              // grace (2 days) has ended

	mustRefuseUnmark(t, h, own, later)
}

// The cycle, end to end: past grace, mark a customer as the operator's
// own to drop under, create one tenant, then try to unmark — refused, so the
// round gains nothing.
func TestIntegration_OperatorUnmark_CycleAttack(t *testing.T) {
	h := newCapHarness(t)
	now := time.Now().Truncate(time.Microsecond)
	h.licence(t, "msp", ptr(1), ptr(1), now.Add(365*24*time.Hour))
	h.mustCreate(t, now, entitlements.TenantCapUnder)
	h.mustCreate(t, now, entitlements.TenantCapGrace) // over: base+2 of base+1
	later := now.Add(2 * 24 * time.Hour)
	if _, err := h.create(t, later); err == nil {
		t.Fatal("past grace, a creation over the licence was admitted")
	}

	// Mark two customers as the operator's own: base+0 of base+1 — room for one.
	var customers []uuid.UUID
	rows, err := h.owner.Query(`SELECT id FROM tenants WHERE deleted_at IS NULL AND NOT is_operator ORDER BY created_at DESC LIMIT 2`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		customers = append(customers, id)
	}
	_ = rows.Close()
	for _, id := range customers {
		if err := h.setOperator(t, id, true, later); err != nil {
			t.Fatalf("mark: %v", err)
		}
	}
	// base+1: at the licence again. Admitted — the state reported is what the
	// NEXT creation meets, which is blocked.
	h.mustCreate(t, later, entitlements.TenantCapBlocked)

	// Unmarking either would take it over the licence: refused.
	for _, id := range customers {
		mustRefuseUnmark(t, h, id, later)
	}
}

// Before any clock has started under this licence the unmark is allowed (it
// takes the install over and the grace period starts — EvaluateTenantCap).
func TestIntegration_OperatorUnmark_AllowedBeforeGraceStarts(t *testing.T) {
	h := newCapHarness(t)
	now := time.Now().Truncate(time.Microsecond)
	h.licence(t, "msp", ptr(0), ptr(5), now.Add(365*24*time.Hour))
	own := h.operatorTenant(t)
	if err := h.setOperator(t, own, false, now); err != nil {
		t.Fatalf("unmark with no clock: %v", err)
	}
	if h.isOperator(t, own) {
		t.Fatal("unmark not written")
	}
}

// While the grace period lasts the unmark is allowed, as a creation would be.
func TestIntegration_OperatorUnmark_AllowedDuringGrace(t *testing.T) {
	h := newCapHarness(t)
	now := time.Now().Truncate(time.Microsecond)
	h.licence(t, "msp", ptr(0), ptr(5), now.Add(365*24*time.Hour))
	own := h.operatorTenant(t)
	h.mustCreate(t, now, entitlements.TenantCapGrace) // over: the clock starts
	if err := h.setOperator(t, own, false, now.Add(24*time.Hour)); err != nil {
		t.Fatalf("unmark during grace: %v", err)
	}
}

// Past grace, an unmark that lands exactly AT the licensed number is within
// the licence — allowed, as a creation into the last slot would be.
func TestIntegration_OperatorUnmark_AllowedBackToTheLicensedNumber(t *testing.T) {
	h := newCapHarness(t)
	now := time.Now().Truncate(time.Microsecond)
	h.licence(t, "msp", ptr(1), ptr(1), now.Add(365*24*time.Hour))
	h.mustCreate(t, now, entitlements.TenantCapUnder)
	h.mustCreate(t, now, entitlements.TenantCapGrace) // base+2 of base+1: clock
	later := now.Add(2 * 24 * time.Hour)
	var newest uuid.UUID
	if err := h.owner.QueryRow(`SELECT id FROM tenants WHERE deleted_at IS NULL AND NOT is_operator ORDER BY created_at DESC LIMIT 1`).Scan(&newest); err != nil {
		t.Fatal(err)
	}
	mustExec(t, h.owner, `UPDATE tenants SET deleted_at = now() WHERE id = $1`, newest) // base+1: at the licence
	own := h.operatorTenant(t)
	mustExec(t, h.owner, `UPDATE tenants SET deleted_at = now() WHERE id = (
		SELECT id FROM tenants WHERE deleted_at IS NULL AND NOT is_operator ORDER BY created_at DESC LIMIT 1)`) // base
	if err := h.setOperator(t, own, false, later); err != nil {
		t.Fatalf("unmark back to the licensed number: %v", err)
	}
}

// Marking takes a tenant OUT of the count: never refused, even blocked.
func TestIntegration_OperatorUnmark_MarkAlwaysAllowed(t *testing.T) {
	h := newCapHarness(t)
	now := time.Now().Truncate(time.Microsecond)
	h.licence(t, "msp", ptr(0), ptr(1), now.Add(365*24*time.Hour))
	h.mustCreate(t, now, entitlements.TenantCapGrace)
	h.mustCreate(t, now, entitlements.TenantCapGrace)
	later := now.Add(2 * 24 * time.Hour)
	var customer uuid.UUID
	if err := h.owner.QueryRow(`SELECT id FROM tenants WHERE deleted_at IS NULL AND NOT is_operator ORDER BY created_at DESC LIMIT 1`).Scan(&customer); err != nil {
		t.Fatal(err)
	}
	if err := h.setOperator(t, customer, true, later); err != nil {
		t.Fatalf("mark while blocked: %v", err)
	}
	// Unmarking a tenant that is not marked changes nothing and is not refused.
	other := uuid.New()
	mustExec(t, h.owner, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'c', $2)`, other, "c-"+other.String())
	if err := h.setOperator(t, other, false, later); err != nil {
		t.Fatalf("unmark of an unmarked tenant: %v", err)
	}
}

// Only an active MSP licence with max_tenants caps anything.
func TestIntegration_OperatorUnmark_NotCappedOffMSP(t *testing.T) {
	h := newCapHarness(t)
	now := time.Now().Truncate(time.Microsecond)
	h.licence(t, "msp", ptr(0), ptr(1), now.Add(365*24*time.Hour))
	h.mustCreate(t, now, entitlements.TenantCapGrace) // a clock exists under this licence
	later := now.Add(2 * 24 * time.Hour)
	for _, tc := range []struct {
		edition string
		expires time.Time
	}{
		{"enterprise", later.Add(24 * time.Hour)},
		{"msp", now.Add(24 * time.Hour)}, // expired by `later`
	} {
		h.licence(t, tc.edition, ptr(0), ptr(1), tc.expires)
		own := h.operatorTenant(t)
		if err := h.setOperator(t, own, false, later); err != nil {
			t.Errorf("%s (expires %s): unmark refused: %v", tc.edition, tc.expires, err)
		}
	}
	// A missing tenant is "not found", not an error.
	if found, err := entitlements.SetTenantOperator(context.Background(), h.bypass, uuid.New(), false, later); found || err != nil {
		t.Errorf("unknown tenant: found=%v err=%v", found, err)
	}
}
