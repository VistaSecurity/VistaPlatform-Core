package services

// Core-edition invariant for tier assignment.
//
// Tier ASSIGNMENT is the one thing that must keep working with no Enterprise
// code in the binary: shared/entitlements resolves a tenant's grants from the
// tier it is on, so if a Core build could not put an organization on a tier,
// entitlements would resolve to nothing and the whole Core product would be
// ungated. That is why tier_management.go and TierService stayed in Core while
// the rest of the /admin/tenants surface moved to ee/msp.
//
// The Enterprise part of tiers is narrow: the TierPricer seam that mints a
// Stripe Product/Price when a stripe-billed tier is SAVED. It is nil in Core.
// This test pins the invariant that the pricer is not on the assignment path —
// a future change that dereferenced it there would silently make Core unable to
// assign a tier, and every route-level test would still pass.
//
// No database needed: sql.Open is lazy, so the call reaches the query and errors
// there. Reaching a query at all is the assertion — a pricer dependency would
// nil-panic before it.

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func TestAssignTierToTenant_NeedsNoPricer(t *testing.T) {
	db, err := sql.Open("postgres", "postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// A Core-edition tier service: constructed exactly as internal/api does it,
	// with SetPricer never called.
	svc := NewTierService(db, db)

	_, err = svc.AssignTierToTenant(uuid.New(), uuid.New())
	if err == nil {
		t.Fatal("expected a database error against an unreachable pool, got nil")
	}
	// It must fail looking the tier up in Postgres, not because a nil pricer was
	// dereferenced (which would be a panic, failing the test outright).
	if !strings.Contains(err.Error(), "tier not found") {
		t.Fatalf("AssignTierToTenant failed for an unexpected reason: %v", err)
	}
}
