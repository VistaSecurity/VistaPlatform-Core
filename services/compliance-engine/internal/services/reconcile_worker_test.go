package services

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestReconcileWorkerEnabled(t *testing.T) {
	cases := map[string]bool{
		"":      true, // unset → on by default
		"true":  true, // anything but "false" → on
		"1":     true,
		"yes":   true,
		"false": false, // the one off switch
	}
	for val, want := range cases {
		t.Run("env="+val, func(t *testing.T) {
			t.Setenv("COMPLIANCE_RECONCILE_WORKER_ENABLED", val)
			if got := ReconcileWorkerEnabled(); got != want {
				t.Fatalf("ReconcileWorkerEnabled() with %q = %v, want %v", val, got, want)
			}
		})
	}
}

// A nil enqueuer and one without a NATS client must both be safe no-ops — the wiring
// is optional (NATS may be down, or the worker disabled), and callers invoke these on
// the hot path of activate/publish without guarding.
func TestReconcileEnqueuerNilSafe(t *testing.T) {
	t.Setenv("COMPLIANCE_RECONCILE_WORKER_ENABLED", "true")

	var nilEnq *ReconcileEnqueuer
	nilEnq.EnqueueTenant(uuid.New(), "x")                   // must not panic
	nilEnq.EnqueueAllTenants("x")                           // must not panic
	nilEnq.EnqueueTenantScoped(uuid.New(), uuid.New(), "x") // must not panic
	nilEnq.EnqueueAllTenantsScoped(uuid.New(), "x")         // must not panic

	noClient := NewReconcileEnqueuer(nil, nil)
	if noClient.ready() {
		t.Fatal("enqueuer with nil client should not be ready")
	}
	if noClient.Ready() {
		t.Fatal("public Ready() should match readiness for callers that must fail closed")
	}
	noClient.EnqueueTenant(uuid.New(), "x") // must not panic, must not touch db
	noClient.EnqueueAllTenants("x")
	noClient.EnqueueTenantScoped(uuid.New(), uuid.New(), "x")
	noClient.EnqueueAllTenantsScoped(uuid.New(), "x")
}

func TestReconcileJobRoundTrip(t *testing.T) {
	in := ReconcileJob{TenantID: uuid.New().String(), Reason: "framework_activated"}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Wire format must be snake_case (the consumer json.Unmarshals raw msg.Data).
	if got := string(b); got == "" || !json.Valid(b) {
		t.Fatalf("bad json: %q", got)
	}
	// An unscoped job must omit framework_id (omitempty), so the wire shape — and the
	// consumer's job.FrameworkID != "" scope check — stays unambiguous.
	if got := string(b); strings.Contains(got, "framework_id") {
		t.Fatalf("unscoped job must omit framework_id, got %q", got)
	}
	var out ReconcileJob
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out != in {
		t.Fatalf("round-trip mismatch: %+v != %+v", out, in)
	}
}

// A scoped job carries framework_id on the wire and round-trips it, so the consumer
// ( control-scoped fan-out) routes to EvaluateTenantFrameworkScoped.
func TestReconcileJobScopedRoundTrip(t *testing.T) {
	in := ReconcileJob{
		TenantID:    uuid.New().String(),
		FrameworkID: uuid.New().String(),
		Reason:      "framework_published",
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got := string(b); !strings.Contains(got, "framework_id") {
		t.Fatalf("scoped job must include framework_id, got %q", got)
	}
	var out ReconcileJob
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out != in {
		t.Fatalf("round-trip mismatch: %+v != %+v", out, in)
	}
}
