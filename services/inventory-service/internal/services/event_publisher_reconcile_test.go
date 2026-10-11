package services

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// The body is compliance-engine's ReconcileJob: tenant_id + reason, nothing
// the worker would refuse.
func TestPublishComplianceReconcile_Shape(t *testing.T) {
	var got []byte
	p := &EventPublisherService{reconcile: func(j ComplianceReconcileJob) error {
		got, _ = json.Marshal(j)
		return nil
	}}
	tenant := uuid.MustParse("6f1c1d3e-0000-4000-8000-000000000001")
	if err := p.PublishComplianceReconcile(context.Background(), tenant, "certificate_trust_changed"); err != nil {
		t.Fatal(err)
	}
	want := `{"tenant_id":"6f1c1d3e-0000-4000-8000-000000000001","reason":"certificate_trust_changed"}`
	if string(got) != want {
		t.Errorf("body %s, want %s", got, want)
	}
	var nilPub *EventPublisherService
	if err := nilPub.PublishComplianceReconcile(context.Background(), tenant, "x"); err != nil {
		t.Errorf("a nil publisher must be a no-op: %v", err)
	}
}
