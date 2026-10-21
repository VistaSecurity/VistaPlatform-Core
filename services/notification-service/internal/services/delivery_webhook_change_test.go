package services

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
)

// An object_changed webhook carries the change at the top level of the body,
// as JSON values (an array, an object), not stringified and not only inside
// metadata. Mutation: delete liftChangeFields(payload, req) → every assertion
// on a top-level field fails.
func TestWebhook_ObjectChangedCarriesTheChangeAtTopLevel(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec.handler(200))
	defer srv.Close()
	ds := newTestDeliveryService()

	req := &models.SendNotificationRequest{
		AlertSource: "inventory-service", AlertType: "object_changed", Severity: "info",
		Title: "Cable updated: CBL-1", Message: "a.person@example.com updated cable CBL-1 (status)",
		EventID: "4f8a4c5e-0000-4000-8000-000000000001",
		Metadata: map[string]interface{}{
			"object_kind": "cable", "object_id": "00000000-0000-4000-8000-0000000000c1", "action": "update",
			"actor":          map[string]interface{}{"user_id": "00000000-0000-4000-8000-0000000000a1", "user_name": "a.person@example.com"},
			"source":         "ui",
			"request_id":     "00000000-0000-4000-8000-0000000000b1",
			"changed_fields": []string{"status", "label"},
			"object_label":   "CBL-1",
			"link":           nil,
			// A field an envelope key shares must not overwrite the envelope.
			"event_id": "not-the-event-id",
		},
	}
	if err := ds.sendWebhook(map[string]interface{}{"url": srv.URL}, req); err != nil {
		t.Fatalf("sendWebhook: %v", err)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.all()[0].body, &body); err != nil {
		t.Fatal(err)
	}
	if body["object_kind"] != "cable" || body["action"] != "update" || body["object_label"] != "CBL-1" || body["source"] != "ui" {
		t.Fatalf("top-level change fields missing: %s", rec.all()[0].body)
	}
	fields, ok := body["changed_fields"].([]interface{})
	if !ok || len(fields) != 2 || fields[0] != "status" {
		t.Fatalf("changed_fields = %#v, want a JSON array", body["changed_fields"])
	}
	if actor, ok := body["actor"].(map[string]interface{}); !ok || actor["user_name"] != "a.person@example.com" {
		t.Fatalf("actor = %#v, want a JSON object", body["actor"])
	}
	if v, present := body["link"]; !present || v != nil {
		t.Fatalf("link = %#v (present=%v), want an explicit null for an object with no page", v, present)
	}
	if body["event_id"] != "4f8a4c5e-0000-4000-8000-000000000001" {
		t.Fatalf("event_id = %v — metadata overwrote the envelope", body["event_id"])
	}
}

// Every other alert type keeps the old body: nothing is lifted.
func TestWebhook_OtherAlertTypesAreNotLifted(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec.handler(200))
	defer srv.Close()
	req := testRequest()
	req.Metadata = map[string]interface{}{"object_kind": "cable"}
	if err := newTestDeliveryService().sendWebhook(map[string]interface{}{"url": srv.URL}, req); err != nil {
		t.Fatal(err)
	}
	var body map[string]interface{}
	_ = json.Unmarshal(rec.all()[0].body, &body)
	if _, lifted := body["object_kind"]; lifted {
		t.Fatalf("a %s webhook was given top-level change fields: %s", req.AlertType, rec.all()[0].body)
	}
}
