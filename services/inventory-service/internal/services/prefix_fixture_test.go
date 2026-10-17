package services

import (
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// declarePrefix declares a prefix through the IPAM service — the path
// Inventory → Networks takes, so the prefix's AfterWrite (utilisation, the
// generated auto-approval rule) runs as it does in production. body is the
// API body (`prefix` required).
func declarePrefix(t *testing.T, db *sql.DB, tenant uuid.UUID, body map[string]any) uuid.UUID {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	out, err := NewIPAMService(db).Create(ipamTestCtx(), tenant, "prefixes", raw)
	if err != nil {
		t.Fatalf("declare prefix %v: %v", body["prefix"], err)
	}
	var row struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(out, &row); err != nil {
		t.Fatal(err)
	}
	return row.ID
}
