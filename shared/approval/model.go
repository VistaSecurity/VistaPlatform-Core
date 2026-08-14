// Package approval evaluates a tenant's segment auto-approval rules.
//
// Auto-approval has exactly one gate: the discovered asset is on a user-defined
// network segment with auto-approve enabled. The rules in
// discovery_auto_approval_rules are generated from those segments by
// inventory-service's ManageAutoApprovalRules; this package only reads and
// evaluates them.
//
// It lives in shared/ because every ingestion path — the discovery pipeline,
// manual asset create, CMDB pull — must reach the same decision. Two
// implementations of an authorization rule is the failure this placement exists
// to prevent.
package approval

import (
	"time"

	"github.com/google/uuid"
)

// Rule represents a row of discovery_auto_approval_rules: a tenant-owned rule
// for auto-approving discoveries.
type Rule struct {
	ID          uuid.UUID              `db:"id"`
	TenantID    uuid.UUID              `db:"tenant_id"`
	Name        string                 `db:"name"`
	Description string                 `db:"description"`
	Conditions  map[string]interface{} `db:"conditions"` // JSONB
	IsActive    bool                   `db:"is_active"`
	CreatedBy   uuid.UUID              `db:"created_by"`
	CreatedAt   time.Time              `db:"created_at"`
	UpdatedAt   time.Time              `db:"updated_at"`
}

// Classification represents the network space/segment classification result.
//
// Ownership has three values:
//   - "internal"    — IP belongs to a known tenant network segment
//   - "third_party" — IP is a public internet address outside any registered segment
//   - "unknown"     — IP is RFC 1918 private but not in any registered segment
//     (may be an unregistered internal subnet)
//
// Only "third_party" discoveries are routed to the external connections path.
// "unknown" private addresses still go through the managed asset pipeline.
type Classification struct {
	Ownership   string     // "internal", "third_party", "unknown"
	Type        string     // "private", "public"
	SpaceID     *uuid.UUID // legacy
	SpaceName   *string    // legacy
	SegmentID   *uuid.UUID
	SegmentName *string
}

// Discovery is the projection of a discovered thing that rule evaluation reads.
//
// Deliberately narrow: the evaluator needs the owning tenant, the discovery's
// confidence, and its raw metadata envelope (to tell a cloud discovery from a
// sensor one). Callers hold richer records — sensor_discoveries rows, asset
// create inputs — and project onto this rather than the shared package taking a
// dependency on any one caller's model.
type Discovery struct {
	TenantID   uuid.UUID
	Confidence float64
	Metadata   []byte // JSONB envelope as stored
}
