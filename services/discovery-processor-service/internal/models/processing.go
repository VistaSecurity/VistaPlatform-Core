package models

import (
	"time"

	"github.com/google/uuid"
)

// SensorDiscovery represents a row from sensor_discoveries table
type SensorDiscovery struct {
	ID                 uuid.UUID  `db:"id"`
	SensorID           uuid.UUID  `db:"sensor_id"`
	TenantID           uuid.UUID  `db:"tenant_id"`
	BatchID            string     `db:"batch_id"`
	Protocol           string     `db:"protocol"`
	DestIP             string     `db:"dest_ip"`
	Port               int        `db:"port"`
	Confidence         float64    `db:"confidence"`
	Metadata           []byte     `db:"metadata"` // JSONB stored as []byte
	Timestamp          time.Time  `db:"timestamp"`
	CreatedAt          time.Time  `db:"created_at"`
	ProcessedAt        *time.Time `db:"processed_at"`
	ApprovalStatus     string     `db:"approval_status"`
	AutoApprovalRuleID *uuid.UUID `db:"auto_approval_rule_id"`
	AssetID            *uuid.UUID `db:"asset_id"`
	Hostname           *string    `db:"hostname"`
	SourceIP           *string    `db:"source_ip"` // optional; for external connection visibility
}

// ProcessingStatus represents the status of a batch processing operation
type ProcessingStatus struct {
	BatchID        string
	Status         string // "processing", "completed", "failed"
	ProcessedCount int
	FailedCount    int
	Error          string
	StartedAt      time.Time
	CompletedAt    *time.Time
}

// AutoApprovalRule represents a rule for auto-approving discoveries
type AutoApprovalRule struct {
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

// NetworkClassification represents the network space/segment classification result.
//
// Ownership has three values:
//   - "internal"    — IP belongs to a known tenant network segment
//   - "third_party" — IP is a public internet address outside any registered segment
//   - "unknown"     — IP is RFC 1918 private but not in any registered segment
//     (may be an unregistered internal subnet)
//
// Only "third_party" discoveries are routed to the external connections path.
// "unknown" private addresses still go through the managed asset pipeline.
type NetworkClassification struct {
	Ownership   string     // "internal", "third_party", "unknown"
	Type        string     // "private", "public"
	SpaceID     *uuid.UUID // legacy
	SpaceName   *string    // legacy
	SegmentID   *uuid.UUID
	SegmentName *string
}
