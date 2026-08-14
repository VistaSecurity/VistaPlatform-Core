package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/approval"
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

// AutoApprovalRule is the shared auto-approval rule type. The rule model and
// its evaluation moved to shared/approval so every ingestion path evaluates one
// implementation; the alias keeps this package's existing name usable.
type AutoApprovalRule = approval.Rule

// NetworkClassification is the shared classification type (see
// shared/approval.Classification for the meaning of each Ownership value).
type NetworkClassification = approval.Classification

// ApprovalInput projects the fields the shared auto-approval evaluator reads.
func (d *SensorDiscovery) ApprovalInput() approval.Discovery {
	return approval.Discovery{
		TenantID:   d.TenantID,
		Confidence: d.Confidence,
		Metadata:   d.Metadata,
	}
}
