package events

import (
	"time"

	"github.com/google/uuid"
)

// Lifecycle event type constants for discovery/ingest flow.
const (
	EventTypeAssetDiscovered          = "asset.discovered"
	EventTypeAssetEnriched            = "asset.enriched"
	EventTypeAssetRiskChanged         = "asset.risk_changed"
	EventTypeCryptoConfigurationAdded = "crypto.configuration_added"
	EventTypeCertificateExpiring      = "certificate.expiring"
)

// Envelope is the standard event envelope (event_type, tenant_id, timestamp, payload).
type Envelope struct {
	EventID   uuid.UUID   `json:"event_id"`
	EventType string      `json:"event_type"`
	TenantID  uuid.UUID   `json:"tenant_id"`
	Timestamp time.Time   `json:"timestamp"`
	Source    string      `json:"source,omitempty"`
	Payload   interface{} `json:"payload"`
}

// AssetDiscoveredPayload is the payload for asset.discovered (new asset created from discovery).
type AssetDiscoveredPayload struct {
	AssetID   uuid.UUID `json:"asset_id"`
	Hostname  *string   `json:"hostname,omitempty"`
	IPAddress *string   `json:"ip_address,omitempty"`
	Port      *int      `json:"port,omitempty"`
	Source    string    `json:"source"`
}

// AssetEnrichedPayload is the payload for asset.enriched (location/segment/service set or updated).
type AssetEnrichedPayload struct {
	AssetID          uuid.UUID  `json:"asset_id"`
	LocationID       *uuid.UUID `json:"location_id,omitempty"`
	SegmentID        *uuid.UUID `json:"segment_id,omitempty"`
	Environment      *string    `json:"environment,omitempty"`
	ServiceName      *string    `json:"service_name,omitempty"`
	EnrichmentSource string     `json:"enrichment_source,omitempty"` // "segment", "service_id", "cloud"
}

// AssetRiskChangedPayload is the payload for asset.risk_changed.
type AssetRiskChangedPayload struct {
	AssetID      uuid.UUID `json:"asset_id"`
	RiskLevel    string    `json:"risk_level"`
	RiskScore    int       `json:"risk_score"`
	ChangeSource string    `json:"change_source,omitempty"`
}

// CryptoConfigurationAddedPayload is the payload for crypto.configuration_added.
type CryptoConfigurationAddedPayload struct {
	AssetID                uuid.UUID `json:"asset_id"`
	CryptoImplementationID uuid.UUID `json:"crypto_implementation_id"`
	Protocol               string    `json:"protocol"`
	ProtocolVersion        *string   `json:"protocol_version,omitempty"`
	RiskScore              int       `json:"risk_score"`
}

// CertificateExpiringPayload is the payload for certificate.expiring (within 30 days).
type CertificateExpiringPayload struct {
	CertificateID uuid.UUID `json:"certificate_id"`
	AssetID       uuid.UUID `json:"asset_id"`
	CommonName    *string   `json:"common_name,omitempty"`
	NotAfter      time.Time `json:"not_after"`
	DaysRemaining int       `json:"days_remaining"`
}
