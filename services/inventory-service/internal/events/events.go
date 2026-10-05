package events

import (
	"time"

	"github.com/google/uuid"
)

// Lifecycle event type constants for discovery/ingest flow.
const (
	EventTypeAssetDiscovered  = "asset.discovered"
	EventTypeAssetEnriched    = "asset.enriched"
	EventTypeAssetRiskChanged = "asset.risk_changed"
	EventTypeAssetMerged      = "asset.merged"
	// The three lifecycle DECISIONS. A merge and a discovery were published;
	// the three acts a human actually performs in Approvals were not, so a
	// downstream cache learned that an asset had appeared and never that it had
	// been accepted, refused or retired.
	EventTypeAssetApproved            = "asset.approved"
	EventTypeAssetDenied              = "asset.denied"
	EventTypeAssetArchived            = "asset.archived"
	EventTypeCryptoConfigurationAdded = "crypto.configuration_added"
	EventTypeCertificateExpiring      = "certificate.expiring"
	// EventTypeAssetIdentityDrift — the identification engine matched an
	// observation to an asset whose identifying material changed, and decided
	// what the change was (owner Decision 4 of): a rotated SSH host
	// key, a moved address, a reimage, or an unverified key change flagged for
	// review. A notification, never a compliance finding.
	EventTypeAssetIdentityDrift = "asset.identity_drift"
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
//
// AssetID is the HOST, never an endpoint, and ClassKey says what kind of thing
// it is — see shared/events for why both matter to a subscriber.
type AssetDiscoveredPayload struct {
	AssetID   uuid.UUID `json:"asset_id"`
	ClassKey  string    `json:"class_key,omitempty"`
	Hostname  *string   `json:"hostname,omitempty"`
	IPAddress *string   `json:"ip_address,omitempty"`
	Port      *int      `json:"port,omitempty"`
	Source    string    `json:"source"`
}

// AssetEnrichedPayload is the payload for asset.enriched (location/segment/service set or updated).
type AssetEnrichedPayload struct {
	AssetID          uuid.UUID  `json:"asset_id"`
	ClassKey         string     `json:"class_key,omitempty"`
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

// AssetMergedPayload is the payload for asset.merged: one asset id stopped
// being the answer for a thing, and this is what to point at instead.
type AssetMergedPayload struct {
	SurvivorAssetID uuid.UUID `json:"survivor_asset_id"`
	MergedAssetID   uuid.UUID `json:"merged_asset_id"`
	ClassKey        string    `json:"class_key,omitempty"`
	ProposalID      uuid.UUID `json:"proposal_id"`
	DecidedBy       string    `json:"decided_by,omitempty"`
}

// AssetLifecyclePayload is the payload for asset.approved / asset.denied /
// asset.archived: a person decided something about assets that are already in
// the inventory.
//
// It names the assets and WHO decided. DecidedBy is empty when no session was
// attached — empty is "no person was involved", not "the system".
type AssetLifecyclePayload struct {
	AssetIDs  []uuid.UUID `json:"asset_ids"`
	Status    string      `json:"status"`
	DecidedBy string      `json:"decided_by,omitempty"`
}

// CryptoConfigurationAddedPayload is the payload for crypto.configuration_added.
type CryptoConfigurationAddedPayload struct {
	AssetID                uuid.UUID `json:"asset_id"`
	CryptoImplementationID uuid.UUID `json:"crypto_implementation_id"`
	Protocol               string    `json:"protocol"`
	ProtocolVersion        *string   `json:"protocol_version,omitempty"`
	// RiskScore is the configuration's stored score; null when it is
	// unassessed (risk_score NULL), which a consumer decoding into an int
	// reads as 0, exactly as before for an unscored configuration.
	RiskScore *int `json:"risk_score"`
}

// CertificateExpiringPayload is the payload for certificate.expiring (within 30 days).
type CertificateExpiringPayload struct {
	CertificateID uuid.UUID `json:"certificate_id"`
	AssetID       uuid.UUID `json:"asset_id"`
	CommonName    *string   `json:"common_name,omitempty"`
	NotAfter      time.Time `json:"not_after"`
	DaysRemaining int       `json:"days_remaining"`
}

// IdentityMaterialChange is one kind of identifying material that changed in
// an asset.identity_drift event: the values the asset held before and the ones
// it was seen with now. For an SSH host key these are fingerprints — public
// identities, never key material.
type IdentityMaterialChange struct {
	Kind     string   `json:"kind"`
	Previous []string `json:"previous,omitempty"`
	Current  []string `json:"current,omitempty"`
	Retired  bool     `json:"retired,omitempty"`
}

// AssetIdentityDriftPayload is the payload for asset.identity_drift.
type AssetIdentityDriftPayload struct {
	AssetID uuid.UUID `json:"asset_id"`
	// AssetName is what the timeline and a notification call the asset.
	AssetName string `json:"asset_name,omitempty"`
	// Verdict is rotated, moved, reimaged or unverified.
	Verdict string `json:"verdict"`
	// Rule is the drift-table row that decided; Explanation the sentence a
	// reviewer reads, with no identifier values in it.
	Rule        string                   `json:"rule"`
	Explanation string                   `json:"explanation"`
	NeedsReview bool                     `json:"needs_review,omitempty"`
	Changes     []IdentityMaterialChange `json:"changes,omitempty"`
}
