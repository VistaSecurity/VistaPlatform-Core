package identity

// IngestResult is an index-aligned acknowledgement of committed ingestion.
// Unresolved and conflict are successful evidence outcomes without an asset.
// Omitted IDs mean absent; callers must never substitute a zero UUID.
// EvidenceHeld is [Resolution.EvidenceHeld]: linked to AssetID, but nothing
// written there, so the caller must not treat the run as materialized.
type IngestResult struct {
	Outcome       string `json:"outcome"`
	AssetID       string `json:"asset_id,omitempty"`
	ObservationID string `json:"observation_id,omitempty"`
	ProposalID    string `json:"proposal_id,omitempty"`
	EvidenceHeld  bool   `json:"evidence_held,omitempty"`
	// Reason says why a finding was "dropped": inventory-service settled it
	// without recording it anywhere, for a property of the finding itself
	// (a third-party connection with no source address, D2). Empty for
	// every other outcome.
	Reason string `json:"reason,omitempty"`
	// AutoApprovalRuleID is the tenant auto-approval rule that decided the
	// status a NEW asset for this finding lands as, when one matched.
	// inventory-service evaluates the rules on the discovery-import path
	// ( WP3), so this is how discovery-processor learns which rule to
	// credit on the discovery row. Empty when no rule matched.
	AutoApprovalRuleID string `json:"auto_approval_rule_id,omitempty"`
	// EndpointsClosed is [Resolution.EndpointsClosed]: how many of the
	// asset's endpoints a complete set closed.
	EndpointsClosed int `json:"endpoints_closed,omitempty"`
}

func (r Resolution) IngestResult() IngestResult {
	return IngestResult{Outcome: string(r.Outcome), AssetID: r.Asset.ID, ObservationID: r.ObservationID, ProposalID: r.Proposal.ID, EvidenceHeld: r.EvidenceHeld, EndpointsClosed: r.EndpointsClosed}
}

// RetainedObservation reports successful durable ingestion to legacy APIs whose
// return type requires an asset. Transports must acknowledge it as accepted,
// not as a failed request or a synthetic asset.
type RetainedObservation struct{ Result IngestResult }

func (r *RetainedObservation) Error() string { return "evidence retained for identity resolution" }
