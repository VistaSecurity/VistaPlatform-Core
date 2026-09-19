package identity

// IngestResult is an index-aligned acknowledgement of committed ingestion.
// Unresolved and conflict are successful evidence outcomes without an asset.
// Omitted IDs mean absent; callers must never substitute a zero UUID.
type IngestResult struct {
	Outcome       string `json:"outcome"`
	AssetID       string `json:"asset_id,omitempty"`
	ObservationID string `json:"observation_id,omitempty"`
	ProposalID    string `json:"proposal_id,omitempty"`
}

func (r Resolution) IngestResult() IngestResult {
	return IngestResult{Outcome: string(r.Outcome), AssetID: r.Asset.ID, ObservationID: r.ObservationID, ProposalID: r.Proposal.ID}
}

// RetainedObservation reports successful durable ingestion to legacy APIs whose
// return type requires an asset. Transports must acknowledge it as accepted,
// not as a failed request or a synthetic asset.
type RetainedObservation struct{ Result IngestResult }

func (r *RetainedObservation) Error() string { return "evidence retained for identity resolution" }
