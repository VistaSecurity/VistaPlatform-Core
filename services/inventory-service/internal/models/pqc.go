package models

// PQCProgress represents quantum-readiness across crypto implementations
type PQCProgress struct {
	TotalImplementations int `json:"total_implementations"`
	PQCReady             int `json:"pqc_ready"`
	SymmetricSafe        int `json:"symmetric_safe"`
	// NonPQC is the count needing migration: at least one classical asymmetric
	// component (NIST IR 8547 — RSA/ECDSA/EdDSA/DH/ECDH, disallowed after 2035).
	NonPQC int `json:"non_pqc"`
	// Unclassified is implementations we could not judge — no component
	// algorithms resolved against the catalogue, or a component whose primitive
	// is unknown. Surfaced rather than folded into a safe/unsafe bucket: it is a
	// data-quality signal, and silently counting it either way would misstate
	// readiness.
	Unclassified  int              `json:"unclassified"`
	PQCPercentage float64          `json:"pqc_percentage"`
	ByFamily      []PQCFamilyStats `json:"by_family"`
}

// PQCFamilyStats represents per-algorithm-family quantum readiness
type PQCFamilyStats struct {
	Family      string `json:"family"`
	Count       int    `json:"count"`
	IsPQC       bool   `json:"is_pqc"`
	QuantumSafe bool   `json:"quantum_safe"`
	MigrateTo   string `json:"migrate_to,omitempty"`
}
