package models

// ServiceHints holds identified service name/version and confidence from banner, JA3S, or port heuristic.
type ServiceHints struct {
	ServiceName          string `json:"service_name"`
	ServiceVersion       string `json:"service_version,omitempty"`
	Confidence           string `json:"confidence"`            // high, medium, low
	IdentificationMethod string `json:"identification_method"` // banner, ja3s, port_heuristic, http_header, manual
	RawBanner            string `json:"raw_banner,omitempty"`
	JA3SFingerprint      string `json:"ja3s_fingerprint,omitempty"`
}

// UpdateAssetServiceInput is the body for PUT infrastructure-assets/:id/service (manual override).
type UpdateAssetServiceInput struct {
	ServiceName    string `json:"service_name" binding:"required"`
	ServiceVersion string `json:"service_version"`
}
