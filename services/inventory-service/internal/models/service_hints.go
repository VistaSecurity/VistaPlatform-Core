package models

import "github.com/google/uuid"

// ServiceHints holds identified service name/version and confidence from banner, JA3S, or port heuristic.
type ServiceHints struct {
	ServiceName          string `json:"service_name"`
	ServiceVersion       string `json:"service_version,omitempty"`
	Confidence           string `json:"confidence"`            // high, medium, low
	IdentificationMethod string `json:"identification_method"` // banner, ja3s, port_heuristic, http_header, manual
	RawBanner            string `json:"raw_banner,omitempty"`
	JA3SFingerprint      string `json:"ja3s_fingerprint,omitempty"`
}

// UpdateAssetServiceInput is the body for a manual service override.
//
// The identified service lives on the ENDPOINT (ADR-0002 D1): a host running
// SSH on 22 and HTTPS on 443 has two endpoints, and "the" service of the host is
// not a thing. EndpointID names which one is being corrected.
//
// It is optional only on the legacy asset-scoped route, where it defaults to the
// asset's PRIMARY endpoint — the one a list row displays — so a correction typed
// against what the user is looking at lands where they are looking. An asset
// with no endpoints has nothing to correct and answers 404.
type UpdateAssetServiceInput struct {
	EndpointID     *uuid.UUID `json:"endpoint_id,omitempty"`
	ServiceName    string     `json:"service_name" binding:"required"`
	ServiceVersion string     `json:"service_version"`
}
