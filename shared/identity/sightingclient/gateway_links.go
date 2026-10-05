package sightingclient

// The gateway-links route (slice B): after an interrogation has posted
// the device's claimed gateway addresses as sightings, it tells
// inventory-service the run's COMPLETE list, and inventory-service links the
// device as the gateway of every segment where it now holds one of them —
// and unlinks it from every segment where it no longer does
// (shared/identity/postgres ReconcileGatewayLinks). Same gate as the sightings
// route: HMAC-only with a signed X-Tenant-ID, denied at the edge.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// GatewayLinksPath is inventory-service's internal gateway-links route.
const GatewayLinksPath = "/api/v1/inventory-service/internal/gateway-links"

// GatewayLinksRequest is one run's statement about one device.
type GatewayLinksRequest struct {
	// AssetID is the interrogated device.
	AssetID string `json:"asset_id"`
	// SourceRef is the run (`interrogation:<job>`), recorded as the link's
	// provenance.
	SourceRef string `json:"source_ref"`
	// ObservedAt is when the run observed the networks; the most recent
	// observation wins a network two devices both claim.
	ObservedAt time.Time `json:"observed_at"`
	// Addresses is EVERY gateway address the run reported, contested or not.
	// The route links only what the device holds, and clears the device's link
	// on any segment the list no longer reaches, so an empty list unlinks the
	// device everywhere.
	Addresses []string `json:"addresses"`
}

// GatewaySegment is one segment in a [GatewayLinksResult].
type GatewaySegment struct {
	SegmentID string `json:"segment_id"`
	Address   string `json:"address"`
}

// GatewayLinksResult is what the route did.
type GatewayLinksResult struct {
	Linked     []GatewaySegment `json:"linked"`
	Candidates []GatewaySegment `json:"candidates"`
	Cleared    []string         `json:"cleared"`
}

// GatewayLinker reconciles a device's gateway links. *Client implements it.
type GatewayLinker interface {
	ReconcileGatewayLinks(ctx context.Context, tenantID string, req GatewayLinksRequest) (GatewayLinksResult, error)
}

var _ GatewayLinker = (*Client)(nil)

// ReconcileGatewayLinks posts one run's gateway addresses for one device.
func (c *Client) ReconcileGatewayLinks(ctx context.Context, tenantID string, req GatewayLinksRequest) (GatewayLinksResult, error) {
	if strings.TrimSpace(tenantID) == "" {
		return GatewayLinksResult{}, errors.New("sightingclient: a tenant is required")
	}
	if strings.TrimSpace(req.AssetID) == "" {
		return GatewayLinksResult{}, errors.New("sightingclient: gateway links need the device's asset id")
	}
	if req.Addresses == nil {
		req.Addresses = []string{}
	}
	body, err := json.Marshal(req)
	if err != nil {
		return GatewayLinksResult{}, fmt.Errorf("sightingclient: encode: %w", err)
	}
	var out GatewayLinksResult
	err = c.withRetry(ctx, func() (bool, error) {
		raw, retry, err := c.once(ctx, tenantID, GatewayLinksPath, body)
		if err != nil {
			return retry, err
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			return false, fmt.Errorf("sightingclient: decode gateway links: %w", err)
		}
		return false, nil
	})
	return out, err
}
