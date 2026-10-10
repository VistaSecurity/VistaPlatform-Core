// Package sightingclient posts identity.Sightings to inventory-service, the one
// service that hosts the identity engine (platform ADR-0003 D3).
//
// A collector outside inventory-service states what it saw as a Sighting and
// sends it here; inventory-service runs identity.Intake and the engine, in one
// transaction, and answers with what the engine decided. The collector then
// does what only it can do with the answer — write the facts, sockets,
// management row or class proposal that ride on the asset — through the
// asset id in the result. It never resolves anything itself.
//
// The route is HMAC-only (shared/serviceauth) with a SIGNED X-Tenant-ID, and
// denied at the edge, the same shape as inventory-service's
// /internal/sources/* (platform ADR-0002). Under serviceMtls the peer URL is
// https://inventory-service:8443 and the http.Client handed to [New] must
// present this service's client certificate (sharedhttp.NewMTLSClient).
package sightingclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// Path is inventory-service's internal sightings route.
const Path = "/api/v1/inventory-service/internal/sightings"

// TestRouteEnv names a running inventory-service base URL that a collector's
// tests post to instead of the reference route
// (shared/identity/identitytest/sightingserver): the end-to-end run against
// the real resolution. Read only by test setup.
const TestRouteEnv = "SIGHTINGS_TEST_INVENTORY_URL"

// Request is the route's body.
type Request struct {
	Sightings []Item `json:"sightings"`
}

// Item is one sighting in a request: the sighting's own fields, flattened,
// and an optional target.
//
// TargetAssetID names the asset a DECLARED (or imported) sighting is about —
// an operator editing that device. The route then attaches its identifiers to
// that asset through Engine.ResolveDeclaredFor (the identifier edit's path:
// the same locks and ownership re-check, a conflict that writes nothing and
// opens a merge proposal) instead of asking the engine which asset it is.
// Empty is an ordinary sighting.
type Item struct {
	identity.Sighting
	TargetAssetID string `json:"target_asset_id,omitempty"`
}

// The outcome and reasons of a declaration for a named asset that the engine
// refused. Outcome is identity.OutcomeConflict, AssetID the named asset, and
// ProposalID the merge proposal opened against the other owner (none for a
// singleton disagreement on the asset itself).
const (
	ReasonDeclaredIdentifierConflict = "declared_identifier_conflict"
	ReasonDeclaredSingletonConflict  = "declared_singleton_conflict"
	// ReasonUnknownTarget rejects a target that is not a live asset of the
	// signed tenant.
	ReasonUnknownTarget = "unknown_target"
)

// Result is what the engine decided about one sighting, in request order.
//
// It is [identity.IngestResult] plus the admission decision's reasons: enough
// for a caller to tell a match from a create, a held observation (no asset,
// an observation id) from a contested one (no asset, a proposal id), and to
// say why.
type Result struct {
	Outcome       identity.Outcome `json:"outcome"`
	AssetID       string           `json:"asset_id,omitempty"`
	ObservationID string           `json:"observation_id,omitempty"`
	ProposalID    string           `json:"proposal_id,omitempty"`
	EvidenceHeld  bool             `json:"evidence_held,omitempty"`
	// EndpointsClosed is how many of the asset's endpoints the engine closed
	// because a complete set ([identity.Sighting.EndpointsComplete]) no
	// longer listed them, inside its own transaction.
	EndpointsClosed int      `json:"endpoints_closed,omitempty"`
	Reasons         []string `json:"reasons,omitempty"`
}

// OutcomeRejected is the outcome of a sighting inventory-service refused
// without reaching the engine (another tenant's, unreadable, nothing usable,
// or an asset the tenant denied); Reasons says which (Reason* below).
const OutcomeRejected identity.Outcome = "rejected"

// The reasons a rejected result carries.
const (
	ReasonTenantMismatch     = "tenant_mismatch"
	ReasonInvalid            = "invalid_sighting"
	ReasonNoUsableIdentifier = "no_usable_identifier"
	ReasonAssetDenied        = "asset_denied"
)

// Rejected reports whether inventory-service refused this sighting.
func (r Result) Rejected() bool { return r.Outcome == OutcomeRejected }

// Response is the route's answer.
type Response struct {
	Results []Result `json:"results"`
}

// Resolution renders the result as the engine's own type, for code written
// against identity.Resolution. Only the fields the route carries are set.
func (r Result) Resolution(tenantID string) identity.Resolution {
	res := identity.Resolution{
		Outcome:       r.Outcome,
		ObservationID: r.ObservationID,
		EvidenceHeld:  r.EvidenceHeld,
		// Carried so a caller reports what the engine closed for it.
		EndpointsClosed: r.EndpointsClosed,
	}
	if r.ProposalID != "" {
		res.Proposal = identity.ProposalRef{TenantID: tenantID, ID: r.ProposalID}
	}
	if len(r.Reasons) > 0 {
		res.AdmissionReason = r.Reasons[0]
	}
	if r.AssetID != "" {
		res.Asset = identity.AssetRef{TenantID: tenantID, ID: r.AssetID}
	}
	return res
}

// Poster is what a collector needs: post sightings, get results. *Client
// implements it; tests substitute their own.
type Poster interface {
	PostItems(ctx context.Context, tenantID string, items []Item) ([]Result, error)
}

// RejectedError is a 4xx: inventory-service read the request and refused it.
// Retrying the same body cannot succeed, so it is not retried.
type RejectedError struct {
	Status int
	Body   string
}

func (e *RejectedError) Error() string {
	return fmt.Sprintf("inventory-service refused the sightings (%d): %s", e.Status, e.Body)
}

// ErrUnavailable wraps a failure that outlived every retry: a 5xx, or a
// transport error. The caller's own retry (the agent's next report, the next
// interrogation, the retained-context worker) is the recovery.
var ErrUnavailable = errors.New("inventory-service sightings route unavailable")

// Client posts sightings over HTTP.
type Client struct {
	baseURL  string
	http     *http.Client
	sign     func(*http.Request)
	attempts int
	backoff  time.Duration
	sleep    func(context.Context, time.Duration) error
	logf     func(string, ...any)
}

// Option configures [New].
type Option func(*Client)

// WithRetry sets how many attempts a 5xx or transport failure gets in all
// (minimum 1) and the first backoff, doubled after each failure.
func WithRetry(attempts int, backoff time.Duration) Option {
	return func(c *Client) {
		if attempts < 1 {
			attempts = 1
		}
		c.attempts, c.backoff = attempts, backoff
	}
}

// WithSigner replaces the request signer (default
// serviceauth.SignRequestFromEnv, the INTERNAL_AUTH_SECRET HMAC). The tenant
// header is set before the signer runs, so it is covered by the signature.
func WithSigner(sign func(*http.Request)) Option { return func(c *Client) { c.sign = sign } }

// WithLogger replaces log.Printf for the 4xx log line.
func WithLogger(logf func(string, ...any)) Option { return func(c *Client) { c.logf = logf } }

// DefaultTimeout bounds one attempt. A resolution is one transaction in
// inventory-service; a batch of a few hundred peers fits comfortably.
const DefaultTimeout = 30 * time.Second

// New builds a client for baseURL (inventory-service's peer URL, from
// sharedconfig.PeerServiceURLAuto). httpClient is nil for plaintext or the
// mTLS client under serviceMtls; its Timeout is set to [DefaultTimeout] when
// it has none.
func New(baseURL string, httpClient *http.Client, opts ...Option) *Client {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	if httpClient.Timeout == 0 {
		httpClient.Timeout = DefaultTimeout
	}
	c := &Client{
		baseURL:  strings.TrimRight(baseURL, "/"),
		http:     httpClient,
		sign:     serviceauth.SignRequestFromEnv,
		attempts: 4,
		backoff:  250 * time.Millisecond,
		sleep:    sleepCtx,
		logf:     log.Printf,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// maxResponse bounds the body read; results are small.
const maxResponse = 4 << 20

// Post sends sightings for one tenant and returns one result per sighting, in
// order. Every sighting must carry tenantID.
func (c *Client) Post(ctx context.Context, tenantID string, sightings []identity.Sighting) ([]Result, error) {
	items := make([]Item, len(sightings))
	for i, s := range sightings {
		items[i] = Item{Sighting: s}
	}
	return c.PostItems(ctx, tenantID, items)
}

// PostItems is Post with per-item targets.
func (c *Client) PostItems(ctx context.Context, tenantID string, items []Item) ([]Result, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, errors.New("sightingclient: a tenant is required")
	}
	if len(items) == 0 {
		return nil, nil
	}
	for i, s := range items {
		if s.TenantID != tenantID {
			return nil, fmt.Errorf("sightingclient: sighting %d is for tenant %q, not %q", i, s.TenantID, tenantID)
		}
	}
	sightings := items
	body, err := json.Marshal(Request{Sightings: items})
	if err != nil {
		return nil, fmt.Errorf("sightingclient: encode: %w", err)
	}
	var results []Result
	err = c.withRetry(ctx, func() (bool, error) {
		raw, retry, err := c.once(ctx, tenantID, Path, body)
		if err != nil {
			return retry, err
		}
		results, err = decode(raw)
		if err != nil {
			return false, err
		}
		if len(results) != len(sightings) {
			return false, fmt.Errorf("sightingclient: %d sightings sent, %d results returned", len(sightings), len(results))
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}

// withRetry runs attempt until it succeeds, says another try cannot help, or
// the attempts run out (5xx and transport failures retry; ErrUnavailable
// wraps the last).
func (c *Client) withRetry(ctx context.Context, attempt func() (retry bool, err error)) error {
	var last error
	wait := c.backoff
	for n := 1; n <= c.attempts; n++ {
		retry, err := attempt()
		if err == nil {
			return nil
		}
		if !retry {
			return err
		}
		last = err
		if n == c.attempts {
			break
		}
		if err := c.sleep(ctx, wait); err != nil {
			return fmt.Errorf("%w: %w (gave up waiting: %w)", ErrUnavailable, last, err)
		}
		wait *= 2
	}
	return fmt.Errorf("%w after %d attempts: %w", ErrUnavailable, c.attempts, last)
}

// once is one attempt; it returns the 200 body. retry says whether another
// attempt could succeed.
func (c *Client) once(ctx context.Context, tenantID, path string, body []byte) ([]byte, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body)) //nolint:gosec // internal service-to-service call to a peer URL from trusted config, not user input
	if err != nil {
		return nil, false, fmt.Errorf("sightingclient: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Before signing: serviceauth folds the tenant header into the message.
	req.Header.Set(serviceauth.HeaderTenantID, tenantID)
	c.sign(req)

	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, false, err
		}
		return nil, true, fmt.Errorf("sightingclient: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponse))

	switch {
	case resp.StatusCode >= 500:
		return nil, true, fmt.Errorf("sightingclient: inventory-service answered %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	case resp.StatusCode >= 400:
		rej := &RejectedError{Status: resp.StatusCode, Body: strings.TrimSpace(string(raw))}
		c.logf("[sightingclient] tenant %s: %v", tenantID, rej)
		return nil, false, rej
	case resp.StatusCode != http.StatusOK:
		return nil, false, fmt.Errorf("sightingclient: inventory-service answered %d", resp.StatusCode)
	}
	return raw, false, nil
}

// decode accepts the documented {"results":[...]} and a bare array.
func decode(raw []byte) ([]Result, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var out []Result
		if err := json.Unmarshal(trimmed, &out); err != nil {
			return nil, fmt.Errorf("sightingclient: decode results: %w", err)
		}
		return out, nil
	}
	var out Response
	if err := json.Unmarshal(trimmed, &out); err != nil {
		return nil, fmt.Errorf("sightingclient: decode results: %w", err)
	}
	return out.Results, nil
}
