package handlers

// Settings → Discovery → Active Scanning: the tenant-admin controls for the
// automatic active scan, and the read-only account of what it has been doing.
//
// The policy lives in `tenant_admin_settings.config` under `discovery_auto_scan`,
// beside `identity` and `drift` — the same document, the same audit trigger, no
// new table for five fields.

import (
	"context"
	"net/http"
	"net/netip"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/autoscan"
	sharedautoscan "github.com/vistasecurity/vistaplatform/shared/autoscan"
)

// AutoScanStore is the slice of internal/autoscan.Store this handler needs.
// An interface so the contract tests can drive the real router without a
// database — the handler shape is what they are pinning.
type AutoScanStore interface {
	GetPolicy(ctx context.Context, tenantID uuid.UUID) (autoscan.Policy, error)
	SetPolicy(ctx context.Context, tenantID, actorUserID uuid.UUID, policy autoscan.Policy) (autoscan.Policy, int, error)
	GetState(ctx context.Context, tenantID uuid.UUID) (autoscan.State, error)
	InScope(ctx context.Context, tenantID uuid.UUID, excluded []netip.Prefix) (int, error)
	RecentJobs(ctx context.Context, tenantID uuid.UUID, limit int) ([]autoscan.RecentJob, error)
}

// AutoScanHandler serves GET/PUT /discovery/auto-scan.
type AutoScanHandler struct {
	store    AutoScanStore
	excluded []netip.Prefix
}

func NewAutoScanHandler(store AutoScanStore) *AutoScanHandler {
	return &AutoScanHandler{store: store, excluded: autoscan.PlatformExcludedPrefixes()}
}

// autoScanPolicyBody is the wire shape of the policy. It is also the PUT body,
// so what the page reads and what it writes cannot drift apart.
type autoScanPolicyBody struct {
	Enabled                *bool    `json:"enabled"`
	ScanOnFirstObservation *bool    `json:"scan_on_first_observation"`
	RescanIntervalHours    *int     `json:"rescan_interval_hours"`
	Protocols              []string `json:"protocols"`
	Ports                  []int    `json:"ports"`
	// PreferObservingSensor is optional on the wire so a client built
	// before the switch existed can still save the policy; absent means
	// "leave it as it is" — which the store reads back as the default (on)
	// for a document that has never carried it.
	PreferObservingSensor *bool `json:"prefer_observing_sensor"`
}

type autoScanPolicyOut struct {
	Enabled                bool     `json:"enabled"`
	ScanOnFirstObservation bool     `json:"scan_on_first_observation"`
	RescanIntervalHours    int      `json:"rescan_interval_hours"`
	Protocols              []string `json:"protocols"`
	Ports                  []int    `json:"ports"`
	PreferObservingSensor  bool     `json:"prefer_observing_sensor"`
}

// autoScanLimitsOut travels in every response so the page validates against the
// server's numbers rather than carrying its own copy of 1 and 720 — the shape
// the drift-baseline control uses, and for the same reason: a change to the
// server's limits must not leave a control accepting values the server refuses.
type autoScanLimitsOut struct {
	MinRescanIntervalHours int      `json:"min_rescan_interval_hours"`
	MaxRescanIntervalHours int      `json:"max_rescan_interval_hours"`
	MaxPorts               int      `json:"max_ports"`
	SupportedProtocols     []string `json:"supported_protocols"`
	DefaultPorts           []int    `json:"default_ports"`
}

type autoScanRecentJobOut struct {
	ID                    string  `json:"id"`
	Status                string  `json:"status"`
	TargetCount           int     `json:"target_count"`
	CreatedAt             string  `json:"created_at"`
	CompletedAt           *string `json:"completed_at,omitempty"`
	Executor              string  `json:"executor"`
	ExecutorName          *string `json:"executor_name,omitempty"`
	ExecutorLastHeartbeat *string `json:"executor_last_heartbeat,omitempty"`
	DispatchedAt          *string `json:"dispatched_at,omitempty"`
	PickedUpAt            *string `json:"picked_up_at,omitempty"`
	ErrorMessage          *string `json:"error_message,omitempty"`
}

// autoScanNotScannedOut is one reason the last sweep left hosts out, with how
// many. The reason is the shared/autoscan Reason string verbatim; the page owns
// the plain-language label and the call to action, because "register the
// segment" is a link only the page can draw.
type autoScanNotScannedOut struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

type autoScanSummaryOut struct {
	LastSweepAt     *string                 `json:"last_sweep_at,omitempty"`
	NextSweepAt     *string                 `json:"next_sweep_at,omitempty"`
	LastSweepJobs   int                     `json:"last_sweep_jobs"`
	LastSweepAssets int                     `json:"last_sweep_assets"`
	AssetsInScope   int                     `json:"assets_in_scope"`
	RecentJobs      []autoScanRecentJobOut  `json:"recent_jobs"`
	NotScanned      []autoScanNotScannedOut `json:"not_scanned"`
}

// notScannedOut renders the sweep's refusal counts for the wire: sorted by
// reason so two responses from the same sweep read the same, zero counts
// dropped, and never nil — an empty list is the "every eligible host was
// scanned" answer and a client should not have to tell `null` from `[]`.
func notScannedOut(refusals map[sharedautoscan.Reason]int) []autoScanNotScannedOut {
	out := []autoScanNotScannedOut{}
	keys := make([]string, 0, len(refusals))
	for reason, n := range refusals {
		if n > 0 {
			keys = append(keys, string(reason))
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, autoScanNotScannedOut{Reason: k, Count: refusals[sharedautoscan.Reason(k)]})
	}
	return out
}

type autoScanResponse struct {
	AutoScan autoScanPolicyOut  `json:"auto_scan"`
	Limits   autoScanLimitsOut  `json:"limits"`
	Summary  autoScanSummaryOut `json:"summary"`
}

func autoScanLimits() autoScanLimitsOut {
	return autoScanLimitsOut{
		MinRescanIntervalHours: sharedautoscan.MinRescanIntervalHours,
		MaxRescanIntervalHours: sharedautoscan.MaxRescanIntervalHours,
		MaxPorts:               sharedautoscan.MaxPorts,
		SupportedProtocols:     append([]string(nil), sharedautoscan.SupportedProtocols...),
		DefaultPorts:           sharedautoscan.DefaultPorts(),
	}
}

func toPolicyOut(p autoscan.Policy) autoScanPolicyOut {
	out := autoScanPolicyOut{
		Enabled:                p.Enabled,
		ScanOnFirstObservation: p.ScanOnFirstObservation,
		RescanIntervalHours:    p.RescanIntervalHours,
		Protocols:              p.Protocols,
		Ports:                  p.Ports,
		PreferObservingSensor:  p.PreferObservingSensor,
	}
	// Never nil on the wire: the spec declares both as arrays, and a client that
	// has to distinguish `null` from `[]` for a list that can never legitimately
	// be empty is a client doing our job.
	if out.Protocols == nil {
		out.Protocols = []string{}
	}
	if out.Ports == nil {
		out.Ports = []int{}
	}
	return out
}

func rfc3339OrNil(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}

// GetAutoScan handles GET /discovery/auto-scan.
func (h *AutoScanHandler) GetAutoScan(c *gin.Context) {
	tenantID, ok := autoScanTenant(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()

	policy, err := h.store.GetPolicy(ctx, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read the automatic-scan policy"})
		return
	}

	c.JSON(http.StatusOK, autoScanResponse{
		AutoScan: toPolicyOut(policy),
		Limits:   autoScanLimits(),
		Summary:  h.summary(ctx, tenantID),
	})
}

// UpdateAutoScan handles PUT /discovery/auto-scan.
//
// Every field is required. A partial update on this policy would be a trap: the
// difference between "leave the ports alone" and "scan no ports" is one absent
// key, and the tenant would have no way to tell which they had asked for.
func (h *AutoScanHandler) UpdateAutoScan(c *gin.Context) {
	tenantID, ok := autoScanTenant(c)
	if !ok {
		return
	}
	userID, _ := autoScanUser(c)

	var body autoScanPolicyBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	if body.Enabled == nil || body.ScanOnFirstObservation == nil || body.RescanIntervalHours == nil ||
		body.Protocols == nil || body.Ports == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "enabled, scan_on_first_observation, rescan_interval_hours, protocols and ports are all required",
		})
		return
	}

	ctx := c.Request.Context()
	// The routing switch is the one optional field: an older client omitting
	// it must not flip it, so the current value is carried forward.
	preferObserving := true
	if body.PreferObservingSensor != nil {
		preferObserving = *body.PreferObservingSensor
	} else if current, err := h.store.GetPolicy(ctx, tenantID); err == nil {
		preferObserving = current.PreferObservingSensor
	}
	saved, _, err := h.store.SetPolicy(ctx, tenantID, userID, autoscan.Policy{
		Enabled:                *body.Enabled,
		ScanOnFirstObservation: *body.ScanOnFirstObservation,
		RescanIntervalHours:    *body.RescanIntervalHours,
		Protocols:              body.Protocols,
		Ports:                  body.Ports,
		PreferObservingSensor:  preferObserving,
	})
	if err != nil {
		// Validation refusals from shared/autoscan name the bound they broke, so
		// the message is actionable. A store failure is a 500, and telling them
		// apart by error text would be guesswork — SetPolicy validates first and
		// returns before touching the database, so a validation error cannot be
		// a database error.
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, autoScanResponse{
		AutoScan: toPolicyOut(saved),
		Limits:   autoScanLimits(),
		Summary:  h.summary(ctx, tenantID),
	})
}

// summary is best-effort. Its three reads are a description of what the worker
// has been doing; none of them is the policy, and failing the whole page
// because a count query errored would hide the controls the tenant came for.
func (h *AutoScanHandler) summary(ctx context.Context, tenantID uuid.UUID) autoScanSummaryOut {
	out := autoScanSummaryOut{RecentJobs: []autoScanRecentJobOut{}, NotScanned: []autoScanNotScannedOut{}}

	if state, err := h.store.GetState(ctx, tenantID); err == nil {
		out.LastSweepAt = rfc3339OrNil(state.LastSweepAt)
		out.NextSweepAt = rfc3339OrNil(state.NextSweepAt)
		out.LastSweepJobs = state.LastSweepJobs
		out.LastSweepAssets = state.LastSweepAssets
		out.NotScanned = notScannedOut(state.LastSweepRefusals)
	}
	if count, err := h.store.InScope(ctx, tenantID, h.excluded); err == nil {
		out.AssetsInScope = count
	}
	if jobs, err := h.store.RecentJobs(ctx, tenantID, 10); err == nil {
		for _, j := range jobs {
			created := j.CreatedAt
			executor := j.Executor
			if executor == "" {
				executor = "platform"
			}
			out.RecentJobs = append(out.RecentJobs, autoScanRecentJobOut{
				ID:                    j.ID,
				Status:                j.Status,
				TargetCount:           j.TargetCount,
				CreatedAt:             created.UTC().Format(time.RFC3339),
				CompletedAt:           rfc3339OrNil(j.CompletedAt),
				Executor:              executor,
				ExecutorName:          j.ExecutorName,
				ExecutorLastHeartbeat: rfc3339OrNil(j.ExecutorLastHeartbeat),
				DispatchedAt:          rfc3339OrNil(j.DispatchedAt),
				PickedUpAt:            rfc3339OrNil(j.PickedUpAt),
				ErrorMessage:          j.ErrorMessage,
			})
		}
	}
	return out
}

func autoScanTenant(c *gin.Context) (uuid.UUID, bool) {
	v, _ := c.Get("tenantID")
	switch t := v.(type) {
	case uuid.UUID:
		return t, true
	case string:
		if id, err := uuid.Parse(t); err == nil {
			return id, true
		}
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": "tenant ID required"})
	return uuid.Nil, false
}

// autoScanUser resolves the actor for the audit trail. uuid.Nil is a legitimate
// answer — an internal caller has no person behind it — and the store writes
// NULL rather than inventing one.
func autoScanUser(c *gin.Context) (uuid.UUID, bool) {
	v, _ := c.Get("userID")
	switch t := v.(type) {
	case uuid.UUID:
		return t, true
	case string:
		if id, err := uuid.Parse(t); err == nil {
			return id, true
		}
	}
	return uuid.Nil, false
}
