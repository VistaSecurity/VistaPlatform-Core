package handlers

// `GET`/`PUT /discovery/auto-scan` against the spec.
//
// `AutoScanResponse` is declared `additionalProperties: false`, so a renamed or
// extra field would ship a spec the generated client disagrees with — and the
// Active Scanning page reads its bounds (1..720, the supported protocols, the
// default port set) straight out of that body rather than carrying its own
// copy. Both polarities on the input: a policy inside the bounds reaches the
// store, and one outside is REFUSED rather than clamped.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/autoscan"
	sharedautoscan "github.com/vistasecurity/vistaplatform/shared/autoscan"
)

type stubAutoScanStore struct {
	policy autoscan.Policy
	state  autoscan.State
	scope  int
	recent []autoscan.RecentJob

	setCalls int
	got      autoscan.Policy
	setErr   error
}

func (s *stubAutoScanStore) GetPolicy(context.Context, uuid.UUID) (autoscan.Policy, error) {
	return s.policy, nil
}

func (s *stubAutoScanStore) SetPolicy(_ context.Context, _, _ uuid.UUID, p autoscan.Policy) (autoscan.Policy, int, error) {
	s.setCalls++
	s.got = p
	if s.setErr != nil {
		return autoscan.Policy{}, 0, s.setErr
	}
	// The real store normalizes before writing; a stub that skipped that would
	// let a test pass against a shape production never produces.
	normalized, err := sharedautoscan.Normalize(p)
	if err != nil {
		return autoscan.Policy{}, 0, err
	}
	s.policy = normalized
	return normalized, 2, nil
}

func (s *stubAutoScanStore) GetState(context.Context, uuid.UUID) (autoscan.State, error) {
	return s.state, nil
}

func (s *stubAutoScanStore) InScope(context.Context, uuid.UUID, []netip.Prefix) (int, error) {
	return s.scope, nil
}

func (s *stubAutoScanStore) RecentJobs(context.Context, uuid.UUID, int) ([]autoscan.RecentJob, error) {
	return s.recent, nil
}

func newAutoScanEngine(h *AutoScanHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})
	grp.GET("/inventory-service/discovery/auto-scan", h.GetAutoScan)
	grp.PUT("/inventory-service/discovery/auto-scan", h.UpdateAutoScan)
	return r
}

func TestContract_AutoScan_GetCarriesThePolicyItsBoundsAndTheSummary(t *testing.T) {
	sv := loadSpec(t)
	swept := time.Date(2026, 9, 17, 6, 0, 0, 0, time.UTC)
	next := swept.Add(15 * time.Minute)
	store := &stubAutoScanStore{
		policy: sharedautoscan.DefaultPolicy(),
		state: autoscan.State{
			LastSweepAt: &swept, NextSweepAt: &next, LastSweepJobs: 2, LastSweepAssets: 41,
			LastSweepRefusals: map[sharedautoscan.Reason]int{
				sharedautoscan.ReasonPublic:          3,
				sharedautoscan.ReasonCarrierGradeNAT: 12,
				sharedautoscan.ReasonLinkLocal:       0, // a zero is not a refusal
			},
		},
		scope:  57,
		recent: []autoscan.RecentJob{{ID: uuid.New().String(), Status: "completed", TargetCount: 20, CreatedAt: swept}},
	}
	eng := newAutoScanEngine(NewAutoScanHandler(store))

	w := do(eng, http.MethodGet, "/api/v1/inventory-service/discovery/auto-scan", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AutoScanResponse", w.Body.Bytes())

	var body struct {
		AutoScan struct {
			Enabled                bool     `json:"enabled"`
			ScanOnFirstObservation bool     `json:"scan_on_first_observation"`
			RescanIntervalHours    int      `json:"rescan_interval_hours"`
			Protocols              []string `json:"protocols"`
			Ports                  []int    `json:"ports"`
		} `json:"auto_scan"`
		Limits struct {
			Min                int      `json:"min_rescan_interval_hours"`
			Max                int      `json:"max_rescan_interval_hours"`
			MaxPorts           int      `json:"max_ports"`
			SupportedProtocols []string `json:"supported_protocols"`
			DefaultPorts       []int    `json:"default_ports"`
		} `json:"limits"`
		Summary struct {
			LastSweepAt   *string `json:"last_sweep_at"`
			NextSweepAt   *string `json:"next_sweep_at"`
			AssetsInScope int     `json:"assets_in_scope"`
			RecentJobs    []struct {
				ID string `json:"id"`
			} `json:"recent_jobs"`
			NotScanned []struct {
				Reason string `json:"reason"`
				Count  int    `json:"count"`
			} `json:"not_scanned"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !body.AutoScan.Enabled || !body.AutoScan.ScanOnFirstObservation || body.AutoScan.RescanIntervalHours != 24 {
		t.Errorf("policy = %+v, want the default: on, on, 24h", body.AutoScan)
	}
	// The bounds travel in the response. Without them the page carries its own
	// copy of 1 and 720, and a change to the server's limits leaves the control
	// accepting numbers the server refuses.
	if body.Limits.Min != sharedautoscan.MinRescanIntervalHours || body.Limits.Max != sharedautoscan.MaxRescanIntervalHours {
		t.Errorf("bounds = %d..%d, want %d..%d", body.Limits.Min, body.Limits.Max,
			sharedautoscan.MinRescanIntervalHours, sharedautoscan.MaxRescanIntervalHours)
	}
	if body.Limits.MaxPorts != sharedautoscan.MaxPorts {
		t.Errorf("max_ports = %d, want %d", body.Limits.MaxPorts, sharedautoscan.MaxPorts)
	}
	if len(body.Limits.SupportedProtocols) != len(sharedautoscan.SupportedProtocols) {
		t.Errorf("supported_protocols = %v, want %v", body.Limits.SupportedProtocols, sharedautoscan.SupportedProtocols)
	}
	if len(body.Limits.DefaultPorts) == 0 {
		t.Error("default_ports is empty — the page cannot offer 'reset to defaults'")
	}

	if body.Summary.AssetsInScope != 57 {
		t.Errorf("assets_in_scope = %d, want 57", body.Summary.AssetsInScope)
	}
	if body.Summary.LastSweepAt == nil || body.Summary.NextSweepAt == nil {
		t.Errorf("summary = %+v, want both sweep timestamps", body.Summary)
	}
	// The recent runs are the whole reachability story for an unattended
	// capability: without them the page says it is scanning and shows no
	// evidence that it ever did.
	if len(body.Summary.RecentJobs) != 1 {
		t.Errorf("recent_jobs = %v, want the one run the store holds", body.Summary.RecentJobs)
	}
	// What the sweep REFUSED travels too, sorted by reason and with the zero
	// dropped. A Tailscale tenant's entire estate is carrier-grade NAT; without
	// this the page says "on" over a sweep that will never scan a host.
	ns := body.Summary.NotScanned
	if len(ns) != 2 || ns[0].Reason != "carrier_grade_nat" || ns[0].Count != 12 || ns[1].Reason != "public" || ns[1].Count != 3 {
		t.Errorf("not_scanned = %+v, want [carrier_grade_nat=12 public=3] in reason order with the zero dropped", ns)
	}
}

// A tenant who has never had a sweep must get a well-formed body, not a body
// with a null where an array belongs.
func TestContract_AutoScan_GetWithNoHistory(t *testing.T) {
	sv := loadSpec(t)
	eng := newAutoScanEngine(NewAutoScanHandler(&stubAutoScanStore{policy: sharedautoscan.DefaultPolicy()}))

	w := do(eng, http.MethodGet, "/api/v1/inventory-service/discovery/auto-scan", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AutoScanResponse", w.Body.Bytes())
	if strings.Contains(w.Body.String(), `"recent_jobs":null`) {
		t.Error("recent_jobs is null; the spec declares an array and a client should not have to tell them apart")
	}
	if !strings.Contains(w.Body.String(), `"not_scanned":[]`) {
		t.Errorf("not_scanned must be an EMPTY array for a tenant with no sweep — the page's \"every eligible host was scanned\" state reads it: %s", w.Body.String())
	}
}

func TestContract_AutoScan_Update(t *testing.T) {
	sv := loadSpec(t)
	store := &stubAutoScanStore{policy: sharedautoscan.DefaultPolicy()}
	eng := newAutoScanEngine(NewAutoScanHandler(store))

	w := do(eng, http.MethodPut, "/api/v1/inventory-service/discovery/auto-scan",
		strings.NewReader(`{"enabled":true,"scan_on_first_observation":false,"rescan_interval_hours":72,"protocols":["TLS"],"ports":[443,8443]}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AutoScanResponse", w.Body.Bytes())

	if store.got.RescanIntervalHours != 72 || store.got.ScanOnFirstObservation {
		t.Errorf("the store was asked for %+v, want 72h with first-observation off", store.got)
	}
	if !strings.Contains(w.Body.String(), `"rescan_interval_hours":72`) {
		t.Errorf("the response does not echo the saved interval: %s", w.Body.String())
	}
}

// An explicit `false` is an ANSWER. If it were read as "field absent" and
// defaulted, turning automatic scanning OFF would turn it back on.
func TestContract_AutoScan_UpdateCanTurnItOff(t *testing.T) {
	store := &stubAutoScanStore{policy: sharedautoscan.DefaultPolicy()}
	eng := newAutoScanEngine(NewAutoScanHandler(store))

	w := do(eng, http.MethodPut, "/api/v1/inventory-service/discovery/auto-scan",
		strings.NewReader(`{"enabled":false,"scan_on_first_observation":false,"rescan_interval_hours":24,"protocols":["TLS"],"ports":[443]}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	if store.got.Enabled {
		t.Fatal("the store was asked to ENABLE automatic scanning by a request that disabled it")
	}
	if !strings.Contains(w.Body.String(), `"enabled":false`) {
		t.Errorf("the response does not report the feature as off: %s", w.Body.String())
	}
}

func TestContract_AutoScan_RejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"malformed":             `{`,
		"empty object":          `{}`,
		"missing ports":         `{"enabled":true,"scan_on_first_observation":true,"rescan_interval_hours":24,"protocols":["TLS"]}`,
		"missing protocols":     `{"enabled":true,"scan_on_first_observation":true,"rescan_interval_hours":24,"ports":[443]}`,
		"missing enabled":       `{"scan_on_first_observation":true,"rescan_interval_hours":24,"protocols":["TLS"],"ports":[443]}`,
		"interval not a number": `{"enabled":true,"scan_on_first_observation":true,"rescan_interval_hours":"daily","protocols":["TLS"],"ports":[443]}`,
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			store := &stubAutoScanStore{policy: sharedautoscan.DefaultPolicy()}
			eng := newAutoScanEngine(NewAutoScanHandler(store))
			w := do(eng, http.MethodPut, "/api/v1/inventory-service/discovery/auto-scan", strings.NewReader(payload))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
			}
			if store.setCalls != 0 {
				t.Error("a rejected request still reached the store")
			}
		})
	}
}

// Out of range is REFUSED, not clamped, and the refusal names the bounds — a
// 400 that does not say what the allowed range is, is a 400 nobody can act on.
func TestContract_AutoScan_OutOfRangeIsRefused(t *testing.T) {
	for _, payload := range []string{
		`{"enabled":true,"scan_on_first_observation":true,"rescan_interval_hours":0,"protocols":["TLS"],"ports":[443]}`,
		`{"enabled":true,"scan_on_first_observation":true,"rescan_interval_hours":100000,"protocols":["TLS"],"ports":[443]}`,
		`{"enabled":true,"scan_on_first_observation":true,"rescan_interval_hours":-5,"protocols":["TLS"],"ports":[443]}`,
	} {
		store := &stubAutoScanStore{policy: sharedautoscan.DefaultPolicy()}
		eng := newAutoScanEngine(NewAutoScanHandler(store))
		w := do(eng, http.MethodPut, "/api/v1/inventory-service/discovery/auto-scan", strings.NewReader(payload))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400; body=%s", payload, w.Code, w.Body.String())
			continue
		}
		if !strings.Contains(w.Body.String(), "1") || !strings.Contains(w.Body.String(), "720") {
			t.Errorf("%s: the refusal does not name the bounds: %s", payload, w.Body.String())
		}
	}
}

// The OT probes are gated by the `ot_active_probing` entitlement through a
// discovery job's separate field. Accepting one here would be a way to probe a
// PLC unattended, on a schedule, past that gate.
func TestContract_AutoScan_RefusesAnOTProtocol(t *testing.T) {
	for _, proto := range []string{"Modbus", "OPC_UA", "BACnet", "SMB"} {
		store := &stubAutoScanStore{policy: sharedautoscan.DefaultPolicy()}
		eng := newAutoScanEngine(NewAutoScanHandler(store))
		w := do(eng, http.MethodPut, "/api/v1/inventory-service/discovery/auto-scan",
			strings.NewReader(`{"enabled":true,"scan_on_first_observation":true,"rescan_interval_hours":24,"protocols":["`+proto+`"],"ports":[502]}`))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400; body=%s", proto, w.Code, w.Body.String())
		}
	}
}
