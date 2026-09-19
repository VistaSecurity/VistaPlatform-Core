package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/hostinventory"
)

// The host-inventory intake handler.
//
// What is being pinned here is mostly refusal — the endpoint takes a payload
// from a customer-network binary and writes it to a tenant's row — plus the
// ORDER of the two things it does: store, then materialise. A materialisation
// that runs before the row exists loses the payload when it fails, which is the
// one failure the 2.11a hold was protecting against and the one this handler
// must not reintroduce now that it materialises.

type fakeHostInventoryStore struct {
	calls    int
	tenantID uuid.UUID
	agentID  uuid.UUID
	params   []byte
	results  []byte
	err      error
}

func (s *fakeHostInventoryStore) RecordHostInventory(_ context.Context, tenantID, agentID uuid.UUID, parameters, results []byte) (uuid.UUID, error) {
	s.calls++
	s.tenantID, s.agentID, s.params, s.results = tenantID, agentID, parameters, results
	if s.err != nil {
		return uuid.Nil, s.err
	}
	return uuid.New(), nil
}

// fakeHostInventoryMaterialiser records what it was handed. It also records
// whether the STORE had already run when it was called, which is the ordering
// invariant.
type fakeHostInventoryMaterialiser struct {
	calls           int
	storeCallsAtRun int
	obs             *di.InterrogateResult
	counts          services.HostInventoryCounts
	err             error
	store           *fakeHostInventoryStore
}

func (m *fakeHostInventoryMaterialiser) MaterialiseAndRecord(
	_ context.Context, _, _, _ uuid.UUID, obs *di.InterrogateResult,
) (services.HostInventoryCounts, error) {
	m.calls++
	m.obs = obs
	if m.store != nil {
		m.storeCallsAtRun = m.store.calls
	}
	return m.counts, m.err
}

// newIntakeRouter builds the REAL gin route with a stand-in for AgentAuth that
// sets exactly what AgentAuth sets. Driving the router rather than the handler
// function keeps the binding and the JSON shape in the test's blast radius.
func newIntakeRouter(store *fakeHostInventoryStore, agentID, tenantID uuid.UUID) *gin.Engine {
	return newIntakeRouterWith(store, defaultFakeMaterialiser(store), agentID, tenantID)
}

func newIntakeRouterWith(store *fakeHostInventoryStore, mat hostInventoryMaterialiser, agentID, tenantID uuid.UUID) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/agents/host-inventory", func(c *gin.Context) {
		if agentID != uuid.Nil {
			c.Set("agent_id", agentID)
		}
		if tenantID != uuid.Nil {
			c.Set("tenantID", tenantID)
		}
		c.Next()
	}, NewHostInventoryHandlerWithStore(store, mat).Submit)
	return r
}

func defaultFakeMaterialiser(store *fakeHostInventoryStore) *fakeHostInventoryMaterialiser {
	return &fakeHostInventoryMaterialiser{
		store: store,
		counts: services.HostInventoryCounts{
			AssetID: "11111111-1111-1111-1111-111111111111", AssetCreated: true,
			Identifiers: 3, Facts: 9, Endpoints: 1, InstallsCreated: 1, InstallsActive: 1,
		},
	}
}

func validSubmission(agentID uuid.UUID) HostInventorySubmission {
	return HostInventorySubmission{
		AgentID:     agentID,
		Mode:        string(hostinventory.ModeLocal),
		CollectedAt: time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC),
		Report: &hostinventory.Report{
			Collected: time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC),
			Mode:      hostinventory.ModeLocal,
			Platform:  hostinventory.PlatformLinux,
			Host:      hostinventory.Host{OS: "Ubuntu", OSVersion: "22.04.3 LTS", Hostname: "app-01"},
			Packages:  []hostinventory.Package{{Name: "openssl", Version: "3.0.2", Manager: "dpkg"}},
			Sections:  map[string]string{"host": hostinventory.SectionOK, "packages": hostinventory.SectionOK},
		},
		Observations: &di.InterrogateResult{
			Assets:     []di.CryptoAsset{{IPAddress: "0.0.0.0", Port: 22, Protocol: "tcp"}},
			DeviceInfo: map[string]interface{}{"host_inventory": map[string]any{"mode": "local"}},
			Facts:      []di.FactObservation{{Key: "agent.mode", Value: "local", Confidence: 1}},
		},
	}
}

func postSubmission(t *testing.T, router *gin.Engine, body any) *httptest.ResponseRecorder {
	t.Helper()
	blob, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/agents/host-inventory", bytes.NewReader(blob))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestHostInventorySubmit_StoresThenMaterialisesAValidLocalCollection(t *testing.T) {
	agentID, tenantID := uuid.New(), uuid.New()
	store := &fakeHostInventoryStore{}
	mat := defaultFakeMaterialiser(store)
	w := postSubmission(t, newIntakeRouterWith(store, mat, agentID, tenantID), validSubmission(agentID))

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if store.calls != 1 {
		t.Fatalf("store calls = %d, want 1", store.calls)
	}
	if mat.calls != 1 {
		t.Fatalf("materialiser calls = %d, want 1 — a stored-and-never-consumed collection is the 2.11a hold, not 2.11b", mat.calls)
	}
	// ORDER. The payload has to be durable before anything reads it, so a
	// materialisation that fails leaves a job row somebody can look at rather
	// than a submission that vanished into an error the agent cannot act on.
	if mat.storeCallsAtRun != 1 {
		t.Errorf("the materialiser ran with %d store call(s) behind it, want 1 — store first, then materialise", mat.storeCallsAtRun)
	}
	// The tenant comes from AgentAuth's resolution, never from the body — a
	// body-supplied tenant on an ingestion path is how one tenant writes into
	// another's inventory.
	if store.tenantID != tenantID || store.agentID != agentID {
		t.Errorf("wrote under tenant %s / agent %s, want %s / %s", store.tenantID, store.agentID, tenantID, agentID)
	}

	// The response says what landed, in numbers an operator can reconcile.
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "materialised" {
		t.Errorf("status = %v, want \"materialised\"", resp["status"])
	}
	counts, ok := resp["counts"].(map[string]any)
	if !ok {
		t.Fatalf("the response carries no counts: %v", resp)
	}
	if counts["asset_id"] != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("the response does not name the asset: %v", counts["asset_id"])
	}

	// Both halves are persisted: the observations that were materialised, and
	// the report that says which sections failed.
	var stored map[string]any
	if err := json.Unmarshal(store.results, &stored); err != nil {
		t.Fatalf("stored results: %v", err)
	}
	if stored["report"] == nil || stored["observations"] == nil {
		t.Errorf("a half of the submission was dropped: %v", storedKeys(stored))
	}
	var params map[string]any
	if err := json.Unmarshal(store.params, &params); err != nil {
		t.Fatalf("stored parameters: %v", err)
	}
	if params["mode"] != "local" || params["origin"] != "agent" || params["platform"] != "linux" {
		t.Errorf("parameters lost the provenance: %v", params)
	}
}

// What the materialiser is handed is the SANITISED observations, not the
// report. The report is the collector's account of what ran; the observations
// are the half that has been through di.Sanitize twice and the half that
// carries the package list now that the report's duplicate copy has been
// dropped from the wire.
func TestHostInventorySubmit_MaterialisesTheSanitisedObservations(t *testing.T) {
	agentID, tenantID := uuid.New(), uuid.New()
	store := &fakeHostInventoryStore{}
	mat := defaultFakeMaterialiser(store)
	body := validSubmission(agentID)
	body.Observations.DeviceInfo["api_key"] = "SHOULD-BE-REDACTED-AT-INTAKE"

	if w := postSubmission(t, newIntakeRouterWith(store, mat, agentID, tenantID), body); w.Code != http.StatusAccepted {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	if mat.obs == nil {
		t.Fatal("the materialiser was handed no observations")
	}
	if v, _ := mat.obs.DeviceInfo["api_key"].(string); v == "SHOULD-BE-REDACTED-AT-INTAKE" {
		t.Error("the materialiser was handed an UNSANITISED payload; the intake's re-sanitise runs before it, or it does not run at all")
	}
}

// A materialisation failure is a 500, not a 202 with a cheerful body.
//
// "We took your report" and "your host is in the inventory" are different
// claims. An agent told the second when only the first is true has no reason to
// look again, and the host quietly never appears.
func TestHostInventorySubmit_AMaterialisationFailureIsReported(t *testing.T) {
	agentID, tenantID := uuid.New(), uuid.New()
	store := &fakeHostInventoryStore{}
	mat := defaultFakeMaterialiser(store)
	mat.err = errors.New("the identification engine is unavailable")

	w := postSubmission(t, newIntakeRouterWith(store, mat, agentID, tenantID), validSubmission(agentID))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", w.Code, w.Body.String())
	}
	// The payload is still stored: nothing is lost, and the response says so.
	if store.calls != 1 {
		t.Errorf("store calls = %d, want 1 — a failed materialisation must not discard the report", store.calls)
	}
	if !strings.Contains(w.Body.String(), "nothing was lost") {
		t.Errorf("the 500 does not tell the caller the report survived: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "identification engine is unavailable") {
		t.Errorf("the internal error leaked to the client: %s", w.Body.String())
	}
}

// A contested identity is its own status: not a failure, and not a success
// either. The engine opened a merge proposal because a human has to say which
// machine this is, and reporting it as "materialised" with an empty asset_id
// would read as a bug.
func TestHostInventorySubmit_AContestedIdentityIsSaidOutLoud(t *testing.T) {
	agentID, tenantID := uuid.New(), uuid.New()
	store := &fakeHostInventoryStore{}
	mat := defaultFakeMaterialiser(store)
	mat.counts = services.HostInventoryCounts{Contested: true, ContestedReason: "merge proposal waiting"}

	w := postSubmission(t, newIntakeRouterWith(store, mat, agentID, tenantID), validSubmission(agentID))
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "contested" {
		t.Errorf("status = %v, want \"contested\"", resp["status"])
	}
}

func TestHostInventorySubmit_RetainedEvidenceIsAcknowledgedWithoutAnAsset(t *testing.T) {
	agentID, tenantID := uuid.New(), uuid.New()
	store := &fakeHostInventoryStore{}
	mat := defaultFakeMaterialiser(store)
	id := uuid.NewString()
	mat.counts = services.HostInventoryCounts{ObservationID: id, IdentityOutcome: "unresolved"}
	w := postSubmission(t, newIntakeRouterWith(store, mat, agentID, tenantID), validSubmission(agentID))
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", w.Code, w.Body.String())
	}
	var response struct {
		Status string                       `json:"status"`
		Counts services.HostInventoryCounts `json:"counts"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Status != "unresolved" || response.Counts.ObservationID != id || response.Counts.AssetID != "" || store.calls != 1 {
		t.Fatalf("retained acknowledgement = %+v, stores=%d", response, store.calls)
	}
}

// A remote collection is a JOB and submits through /results. Accepting one here
// would create a device_jobs row that no job produced, and the job list would
// then contain a job nobody queued.
func TestHostInventorySubmit_RefusesARemoteCollection(t *testing.T) {
	agentID, tenantID := uuid.New(), uuid.New()
	store := &fakeHostInventoryStore{}
	body := validSubmission(agentID)
	body.Mode = string(hostinventory.ModeRemote)

	w := postSubmission(t, newIntakeRouter(store, agentID, tenantID), body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
	}
	if store.calls != 0 {
		t.Error("a remote collection was written anyway")
	}
}

// The body's agent_id is a claim; AgentAuth's is the authenticated identity.
func TestHostInventorySubmit_RefusesAMismatchedAgentID(t *testing.T) {
	agentID, tenantID := uuid.New(), uuid.New()
	store := &fakeHostInventoryStore{}
	body := validSubmission(uuid.New()) // a different agent

	w := postSubmission(t, newIntakeRouter(store, agentID, tenantID), body)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", w.Code, w.Body.String())
	}
	if store.calls != 0 {
		t.Error("a submission claiming another agent's id was written")
	}
}

// Half a submission cannot be stored: observations with no report cannot say
// which sections failed, and a report with no observations cannot be
// materialised.
func TestHostInventorySubmit_RefusesAHalfSubmission(t *testing.T) {
	agentID, tenantID := uuid.New(), uuid.New()

	t.Run("no report", func(t *testing.T) {
		store := &fakeHostInventoryStore{}
		body := validSubmission(agentID)
		body.Report = nil
		if w := postSubmission(t, newIntakeRouter(store, agentID, tenantID), body); w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
		if store.calls != 0 {
			t.Error("stored anyway")
		}
	})

	t.Run("no observations", func(t *testing.T) {
		store := &fakeHostInventoryStore{}
		body := validSubmission(agentID)
		body.Observations = nil
		if w := postSubmission(t, newIntakeRouter(store, agentID, tenantID), body); w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
		if store.calls != 0 {
			t.Error("stored anyway")
		}
	})
}

// TestHostInventorySubmit_RefusesAMarkedSubmissionWithNoPackageList is the
// intake half of the travels-once contract.
//
// `packages_omitted` is a POSITIVE assertion: "I had a list and removed it,
// because the sanitised copy is in the observations." A submission making that
// claim while carrying no observations copy can only mean the surviving half
// was lost, and stored it would reach the consumer as a SUCCESSFUL package
// section with no packages — the shape that marks a host's entire software
// inventory uninstalled.
//
// Refused before storage, and named, so the agent can act on it rather than a
// person reading a count off a job row much later.
//
// Mutation check: delete the guard and the first case stores a payload the
// consumer then has to catch by counting.
func TestHostInventorySubmit_RefusesAMarkedSubmissionWithNoPackageList(t *testing.T) {
	agentID, tenantID := uuid.New(), uuid.New()

	t.Run("marked and no observations list", func(t *testing.T) {
		store := &fakeHostInventoryStore{}
		body := validSubmission(agentID)
		body.Report.PackagesOmitted = true
		delete(body.Observations.DeviceInfo, "packages")

		w := postSubmission(t, newIntakeRouter(store, agentID, tenantID), body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
		if store.calls != 0 {
			t.Error("a self-contradictory submission was stored")
		}
		// The message has to name the field, or the agent's operator is left
		// with "Invalid request" for a specific, fixable condition.
		if !strings.Contains(w.Body.String(), "packages_omitted") {
			t.Errorf("the refusal does not name the marker: %s", w.Body.String())
		}
	})

	t.Run("marked WITH the observations list is accepted", func(t *testing.T) {
		store := &fakeHostInventoryStore{}
		body := validSubmission(agentID)
		body.Report.Packages = nil
		body.Report.PackagesOmitted = true
		body.Observations.DeviceInfo["packages"] = []map[string]any{{"name": "openssl", "version": "3.0.2"}}

		w := postSubmission(t, newIntakeRouter(store, agentID, tenantID), body)
		if w.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202 — this is the NORMAL shape of every modern submission: %s",
				w.Code, w.Body.String())
		}
		if store.calls != 1 {
			t.Errorf("store calls = %d, want 1", store.calls)
		}
	})

	// The other polarity, and the one an over-strict guard breaks: no marker
	// means no claim was made. A host whose package step FAILED, a host with no
	// packages, and an agent old enough to send both copies all arrive this way
	// and are all legitimate.
	t.Run("unmarked and no list is the old behaviour", func(t *testing.T) {
		store := &fakeHostInventoryStore{}
		body := validSubmission(agentID)
		body.Report.Packages = nil
		body.Report.Sections["packages"] = hostinventory.SectionFailed
		delete(body.Observations.DeviceInfo, "packages")

		w := postSubmission(t, newIntakeRouter(store, agentID, tenantID), body)
		if w.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202 — a failed package step is a normal submission: %s",
				w.Code, w.Body.String())
		}
		if store.calls != 1 {
			t.Errorf("store calls = %d, want 1", store.calls)
		}
	})
}

func TestHasPackageList(t *testing.T) {
	if hasPackageList(nil) {
		t.Error("nil observations reported a package list")
	}
	if hasPackageList(&di.InterrogateResult{}) {
		t.Error("observations with no device_info reported a package list")
	}
	if hasPackageList(&di.InterrogateResult{DeviceInfo: map[string]interface{}{}}) {
		t.Error("an empty device_info reported a package list")
	}
	if hasPackageList(&di.InterrogateResult{DeviceInfo: map[string]interface{}{"packages": nil}}) {
		t.Error("an explicit null reported a package list")
	}
	if !hasPackageList(&di.InterrogateResult{DeviceInfo: map[string]interface{}{
		"packages": []map[string]any{{"name": "openssl"}},
	}}) {
		t.Error("a real list was not found")
	}
}

// Without an authenticated agent, or without the tenant AgentAuth derives from
// it, nothing is written. A submission that fell through to a nil tenant would
// write a row belonging to nobody.
func TestHostInventorySubmit_RefusesAnUnauthenticatedCaller(t *testing.T) {
	t.Run("no agent", func(t *testing.T) {
		store := &fakeHostInventoryStore{}
		w := postSubmission(t, newIntakeRouter(store, uuid.Nil, uuid.New()), validSubmission(uuid.New()))
		if w.Code != http.StatusBadRequest || store.calls != 0 {
			t.Fatalf("status = %d, store calls = %d", w.Code, store.calls)
		}
	})

	t.Run("no tenant", func(t *testing.T) {
		agentID := uuid.New()
		store := &fakeHostInventoryStore{}
		w := postSubmission(t, newIntakeRouter(store, agentID, uuid.Nil), validSubmission(agentID))
		if w.Code != http.StatusUnauthorized || store.calls != 0 {
			t.Fatalf("status = %d, store calls = %d", w.Code, store.calls)
		}
	})
}

// The intake re-sanitises rather than trusting that the far end of the wire ran
// the agent version we think it did.
//
// To mutation-test: delete the di.Sanitize call in Submit and this fails.
func TestHostInventorySubmit_ReSanitisesTheSubmission(t *testing.T) {
	agentID, tenantID := uuid.New(), uuid.New()
	store := &fakeHostInventoryStore{}
	body := validSubmission(agentID)
	body.Observations.DeviceInfo["api_key"] = "SHOULD-BE-REDACTED-AT-INTAKE"
	body.Observations.Assets[0].ServiceHints = &di.ServiceHints{
		ServiceName: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
	}

	if w := postSubmission(t, newIntakeRouter(store, agentID, tenantID), body); w.Code != http.StatusAccepted {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	stored := string(store.results)
	if strings.Contains(stored, "SHOULD-BE-REDACTED-AT-INTAKE") {
		t.Error("a secret-named field was stored verbatim")
	}
	if strings.Contains(stored, "BEGIN PRIVATE KEY") {
		t.Error("a PEM block in a process name was stored verbatim")
	}
}

// A storage failure is an error, not a silent drop. An agent that gets a 200
// for a submission that was never written stops retrying.
func TestHostInventorySubmit_AStorageFailureIsReported(t *testing.T) {
	agentID, tenantID := uuid.New(), uuid.New()
	store := &fakeHostInventoryStore{err: errors.New("db is down")}

	w := postSubmission(t, newIntakeRouter(store, agentID, tenantID), validSubmission(agentID))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	// And the internal error text must not reach the client.
	if strings.Contains(w.Body.String(), "db is down") {
		t.Errorf("the internal error leaked to the client: %s", w.Body.String())
	}
}

// An over-cap report is its OWN outcome.
//
// Both an over-cap body and a malformed one used to answer 400 "Invalid
// request", which told the agent nothing it could act on. They are opposite
// kinds of failure: a malformed body is worth retrying after an upgrade, an
// over-cap one will be over-cap again in an hour and every hour after that.
// Collapsed into one status, a host too big to report became a host that
// retried forever and never appeared in the inventory.
//
// To mutation-test: delete the errors.As(err, &tooLarge) branch in Submit and
// the first subtest sees 400 instead of 413.
func TestHostInventorySubmit_AnOverCapReportIs413NotABadRequest(t *testing.T) {
	agentID, tenantID := uuid.New(), uuid.New()

	t.Run("over the cap is 413 and is not stored", func(t *testing.T) {
		store := &fakeHostInventoryStore{}
		// A body that is well-formed JSON and simply too big — the point is
		// that size alone, not malformation, produces this answer.
		big := validSubmission(agentID)
		filler := strings.Repeat("p", 1024)
		for i := 0; i < (maxHostInventoryBytes/1024)+64; i++ {
			big.Report.Packages = append(big.Report.Packages, hostinventory.Package{Name: filler, Manager: "dpkg"})
		}

		w := postSubmission(t, newIntakeRouter(store, agentID, tenantID), big)

		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413 — an over-cap report must be distinguishable from a malformed one", w.Code)
		}
		if store.calls != 0 {
			t.Errorf("an over-cap report was stored anyway (%d call(s))", store.calls)
		}
		// The body has to name the cap and what the caller declared, or the
		// agent cannot say how far over it is and an operator cannot size it.
		var answer map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil {
			t.Fatalf("decode 413 body: %v", err)
		}
		if got, ok := answer["max_bytes"].(float64); !ok || int(got) != maxHostInventoryBytes {
			t.Errorf("413 body does not name the cap: %v", answer["max_bytes"])
		}
		if _, ok := answer["declared_size"]; !ok {
			t.Error("413 body does not say what the caller declared it was sending")
		}
		// And it must say this is not worth retrying, since that is the whole
		// difference from a 400.
		if detail, _ := answer["detail"].(string); !strings.Contains(detail, "not a transient failure") {
			t.Errorf("413 body does not tell the caller this will not fix itself: %q", detail)
		}
	})

	t.Run("a malformed body is still 400", func(t *testing.T) {
		store := &fakeHostInventoryStore{}
		req := httptest.NewRequest(http.MethodPost, "/agents/host-inventory",
			strings.NewReader(`{"mode": "local", "report": {` /* truncated on purpose */))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		newIntakeRouter(store, agentID, tenantID).ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 — a malformed body must not be reported as an over-cap one", w.Code)
		}
	})

	t.Run("a submission comfortably under the cap is still accepted", func(t *testing.T) {
		store := &fakeHostInventoryStore{}
		w := postSubmission(t, newIntakeRouter(store, agentID, tenantID), validSubmission(agentID))
		if w.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202", w.Code)
		}
	})
}

// The cap has to sit above what the collector's own ceilings can legally
// produce, or it is not a bound on abuse — it is a silent per-host outage.
//
// Measured on a real Ubuntu 24.04 collection, the package list cost 443 bytes
// per package across the whole submission — of which exactly half was the
// DUPLICATE copy in `report.packages`, because the observations' projection
// enumerates every field a Package has. 2.11b drops that copy at the wire
// (device-agent's withoutPackageList), so the per-package cost is half what it
// was and the headroom over the worst legal collection roughly doubles.
//
// The trust-store summary still rides twice at 584 bytes per certificate, and
// deliberately: three stores of 500 is an order of magnitude less than 20,000
// packages, and the report's copy is the half a hygiene finding will read
// (BUILD_PLAN 3.5).
func TestMaxHostInventoryBytes_ClearsTheCollectorsOwnCeilings(t *testing.T) {
	const (
		bytesPerPackage = 222 // one copy; was 443 for two
		bytesPerCert    = 584
		maxPackages     = 20000 // hostinventory.defaultMaxPackages
		maxCerts        = 500 * 3
	)
	worstLegal := bytesPerPackage*maxPackages + bytesPerCert*maxCerts

	if maxHostInventoryBytes <= worstLegal {
		t.Fatalf("the cap (%d) is below the worst LEGAL collection (%d); a host at the collector's own "+
			"limits could never report, and would retry forever", maxHostInventoryBytes, worstLegal)
	}
	if ratio := float64(maxHostInventoryBytes) / float64(worstLegal); ratio < 2 {
		t.Errorf("headroom is only x%.2f over the worst legal collection; package names, versions and "+
			"purls are longer on some distributions than the one that was measured", ratio)
	}
}

func storedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
