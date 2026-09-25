package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// DiscoveryHandler provides endpoints for discovery jobs.
type DiscoveryHandler struct {
	svc    *services.DiscoveryService
	assets *services.AssetService
}

func NewDiscoveryHandler(assetSvc *services.AssetService, discoverySvc *services.DiscoveryService) *DiscoveryHandler {
	return &DiscoveryHandler{svc: discoverySvc, assets: assetSvc}
}

// CreateJob handles POST /api/v1/inventory/discovery/jobs
func (h *DiscoveryHandler) CreateJob(c *gin.Context) {
	tenantIDVal, _ := c.Get("tenantID")
	userIDVal, _ := c.Get("userID")

	var input models.CreateDiscoveryJobInput
	if err := c.ShouldBindJSON(&input); err != nil {
		// Log the actual error for debugging
		log.Printf("[DiscoveryHandler] JSON binding error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	log.Printf("[DiscoveryHandler] Received discovery job request: targets=%v, execution_mode=%s, protocols=%v, ports=%v",
		input.Targets, input.ExecutionMode, input.Protocols, input.Ports)

	// Validate required fields
	if len(input.Targets) == 0 {
		log.Printf("[DiscoveryHandler] Validation error: no targets provided")
		c.JSON(http.StatusBadRequest, gin.H{"error": "validation_error", "details": "at least one target is required"})
		return
	}

	// Tenant-sensor dispatch. cluster-sensor-service dispatches a
	// `sensors` job to the one tenant sensor it names and decides whether that
	// sensor exists, is the tenant's and is live. What is refused HERE is the
	// request shape no dispatcher can honour, so the message stays specific:
	// this proxy otherwise collapses downstream errors into one line.
	if details := validateSensorDispatchShape(input.ExecutionMode, input.PreferredSensorIDs); details != "" {
		log.Printf("[DiscoveryHandler] Rejected sensor dispatch request: execution_mode=%q preferred_sensor_ids=%d: %s",
			input.ExecutionMode, len(input.PreferredSensorIDs), details)
		c.JSON(http.StatusBadRequest, gin.H{"error": "validation_error", "details": details})
		return
	}

	// Convert tenantID and userID from UUID to string
	tenantIDStr := ""
	if tenantID, ok := tenantIDVal.(uuid.UUID); ok {
		tenantIDStr = tenantID.String()
		log.Printf("[DiscoveryHandler] Converted tenantID from UUID: %s", tenantIDStr)
	} else if tenantIDStrVal, ok := tenantIDVal.(string); ok {
		tenantIDStr = tenantIDStrVal
		log.Printf("[DiscoveryHandler] Using tenantID as string: %s", tenantIDStr)
	} else {
		log.Printf("[DiscoveryHandler] Invalid tenantID type: %T, value: %v", tenantIDVal, tenantIDVal)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_tenant"})
		return
	}

	userIDStr := ""
	if userID, ok := userIDVal.(uuid.UUID); ok {
		userIDStr = userID.String()
		log.Printf("[DiscoveryHandler] Converted userID from UUID: %s", userIDStr)
	} else if userIDStrVal, ok := userIDVal.(string); ok {
		userIDStr = userIDStrVal
		log.Printf("[DiscoveryHandler] Using userID as string: %s", userIDStr)
	} else {
		log.Printf("[DiscoveryHandler] Invalid userID type: %T, value: %v", userIDVal, userIDVal)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_user"})
		return
	}

	// Forward request to cluster-sensor-service
	// This is a proxy to maintain API consistency
	// The actual job processing happens in cluster-sensor-service
	job, err := h.svc.CreateJob(tenantIDStr, userIDStr, input, clusterAuthHeader(c))
	if err != nil {
		log.Printf("[DiscoveryHandler] CreateJob service error: %v", err)
		// A downstream 4xx is a verdict the caller can act on — the sensor
		// they named is unknown (404), offline (409) or the platform's own
		// (400) — so it passes through with its reason. Anything else stays
		// the generic line: a 5xx body is not a reason a caller can act on.
		var downstream *services.DownstreamError
		if errors.As(err, &downstream) && downstream.Status >= 400 && downstream.Status < 500 {
			// A target-authorization verdict keeps its code and its target
			// lists ( W5.13b): the UI branches on the code — ask for
			// confirmation, explain the operator switch, show why each
			// refused target can never be scanned — and needs the lists
			// verbatim to do it.
			if downstream.Code != "" {
				resp := gin.H{"error": downstream.Code, "details": downstream.Message}
				if len(downstream.ExternalTargets) > 0 {
					resp["external_targets"] = downstream.ExternalTargets
				}
				if len(downstream.RefusedTargets) > 0 {
					resp["refused_targets"] = downstream.RefusedTargets
				}
				c.JSON(downstream.Status, resp)
				return
			}
			c.JSON(downstream.Status, gin.H{"error": "validation_error", "details": downstream.Message})
			return
		}
		sharedapi.BadRequest(c, "failed to create discovery job")
		return
	}

	// Log audit event
	if jobID, err := uuid.Parse(job.ID); err == nil {
		resourceType := "discovery_job"
		logAuditActivity(c, "discovery.job.created", "discovery", "create", &resourceType, &jobID, nil, map[string]interface{}{
			"execution_mode": input.ExecutionMode,
			"target_count":   len(input.Targets),
			"status":         job.Status,
		}, []string{}, map[string]interface{}{
			"protocols":        input.Protocols,
			"ports":            input.Ports,
			"external_targets": job.ExternalTargets,
		})
	}

	// cluster-sensor-service's create response carries neither list, and a
	// nil slice re-marshals as null — which DiscoveryJob in the spec does not
	// allow. Found by the create-response contract test ( W5.13b).
	if job.Targets == nil {
		job.Targets = input.Targets
	}
	if job.RequestedSensorIDs == nil {
		job.RequestedSensorIDs = []string{}
	}
	c.JSON(http.StatusAccepted, gin.H{"job": job})
}

// validateSensorDispatchShape returns a reason when the request asks for a
// tenant sensor in a shape no dispatcher can honour, and "" when it is either
// not a sensor request or a well-formed one. Whether the sensor exists, is the
// tenant's and is live is cluster-sensor-service's decision, not this proxy's.
func validateSensorDispatchShape(executionMode string, preferredSensorIDs []string) string {
	sensors := strings.EqualFold(strings.TrimSpace(executionMode), "sensors")
	switch {
	case !sensors && len(preferredSensorIDs) > 0:
		return "preferred_sensor_ids only applies to execution_mode \"sensors\""
	case !sensors:
		return ""
	case len(preferredSensorIDs) != 1:
		return "execution_mode \"sensors\" needs exactly one preferred_sensor_id — the tenant sensor to run from"
	}
	if _, err := uuid.Parse(strings.TrimSpace(preferredSensorIDs[0])); err != nil {
		return "preferred_sensor_id \"" + preferredSensorIDs[0] + "\" is not a UUID"
	}
	return ""
}

// clusterAuthHeader returns a Bearer token suitable for forwarding to cluster-sensor-service.
// It prefers an explicit Authorization header and falls back to the access_token cookie,
// which is how cookie-based browser sessions authenticate.
func clusterAuthHeader(c *gin.Context) string {
	if h := c.GetHeader("Authorization"); h != "" {
		return h
	}
	if cookie, err := c.Cookie("access_token"); err == nil && cookie != "" {
		return "Bearer " + cookie
	}
	return ""
}

// ListJobs handles GET /discovery/jobs — the tenant's discovery jobs (Active
// Scan, the Discover wizard, and the automatic-scan sweep) with their
// executor and dispatch timeline, proxied from cluster-sensor-service. This is
// what the unified Discovery → Discovery Jobs page merges with
// device-interrogation-service's device_jobs (morning-notes decision 7b).
//
// A near-identical proxy existed briefly under and was removed same-day
// (93edc38b) because nothing rendered it yet — that was a reachability
// violation, not a design flaw in the endpoint itself. It is restored here
// with its consumer landing in the same change.
func (h *DiscoveryHandler) ListJobs(c *gin.Context) {
	url := h.svc.GetClusterSensorURL() + "/api/v1/discovery/jobs"
	if q := c.Request.URL.Query(); len(q) > 0 {
		url += "?" + q.Encode()
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create request"})
		return
	}
	req.Header.Set("Authorization", clusterAuthHeader(c))

	resp, err := h.svc.GetHTTPClient().Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to call cluster-sensor-service"})
		return
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read response"})
		return
	}
	c.Data(resp.StatusCode, "application/json", body)
}

// GetJob handles GET /api/v1/inventory/discovery/jobs/:id
func (h *DiscoveryHandler) GetJob(c *gin.Context) {
	jobID := c.Param("id")

	// Proxy request to cluster-sensor-service using service's HTTP client
	url := h.svc.GetClusterSensorURL() + "/api/v1/discovery/jobs/" + jobID
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create request"})
		return
	}

	req.Header.Set("Authorization", clusterAuthHeader(c))

	client := h.svc.GetHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to call cluster-sensor-service"})
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read response"})
		return
	}

	// Forward the response with the same status code
	c.Data(resp.StatusCode, "application/json", body)
}

// GetJobResults handles GET /api/v1/inventory/discovery/jobs/:id/results
func (h *DiscoveryHandler) GetJobResults(c *gin.Context) {
	log.Printf("[DiscoveryHandler] GetJobResults called for job ID: %s", c.Param("id"))
	jobID := c.Param("id")

	// Build query string from request
	queryParams := c.Request.URL.Query()
	url := h.svc.GetClusterSensorURL() + "/api/v1/discovery/jobs/" + jobID + "/results"
	if len(queryParams) > 0 {
		url += "?" + queryParams.Encode()
	}

	// Proxy request to cluster-sensor-service
	log.Printf("[DiscoveryHandler] Proxying request to: %s", url)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("[DiscoveryHandler] Failed to create request: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create request"})
		return
	}

	req.Header.Set("Authorization", clusterAuthHeader(c))

	resp, err := h.svc.GetHTTPClient().Do(req)
	if err != nil {
		log.Printf("[DiscoveryHandler] Failed to call cluster-sensor-service: %v", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to call cluster-sensor-service"})
		return
	}
	defer func() { _ = resp.Body.Close() }()

	log.Printf("[DiscoveryHandler] cluster-sensor-service response status: %d", resp.StatusCode)

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[DiscoveryHandler] Failed to read response: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read response"})
		return
	}

	// Log response body length and first 500 chars for debugging
	bodyStr := string(body)
	log.Printf("[DiscoveryHandler] Response body length: %d bytes", len(bodyStr))
	if len(bodyStr) > 500 {
		log.Printf("[DiscoveryHandler] Response body (first 500 chars): %s...", bodyStr[:500])
	} else {
		log.Printf("[DiscoveryHandler] Response body: %s", bodyStr)
	}

	// Try to parse JSON to check for data field
	var jsonData map[string]interface{}
	if err := json.Unmarshal(body, &jsonData); err == nil {
		if findings, ok := jsonData["findings"].([]interface{}); ok {
			log.Printf("[DiscoveryHandler] Found %d findings in response", len(findings))
			for i, finding := range findings {
				if i >= 2 { // Only log first 2
					break
				}
				if fMap, ok := finding.(map[string]interface{}); ok {
					hasData := fMap["data"] != nil
					dataKeys := []string{}
					if data, ok := fMap["data"].(map[string]interface{}); ok {
						for k := range data {
							dataKeys = append(dataKeys, k)
						}
					}
					log.Printf("[DiscoveryHandler] Finding %d: protocol=%v, port=%v, hasData=%v, dataKeys=%v",
						i, fMap["protocol"], fMap["port"], hasData, dataKeys)
				}
			}
		}
	}

	// Forward the response with the same status code
	c.Data(resp.StatusCode, "application/json", body)
}

// ingestFindingsBody is the wire shape of the internal ingestion transport.
//
// Two-phase bind: findings arrive as raw JSON and are mapped through the typed
// ClusterSensorFinding adapter, because cluster-sensor-service emits a shape that
// differs from IngestFinding ("data" vs "raw_data", "resolved_ip" vs
// "ip_address", crypto fields nested in "data"); the adapter normalises it in one
// tested place (see services/discovery_ingest_adapter.go).
//
// There is deliberately NO auto_approve field. It used to exist and be honoured,
// which is how a tenant-facing caller could promote its own assets.
type ingestFindingsBody struct {
	Findings []json.RawMessage `json:"findings"`
	// AssetStatus carries discovery-processor's already-evaluated decision.
	AssetStatus *string `json:"asset_status,omitempty"`
}

// resolveIngestedAssetStatus turns the transported status into the one this
// service acts on.
//
// Default deny. Only "monitoring" — the outcome of an auto-approval rule
// discovery-processor matched before this call — moves off pending_approval;
// anything else falls back rather than being trusted verbatim, so the transport
// cannot introduce a status of its own.
func resolveIngestedAssetStatus(supplied *string) string {
	if supplied != nil && *supplied == "monitoring" {
		return "monitoring"
	}
	return "pending_approval"
}

// IngestPipelineFindings handles POST /api/v1/inventory-service/discovery/jobs/:id/import.
//
// INTERNAL ONLY. This is the transport discovery-processor-service uses to hand
// inventory-service a batch of findings it has ALREADY classified and run the
// tenant's segment auto-approval rules over (see batch_processor.go) — the
// asset_status in the body is that server-side decision in flight between two
// services, not a caller's request.
//
// It used to double as a tenant-facing endpoint: the Discover wizard fetched a
// job's results into the browser and POSTed them back, and the body's
// `auto_approve` / `asset_status` were honoured for that caller too — so anyone
// holding discovery.create could post `auto_approve: true` and inject assets
// straight to `monitoring`, bypassing the tenant's own approval policy. The
// wizard path is gone (findings are mirrored server-side now) and this handler
// rejects anything that is not an HMAC-verified internal service call.
//
// `auto_approve` is no longer read at all, from any caller.
func (h *DiscoveryHandler) IngestPipelineFindings(c *gin.Context) {
	// The gateway exposes /api/v1/inventory-service/* wholesale, so this route is
	// reachable from a browser. The guard — not the route table — is what makes it
	// internal.
	if !sharedmw.IsInternalCall(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "internal_only"})
		return
	}

	tenantIDVal, _ := c.Get("tenantID")

	// Two-phase bind: accept findings as raw JSON, then map each through the
	// typed ClusterSensorFinding adapter. cluster-sensor-service emits a wire
	// shape that differs from IngestFinding ("data" vs "raw_data", "resolved_ip"
	// vs "ip_address", crypto fields nested in "data"); the adapter normalises
	// it in one tested place (see services/discovery_ingest_adapter.go).
	var rawBody ingestFindingsBody
	if err := c.ShouldBindJSON(&rawBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	findings := make([]services.IngestFinding, 0, len(rawBody.Findings))
	// Where each accepted finding sat in the REQUEST. A malformed one is
	// skipped, so the two slices are not the same length, and the caller reads
	// the per-finding statuses below by its own index — an off-by-one here would
	// stamp one discovery row with another's outcome.
	requestIndex := make([]int, 0, len(rawBody.Findings))
	for i, raw := range rawBody.Findings {
		var csf services.ClusterSensorFinding
		if err := json.Unmarshal(raw, &csf); err != nil {
			log.Printf("[DiscoveryHandler] IngestPipelineFindings: skipping malformed finding: %v", err)
			continue
		}
		findings = append(findings, csf.ToIngestFinding())
		requestIndex = append(requestIndex, i)
	}

	// tenantID is stored as uuid.UUID in context by JWT middleware
	tenantUUID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_tenant"})
		return
	}

	log.Printf("[DiscoveryHandler] IngestPipelineFindings: received %d findings for batch %s", len(findings), c.Param("id"))
	if len(findings) > 0 {
		log.Printf("[DiscoveryHandler] First finding sample: hostname=%v, ip_address=%v, port=%v, protocol=%v, cipher_suite=%v",
			findings[0].Hostname, findings[0].IPAddress, findings[0].Port,
			findings[0].Protocol, findings[0].CipherSuite)
	}

	assetStatus := resolveIngestedAssetStatus(rawBody.AssetStatus)

	report, err := h.assets.IngestFindingsReport(tenantUUID, findings, assetStatus)
	if err != nil {
		log.Printf("[DiscoveryHandler] IngestPipelineFindings failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ingest_failed"})
		return
	}
	imported := report.Imported

	log.Printf("[DiscoveryHandler] IngestPipelineFindings: ingested %d findings (status=%s)", imported, assetStatus)

	// Log audit event
	jobIDStr := c.Param("id")
	if jobUUID, err := uuid.Parse(jobIDStr); err == nil {
		resourceType := "discovery_job"
		logAuditActivity(c, "discovery.finding.imported", "discovery", "import", &resourceType, &jobUUID, nil, map[string]interface{}{
			"findings_count": len(findings),
			"imported_count": imported,
		}, []string{}, nil)
	}

	// `asset_statuses` is index-aligned with the REQUEST's findings, and is what
	// lets discovery-processor stamp a discovery row with what actually happened
	// to it rather than with what it asked for. A finding that landed on no
	// asset — skipped, held by a merge proposal, routed to external_connections
	// — reports the empty string, which the caller leaves alone.
	c.JSON(http.StatusOK, gin.H{
		"imported":       imported,
		"asset_statuses": alignToRequest(len(rawBody.Findings), requestIndex, report.EffectiveStatus),
		"results":        alignResultsToRequest(len(rawBody.Findings), requestIndex, report.Results),
	})
}

// alignToRequest maps a per-finding result from the slice IngestFindingsReport
// saw back onto the slice the caller sent, filling the gaps left by findings
// this handler could not parse.
func alignResultsToRequest(requested int, requestIndex []int, results []identity.IngestResult) []identity.IngestResult {
	out := make([]identity.IngestResult, requested)
	for i := range out {
		out[i].Outcome = "rejected"
	}
	for i, result := range results {
		if i < len(requestIndex) && requestIndex[i] >= 0 && requestIndex[i] < requested {
			out[requestIndex[i]] = result
		}
	}
	return out
}

func alignToRequest(requested int, requestIndex []int, statuses []string) []string {
	out := make([]string, requested)
	for i, status := range statuses {
		if i >= len(requestIndex) {
			break
		}
		if at := requestIndex[i]; at >= 0 && at < requested {
			out[at] = status
		}
	}
	return out
}

// CancelJob handles POST /api/v1/inventory/discovery/jobs/:id/cancel
func (h *DiscoveryHandler) CancelJob(c *gin.Context) {
	jobIDStr := c.Param("id")

	c.JSON(http.StatusOK, gin.H{
		"message": "Job cancelled",
	})

	// Log audit event
	if jobUUID, err := uuid.Parse(jobIDStr); err == nil {
		resourceType := "discovery_job"
		logAuditActivity(c, "discovery.job.cancelled", "discovery", "cancel", &resourceType, &jobUUID, nil, map[string]interface{}{
			"status": "cancelled",
		}, []string{"status"}, nil)
	}
}

// RerunJob handles POST /api/v1/inventory/discovery/jobs/:id/rerun
func (h *DiscoveryHandler) RerunJob(c *gin.Context) {
	c.JSON(http.StatusAccepted, gin.H{
		"message": "Job rerun initiated",
	})
}
