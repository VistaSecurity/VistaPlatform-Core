package handlers

import (
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// DiscoveryHandler provides endpoints for discovery jobs.
type DiscoveryHandler struct {
	svc    *services.DiscoveryService
	assets *services.AssetService
	db     *database.DB
}

func NewDiscoveryHandler(assetSvc *services.AssetService, discoverySvc *services.DiscoveryService) *DiscoveryHandler {
	return &DiscoveryHandler{svc: discoverySvc, assets: assetSvc}
}

// SetDB sets the database connection for capability policy queries.
func (h *DiscoveryHandler) SetDB(db *database.DB) {
	h.db = db
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
			"protocols": input.Protocols,
			"ports":     input.Ports,
		})
	}

	c.JSON(http.StatusAccepted, gin.H{"job": job})
}

// GetJob handles GET /api/v1/inventory/discovery/jobs/:id
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
	for _, raw := range rawBody.Findings {
		var csf services.ClusterSensorFinding
		if err := json.Unmarshal(raw, &csf); err != nil {
			log.Printf("[DiscoveryHandler] IngestPipelineFindings: skipping malformed finding: %v", err)
			continue
		}
		findings = append(findings, csf.ToIngestFinding())
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

	imported, err := h.assets.IngestFindings(tenantUUID, findings, assetStatus)
	if err != nil {
		log.Printf("[DiscoveryHandler] IngestPipelineFindings failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ingest_failed"})
		return
	}

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

	c.JSON(http.StatusOK, gin.H{"imported": imported})
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

// GetCapabilities returns the tenant's capability policy for the discovery
// wizard. Regular tenant users can call this to determine which scanning
// features their tenant admin has enabled or disabled.
func (h *DiscoveryHandler) GetCapabilities(c *gin.Context) {
	tenantIDVal, _ := c.Get("tenantID")
	tenantIDStr := ""
	if tenantID, ok := tenantIDVal.(uuid.UUID); ok {
		tenantIDStr = tenantID.String()
	} else if s, ok := tenantIDVal.(string); ok {
		tenantIDStr = s
	}
	if tenantIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant ID required"})
		return
	}

	// Default capabilities — everything enabled
	capabilities := map[string]interface{}{
		"active_scanning":         true,
		"tls_version_enumeration": true,
		"ssh_probing":             true,
	}

	if h.db == nil {
		// No DB available — return defaults
		c.JSON(http.StatusOK, gin.H{"capabilities": capabilities})
		return
	}

	// Read tenant_admin_settings (RLS-scoped, filtered by tenant_id) to check for
	// capability policy overrides — scope the read to this tenant under RLS.
	tenantUUID, parseErr := uuid.Parse(tenantIDStr)
	if parseErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant ID"})
		return
	}
	var configJSON []byte
	err := database.WithTenantTx(c.Request.Context(), h.db, tenantUUID, func(tx *sqlx.Tx) error {
		row := tx.QueryRow(`SELECT config FROM tenant_admin_settings WHERE tenant_id = $1`, tenantIDStr)
		if scanErr := row.Scan(&configJSON); scanErr != nil && scanErr != sql.ErrNoRows {
			return scanErr
		}
		return nil
	})

	if err == nil && len(configJSON) > 0 {
		var config map[string]interface{}
		if json.Unmarshal(configJSON, &config) == nil {
			if policy, ok := config["capability_policy"].(map[string]interface{}); ok {
				// Override defaults with tenant policy values
				for key, val := range policy {
					switch v := val.(type) {
					case bool:
						capabilities[key] = v
					case []interface{}:
						capabilities[key] = v
					}
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"capabilities": capabilities})
}

// userCanUpdateCapabilityPolicy returns true if the caller may change tenant discovery capabilities.
func (h *DiscoveryHandler) userCanUpdateCapabilityPolicy(c *gin.Context, tenantID, userID uuid.UUID) (bool, error) {
	if internal, ok := c.Get("isInternalCall"); ok {
		if b, ok := internal.(bool); ok && b {
			return true, nil
		}
	}
	if roleVal, ok := c.Get("role"); ok {
		if roleStr, ok := roleVal.(string); ok {
			rl := strings.ToLower(roleStr)
			if strings.Contains(rl, "platform") || strings.Contains(rl, "super_admin") {
				return true, nil
			}
		}
	}
	// RLS-scoped tables (user_tenant_roles, tenant_roles) filtered by r.tenant_id —
	// scope the read to this tenant under RLS.
	var allowed bool
	err := database.WithTenantTx(c.Request.Context(), h.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`
			SELECT EXISTS (
				SELECT 1
				FROM user_tenant_roles ur
				JOIN tenant_roles r ON r.id = ur.role_id
				WHERE ur.user_id = $1 AND r.tenant_id = $2 AND ur.is_active = true
				  AND r.name IN ('tenant_admin', 'security_admin')
			)`, userID, tenantID).Scan(&allowed)
	})
	if err != nil {
		return false, err
	}
	return allowed, nil
}

// UpdateCapabilities saves the tenant's capability policy. This is called
// from the sensor configuration page by tenant admins.
func (h *DiscoveryHandler) UpdateCapabilities(c *gin.Context) {
	tenantIDVal, _ := c.Get("tenantID")
	userIDVal, _ := c.Get("userID")
	tenantUUID, tenantOK := tenantIDVal.(uuid.UUID)
	userUUID, userOK := userIDVal.(uuid.UUID)
	if !tenantOK || !userOK {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant ID and user ID required"})
		return
	}
	tenantIDStr := tenantUUID.String()
	userIDStr := userUUID.String()

	if h.db == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not available"})
		return
	}

	allowed, err := h.userCanUpdateCapabilityPolicy(c, tenantUUID, userUUID)
	if err != nil {
		log.Printf("[DiscoveryHandler] capability policy auth check failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify permissions"})
		return
	}
	if !allowed {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions to update capability policy"})
		return
	}

	var req struct {
		Capabilities map[string]interface{} `json:"capabilities"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	// Read current config — tenant_admin_settings is RLS-scoped (filtered by
	// tenant_id); scope the read to this tenant under RLS.
	var configJSON []byte
	var currentVersion int
	err = database.WithTenantTx(c.Request.Context(), h.db, tenantUUID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(
			`SELECT config, version FROM tenant_admin_settings WHERE tenant_id = $1`,
			tenantIDStr,
		).Scan(&configJSON, &currentVersion)
	})

	config := map[string]interface{}{}
	if err == nil && len(configJSON) > 0 {
		_ = json.Unmarshal(configJSON, &config)
	}

	// Merge capabilities into capability_policy
	config["capability_policy"] = req.Capabilities

	newConfigJSON, err := json.Marshal(config)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to marshal config"})
		return
	}

	// Upsert with version bump — tenant_admin_settings is RLS-scoped; scope the
	// write to this tenant so the INSERT satisfies the RLS WITH CHECK predicate.
	var newVersion int
	upsertQuery := `
		INSERT INTO tenant_admin_settings (tenant_id, config, version, updated_by, created_at, updated_at)
		VALUES ($1, $2, 1, $3, NOW(), NOW())
		ON CONFLICT (tenant_id) DO UPDATE
		SET config = EXCLUDED.config,
			version = tenant_admin_settings.version + 1,
			updated_by = EXCLUDED.updated_by,
			updated_at = NOW()
		RETURNING version`

	err = database.WithTenantTx(c.Request.Context(), h.db, tenantUUID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(upsertQuery, tenantIDStr, newConfigJSON, userIDStr).Scan(&newVersion)
	})
	if err != nil {
		log.Printf("[DiscoveryHandler] Failed to save capability policy: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save capability policy"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      "capability policy updated",
		"capabilities": req.Capabilities,
		"version":      newVersion,
	})
}
