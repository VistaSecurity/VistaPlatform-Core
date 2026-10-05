package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/config"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

type DiscoveryService struct {
	httpClient       *http.Client
	clusterSensorURL string
}

// GetHTTPClient returns the HTTP client (for use by handlers)
func (s *DiscoveryService) GetHTTPClient() *http.Client {
	return s.httpClient
}

// GetClusterSensorURL returns the cluster sensor service URL (for use by handlers)
func (s *DiscoveryService) GetClusterSensorURL() string {
	return s.clusterSensorURL
}

func NewDiscoveryService(cfg *config.Config) (*DiscoveryService, error) {
	clusterSensorURL := os.Getenv("CLUSTER_SENSOR_SERVICE_URL")
	if clusterSensorURL == "" {
		// Use HTTPS with mTLS port if mTLS is enabled
		if cfg.UseMTLS {
			clusterSensorURL = "https://cluster-sensor-service:8443"
		} else {
			clusterSensorURL = sharedconfig.PeerURL("cluster-sensor-service", sharedconfig.MTLSEnabled())
		}
	} else {
		// Update URL to use HTTPS and port 8443 if mTLS is enabled
		if cfg.UseMTLS {
			clusterSensorURL = strings.Replace(clusterSensorURL, "http://", "https://", 1)
			clusterSensorURL = strings.Replace(clusterSensorURL, ":8080", ":8443", 1)
		}
	}

	var httpClient *http.Client
	var err error
	if cfg.UseMTLS {
		httpClient, err = sharedhttp.NewMTLSClient(
			cfg.ClientCertPath,
			cfg.ClientKeyPath,
			cfg.PlatformCACertPath,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create mTLS client: %w", err)
		}
		// Override timeout
		httpClient.Timeout = 30 * time.Second
	} else {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	return &DiscoveryService{
		httpClient:       httpClient,
		clusterSensorURL: clusterSensorURL,
	}, nil
}

// CreateJobInternal dispatches a discovery job with no person behind it.
//
// The automatic active-scan sweep runs on a ticker in this service: there is no
// browser, no cookie and no Authorization header to forward. It authenticates
// with the platform's HMAC service-auth instead (the same
// `serviceauth.SignRequestFromEnv` every other peer-to-peer call uses) and
// names the tenant in `X-Tenant-ID`, which is how cluster-sensor-service's auth
// middleware resolves the tenant for an internal call.
//
// It fails CLOSED at the other end: with INTERNAL_AUTH_SECRET unset,
// cluster-sensor builds no internal verifier and the call is rejected as
// unauthenticated rather than let through.
func (s *DiscoveryService) CreateJobInternal(tenantID string, input models.CreateDiscoveryJobInput) (*models.DiscoveryJob, error) {
	return s.createJob(tenantID, input, func(req *http.Request) {
		req.Header.Set("X-Tenant-ID", tenantID)
		serviceauth.SignRequestFromEnv(req)
	})
}

func (s *DiscoveryService) CreateJob(tenantID string, userID string, input models.CreateDiscoveryJobInput, authHeader string) (*models.DiscoveryJob, error) {
	return s.createJob(tenantID, input, func(req *http.Request) {
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
	})
}

// PreviewJob forwards a dry run ( WP3b): the same request, with
// `dry_run`, to the same cluster-sensor-service endpoint. The answer is the
// plan, a time estimate and whether external targets still need confirming;
// nothing is created, so nothing is audited as a created job. Refusals come
// back as the *DownstreamError a real create's refusal does.
func (s *DiscoveryService) PreviewJob(tenantID string, input models.CreateDiscoveryJobInput, authHeader string) (*shareddisc.ScanPreview, error) {
	status, body, err := s.postJob(tenantID, input, true, func(req *http.Request) {
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
	})
	if err != nil {
		return nil, err
	}
	if status == http.StatusAccepted {
		// A cluster-sensor-service that predates dry_run ignores the flag and
		// CREATES the job. That is a version skew during a rolling upgrade, not
		// a preview; say so loudly rather than report a refusal.
		log.Printf("[DiscoveryService] cluster-sensor-service answered a dry run with 202 Accepted: it does not support dry_run and CREATED a job (version skew): %s", string(body))
		return nil, fmt.Errorf("cluster-sensor-service does not support dry_run")
	}
	if status != http.StatusOK {
		derr := &DownstreamError{Status: status, Message: downstreamMessage(body), Body: string(body)}
		derr.parseTargetVerdict(body)
		return nil, derr
	}
	var preview shareddisc.ScanPreview
	if err := json.Unmarshal(body, &preview); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &preview, nil
}

func (s *DiscoveryService) createJob(tenantID string, input models.CreateDiscoveryJobInput, authorize func(*http.Request)) (*models.DiscoveryJob, error) {
	status, body, err := s.postJob(tenantID, input, false, authorize)
	if err != nil {
		return nil, err
	}
	if status != http.StatusAccepted {
		derr := &DownstreamError{Status: status, Message: downstreamMessage(body), Body: string(body)}
		derr.parseTargetVerdict(body)
		return nil, derr
	}

	// Parse response - cluster-sensor-service returns { "job": {...} }
	var response struct {
		Job models.DiscoveryJob `json:"job"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response.Job, nil
}

// postJob sends the job request to cluster-sensor-service and returns the
// status and body it answered with. A real create and a dry run build the
// same payload — dryRun only adds the flag.
func (s *DiscoveryService) postJob(tenantID string, input models.CreateDiscoveryJobInput, dryRun bool, authorize func(*http.Request)) (int, []byte, error) {
	if len(input.Targets) == 0 {
		return 0, nil, fmt.Errorf("at least one target is required")
	}
	if len(input.Targets) > 1000 {
		return 0, nil, fmt.Errorf("too many targets; limit is 1000 per job")
	}

	// Map input to cluster-sensor-service request format
	ports := input.Ports
	if ports == nil {
		ports = []int{}
	}
	protocols := input.Protocols
	if protocols == nil {
		protocols = []string{}
	}

	requestPayload := map[string]interface{}{
		"targets":              input.Targets,
		"execution_mode":       input.ExecutionMode,
		"preferred_sensor_ids": input.PreferredSensorIDs,
		"retention_cap_mb":     valueOrDefault(input.RetentionCapMB, 25),
		"retention_ttl_hours":  valueOrDefault(input.RetentionTTLHours, 24),
		"ports":                ports,
		"protocols":            protocols,
	}
	if input.Options != nil {
		requestPayload["options"] = input.Options
	}
	if input.ExternalTargetsConfirmed {
		requestPayload["external_targets_confirmed"] = true
	}
	// The explicit OT opt-in: cluster-sensor-service always accepted it, and
	// this proxy never sent it, so OT probing was unreachable from the UI.
	if len(input.OTProbeProtocols) > 0 {
		requestPayload["ot_probe_protocols"] = input.OTProbeProtocols
	}
	// Scan-plan fields ( WP3), only when set, so a legacy request is
	// forwarded exactly as before.
	for key, value := range map[string]string{
		"scan_depth": input.ScanDepth, "tcp_ports": input.TCPPorts, "udp_ports": input.UDPPorts,
		"pace": input.Pace, "run_from": input.RunFrom, "sensor_id": input.SensorID,
	} {
		if value != "" {
			requestPayload[key] = value
		}
	}

	if dryRun {
		requestPayload["dry_run"] = true
	}

	// Convert to JSON
	jsonData, err := json.Marshal(requestPayload)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Log the payload being sent for debugging
	fmt.Printf("[DiscoveryService] Sending payload to cluster-sensor-service: %s\n", string(jsonData))

	// Make HTTP request to cluster-sensor-service
	// Note: We need the Authorization header from the original request, but we don't have access to it here
	// The handler should pass it through, or we need to restructure this
	req, err := http.NewRequest("POST", s.clusterSensorURL+"/api/v1/discovery/jobs", bytes.NewBuffer(jsonData))
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	// Headers that are part of the signed message must be set BEFORE signing —
	// serviceauth folds X-Tenant-ID and the body hash into the HMAC.
	authorize(req)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to call cluster-sensor-service: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read response: %w", err)
	}
	return resp.StatusCode, body, nil
}

// CancelJob asks cluster-sensor-service to cancel the caller's job. The
// caller's own credential is forwarded, so the tenant check — and the 404 that
// makes another tenant's job indistinguishable from a missing one — is
// cluster-sensor's, not a second opinion here. A non-2xx answer comes back as
// a *DownstreamError; nil means cluster-sensor confirmed the cancel.
func (s *DiscoveryService) CancelJob(jobID, authHeader string) error {
	return s.postJobAction(jobID, "cancel", authHeader)
}

// RetryJob asks cluster-sensor-service to re-queue the caller's job. Same
// contract as CancelJob.
func (s *DiscoveryService) RetryJob(jobID, authHeader string) error {
	return s.postJobAction(jobID, "retry", authHeader)
}

func (s *DiscoveryService) postJobAction(jobID, action, authHeader string) error {
	req, err := http.NewRequest(http.MethodPost, s.clusterSensorURL+"/api/v1/discovery/jobs/"+url.PathEscape(jobID)+"/"+action, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call cluster-sensor-service: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &DownstreamError{Status: resp.StatusCode, Message: downstreamMessage(body), Body: string(body)}
	}
	return nil
}

// DownstreamError is cluster-sensor-service's non-2xx answer to a job request,
// kept with its status so a 4xx verdict — an unknown, offline or undispatchable
// sensor — can reach the caller with the reason instead of collapsing
// into "failed to create discovery job".
type DownstreamError struct {
	Status  int
	Message string
	Body    string
	// Target-authorization verdicts ( W5.13b) carry a machine-readable
	// code and the targets concerned, which the UI needs verbatim: the
	// confirmation dialog lists the external targets, the refusal lists why
	// each refused target can never be scanned. Code is "" for any other
	// error.
	Code            string
	ExternalTargets json.RawMessage
	RefusedTargets  json.RawMessage
	// Extra holds the further fields of a scan_target_too_large verdict
	// (oversize_targets, target_limit, job_addresses, job_limit) or a
	// scan_budget_exceeded one (estimated_probes, probe_limit,
	// largest_target), relayed verbatim so the UI can name the numbers.
	Extra map[string]json.RawMessage
}

// targetVerdictCodes are cluster-sensor-service's target-authorization
// answers (dispatchguard.Code*). Spelled here rather than imported because
// this proxy only relays them.
var targetVerdictCodes = map[string]bool{
	"targets_refused":              true,
	"external_targets_unconfirmed": true,
	"external_targets_disabled":    true,
	"scan_target_too_large":        true,
	"scan_budget_exceeded":         true,
	// The scan-plan shape refused because plan execution is switched off
	// (cluster-sensor-service's planExecutionAvailable). Relayed, not
	// re-decided here, so one switch governs both layers.
	"scan_plan_unavailable": true,
	// A scan-plan job naming a tenant sensor whose software cannot run one
	// ( WP2b), 409: relayed with its code so the wizard can offer to run
	// from the platform.
	"sensor_scan_plan_unsupported": true,
}

// targetSizeFields are the fields of a scan_target_too_large verdict beyond
// the code and message.
var targetSizeFields = []string{"oversize_targets", "target_limit", "job_addresses", "job_limit"}

// budgetFields are the fields of a scan_budget_exceeded verdict ( H19)
// beyond the code and message: the numbers the UI names.
var budgetFields = []string{"estimated_probes", "probe_limit", "largest_target"}

func (e *DownstreamError) parseTargetVerdict(body []byte) {
	var parsed struct {
		Error           string          `json:"error"`
		Message         string          `json:"message"`
		ExternalTargets json.RawMessage `json:"external_targets"`
		RefusedTargets  json.RawMessage `json:"refused_targets"`
	}
	if json.Unmarshal(body, &parsed) != nil || !targetVerdictCodes[parsed.Error] {
		return
	}
	e.Code = parsed.Error
	if parsed.Message != "" {
		e.Message = parsed.Message
	}
	e.ExternalTargets = parsed.ExternalTargets
	e.RefusedTargets = parsed.RefusedTargets
	extra := map[string][]string{"scan_target_too_large": targetSizeFields, "scan_budget_exceeded": budgetFields}[parsed.Error]
	if len(extra) > 0 {
		var all map[string]json.RawMessage
		if json.Unmarshal(body, &all) == nil {
			for _, k := range extra {
				if v, ok := all[k]; ok {
					if e.Extra == nil {
						e.Extra = map[string]json.RawMessage{}
					}
					e.Extra[k] = v
				}
			}
		}
	}
}

func (e *DownstreamError) Error() string {
	return fmt.Sprintf("cluster-sensor-service returned status %d: %s", e.Status, e.Body)
}

// downstreamMessage pulls the `error` line out of a cluster-sensor error body,
// falling back to the raw body when it is not that shape.
func downstreamMessage(body []byte) string {
	var parsed struct {
		Error   string `json:"error"`
		Message string `json:"message"`
		Details string `json:"details"`
	}
	if json.Unmarshal(body, &parsed) == nil {
		// {"error":"validation_error","details":"<reason>"}: the code alone says
		// nothing, the reason is what the caller can act on.
		if parsed.Error == "validation_error" && parsed.Details != "" {
			return parsed.Details
		}
		if parsed.Error != "" {
			return parsed.Error
		}
		if parsed.Message != "" {
			return parsed.Message
		}
	}
	return string(body)
}

func valueOrDefault[T ~int](v *T, d T) T {
	if v == nil {
		return d
	}
	return *v
}
