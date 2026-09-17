package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/config"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
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

func (s *DiscoveryService) createJob(tenantID string, input models.CreateDiscoveryJobInput, authorize func(*http.Request)) (*models.DiscoveryJob, error) {
	if len(input.Targets) == 0 {
		return nil, fmt.Errorf("at least one target is required")
	}
	if len(input.Targets) > 1000 {
		return nil, fmt.Errorf("too many targets; limit is 1000 per job")
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

	// Convert to JSON
	jsonData, err := json.Marshal(requestPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Log the payload being sent for debugging
	fmt.Printf("[DiscoveryService] Sending payload to cluster-sensor-service: %s\n", string(jsonData))

	// Make HTTP request to cluster-sensor-service
	// Note: We need the Authorization header from the original request, but we don't have access to it here
	// The handler should pass it through, or we need to restructure this
	req, err := http.NewRequest("POST", s.clusterSensorURL+"/api/v1/discovery/jobs", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	// Headers that are part of the signed message must be set BEFORE signing —
	// serviceauth folds X-Tenant-ID and the body hash into the HMAC.
	authorize(req)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call cluster-sensor-service: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return nil, &DownstreamError{Status: resp.StatusCode, Message: downstreamMessage(body), Body: string(body)}
	}

	// Parse response - cluster-sensor-service returns { "job": {...} }
	var response struct {
		Job models.DiscoveryJob `json:"job"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response.Job, nil
}

// DownstreamError is cluster-sensor-service's non-2xx answer to a job request,
// kept with its status so a 4xx verdict — an unknown, offline or undispatchable
// sensor — can reach the caller with the reason instead of collapsing
// into "failed to create discovery job".
type DownstreamError struct {
	Status  int
	Message string
	Body    string
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
	}
	if json.Unmarshal(body, &parsed) == nil {
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
