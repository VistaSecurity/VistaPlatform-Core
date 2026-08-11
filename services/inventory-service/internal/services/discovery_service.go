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

func (s *DiscoveryService) CreateJob(tenantID string, userID string, input models.CreateDiscoveryJobInput, authHeader string) (*models.DiscoveryJob, error) {
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
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call cluster-sensor-service: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("cluster-sensor-service returned status %d: %s", resp.StatusCode, string(body))
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

func valueOrDefault[T ~int](v *T, d T) T {
	if v == nil {
		return d
	}
	return *v
}
