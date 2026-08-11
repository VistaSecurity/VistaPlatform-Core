package services

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"time"

	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// SystemSensorHealthService monitors and updates the health status of platform system sensors
// These are shared platform resources (cluster-sensor-service, device-interrogation-service)
// that appear in each tenant's sensor list.
type SystemSensorHealthService struct {
	db                            *sql.DB
	clusterSensorServiceURL       string
	deviceInterrogationServiceURL string
	checkInterval                 time.Duration
	httpClient                    *http.Client
}

// NewSystemSensorHealthService creates a new system sensor health service
//
// The health probes deliberately target the PLAINTEXT port, not the peer URL,
// even when app-level mTLS is on.
//
// PeerURL() flips to https://<svc>:8443 with USE_MTLS, and 8443 demands a client
// certificate. This service polls with a plain http.Client that has none, so
// every probe failed the TLS handshake, checkServiceHealth() mapped the error to
// "offline", and BOTH platform agents showed permanently offline on any cluster
// with serviceMtls.enabled — while heartbeating normally, because the same pass
// writes last_heartbeat whatever the outcome. A fresh heartbeat next to an
// offline status is the signature of this bug.
//
// Plaintext /health on 8080 is kept precisely so probes work without a cert
// (same reason the kubelet liveness/readiness probes use it), so that is what a
// health poller should ask. This also keeps the check working whether or not
// mTLS is enabled, rather than silently depending on it.
func NewSystemSensorHealthService(db *sql.DB, clusterURL, deviceInterrogationURL string) *SystemSensorHealthService {
	if clusterURL == "" {
		clusterURL = sharedconfig.PeerURL("cluster-sensor-service", false)
	}
	if deviceInterrogationURL == "" {
		deviceInterrogationURL = sharedconfig.PeerURL("device-interrogation-service", false)
	}

	return &SystemSensorHealthService{
		db:                            db,
		clusterSensorServiceURL:       clusterURL,
		deviceInterrogationServiceURL: deviceInterrogationURL,
		checkInterval:                 30 * time.Second,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Start begins the background health check loop
func (s *SystemSensorHealthService) Start(ctx context.Context) {
	log.Printf("🏥 Starting system sensor health monitor (interval: %s)", s.checkInterval)

	// Run immediately on start
	s.updateSystemSensorHealth(ctx)

	ticker := time.NewTicker(s.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("🛑 System sensor health monitor stopped")
			return
		case <-ticker.C:
			s.updateSystemSensorHealth(ctx)
		}
	}
}

// updateSystemSensorHealth checks the health of platform services and updates sensor records
func (s *SystemSensorHealthService) updateSystemSensorHealth(ctx context.Context) {
	if s.db == nil {
		return
	}

	// Check cluster-sensor-service health
	clusterStatus := s.checkServiceHealth(s.clusterSensorServiceURL + "/health")

	// Check device-interrogation-service health
	deviceInterrogationStatus := s.checkServiceHealth(s.deviceInterrogationServiceURL + "/health")

	// Update Platform Discovery Sensor records for all tenants
	s.updateSensorStatus(ctx, "discovery", clusterStatus)

	// Update Platform Device Interrogation Agent records for all tenants
	s.updateSensorStatus(ctx, "device_interrogation", deviceInterrogationStatus)
}

// checkServiceHealth performs a health check against a service endpoint
func (s *SystemSensorHealthService) checkServiceHealth(url string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "error"
	}

	serviceauth.SignRequestFromEnv(req)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "offline"
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return "active"
	}
	return "error"
}

// updateSensorStatus updates the status and last_heartbeat for system sensors
func (s *SystemSensorHealthService) updateSensorStatus(ctx context.Context, profile, status string) {
	query := `
		UPDATE sensors
		SET status = $1,
		    last_heartbeat = NOW(),
		    updated_at = NOW()
		WHERE platform = 'platform'
		  AND profile = $2
		  AND 'system' = ANY(tags)
		  AND deleted_at IS NULL`

	result, err := s.db.ExecContext(ctx, query, status, profile)
	if err != nil {
		log.Printf("⚠️  Failed to update system sensor status (profile=%s): %v", profile, err)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		log.Printf("✅ Updated %d %s system sensor(s) to status '%s'", rowsAffected, profile, status)
	}
}
