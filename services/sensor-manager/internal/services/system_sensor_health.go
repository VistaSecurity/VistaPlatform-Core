package services

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"time"

	"encoding/json"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
	"io"
	"strings"
)

// SystemSensorHealthService monitors and updates the health status of platform system sensors
// These are shared platform resources (cluster-sensor-service, device-interrogation-service)
// that appear in each tenant's sensor list.
type SystemSensorHealthService struct {
	db *sql.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) handle. Platform sensors are
	// maintained for all tenants at once, so this service has no tenant in scope
	// and must not run its writes on the RLS-scoped handle.
	bypassDB                      *sql.DB
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
func NewSystemSensorHealthService(db, bypassDB *sql.DB, clusterURL, deviceInterrogationURL string) *SystemSensorHealthService {
	if clusterURL == "" {
		clusterURL = sharedconfig.PeerURL("cluster-sensor-service", false)
	}
	if deviceInterrogationURL == "" {
		deviceInterrogationURL = sharedconfig.PeerURL("device-interrogation-service", false)
	}

	return &SystemSensorHealthService{
		db:                            db,
		bypassDB:                      bypassDB,
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
	clusterStatus, clusterVersion := s.checkServiceHealth(s.clusterSensorServiceURL + "/health")

	// Check device-interrogation-service health
	deviceInterrogationStatus, deviceInterrogationVersion := s.checkServiceHealth(s.deviceInterrogationServiceURL + "/health")

	// Update Platform Discovery Sensor records for all tenants
	s.updateSensorStatus(ctx, "discovery", clusterStatus, clusterVersion)

	// Update Platform Device Interrogation Agent records for all tenants
	s.updateSensorStatus(ctx, "device_interrogation", deviceInterrogationStatus, deviceInterrogationVersion)
}

// checkServiceHealth performs a health check against a service endpoint.
// The second return is the checked service's own release version as reported
// by its /health body — this sweep is the platform agents' heartbeat, and the
// version must come from the service being swept, not from sensor-manager,
// or a partially-rolled upgrade would stamp rows with the wrong release.
// Empty when the body carries none (older service, parse failure).
func (s *SystemSensorHealthService) checkServiceHealth(url string) (string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "error", ""
	}

	serviceauth.SignRequestFromEnv(req)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "offline", ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "error", ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return "active", parseHealthVersion(body)
}

// parseHealthVersion extracts the service's release version from a /health
// response body ({"version":{"service":"vX.Y.Z"}}), normalized to the bare
// form the sensors.version column stores (leading "v" stripped, as the UI
// renders "v"+version). Anything unparsable is "" — the caller's COALESCE
// treats that as "not reported" rather than blanking the stored value.
func parseHealthVersion(body []byte) string {
	var h struct {
		Version struct {
			Service string `json:"service"`
		} `json:"version"`
	}
	if err := json.Unmarshal(body, &h); err != nil {
		return ""
	}
	return strings.TrimPrefix(h.Version.Service, "v")
}

// updateSensorStatus updates status, last_heartbeat and — when the swept
// service reported one — the recorded version for system sensors. The seeded
// rows carry the placeholder version 'system'; this sweep is what converges
// them to the running release, including across in-place upgrades, without
// any re-registration.
func (s *SystemSensorHealthService) updateSensorStatus(ctx context.Context, profile, status, version string) {
	query := `
		UPDATE sensors
		SET status = $1,
		    last_heartbeat = NOW(),
		    version = COALESCE(NULLIF($3, ''), version),
		    updated_at = NOW()
		WHERE platform = 'platform'
		  AND profile = $2
		  AND 'system' = ANY(tags)
		  AND deleted_at IS NULL`

	// RLS: cross-tenant — runs on the bypass role. Platform sensors exist per
	// tenant and this sweep updates all of them, so there is no single
	// app.tenant_id to set. On the RLS-scoped handle the UPDATE silently matches
	// nothing and every platform sensor's status freezes.
	if s.bypassDB == nil {
		return
	}
	result, err := s.bypassDB.ExecContext(ctx, query, status, profile, version)
	if err != nil {
		log.Printf("⚠️  Failed to update system sensor status (profile=%s): %v", profile, err)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		log.Printf("✅ Updated %d %s system sensor(s) to status '%s'", rowsAffected, profile, status)
	}
}
