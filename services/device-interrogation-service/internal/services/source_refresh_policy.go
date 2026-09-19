package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/autoscan"
	database "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// authorizeTargetedRefresh applies unattended-probe policy to a direct device
// interrogation. Controller inventory/API queries do not require the observed
// peer to already have an address; only the configured controller is contacted.
func (s *ConfiguredSourceRefresh) authorizeTargetedRefresh(ctx context.Context, tenant uuid.UUID, device *models.Device) (string, error) {
	var reason string
	err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		var err error
		reason, err = s.authorizeTargetedRefreshTx(ctx, tx, tenant, device)
		return err
	})
	return reason, err
}

func (s *ConfiguredSourceRefresh) authorizeTargetedRefreshTx(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, device *models.Device) (string, error) {
	var config []byte
	err := tx.QueryRowContext(ctx, `SELECT config FROM tenant_admin_settings WHERE tenant_id=$1 FOR SHARE`, tenant).Scan(&config)
	if errors.Is(err, sql.ErrNoRows) {
		config = []byte(`{}`)
	} else if err != nil {
		return "", err
	}
	var settings struct {
		Enrichment struct {
			Sensitive []uuid.UUID `json:"sensitive_asset_ids"`
			Excluded  []string    `json:"excluded_cidrs"`
		} `json:"identity_enrichment"`
	}
	if err := json.Unmarshal(config, &settings); err != nil {
		return "invalid_enrichment_policy", nil
	}
	for _, id := range settings.Enrichment.Sensitive {
		if id == device.ID {
			return "sensitive_device_requires_review", nil
		}
	}
	class := device.ClassKey
	if strings.Contains(class, "industrial") || strings.Contains(class, "medical") || assetclass.IsAncestor(assetclass.KeyOtDevice, class) || strings.HasPrefix(class, "ot_") {
		return "sensitive_device_requires_review", nil
	}
	var generic map[string]interface{}
	if err := json.Unmarshal(config, &generic); err != nil {
		return "invalid_enrichment_policy", nil
	}
	policy, err := autoscan.Normalize(autoscan.FromConfig(generic))
	if err != nil {
		return "invalid_enrichment_policy", nil
	}
	if !policy.Enabled {
		return "automatic_probes_disabled", nil
	}
	protocol := "TLS"
	port := 443
	target := ""
	if device.ManagementURL == nil || *device.ManagementURL == "" {
		return "configured_protocol_not_authorized", nil
	}
	if device.IPAddress != nil {
		target = *device.IPAddress
	}
	if device.ManagementURL != nil && *device.ManagementURL != "" {
		u, err := url.Parse(*device.ManagementURL)
		if err != nil {
			return "configured_target_requires_scoped_address", nil
		}
		switch u.Scheme {
		case "https":
			protocol = "TLS"
		case "ssh":
			protocol = "SSH"
			port = 22
		default:
			return "configured_protocol_not_authorized", nil
		}
		target = u.Hostname()
		if u.Port() != "" {
			var err error
			port, err = strconv.Atoi(u.Port())
			if err != nil {
				return "configured_protocol_not_authorized", nil
			}
		}
	}
	allowed := false
	for _, p := range policy.Protocols {
		if p == protocol {
			allowed = true
		}
	}
	if !allowed {
		return "configured_protocol_not_authorized", nil
	}
	allowedPort := false
	for _, p := range policy.Ports {
		if p == port {
			allowedPort = true
		}
	}
	if !allowedPort {
		return "configured_port_not_authorized", nil
	}
	address, err := netip.ParseAddr(target)
	if err != nil || !address.IsGlobalUnicast() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return "configured_target_requires_scoped_address", nil
	}
	address = address.Unmap()
	for _, excluded := range autoscan.PlatformExcludedPrefixes() {
		if excluded.Contains(address) {
			return "platform_target_excluded", nil
		}
	}
	for _, raw := range settings.Enrichment.Excluded {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return "invalid_exclusion_policy", nil
		}
		if prefix.Contains(address) {
			return "target_excluded", nil
		}
	}
	// Resolve the actual configured management address, not the weak peer's
	// observed segment. Overlapping networks require an explicit source workflow.
	var scopes int
	var restricted bool
	err = tx.QueryRowContext(ctx, `SELECT count(*),COALESCE(bool_or(COALESCE(metadata->>'sensitive','false')='true' OR COALESCE(metadata->>'active_probes_disabled','false')='true' OR COALESCE(cloud_network_ref,'')<>''),false) FROM network_segments WHERE tenant_id=$1 AND is_active AND CASE WHEN segment_type='cidr' THEN $2::inet <<= value::cidr ELSE false END`, tenant, address.String()).Scan(&scopes, &restricted)
	if err != nil {
		return "", err
	}
	if scopes != 1 {
		return "network_scope_unresolved_or_ambiguous", nil
	}
	if restricted {
		return "sensitive_network_requires_review", nil
	}
	return "", nil
}

// Recheck immediately before handing work to an executor. Revoked monitoring,
// changed targets, paused enrichment and tightened policy invalidate queued work.
var errSourceRefreshPaused = errors.New("enrichment paused")
var errSourceRefreshDenied = errors.New("configured source authorization denied")

// Policy precedes asset/job locks and stays held until authorization and claim
// commit. No credential preparation or external I/O runs in this transaction.
func lockSourceRefreshPolicy(ctx context.Context, tx *sql.Tx, tenant uuid.UUID) (bool, error) {
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT config FROM tenant_admin_settings WHERE tenant_id=$1 FOR SHARE`, tenant).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var settings struct {
		Admission struct {
			Mode string `json:"mode"`
		} `json:"identity_admission"`
		Enrichment struct {
			Enabled bool `json:"enabled"`
		} `json:"identity_enrichment"`
	}
	if err := json.Unmarshal(raw, &settings); err != nil {
		return false, err
	}
	capabilities := identity.AvailableCapabilities()
	return capabilities.Admission && capabilities.Enrichment && settings.Admission.Mode == "enforce" && settings.Enrichment.Enabled, nil
}

func (s *JobQueueService) validateRefreshClaim(ctx context.Context, job *models.DeviceJob) error {
	return database.WithTenantTx(ctx, s.db, job.TenantID, func(tx *sql.Tx) error { return s.validateRefreshClaimTx(ctx, tx, job, true) })
}

func (s *JobQueueService) validateRefreshClaimTx(ctx context.Context, tx *sql.Tx, job *models.DeviceJob, requireReceipt bool) error {
	if _, ok := job.Parameters["identity_refresh_request_id"]; !ok {
		return nil
	}
	active, err := lockSourceRefreshPolicy(ctx, tx, job.TenantID)
	if err != nil {
		return err
	}
	if !active {
		return errSourceRefreshPaused
	}
	if requireReceipt {
		var observationID uuid.UUID
		err := tx.QueryRowContext(ctx, `SELECT o.id FROM identity_source_refreshes r JOIN identity_observations o ON o.tenant_id=r.tenant_id AND o.id=r.observation_id WHERE r.tenant_id=$1 AND r.device_job_id=$2 AND o.state NOT IN ('dismissed','expired','conflict') ORDER BY o.id LIMIT 1 FOR SHARE OF o`, job.TenantID, job.ID).Scan(&observationID)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: source observation no longer eligible", errSourceRefreshDenied)
		}
		if err != nil {
			return err
		}
	}

	if job.JobType == models.JobTypeCloudDiscovery {
		if job.IntegrationID == nil {
			return fmt.Errorf("%w: source integration unavailable", errSourceRefreshDenied)
		}
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(is_enabled,false) AND COALESCE(is_active,false) AND deleted_at IS NULL AND config<>'{}'::jsonb AND integration_type=$3 FROM platform_integrations WHERE tenant_id=$1 AND id=$2 FOR SHARE`, job.TenantID, *job.IntegrationID, job.Parameters["cloud_provider"]).Scan(&active); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errSourceRefreshDenied
			}
			return err
		}
		if !active {
			return fmt.Errorf("%w: source integration disabled", errSourceRefreshDenied)
		}
		return nil
	}
	if job.AssetID == nil {
		return fmt.Errorf("%w: source asset unavailable", errSourceRefreshDenied)
	}
	device := &models.Device{ID: *job.AssetID}
	var metadata []byte
	if err := tx.QueryRowContext(ctx, `SELECT a.class_key,host(a.primary_address),COALESCE(a.metadata->'device_metadata','{}'::jsonb),m.management_url FROM assets a JOIN asset_management m ON m.tenant_id=a.tenant_id AND m.asset_id=a.id WHERE a.tenant_id=$1 AND a.id=$2 AND a.asset_status='monitoring' AND a.deleted_at IS NULL FOR SHARE OF a,m`, job.TenantID, *job.AssetID).Scan(&device.ClassKey, &device.IPAddress, &metadata, &device.ManagementURL); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errSourceRefreshDenied
		}
		return err
	}
	if err := json.Unmarshal(metadata, &device.Metadata); err != nil {
		return err
	}
	if device.ManagementURL == nil || job.Parameters["management_url"] != *device.ManagementURL {
		return fmt.Errorf("%w: configured source address changed", errSourceRefreshDenied)
	}
	executor, _ := job.Parameters["identity_refresh_executor"].(string)
	if executor == "platform" {
		if job.AgentID != nil || device.Metadata["identity_enrichment_executor"] != "platform" {
			return fmt.Errorf("%w: configured executor changed", errSourceRefreshDenied)
		}
	} else if job.AgentID == nil || executor != job.AgentID.String() {
		return fmt.Errorf("%w: configured executor changed", errSourceRefreshDenied)
	}
	if job.AgentID != nil {
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM device_agents WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL AND status='active' AND last_heartbeat>clock_timestamp()-interval '5 minutes' AND version<>'' AND profile<>'')`, job.TenantID, *job.AgentID).Scan(&active); err != nil {
			return err
		}
		if !active {
			return fmt.Errorf("%w: configured executor unavailable", errSourceRefreshDenied)
		}
	}
	service := NewConfiguredSourceRefresh(s.db, s, nil, nil)
	reason, err := service.authorizeTargetedRefreshTx(ctx, tx, job.TenantID, device)
	if err != nil {
		return err
	}
	if reason != "" {
		return fmt.Errorf("%w: %s", errSourceRefreshDenied, reason)
	}
	return nil
}
