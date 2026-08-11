package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/discovery"
)

// ResultProcessor processes device job results and creates discovery findings
type ResultProcessor struct {
	db                   *sql.DB
	bypassDB             *sql.DB
	discoveryIntegration *DiscoveryIntegrationService
}

// NewResultProcessor creates a new result processor. db is the RLS-scoped
// (crypto_app) connection; bypassDB is the BYPASSRLS (crypto_bypass) connection
// threaded into the JobQueueService GetJobByID (keyed by job id) path. The
// findings/devices/sensor_discoveries writes here run under the RESOLVED
// deviceJob.TenantID via WithTenantTx.
func NewResultProcessor(db, bypassDB *sql.DB) *ResultProcessor {
	return &ResultProcessor{
		db:                   db,
		bypassDB:             bypassDB,
		discoveryIntegration: NewDiscoveryIntegrationService(db, bypassDB),
	}
}

// ProcessJobResults processes job results and creates discovery findings
func (s *ResultProcessor) ProcessJobResults(ctx context.Context, jobID uuid.UUID, result *models.JobResult) error {
	// Get the device job to retrieve tenant_id and device_id. GetJobByID runs on
	// the bypass role (keyed by job id; tenant is the output).
	jobQueue := NewJobQueueService(s.db, s.bypassDB, nil) // Redis not needed for reading
	deviceJob, err := jobQueue.GetJobByID(ctx, jobID)
	if err != nil {
		return fmt.Errorf("failed to get device job: %w", err)
	}

	// Get or create discovery job for this device interrogation
	// Use system user ID for device-initiated jobs
	systemUserID := uuid.MustParse("00000000-0000-0000-0000-000000000000")

	// Determine source type and build metadata for source tracking
	sourceType := "device_interrogation"
	jobMetadata := map[string]interface{}{
		"device_job_id": jobID.String(),
		"source":        sourceType,
	}

	// Add device_id for device interrogation jobs
	if deviceJob.DeviceID != nil {
		jobMetadata["source_device_id"] = deviceJob.DeviceID.String()
		jobMetadata["device_id"] = deviceJob.DeviceID.String()
	}

	// Add integration_id for cloud discovery jobs
	if deviceJob.IntegrationID != nil {
		sourceType = "cloud_discovery"
		jobMetadata["source"] = sourceType
		jobMetadata["source_integration_id"] = deviceJob.IntegrationID.String()
		jobMetadata["integration_id"] = deviceJob.IntegrationID.String()
	}

	// Check if discovery job already exists in metadata
	var discoveryJobID uuid.UUID
	if metadata, ok := deviceJob.Parameters["discovery_job_id"].(string); ok {
		discoveryJobID, _ = uuid.Parse(metadata)
	} else {
		// Create new discovery job with enhanced source tracking
		discoveryJobID, err = s.discoveryIntegration.CreateDiscoveryJob(
			ctx, deviceJob.TenantID, systemUserID, sourceType, jobMetadata,
		)
		if err != nil {
			return fmt.Errorf("failed to create discovery job: %w", err)
		}
	}

	// Update device record with identity info from first asset (if available)
	if deviceJob.DeviceID != nil && len(result.Assets) > 0 {
		s.updateDeviceIdentity(ctx, deviceJob.TenantID, *deviceJob.DeviceID, result.Assets[0])
	}

	// Look up the tenant's platform system sensor once. Device interrogation
	// findings are additionally published into sensor_discoveries under it so
	// they flow through the unified discovery pipeline (network classification +
	// auto-approval + auto-import), the same path the cloud discovery flow uses.
	// uuid.Nil means no system sensor is provisioned for this tenant — we then
	// fall back to discovery_findings only (the prior behaviour). Cloud jobs
	// (IntegrationID set) already write sensor_discoveries in the router and must
	// not be double-written here.
	var systemSensorID uuid.UUID
	batchID := discoveryJobID.String()
	if deviceJob.IntegrationID == nil {
		systemSensorID = s.lookupSystemSensor(ctx, deviceJob.TenantID)
	}

	// Process each discovered asset
	for _, asset := range result.Assets {
		// Determine target input (hostname or IP)
		targetInput := asset.Hostname
		if targetInput == "" && asset.IPAddress != "" {
			targetInput = asset.IPAddress
		}
		if targetInput == "" {
			continue // Skip assets without hostname or IP
		}

		// Determine protocols and ports
		protocols := []string{"TLS", "HTTPS"}
		if asset.Protocol != "" {
			protocols = []string{asset.Protocol}
		}

		ports := []int32{443}
		if asset.Port > 0 {
			ports = []int32{int32(asset.Port)} //nolint:gosec // intentional — TCP/UDP port range 0-65535 fits comfortably in int32
		}

		// Create discovery target
		targetID, err := s.discoveryIntegration.CreateDiscoveryTarget(
			ctx, deviceJob.TenantID, discoveryJobID, targetInput, protocols, ports,
		)
		if err != nil {
			fmt.Printf("Warning: failed to create discovery target for %s: %v\n", targetInput, err)
			continue
		}

		// Prepare hostname and IP pointers
		var hostnamePtr, ipPtr *string
		if asset.Hostname != "" {
			hostnamePtr = &asset.Hostname
		}
		if asset.IPAddress != "" {
			ipPtr = &asset.IPAddress
		}

		// Compute certificate quality flags + OCSP status once per asset and share
		// them across both sinks (discovery_findings and sensor_discoveries) so
		// device interrogation reaches the same enrichment as sensor/cloud
		// discovery without paying for OCSP queries twice.
		certFlags, ocspStatus, ocspDetail, derivedStatus := s.assetCertQualityFlags(asset)

		// Build enriched finding details with source tracking
		details := s.buildFindingDetails(jobID, deviceJob.DeviceID, deviceJob.IntegrationID, asset, sourceType)
		mergeCertFlags(details, certFlags, ocspStatus, ocspDetail)
		// Only fill validation status when the agent didn't set one; the agent's
		// vendor-specific result is authoritative when present.
		if asset.CertValidationStatus == "" && derivedStatus != "" {
			details["cert_validation_status"] = derivedStatus
		}

		// Determine protocol and port for finding
		protocol := "TLS"
		if asset.Protocol != "" {
			protocol = asset.Protocol
		}

		port := 443
		if asset.Port > 0 {
			port = asset.Port
		}

		// Calculate confidence score (high for device interrogation)
		confidenceScore := 0.95
		if asset.IPAddress != "" {
			if net.ParseIP(asset.IPAddress) == nil {
				confidenceScore = 0.85 // Lower confidence for invalid IP
			}
		}

		// Create discovery finding with proper source type
		_, err = s.discoveryIntegration.CreateDiscoveryFinding(
			ctx, discoveryJobID, targetID, sourceType,
			protocol, port, hostnamePtr, ipPtr,
			details, confidenceScore,
		)
		if err != nil {
			fmt.Printf("Warning: failed to create discovery finding for %s: %v\n", targetInput, err)
			continue
		}

		// Also publish into the unified sensor_discoveries pipeline so the
		// discovery-processor applies network classification + tenant
		// auto-approval rules and auto-imports the asset. discovery-processor's
		// DB poller picks up the batch; no explicit trigger is required.
		if systemSensorID != uuid.Nil {
			s.writeSensorDiscovery(ctx, systemSensorID, deviceJob, batchID, asset, certFlags, ocspStatus, ocspDetail)
		}
	}

	// Mark discovery job as completed if all assets processed
	if len(result.Assets) > 0 {
		err = s.discoveryIntegration.MarkJobCompleted(ctx, discoveryJobID)
		if err != nil {
			fmt.Printf("Warning: failed to mark discovery job as completed: %v\n", err)
		}
	}

	return nil
}

// buildFindingDetails constructs the enriched details map for a discovery finding,
// preserving all data from the agent's enriched DiscoveredAsset model.
func (s *ResultProcessor) buildFindingDetails(
	jobID uuid.UUID,
	deviceID *uuid.UUID,
	integrationID *uuid.UUID,
	asset models.DiscoveredAsset,
	sourceType string,
) map[string]interface{} {
	details := map[string]interface{}{
		"device_job_id":    jobID.String(),
		"protocol_version": asset.ProtocolVersion,
		"cipher_suite":     asset.CipherSuite,
		"key_size":         asset.KeySize,
		"discovery_method": sourceType,
	}

	// Enriched crypto fields
	if asset.KeyExchangeAlgorithm != "" {
		details["key_exchange_algorithm"] = asset.KeyExchangeAlgorithm
	}
	if asset.HashAlgorithm != "" {
		details["hash_algorithm"] = asset.HashAlgorithm
	}
	if len(asset.SupportedCiphers) > 0 {
		details["supported_ciphers"] = asset.SupportedCiphers
	}
	if len(asset.TLSVersions) > 0 {
		details["tls_versions"] = asset.TLSVersions
	}
	if asset.AssetType != "" {
		details["asset_type"] = asset.AssetType
	}

	// Certificate validation
	if asset.CertValidationStatus != "" {
		details["cert_validation_status"] = asset.CertValidationStatus
	}
	if asset.CertValidationError != "" {
		details["cert_validation_error"] = asset.CertValidationError
	}

	// Full certificate chain. Certificate quality flags + OCSP status are merged
	// by the caller via mergeCertFlags so the computation (including OCSP network
	// I/O) happens once per asset and is shared with the sensor_discoveries sink.
	if len(asset.Certificates) > 0 {
		certs := make([]map[string]interface{}, 0, len(asset.Certificates))
		for _, cert := range asset.Certificates {
			certs = append(certs, certToMap(cert))
		}
		details["certificates"] = certs
	} else if asset.Certificate != nil {
		// Backward compat: single certificate
		details["certificate"] = map[string]interface{}{
			"subject_dn":         asset.Certificate.SubjectDN,
			"issuer_dn":          asset.Certificate.IssuerDN,
			"serial_number":      asset.Certificate.SerialNumber,
			"not_before":         asset.Certificate.NotBefore,
			"not_after":          asset.Certificate.NotAfter,
			"fingerprint":        asset.Certificate.Fingerprint,
			"fingerprint_sha256": asset.Certificate.FingerprintSHA256,
			"key_algorithm":      asset.Certificate.KeyAlgorithm,
			"key_size":           asset.Certificate.KeySize,
		}
	}

	// SSH info
	if asset.SSHInfo != nil {
		details["ssh_info"] = map[string]interface{}{
			"banner":               asset.SSHInfo.Banner,
			"host_key_type":        asset.SSHInfo.HostKeyType,
			"host_key_fingerprint": asset.SSHInfo.HostKeyFingerprint,
			"kex_algorithm":        asset.SSHInfo.KexAlgorithm,
			"key_types":            asset.SSHInfo.KeyTypes,
		}
	}

	// Device identity
	if asset.DeviceInfo != nil {
		details["device_identity"] = map[string]interface{}{
			"vendor":           asset.DeviceInfo.Vendor,
			"model":            asset.DeviceInfo.Model,
			"firmware_version": asset.DeviceInfo.FirmwareVersion,
			"serial_number":    asset.DeviceInfo.SerialNumber,
			"os_version":       asset.DeviceInfo.OSVersion,
		}
	}

	// Service hints
	if asset.ServiceHints != nil {
		details["service_hints"] = map[string]interface{}{
			"service_name":          asset.ServiceHints.ServiceName,
			"service_version":       asset.ServiceHints.ServiceVersion,
			"confidence":            asset.ServiceHints.Confidence,
			"identification_method": asset.ServiceHints.IdentificationMethod,
		}
	}

	// Source tracking
	if deviceID != nil {
		details["source_device_id"] = deviceID.String()
		details["device_id"] = deviceID.String()
	}
	if integrationID != nil {
		details["source_integration_id"] = integrationID.String()
		details["integration_id"] = integrationID.String()
	}

	// Pass through freeform metadata
	if asset.Metadata != nil {
		details["metadata"] = asset.Metadata
	}

	return details
}

// orderedCertPEMs returns the non-empty certificate PEMs from an interrogated
// asset's chain, ordered leaf-first by ChainOrder, ready for
// discovery.ClassifyCertChainFromPEMs.
func orderedCertPEMs(certs []models.CertificateInfo) []string {
	ordered := make([]models.CertificateInfo, len(certs))
	copy(ordered, certs)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].ChainOrder < ordered[j].ChainOrder
	})
	pems := make([]string, 0, len(ordered))
	for _, c := range ordered {
		if c.CertificatePEM != "" {
			pems = append(pems, c.CertificatePEM)
		}
	}
	return pems
}

// certToMap renders one interrogated certificate into the canonical
// "certificates" array entry shape shared by every discovery sink.
func certToMap(cert models.CertificateInfo) map[string]interface{} {
	return map[string]interface{}{
		"subject_dn":                cert.SubjectDN,
		"issuer_dn":                 cert.IssuerDN,
		"serial_number":             cert.SerialNumber,
		"not_before":                cert.NotBefore,
		"not_after":                 cert.NotAfter,
		"fingerprint_sha256":        cert.FingerprintSHA256,
		"fingerprint_sha1":          cert.FingerprintSHA1,
		"key_algorithm":             cert.KeyAlgorithm,
		"key_size":                  cert.KeySize,
		"signature_alg":             cert.SignatureAlgorithm,
		"is_ca":                     cert.IsCA,
		"certificate_pem":           cert.CertificatePEM,
		"subject_alternative_names": cert.SubjectAlternativeNames,
		"chain_order":               cert.ChainOrder,
	}
}

// assetCertQualityFlags computes the certificate quality flags + OCSP status for
// an interrogated asset's chain exactly as the active TLS prober would, so both
// the discovery_findings and sensor_discoveries sinks emit identical flags. The
// derived validation status is returned separately so the caller can apply it
// only when the agent supplied none. Runs in-cluster, so OCSP queries are on.
// Returns zero values when the asset carries no parseable certificates.
func (s *ResultProcessor) assetCertQualityFlags(asset models.DiscoveredAsset) (flags map[string]interface{}, ocspStatus, ocspDetail, derivedStatus string) {
	pems := orderedCertPEMs(asset.Certificates)
	if len(pems) == 0 {
		return nil, "", "", ""
	}
	v := discovery.ClassifyCertChainFromPEMs(pems, true)
	if v == nil {
		return nil, "", "", ""
	}
	return v.QualityFlags, v.OCSPStatus, v.OCSPDetail, v.ValidationStatus
}

// mergeCertFlags copies precomputed certificate quality flags + OCSP status into
// a discovery metadata map. No-op for nil/empty inputs.
func mergeCertFlags(dst, flags map[string]interface{}, ocspStatus, ocspDetail string) {
	for k, v := range flags {
		dst[k] = v
	}
	if ocspStatus != "" {
		dst["ocsp_status"] = ocspStatus
		if ocspDetail != "" {
			dst["ocsp_detail"] = ocspDetail
		}
	}
}

// lookupSystemSensor returns the tenant's platform "device_interrogation" system
// sensor id, or uuid.Nil if none is provisioned (caller falls back to
// discovery_findings only). This is the same sensor the cloud discovery path
// writes sensor_discoveries under.
func (s *ResultProcessor) lookupSystemSensor(ctx context.Context, tenantID uuid.UUID) uuid.UUID {
	// RLS-scoped read on `sensors`: WithTenantTx sets app.tenant_id; the explicit
	// WHERE tenant_id = $1 is kept as the primary control.
	var id uuid.UUID
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT id FROM sensors
			WHERE tenant_id = $1 AND profile = 'device_interrogation' AND 'system' = ANY(tags)
			LIMIT 1`, tenantID).Scan(&id)
	})
	if err != nil {
		if err != sql.ErrNoRows {
			fmt.Printf("Warning: failed to look up system sensor for tenant %s: %v\n", tenantID, err)
		}
		return uuid.Nil
	}
	return id
}

// writeSensorDiscovery publishes a single interrogated asset into the
// sensor_discoveries table so it flows through the unified discovery pipeline
// (discovery-processor → network classification → auto-approval → inventory
// import), mirroring the cloud discovery path. Best-effort: failures are logged
// and do not abort result processing (the discovery_findings row already exists).
func (s *ResultProcessor) writeSensorDiscovery(
	ctx context.Context,
	sensorID uuid.UUID,
	deviceJob *models.DeviceJob,
	batchID string,
	asset models.DiscoveredAsset,
	certFlags map[string]interface{},
	ocspStatus, ocspDetail string,
) {
	// Resolve a destination IP: explicit IP, else DNS-resolved hostname, else a
	// placeholder so the row is still classifiable by hostname.
	destIP := "0.0.0.0"
	if asset.IPAddress != "" {
		destIP = asset.IPAddress
	} else if asset.Hostname != "" {
		if ips, err := net.LookupIP(asset.Hostname); err == nil && len(ips) > 0 {
			destIP = ips[0].String()
		}
	}

	protocol := "TLS"
	if asset.Protocol != "" {
		protocol = asset.Protocol
	}
	port := 443
	if asset.Port > 0 {
		port = asset.Port
	}

	metadata := buildSensorDiscoveryMetadata(deviceJob, asset)
	mergeCertFlags(metadata, certFlags, ocspStatus, ocspDetail)

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		fmt.Printf("Warning: failed to marshal sensor_discovery metadata: %v\n", err)
		return
	}

	now := time.Now()
	// RLS-scoped write on `sensor_discoveries` under the resolved deviceJob.TenantID.
	err = shareddatabase.WithTenantTx(ctx, s.db, deviceJob.TenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, `
			INSERT INTO sensor_discoveries (
				id, sensor_id, tenant_id, batch_id, protocol, dest_ip, port,
				confidence, metadata, hostname, timestamp, created_at
			) VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8, $9, $10, $11, $12)`,
			uuid.New(), sensorID, deviceJob.TenantID, batchID,
			protocol, destIP, port,
			0.95, metadataJSON, stringPtr(asset.Hostname),
			now, now,
		)
		return e
	})
	if err != nil {
		fmt.Printf("Warning: failed to insert sensor_discovery for %s: %v\n", asset.Hostname, err)
	}
}

// buildSensorDiscoveryMetadata builds the sensor_discoveries metadata blob for an
// interrogated asset using the key names discovery-processor's extractCryptoDetails
// expects (note: "version" for the protocol version, not "protocol_version").
func buildSensorDiscoveryMetadata(deviceJob *models.DeviceJob, asset models.DiscoveredAsset) map[string]interface{} {
	meta := map[string]interface{}{
		"discovery_method": "device_interrogation",
		"version":          asset.ProtocolVersion,
		"cipher_suite":     asset.CipherSuite,
	}
	if deviceJob.DeviceID != nil {
		meta["device_id"] = deviceJob.DeviceID.String()
		meta["source_device_id"] = deviceJob.DeviceID.String()
	}
	if asset.HashAlgorithm != "" {
		meta["hash_algorithm"] = asset.HashAlgorithm
	}
	if asset.KeyExchangeAlgorithm != "" {
		meta["key_exchange_algorithm"] = asset.KeyExchangeAlgorithm
	}
	if asset.KeySize > 0 {
		meta["key_size"] = asset.KeySize
	}
	if len(asset.TLSVersions) > 0 {
		meta["tls_versions"] = asset.TLSVersions
	}
	if len(asset.SupportedCiphers) > 0 {
		meta["supported_ciphers"] = asset.SupportedCiphers
	}
	if asset.AssetType != "" {
		meta["asset_type"] = asset.AssetType
	}
	if asset.CertValidationStatus != "" {
		meta["cert_validation_status"] = asset.CertValidationStatus
	}
	if len(asset.Certificates) > 0 {
		certs := make([]map[string]interface{}, 0, len(asset.Certificates))
		for _, cert := range asset.Certificates {
			certs = append(certs, certToMap(cert))
		}
		meta["certificates"] = certs
	}
	return meta
}

// updateDeviceIdentity updates the devices table with identity info from the
// agent, under the resolved tenantID (devices is RLS-scoped).
func (s *ResultProcessor) updateDeviceIdentity(ctx context.Context, tenantID, deviceID uuid.UUID, asset models.DiscoveredAsset) {
	if asset.DeviceInfo == nil {
		return
	}

	di := asset.DeviceInfo

	// Build SET clauses dynamically for non-empty fields
	var setClauses []string
	var args []interface{}
	argIdx := 1

	if di.Vendor != "" {
		setClauses = append(setClauses, fmt.Sprintf("vendor = $%d", argIdx))
		args = append(args, di.Vendor)
		argIdx++
	}
	if di.Model != "" {
		setClauses = append(setClauses, fmt.Sprintf("model = $%d", argIdx))
		args = append(args, di.Model)
		argIdx++
	}
	if di.FirmwareVersion != "" {
		setClauses = append(setClauses, fmt.Sprintf("firmware_version = $%d", argIdx))
		args = append(args, di.FirmwareVersion)
		argIdx++
	}
	if di.SerialNumber != "" {
		setClauses = append(setClauses, fmt.Sprintf("serial_number = $%d", argIdx))
		args = append(args, di.SerialNumber)
		argIdx++
	}

	if len(setClauses) == 0 {
		return
	}

	// Add updated_at and last_interrogated_at
	setClauses = append(setClauses, fmt.Sprintf("updated_at = NOW(), last_interrogated_at = NOW(), connection_status = 'connected'"))

	//nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
	query := fmt.Sprintf(
		"UPDATE devices SET %s WHERE id = $%d AND deleted_at IS NULL",
		strings.Join(setClauses, ", "),
		argIdx,
	)
	args = append(args, deviceID)

	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query, args...)
		return e
	})
	if err != nil {
		fmt.Printf("Warning: failed to update device identity for %s: %v\n", deviceID, err)
	}
}
