package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
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

	// Reuse the discovery job an upstream executor already created for this
	// device job, when one was stamped on it (see RecordDiscoveryJob). Only a
	// parseable, non-nil id counts — a malformed value must not silently become
	// a uuid.Nil foreign key on every target and finding we then write.
	var discoveryJobID uuid.UUID
	reusedDiscoveryJob := false
	if raw, ok := deviceJob.Parameters["discovery_job_id"].(string); ok {
		if parsed, perr := uuid.Parse(raw); perr == nil && parsed != uuid.Nil {
			discoveryJobID = parsed
			reusedDiscoveryJob = true
		} else {
			fmt.Printf("Warning: device job %s carries an unusable discovery_job_id %q; creating a new discovery job\n", jobID, raw)
		}
	}
	if !reusedDiscoveryJob {
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

	// Record what actually happens to each asset so the outcome is visible in
	// the UI rather than only on this process's stdout.
	//
	// When we are reusing a discovery job, count what it already holds first.
	// The in-cluster executor materializes its findings itself and hands this
	// processor an empty asset list, so without the pre-count the log reports
	// 0/0/0 for a run that discovered a dozen devices.
	steps := &ProcessingLog{AssetsReceived: len(result.Assets), DiscoveryJobID: discoveryJobID.String()}
	if reusedDiscoveryJob {
		steps.ExistingFindings = s.countDiscoveryFindings(ctx, discoveryJobID)
	}
	defer func() {
		if err := steps.persist(ctx, s.bypassDB, jobID); err != nil {
			fmt.Printf("Warning: %v\n", err)
		}
	}()

	// Look up the tenant's platform system sensor once. Assets handed to this
	// processor are additionally published into sensor_discoveries under it so
	// they flow through the unified discovery pipeline (network classification +
	// auto-approval + auto-import). discovery_findings alone reaches nothing.
	//
	// This lookup is UNCONDITIONAL, and the gate it replaced (`IntegrationID ==
	// nil`) was wrong in both directions. It read as "cloud jobs already wrote
	// sensor_discoveries upstream, don't double-write" — but the only cloud path
	// that writes them upstream is the interactive handler
	// (api/router.go -> CloudDiscoveryService.WriteSensorDiscoveries), and that
	// path never calls this processor at all: it marks its own device_job
	// in_progress at creation so the platform worker cannot claim it, and
	// finalises the job itself. Every executor that DOES reach here — the
	// platform worker (scheduled cloud discovery and device interrogation) and an
	// agent submitting results — has written no sensor_discoveries row.
	//
	// The gate was also inert, because GetJobByID omitted integration_id and so
	// reported nil for every job. Fixing that SELECT without also fixing this
	// gate would have switched scheduled cloud discovery onto the skip branch and
	// silently stopped its assets reaching inventory — the accidental nil was the
	// only reason they arrived.
	//
	// A missing sensor row used to fall back to discovery_findings only. That
	// fallback is gone: nothing downstream reads discovery_findings into
	// inventory, so it converted a broken invariant into "the job succeeded and
	// produced nothing a user will ever see" — on a timer, because scheduled
	// scans run this same path. The job now FAILS, with the reason on the job
	// itself.
	batchID := discoveryJobID.String()
	systemSensorID, err := s.lookupSystemSensor(ctx, deviceJob.TenantID)
	if err != nil {
		return s.failMissingPlatformSensor(ctx, jobQueue, jobID, deviceJob, result, steps, err)
	}

	// Process each discovered asset
	for _, asset := range result.Assets {
		// Determine target input (hostname or IP)
		targetInput := asset.Hostname
		if targetInput == "" && asset.IPAddress != "" {
			targetInput = asset.IPAddress
		}
		if targetInput == "" {
			steps.skip("(unidentified)", StageDiscoveryTarget, "asset has neither hostname nor IP address")
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
			steps.fail(targetInput, StageDiscoveryTarget, err)
			continue
		}
		steps.ok(targetInput, StageDiscoveryTarget)

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
			ctx, deviceJob.TenantID, discoveryJobID, targetID, sourceType,
			protocol, port, hostnamePtr, ipPtr,
			details, confidenceScore,
		)
		if err != nil {
			fmt.Printf("Warning: failed to create discovery finding for %s: %v\n", targetInput, err)
			steps.fail(targetInput, StageDiscoveryFinding, err)
			// Deliberately NOT `continue`: the two sinks are independent, and
			// skipping the sensor_discoveries write on a findings failure is
			// what turned one broken INSERT into a total pipeline outage —
			// no findings AND no classification/auto-approval/auto-import.
		} else {
			steps.ok(targetInput, StageDiscoveryFinding)
		}

		// Also publish into the unified sensor_discoveries pipeline so the
		// discovery-processor applies network classification + tenant
		// auto-approval rules and auto-imports the asset. discovery-processor's
		// DB poller picks up the batch; no explicit trigger is required.
		//
		// systemSensorID cannot be uuid.Nil here — a missing platform sensor
		// fails the job before this loop runs.
		if err := s.writeSensorDiscovery(ctx, systemSensorID, deviceJob.TenantID, deviceJob.DeviceID, batchID, asset, certFlags, ocspStatus, ocspDetail); err != nil {
			fmt.Printf("Warning: failed to write sensor discovery for %s: %v\n", targetInput, err)
			steps.fail(targetInput, StageSensorDiscovery, err)
		} else {
			steps.ok(targetInput, StageSensorDiscovery)
		}
	}

	// Mark the discovery job completed once the assets are processed. A job WE
	// created is also marked completed when the payload was empty — otherwise it
	// stays `queued` forever on Discovery → Discovery Jobs with nothing in it. A
	// reused job's own creator owns its lifecycle when there was nothing for us
	// to add.
	if !reusedDiscoveryJob || len(result.Assets) > 0 {
		err = s.discoveryIntegration.MarkJobCompleted(ctx, discoveryJobID)
		if err != nil {
			fmt.Printf("Warning: failed to mark discovery job as completed: %v\n", err)
		}
	}

	return nil
}

// failMissingPlatformSensor turns a broken platform-sensor invariant into a
// visible job failure.
//
// Three surfaces, matching how the neighbouring failures in this file report:
// the device job's status + error_message (what the Discovery → Jobs list
// shows), the persisted processing log's `fatal` (what the job detail modal
// shows, written by the caller's deferred persist), and stdout for the operator
// tailing logs. The message names the fix, because the person who sees it is a
// tenant user who cannot be expected to infer "a database trigger did not run".
func (s *ResultProcessor) failMissingPlatformSensor(
	ctx context.Context,
	jobQueue *JobQueueService,
	jobID uuid.UUID,
	deviceJob *models.DeviceJob,
	result *models.JobResult,
	steps *ProcessingLog,
	cause error,
) error {
	reason := fmt.Sprintf(
		"platform device-interrogation sensor is missing for this tenant (%s), so interrogation results cannot reach inventory. "+
			"The platform sensor rows are created for every tenant automatically; if one was deleted, contact your platform administrator to restore it. (%v)",
		deviceJob.TenantID, cause,
	)
	steps.Fatal = reason
	fmt.Printf("ERROR: device job %s: %s\n", jobID, reason)

	// `result` is passed back verbatim: UpdateJobStatus REWRITES device_jobs.results
	// on a failed status, so handing it nil would blank the agent's payload — the
	// evidence of what the run actually found — while marking the job failed.
	if err := jobQueue.UpdateJobStatus(ctx, jobID, models.JobStatusFailed, result, &reason); err != nil {
		fmt.Printf("Warning: failed to mark device job %s failed after missing platform sensor: %v\n", jobID, err)
	}
	return fmt.Errorf("%s: %w", reason, cause)
}

// countDiscoveryFindings returns how many findings a discovery job already
// carries. Used to reconcile the processing log against reality when the results
// were materialized by whoever created the discovery job rather than here.
//
// RLS: keyed by discovery job id with no tenant input → bypass role, matching
// the other finalize-by-id paths. A failure yields 0 and a warning; it must not
// abort result processing.
func (s *ResultProcessor) countDiscoveryFindings(ctx context.Context, discoveryJobID uuid.UUID) int {
	var n int
	if err := s.bypassDB.QueryRowContext(ctx,
		`SELECT count(*) FROM discovery_findings WHERE job_id = $1`, discoveryJobID,
	).Scan(&n); err != nil {
		fmt.Printf("Warning: failed to count existing findings for discovery job %s: %v\n", discoveryJobID, err)
		return 0
	}
	return n
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

// ErrNoPlatformSensor is returned when a tenant has no live platform device
// interrogation sensor row. It is a BROKEN INVARIANT, not a missing optional
// prerequisite: `create_system_sensors_on_tenant_create` gives every tenant an
// identity row for the shared in-cluster agent at tenant creation, so its
// absence means the row was deleted, or the trigger did not run. Callers must
// surface it, never degrade past it — see ProcessJobResults.
var ErrNoPlatformSensor = errors.New("tenant has no platform device-interrogation sensor")

// lookupSystemSensor returns the tenant's platform "device_interrogation" system
// sensor id. This is the same sensor the cloud discovery path writes
// sensor_discoveries under.
//
// Returns ErrNoPlatformSensor when no live row matches. `deleted_at IS NULL` is
// part of the predicate rather than an afterthought: `sensors` soft-deletes, so
// without it a tenant who removed the row kept getting its id back and every
// interrogated asset was attributed to a sensor the user had deleted — wrong
// rather than absent, which is why the nil branch was almost never observed.
func (s *ResultProcessor) lookupSystemSensor(ctx context.Context, tenantID uuid.UUID) (uuid.UUID, error) {
	// RLS-scoped read on `sensors`: WithTenantTx sets app.tenant_id; the explicit
	// WHERE tenant_id = $1 is kept as the primary control.
	var id uuid.UUID
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT id FROM sensors
			WHERE tenant_id = $1 AND profile = 'device_interrogation' AND 'system' = ANY(tags)
			  AND deleted_at IS NULL
			LIMIT 1`, tenantID).Scan(&id)
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return uuid.Nil, ErrNoPlatformSensor
		}
		return uuid.Nil, fmt.Errorf("failed to look up platform system sensor for tenant %s: %w", tenantID, err)
	}
	return id, nil
}

// writeSensorDiscovery publishes a single interrogated asset into the
// sensor_discoveries table so it flows through the unified discovery pipeline
// (discovery-processor → network classification → auto-approval → inventory
// import), mirroring the cloud discovery path. Failures do not abort result
// processing, but they ARE returned so the caller can record them in the job's
// processing log — a silently swallowed error here is invisible to the user.
//
// It takes tenantID/deviceID rather than a *models.DeviceJob because the
// in-cluster interrogation path (DeviceInterrogationService) publishes through
// this same function and holds no device job — the two runtimes must write
// byte-identical rows, so they share this writer rather than each growing one.
func (s *ResultProcessor) writeSensorDiscovery(
	ctx context.Context,
	sensorID uuid.UUID,
	tenantID uuid.UUID,
	deviceID *uuid.UUID,
	batchID string,
	asset models.DiscoveredAsset,
	certFlags map[string]interface{},
	ocspStatus, ocspDetail string,
) error {
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

	metadata := buildSensorDiscoveryMetadata(deviceID, asset)
	mergeCertFlags(metadata, certFlags, ocspStatus, ocspDetail)

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal sensor_discovery metadata: %w", err)
	}

	now := time.Now()
	// RLS-scoped write on `sensor_discoveries` under the resolved tenantID.
	err = shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, `
			INSERT INTO sensor_discoveries (
				id, sensor_id, tenant_id, batch_id, protocol, dest_ip, port,
				confidence, metadata, hostname, timestamp, created_at
			) VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8, $9, $10, $11, $12)`,
			uuid.New(), sensorID, tenantID, batchID,
			// Canonical protocol_type spelling — see cryptoparse.NormalizeProtocol.
			cryptoparse.NormalizeProtocol(protocol), destIP, port,
			0.95, metadataJSON, stringPtr(asset.Hostname),
			now, now,
		)
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to insert sensor_discovery: %w", err)
	}
	return nil
}

// buildSensorDiscoveryMetadata builds the sensor_discoveries metadata blob for an
// interrogated asset using the key names discovery-processor's extractCryptoDetails
// expects (note: "version" for the protocol version, not "protocol_version").
func buildSensorDiscoveryMetadata(deviceID *uuid.UUID, asset models.DiscoveredAsset) map[string]interface{} {
	meta := map[string]interface{}{
		"discovery_method": "device_interrogation",
		"version":          asset.ProtocolVersion,
		"cipher_suite":     asset.CipherSuite,
	}
	if deviceID != nil {
		meta["device_id"] = deviceID.String()
		meta["source_device_id"] = deviceID.String()
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

	setClauses, args := deviceIdentitySetClauses(di.Vendor, di.Model, di.FirmwareVersion, di.SerialNumber, 1)
	if len(setClauses) == 0 {
		return
	}
	argIdx := len(args) + 1

	// Add updated_at and last_interrogated_at
	setClauses = append(setClauses, "updated_at = NOW(), last_interrogated_at = NOW(), connection_status = 'connected'")

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
