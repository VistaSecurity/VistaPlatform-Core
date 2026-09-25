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
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/forwardmeta"
	"github.com/vistasecurity/vistaplatform/shared/discovery"
)

// ResultProcessor processes device job results and creates discovery findings
type ResultProcessor struct {
	db                   *sql.DB
	bypassDB             *sql.DB
	discoveryIntegration *DiscoveryIntegrationService
	observations         *ObservationSink
	hostInventory        *HostInventoryIngest
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
		observations:         NewObservationSink(db),
		hostInventory:        NewHostInventoryIngest(db, bypassDB),
	}
}

// ProcessJobResults processes job results and creates discovery findings
func (s *ResultProcessor) ProcessJobResults(ctx context.Context, jobID uuid.UUID, result *models.JobResult) error {
	// Get the device job to retrieve tenant_id and asset_id. GetJobByID runs on
	// the bypass role (keyed by job id; tenant is the output).
	jobQueue := NewJobQueueService(s.db, s.bypassDB, nil) // Redis not needed for reading
	deviceJob, err := jobQueue.GetJobByID(ctx, jobID)
	if err != nil {
		return fmt.Errorf("failed to get device job: %w", err)
	}

	// Host inventory takes its OWN path (asset-inventory workstream 2.11b), and
	// it is not a detour around the pipeline below — it is a different
	// pipeline, because a host inventory is not a crypto finding.
	//
	// It was HELD here through 2.11a, and the reason it was held is the reason
	// it now branches rather than joins. Handed to the pipeline below, a
	// host-inventory result would:
	//
	//   - create a discovery job and a discovery finding per socket, so a
	//     laptop with 50 listeners produces 50 findings that describe nothing
	//     anyone asked about;
	//   - publish them into sensor_discoveries, where network classification
	//     routes a 127.0.0.1 endpoint by address — and a loopback socket is not
	//     a connection between two endpoints at all;
	//   - reach the identification engine with a subject built by the crypto
	//     path's builder, which cannot match on an agent id, so every
	//     collection would mint another nameless asset.
	//
	// None of those is a bug in the pipeline below. It is a pipeline for
	// findings about cryptography, and what a host inventory carries — an OS
	// name, a package database, a set of sockets, an agent id — has no crypto
	// posture in it at all. HostInventoryIngest is the consumer that does know
	// what to do with those, and every guard the hold put up is restated there.
	if deviceJob.JobType == models.JobTypeHostInventory {
		return s.materialiseHostInventory(ctx, jobID, deviceJob, result)
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

	// Add the target asset for device interrogation jobs.
	//
	// `device_id` / `source_device_id` are deprecated aliases carrying the SAME
	// value (a device's id IS its asset's id as of phase 1). They are emitted
	// for one release so the discovery-processor and inventory-service readers
	// that still key on them keep working; dropping them is a follow-up on the
	// finding shape.
	if deviceJob.AssetID != nil {
		jobMetadata["source_asset_id"] = deviceJob.AssetID.String()
		jobMetadata["asset_id"] = deviceJob.AssetID.String()
		jobMetadata["source_device_id"] = deviceJob.AssetID.String()
		jobMetadata["device_id"] = deviceJob.AssetID.String()
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

	// Record what the run observed about the interrogated asset itself: its
	// hardware identity, the ops facts, the edges, and that we reached it.
	// None of it is gated on the asset list: a run that found no crypto
	// assets still reached the device and still read what it is.
	var observationsErr error
	if deviceJob.AssetID != nil {
		observationsErr = s.recordInterrogationObservations(ctx, deviceJob.TenantID, *deviceJob.AssetID, jobID, jobResultDeviceIdentity(result), result)
	}

	// Record what actually happens to each asset so the outcome is visible in
	// the UI rather than only on this process's stdout.
	//
	// When we are reusing a discovery job, count what it already holds first.
	// The in-cluster executor materializes its findings itself and hands this
	// processor an empty asset list, so without the pre-count the log reports
	// 0/0/0 for a run that discovered a dozen devices.
	steps := &ProcessingLog{
		AssetsReceived: len(result.Assets),
		DiscoveryJobID: discoveryJobID.String(),
		// What the collector could not read, from whichever executor ran it.
		// Both hand the same shape here, so the job detail cannot tell — and
		// must not be able to tell — which runtime interrogated the device.
		Warnings: di.SanitizeWarnings(result.Warnings),
	}
	if reusedDiscoveryJob {
		steps.ExistingFindings = s.countDiscoveryFindings(ctx, discoveryJobID)
	}
	defer func() {
		if err := steps.persist(ctx, s.bypassDB, jobID); err != nil {
			fmt.Printf("Warning: %v\n", err)
		}
	}()
	// Dropped facts and edges do not fail the job (the crypto assets landed),
	// but they must not leave it reading as a clean success either. Recorded
	// before anything below can return, so the deferred persist carries them.
	if deviceJob.AssetID != nil {
		steps.observationsFailed(deviceJob.AssetID.String(), result.ObservationsErr)
		steps.observationsFailed(deviceJob.AssetID.String(), observationsErr)
	}

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
		// An asset with no address is still a finding ABOUT the interrogated
		// device — a decryption profile, a tunnel whose own address the
		// device did not report — and the device owns it ( W2.2). The
		// in-cluster executor has always written these; this path used to
		// skip them, so which runtime happened to claim the job decided
		// whether the finding existed. Both now write it, owned.
		//
		// Only when there is NO device to own it is it dropped, and then it
		// says so in the job's processing block rather than on stdout.
		if deviceJob.AssetID == nil && deviceJob.IntegrationID == nil && interrogatedDestIP(asset.IPAddress, asset.Hostname, nil) == unspecifiedDestIP {
			label := targetInput
			if label == "" {
				label = "(unidentified)"
			}
			steps.skip(label, StageSensorDiscovery, "the finding has no address and the job names no interrogated device to own it, so it cannot reach inventory")
			continue
		}
		if targetInput == "" {
			if deviceJob.AssetID == nil {
				steps.skip("(unidentified)", StageDiscoveryTarget, "asset has neither hostname nor IP address")
				continue
			}
			targetInput = ownedFindingLabel(*deviceJob.AssetID)
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
		details := s.buildFindingDetails(jobID, deviceJob.AssetID, deviceJob.IntegrationID, asset, sourceType)
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
		if err := s.writeSensorDiscovery(ctx, systemSensorID, deviceJob.TenantID, deviceJob.AssetID, deviceJob.IntegrationID, jobID, batchID, asset, certFlags, ocspStatus, ocspDetail); err != nil {
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
	v := discovery.ClassifyCertChainFromPEMsWith(pems, true, platformOCSPClient())
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
			WHERE tenant_id = $1 AND profile = 'device_interrogation' AND platform_managed
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
	integrationID *uuid.UUID,
	deviceJobID uuid.UUID,
	batchID string,
	asset models.DiscoveredAsset,
	certFlags map[string]interface{},
	ocspStatus, ocspDetail string,
) error {
	protocol := "TLS"
	if asset.Protocol != "" {
		protocol = asset.Protocol
	}
	port := 443
	if asset.Port > 0 {
		port = asset.Port
	}

	metadata := buildSensorDiscoveryMetadata(deviceID, integrationID, asset)
	mergeCertFlags(metadata, certFlags, ocspStatus, ocspDetail)
	// The device job this row was produced by, stamped from the SERVER's own
	// record of the run — never from anything the collector or an agent sent.
	// It is what binds the row's ownership claim to a real interrogation:
	// inventory honours source_asset_id only when this job exists in the
	// tenant, is a device interrogation, and interrogated exactly that asset.
	// Written last, after the forwarded subset, so nothing forwarded can set it.
	delete(metadata, "device_job_id")
	if deviceJobID != uuid.Nil {
		metadata["device_job_id"] = deviceJobID.String()
	}

	// The destination is the address the collector REPORTED, or the
	// unspecified placeholder. Never a DNS answer (finding P-10): an asset
	// with a name and no address is almost always named by a collector label —
	// a PAN-OS rule, an F5 virtual server, a FortiOS tunnel — and resolving it
	// here resolved it through the CLUSTER's search domain, so a rule called
	// `postgres` became the platform's own database. The label stays in
	// metadata (config_name) and on the row's hostname; the finding is owned
	// by the interrogated device, which is what source_asset_id says.
	destIP := interrogatedDestIP(asset.IPAddress, asset.Hostname, metadata)

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
func buildSensorDiscoveryMetadata(deviceID *uuid.UUID, integrationID *uuid.UUID, asset models.DiscoveredAsset) map[string]interface{} {
	discoveryMethod := "device_interrogation"
	if integrationID != nil {
		discoveryMethod = "cloud_api"
	}
	meta := map[string]interface{}{
		"discovery_method": discoveryMethod,
		"version":          asset.ProtocolVersion,
		"cipher_suite":     asset.CipherSuite,
	}
	if deviceID != nil {
		meta["device_id"] = deviceID.String()
		meta["source_device_id"] = deviceID.String()
		// The interrogated device OWNS this finding ( W2.2). The key is
		// the one host inventory already uses for the same statement. It is
		// what lets a finding with a public address or no address at all land
		// on the device instead of being classified third-party and dropped;
		// inventory-service honours it only for a row written under the
		// tenant's platform interrogation sensor (see interrogationOwner).
		meta["source_asset_id"] = deviceID.String()
	}
	if integrationID != nil {
		meta["integration_id"] = integrationID.String()
		meta["source_integration_id"] = integrationID.String()
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
	applyVPNKeyExchange(meta, asset)
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
	if asset.Metadata != nil {
		for _, key := range []string{"cloud_provider", "cloud_region", "cloud_account_id", "vpc_id"} {
			if value, ok := asset.Metadata[key]; ok && value != "" {
				meta[key] = value
			}
		}
		copyTLSKeyExchangeSupport(meta, asset.Metadata)
	}
	// The vetted posture subset ( W2.1): VPN peer, IKE version, SSH
	// banner and host key, MAC, profile / certificate / object names — each
	// under ONE canonical key whatever the vendor called it, validated, and
	// nothing outside the allowlist. See shared/deviceinterrogation/forwardmeta
	// for what is deliberately left behind (the device's own serial above all).
	for k, v := range forwardmeta.Project(forwardSource(asset)) {
		meta[k] = v
	}
	applySSHBannerVersion(meta, asset)
	if len(asset.Certificates) > 0 {
		certs := make([]map[string]interface{}, 0, len(asset.Certificates))
		for _, cert := range asset.Certificates {
			certs = append(certs, certToMap(cert))
		}
		meta["certificates"] = certs
	}
	return meta
}

// unspecifiedDestIP is the sensor_discoveries placeholder for "no address was
// reported". dest_ip is NOT NULL; every reader treats this value as absent.
const unspecifiedDestIP = "0.0.0.0"

// interrogatedDestIP is the dest_ip an interrogated asset is written with.
//
//   - A reported address that is a valid IP literal is used as is. Anything
//     else — empty, a name, an IPv6 zone Postgres `inet` refuses — is not an
//     address, and the row is written address-less rather than failing the
//     INSERT or guessing.
//
//   - An address that IS the tunnel's peer is not the asset's address.
//     FortiOS and Cisco put the peer in the asset's address field (remote-gw,
//     `set peer`), which made the far end of every tunnel an address of the
//     interrogated device's configuration — a public one classified
//     third-party and dropped, a private one minted as a new "server". The
//     peer is kept under vpn_peer_address; the configuration belongs to the
//     device, with no endpoint, because the device's own tunnel address was
//     not reported.
//
//   - When the reported address is unusable or is the peer, a hostname that is
//     itself an IP LITERAL is the address instead. Cisco sets every row's
//     hostname to the address it interrogated the device on, so its crypto
//     maps land on the device's own address. That is a literal read, not a
//     lookup: a hostname that is a name stays a label.
//
// Nothing here resolves a name.
func interrogatedDestIP(reported, hostname string, metadata map[string]interface{}) string {
	peer := net.ParseIP(stringMeta(metadata, forwardmeta.KeyVPNPeerAddress))
	for _, candidate := range []string{reported, hostname} {
		if ip := literalAddress(candidate); ip != nil && (peer == nil || !peer.Equal(ip)) {
			return ip.String()
		}
	}
	return unspecifiedDestIP
}

// literalAddress parses s as an IP literal usable as dest_ip: no IPv6 zone
// (Postgres `inet` refuses one) and not the unspecified address.
func literalAddress(s string) net.IP {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "%") {
		return nil
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.IsUnspecified() {
		return nil
	}
	return ip
}

func stringMeta(m map[string]interface{}, key string) string {
	v, _ := m[key].(string)
	return v
}

// forwardSource adapts the platform's asset struct to the forwarding
// projection. The two runtimes both reach this through writeSensorDiscovery,
// so there is one mapping, not one per executor.
func forwardSource(asset models.DiscoveredAsset) forwardmeta.Source {
	src := forwardmeta.Source{AssetType: asset.AssetType, Metadata: asset.Metadata}
	if s := asset.SSHInfo; s != nil {
		src.SSH = forwardmeta.SSH{
			Banner:             s.Banner,
			HostKeyType:        s.HostKeyType,
			HostKeyFingerprint: s.HostKeyFingerprint,
			KexAlgorithm:       s.KexAlgorithm,
			EncryptionAlgC2S:   s.EncryptionAlgC2S,
			MACAlgC2S:          s.MACAlgC2S,
		}
	}
	return src
}

// applySSHBannerVersion makes an SSH configuration's protocol version the one
// its banner states.
//
// The banner is the measurement: RFC 4253 §4.2 puts the protocol version in
// it, and `SSH-1.99` is a server that still accepts the broken SSH-1 protocol
// (catalogue risk 78). The collectors' own field is not — Cisco's collector and
// the generic SSH prober write a constant `SSH-2.0` whatever the server said,
// so an IOS box advertising 1.99 was linked, scored and shown as 2.0 (risk 15).
// Inventory's SSH ingest reads the same banner and links the same code
// (cryptoparse.SSHProtocolVersionCode); this keeps the configuration's
// protocol_version column saying the same thing rather than the fabricated
// constant. Done here, in the writer both runtimes share, because agents in
// the field keep sending the constant after the collectors are fixed.
//
// The banner is the ONLY source. When there is none, or it states no
// recognisable version, the version is unknown and the field is removed —
// forwarding the collector's constant instead would be exactly the fabricated
// `SSH-2.0` this exists to stop (unknown stays unknown; removes the
// constant at the collectors, this is the defensive half for agents that
// still send it).
func applySSHBannerVersion(meta map[string]interface{}, asset models.DiscoveredAsset) {
	if !strings.EqualFold(strings.TrimSpace(asset.Protocol), "SSH") {
		return
	}
	banner, _ := meta[forwardmeta.KeySSHBanner].(string)
	if code := cryptoparse.SSHProtocolVersionCode(banner); code != "" {
		meta["version"] = code
		return
	}
	delete(meta, "version")
}

// applyVPNKeyExchange writes an IPsec tunnel's key exchange from the DH-group
// settings the VPN collectors keep in metadata: "dh_group" is the IKE SA's
// group setting ("14", "14 5", "Group 19"), "pfs_dh_group" the phase-2 PFS
// group.
//
//   - key_exchange_algorithm is the IKE setting's preferred (first) group as
//     its catalogue code. When that group has no catalogue row, or only a PFS
//     group is known, the key exchange is UNKNOWN and the key is absent: the
//     second choice, or the PFS group, is not the one in use.
//   - kex_algorithms is every group the catalogue can assess — IKE groups in
//     preference order, then PFS — because a peer can steer the tunnel onto
//     any of them: inventory links each, the tunnel is scored on its weakest,
//     and any classical group makes it quantum-vulnerable. It is an OFFER
//     list; the converter does not promote its head to the key exchange for
//     an interrogation row.
//   - key_size is the chosen key exchange's key size, or absent. Once any
//     group parses it is never the collector's value: key_size is read against
//     the key-exchange family (SP 800-131A floors), and the AES length a
//     collector put there reads as a 256-bit finite-field key — Critical.
//
// It is done HERE, in the one writer both runtimes share, rather than trusted
// to the collector alone, because agents in the field update later than the
// platform: an agent built before this change still sends the group only in
// metadata, the AES length in key_size — and, from UniFi, the IKE VERSION as
// the key exchange. A current collector sends values this reproduces exactly.
//
// Nothing resolvable, nothing written: an unassigned group stays unknown.
func applyVPNKeyExchange(meta map[string]interface{}, asset models.DiscoveredAsset) {
	if v := legacyIKEVersionScalar(asset.KeyExchangeAlgorithm); v != "" {
		delete(meta, "key_exchange_algorithm")
		if asset.ProtocolVersion == "" {
			meta["version"] = v
		}
	}

	ike := cryptoparse.ParseIKEGroups(dhGroupSetting(asset.Metadata["dh_group"]))
	pfs := cryptoparse.ParseIKEGroups(dhGroupSetting(asset.Metadata["pfs_dh_group"]))
	if len(ike)+len(pfs) == 0 {
		return
	}
	// A group is configured: the key exchange and its size come from the
	// groups and from nothing else.
	delete(meta, "key_exchange_algorithm")
	delete(meta, "key_size")
	if offered := cryptoparse.OfferedIKEGroupCodes(ike, pfs); len(offered) > 0 {
		meta["kex_algorithms"] = offered
	}
	if g, ok := cryptoparse.PreferredIKEGroup(ike); ok {
		meta["key_exchange_algorithm"] = g.Code
		if g.Bits > 0 {
			meta["key_size"] = g.Bits
		}
	}
}

// dhGroupSetting reads a collector's DH-group setting, which UniFi serialises
// as a JSON number and everyone else as a string.
func dhGroupSetting(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return fmt.Sprint(int(t))
	}
	return ""
}

// legacyIKEVersionScalar recognises the IKE version an older UniFi collector
// wrote into the key-exchange field ("IKEV2"), and returns it in the spelling
// the protocol-version field uses.
func legacyIKEVersionScalar(kex string) string {
	switch strings.ToUpper(strings.TrimSpace(kex)) {
	case "IKEV1":
		return "IKEv1"
	case "IKEV2":
		return "IKEv2"
	}
	return ""
}

// recordInterrogationObservations writes what an agent's run observed about the
// interrogated asset back onto the asset model.
//
// Three destinations, and the split is the point:
//
//   - vendor / model / firmware / os version → asset_facts, as MEASURED facts
//     under `interrogation:<job>`. They used to be columns of `devices`, where
//     a later interrogation silently overwrote an operator's correction and
//     nothing recorded that it had.
//   - serial number → asset_identifiers, because it is how the asset is
//     recognised, not a property of it.
// - ops facts and observed edges → asset_facts / asset_relationships,
//     through the identification engine so a peer becomes an asset.
//
// The management row is advanced separately (markInterrogated), because
// "we reached it" is true whether or not the device told us anything about
// itself.
//
// It returns what the sink could not persist, for the job's processing block.
func (s *ResultProcessor) recordInterrogationObservations(
	ctx context.Context,
	tenantID, assetID, jobID uuid.UUID,
	identity *di.DeviceIdentity,
	result *models.JobResult,
) error {
	obs := InterrogationObservations{
		ObservedAt:     result.CompletedAt,
		Facts:          result.Facts,
		Relationships:  result.Relationships,
		DeviceIdentity: identity,
	}
	// Pin the SSH host key the AGENT was shown, when this device has none
	// pinned. The in-cluster path does the same thing at its own call site; both
	// runtimes have to enrol, or a device only ever interrogated by an agent
	// would never acquire a pin and the comparison would have nothing to read.
	if fp, keyType := hostKeyFromJobResult(result); fp != "" {
		if _, err := pinSSHHostKeyIfUnset(ctx, s.db, tenantID, assetID, fp, keyType); err != nil {
			fmt.Printf("Warning: failed to pin ssh host key for asset %s: %v\n", assetID, err)
		}
	}
	var persistErr error
	if !obs.Empty() {
		if persistErr = s.observations.Persist(ctx, tenantID, assetID, interrogationSource(jobID), obs); persistErr != nil {
			// The crypto assets have already landed. Losing the ops
			// observations is not a failed job that tells the operator the
			// interrogation did not happen — but it is returned so the job's
			// processing block says what was lost.
			fmt.Printf("Warning: failed to persist interrogation observations for asset %s: %v\n", assetID, persistErr)
		}
	}
	s.markInterrogated(ctx, tenantID, assetID)
	return persistErr
}

// jobResultDeviceIdentity returns what the interrogated device said it is.
//
// A current agent sends it once, on the result ( W2.7), exactly as the
// in-cluster executor hands its own InterrogateResult.DeviceIdentity to the
// observation sink. An older agent sends it only on each ASSET — which is why a
// PAN-OS box with no decryption profiles, a run that found no crypto assets at
// all, lost its vendor, model and serial: there was no asset to carry them.
// The first asset's copy is still read when the result carries none, so an
// agent built before this change keeps working.
//
// The result-level copy wins when both are present: it is the device's
// identity by construction, where an asset's copy is a duplicate of it.
func jobResultDeviceIdentity(result *models.JobResult) *di.DeviceIdentity {
	if result == nil {
		return nil
	}
	if id := result.DeviceIdentity; !deviceIdentityEmpty(id) {
		out := *id
		return &out
	}
	// Only the first asset: every asset carries the same copy, and a later one
	// disagreeing would be a collector bug, not a second device.
	if len(result.Assets) == 0 || result.Assets[0].DeviceInfo == nil {
		return nil
	}
	d := result.Assets[0].DeviceInfo
	out := &di.DeviceIdentity{
		Vendor:          d.Vendor,
		Model:           d.Model,
		FirmwareVersion: d.FirmwareVersion,
		SerialNumber:    d.SerialNumber,
		OSVersion:       d.OSVersion,
	}
	if deviceIdentityEmpty(out) {
		return nil
	}
	return out
}

func deviceIdentityEmpty(d *di.DeviceIdentity) bool {
	return d == nil || (strings.TrimSpace(d.Vendor) == "" && strings.TrimSpace(d.Model) == "" &&
		strings.TrimSpace(d.FirmwareVersion) == "" && strings.TrimSpace(d.SerialNumber) == "" &&
		strings.TrimSpace(d.OSVersion) == "" && strings.TrimSpace(d.ClassHint) == "")
}

// ownedFindingLabel is the discovery-target input for a finding that has no
// address or name of its own: the device that owns it.
func ownedFindingLabel(deviceAssetID uuid.UUID) string {
	return "interrogated-device:" + deviceAssetID.String()
}

// markInterrogated advances the asset's management row after a successful run:
// reached, at this time, with no outstanding error.
func (s *ResultProcessor) markInterrogated(ctx context.Context, tenantID, assetID uuid.UUID) {
	now := time.Now().UTC()
	connected := "connected"
	if err := upsertManagementOwnTx(ctx, s.db, tenantID, assetID, managementUpsert{
		ConnectionStatus:        &connected,
		LastInterrogatedAt:      &now,
		ClearInterrogationError: true,
	}); err != nil {
		fmt.Printf("Warning: failed to update management status for asset %s: %v\n", assetID, err)
	}
}

// materialiseHostInventory turns a REMOTE host-inventory collection into
// inventory (asset-inventory workstream 2.11b).
//
// Remote only, because that is the only mode that arrives as a job result: a
// local collection has no job behind it and posts to its own intake route,
// which calls the same HostInventoryIngest directly. One consumer, two doors.
//
// The counts land on the job row in place of 2.11a's `fatal` line. That line
// said outright that nothing had been materialised, which was the honest thing
// to say while nothing was; saying anything like it now, or reporting the
// finding-shaped zeros the pipeline below would produce, would be the "feature
// that silently does nothing" failure the other way round.
//
// A failure here fails the JOB. That is deliberate and it is the opposite of
// how the crypto path treats its ops observations: there, the crypto assets
// have already landed and losing the facts is worth a warning. Here the facts
// ARE the result, so a run that could not write them produced nothing, and an
// operator told "completed" would have no way to find that out.
func (s *ResultProcessor) materialiseHostInventory(
	ctx context.Context, jobID uuid.UUID, deviceJob *models.DeviceJob, result *models.JobResult,
) error {
	agentID := uuid.Nil
	if deviceJob.AgentID != nil {
		agentID = *deviceJob.AgentID
	}
	if _, err := s.hostInventory.MaterialiseAndRecord(ctx, deviceJob.TenantID, agentID, jobID,
		hostInventoryObservationsFromResult(result)); err != nil {
		return fmt.Errorf("host inventory materialisation failed: %w", err)
	}
	return nil
}

// hostInventoryObservationsFromResult rebuilds the collector's observation
// shape from the job-result envelope it travelled in.
//
// The agent submits a host-inventory job result through the ordinary /results
// route, which carries `models.JobResult` — so the same three pieces the local
// intake receives as a `di.InterrogateResult` arrive here as Facts, Metadata
// and a slice of DiscoveredAsset. Reassembling them costs one pass and means
// the consumer has ONE input shape rather than a local branch and a remote
// branch that can disagree about what a host inventory is.
//
// Only the fields a host inventory actually populates are carried. Every crypto
// field on DiscoveredAsset is nil on this path by construction — the collector
// leaves them nil so that "not probed" stays distinguishable from "probed and
// found nothing" — so copying them would be copying nils with extra steps.
func hostInventoryObservationsFromResult(result *models.JobResult) *di.InterrogateResult {
	if result == nil {
		return nil
	}
	out := &di.InterrogateResult{
		Facts:      result.Facts,
		DeviceInfo: result.Metadata,
		Assets:     make([]di.CryptoAsset, 0, len(result.Assets)),
	}
	if out.DeviceInfo == nil {
		out.DeviceInfo = map[string]interface{}{}
	}
	for i := range result.Assets {
		a := &result.Assets[i]
		asset := di.CryptoAsset{
			Hostname:  a.Hostname,
			IPAddress: a.IPAddress,
			Port:      a.Port,
			Protocol:  a.Protocol,
			Metadata:  a.Metadata,
		}
		if a.ServiceHints != nil {
			asset.ServiceHints = &di.ServiceHints{
				ServiceName:          a.ServiceHints.ServiceName,
				Confidence:           a.ServiceHints.Confidence,
				IdentificationMethod: a.ServiceHints.IdentificationMethod,
			}
		}
		out.Assets = append(out.Assets, asset)
	}
	return out
}

// hostKeyFromJobResult returns the SSH host key an agent-run interrogation
// observed. Mirrors hostKeyFingerprintFromResult on the in-cluster path; the
// two differ only because each runtime carries its own asset struct.
func hostKeyFromJobResult(result *models.JobResult) (fingerprint, keyType string) {
	if result == nil {
		return "", ""
	}
	for i := range result.Assets {
		info := result.Assets[i].SSHInfo
		if info != nil && info.HostKeyFingerprint != "" {
			return info.HostKeyFingerprint, info.HostKeyType
		}
	}
	return "", ""
}
