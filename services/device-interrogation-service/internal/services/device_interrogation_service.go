package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

// DeviceInterrogationService handles device interrogation logic. The vendor and
// database interrogation logic lives in the shared deviceinterrogation core;
// this service is the in-cluster wrapper that resolves multi-tenant device
// records + credentials, runs the shared interrogator, and persists results as
// discovery findings.
type DeviceInterrogationService struct {
	db                   *sql.DB
	bypassDB             *sql.DB
	masterKey            string
	discoveryIntegration *DiscoveryIntegrationService
	// resultProcessor is borrowed for its materialization half only — the
	// platform-sensor lookup, the certificate quality-flag computation and the
	// sensor_discoveries writer. The agent path reaches those through
	// ProcessJobResults; this in-cluster path has no agent payload to process,
	// so it calls them directly rather than growing a second copy that can drift.
	resultProcessor *ResultProcessor
	registry        *di.Registry
	// observations writes the ops facts and observed relationships a collector
	// emitted. Shared with the agent path so both runtimes persist one shape.
	observations *ObservationSink
}

// NewDeviceInterrogationService creates a new device interrogation service. db is
// the RLS-scoped (crypto_app) connection; bypassDB is the BYPASSRLS
// (crypto_bypass) connection threaded into the discovery integration's
// keyed-by-job-id finalize paths and shared-integration credential reads.
func NewDeviceInterrogationService(db, bypassDB *sql.DB, masterKey string) *DeviceInterrogationService {
	return &DeviceInterrogationService{
		db:                   db,
		bypassDB:             bypassDB,
		masterKey:            masterKey,
		discoveryIntegration: NewDiscoveryIntegrationService(db, bypassDB),
		resultProcessor:      NewResultProcessor(db, bypassDB),
		registry:             di.NewRegistry(),
		observations:         NewObservationSink(db),
	}
}

// markJobFailed stamps a discovery job "failed" with the given reason. The
// caller is always on its way out with an error that carries the same reason,
// so a failure here loses the annotation on the job row, not the signal — but
// it does mean the row keeps whatever status it had (typically "running"), so
// it is logged rather than discarded.
func markJobFailed(ctx context.Context, integration *DiscoveryIntegrationService, jobID uuid.UUID, reason string) {
	if err := integration.UpdateJobStatus(ctx, jobID, "failed", &reason); err != nil {
		log.Printf("device-interrogation: failed to mark job %s failed (%q) — the job row may stay in its previous status: %v", jobID, reason, err)
	}
}

// InterrogateDevice interrogates a device and materializes the results into
// BOTH discovery sinks: discovery_findings (the job's inspection record) and
// sensor_discoveries (the ingestion queue that actually reaches Inventory).
//
// It returns the discovery job id and how many assets were materialized, so the
// caller can report a count describing what landed rather than the empty asset
// list it forwards to the result processor.
func (s *DeviceInterrogationService) InterrogateDevice(
	ctx context.Context,
	tenantID, userID, deviceID uuid.UUID,
) (uuid.UUID, int, error) {
	device, err := s.getDevice(ctx, tenantID, deviceID)
	if err != nil {
		return uuid.Nil, 0, fmt.Errorf("failed to get device: %w", err)
	}
	if device.TenantID != tenantID {
		return uuid.Nil, 0, fmt.Errorf("device not found")
	}

	jobMetadata := map[string]interface{}{
		"asset_id": deviceID.String(),
		// Deprecated alias, one release: the value IS the asset id.
		"device_id":   deviceID.String(),
		"device_type": device.DeviceType,
		"source":      "device_interrogation",
	}

	jobID, err := s.discoveryIntegration.CreateDiscoveryJob(ctx, tenantID, userID, "device_interrogation", jobMetadata)
	if err != nil {
		return uuid.Nil, 0, fmt.Errorf("failed to create discovery job: %w", err)
	}
	if err := s.discoveryIntegration.MarkJobStarted(ctx, jobID); err != nil {
		return uuid.Nil, 0, fmt.Errorf("failed to mark job started: %w", err)
	}

	targetID, err := s.discoveryIntegration.CreateDiscoveryTarget(ctx, tenantID, jobID,
		func() string {
			if device.Hostname != nil {
				return *device.Hostname
			}
			if device.IPAddress != nil {
				return *device.IPAddress
			}
			return device.DeviceType
		}(),
		[]string{"TLS", "IPSec", "SSL VPN"},
		[]int32{443, 500, 4500},
	)
	if err != nil {
		markJobFailed(ctx, s.discoveryIntegration, jobID, "Failed to create discovery target")
		return uuid.Nil, 0, fmt.Errorf("failed to create discovery target: %w", err)
	}

	// Resolve + decrypt credentials, build the shared core's request shape.
	username, password, baseURL, insecureSkipVerify, err := s.getDeviceCredentials(ctx, tenantID, device)
	if err != nil {
		s.updateDeviceError(ctx, tenantID, deviceID, err.Error())
		markJobFailed(ctx, s.discoveryIntegration, jobID, err.Error())
		return uuid.Nil, 0, fmt.Errorf("failed to get credentials: %w", err)
	}
	coreDevice := buildCoreDeviceInfo(device, baseURL)
	coreCreds := di.Credentials{Username: username, Password: password, InsecureSkipVerify: insecureSkipVerify}

	// Databases keep the special persistence path (database_encryption_states).
	switch device.DeviceType {
	case "postgresql", "mysql":
		return s.interrogateDatabase(ctx, tenantID, jobID, targetID, device, coreDevice, coreCreds)
	}

	interrogator, err := s.registry.Get(device.DeviceType)
	if err != nil {
		markJobFailed(ctx, s.discoveryIntegration, jobID, fmt.Sprintf("Unsupported device type: %s", device.DeviceType))
		return uuid.Nil, 0, fmt.Errorf("unsupported device type: %s", device.DeviceType)
	}

	// Resolve the tenant's platform system sensor BEFORE touching the device.
	// Everything this function discovers has to land in sensor_discoveries to
	// reach inventory, and that write needs a sensor id; without one there is no
	// point connecting to the device at all. Same invariant, same failure
	// posture as ProcessJobResults — a missing row is a broken invariant
	// (`create_system_sensors_on_tenant_create` provisions it for every tenant),
	// never a reason to degrade to a findings-only run that reports success and
	// produces nothing a user will ever see.
	systemSensorID, err := s.resultProcessor.lookupSystemSensor(ctx, tenantID)
	if err != nil {
		reason := fmt.Sprintf(
			"platform device-interrogation sensor is missing for this tenant (%s), so interrogation results cannot reach inventory. "+
				"The platform sensor rows are created for every tenant automatically; if one was deleted, contact your platform administrator to restore it. (%v)",
			tenantID, err,
		)
		// Best-effort: the caller receives the same reason via the returned
		// error below, so a failure to stamp the job here loses annotation, not
		// the signal. Matches the sibling failure paths in this function.
		markJobFailed(ctx, s.discoveryIntegration, jobID, reason)
		return uuid.Nil, 0, fmt.Errorf("%s: %w", reason, err)
	}

	result, err := interrogator.Interrogate(ctx, coreDevice, coreCreds)
	if err != nil {
		s.updateDeviceError(ctx, tenantID, deviceID, err.Error())
		markJobFailed(ctx, s.discoveryIntegration, jobID, err.Error())
		return uuid.Nil, 0, fmt.Errorf("device interrogation failed: %w", err)
	}

	// The sensor_discoveries batch is keyed by this run's discovery job, exactly
	// as ProcessJobResults keys its own — so a job's rows are identifiable and
	// one run can never merge into another's batch.
	batchID := jobID.String()

	// materialized counts assets that reached sensor_discoveries — the sink that
	// reaches Inventory. It is deliberately not len(result.Assets): a count of
	// what was discovered, reported as a count of what landed, is exactly the
	// claim that made this bug invisible.
	materialized := 0

	for i := range result.Assets {
		if s.materializeInterrogatedAsset(ctx, tenantID, deviceID, jobID, targetID, systemSensorID, batchID, &result.Assets[i], result) {
			materialized++
		}
	}

	// Persist what the interrogator observed about the device itself: its
	// hardware identity as measured facts and a serial identifier, plus the ops
	// facts and the edges the collectors emitted. Without the identity
	// half the finding carries it (see "device_identity" above) but the Devices
	// page keeps showing "—" for firmware forever, even after a successful
	// interrogation that plainly reported one (L-7).
	s.persistObservations(ctx, tenantID, deviceID, jobID, result)

	s.updateDeviceInterrogationTime(ctx, tenantID, deviceID)
	if err := s.discoveryIntegration.MarkJobCompleted(ctx, jobID); err != nil {
		return uuid.Nil, 0, fmt.Errorf("failed to mark job completed: %w", err)
	}
	return jobID, materialized, nil
}

// materializeInterrogatedAsset writes ONE interrogated asset into both discovery
// sinks and reports whether it reached the inventory sink.
//
//   - discovery_findings — the job's inspection record ("what did this run see?")
//   - sensor_discoveries — the ingestion queue discovery-processor polls, from
//     which it classifies the asset, evaluates the tenant's auto-approval rules
//     and imports it into Inventory (or parks it in Approvals)
//
// The second sink was missing here entirely. An interrogation wrote findings,
// flipped the device to 'connected' and reported a count, while Inventory gained
// nothing and Approvals showed no pending discoveries — because nothing
// downstream reads discovery_findings into inventory. The agent path has always
// reached this sink through ResultProcessor.ProcessJobResults; the in-cluster
// path never did, and which executor claims a given job is a race.
//
// No double-write risk: for jobs that came through here the platform worker
// hands ProcessJobResults an EMPTY asset list, so its per-asset loop — the only
// other writer of these rows — iterates zero times.
//
// Returns true only when the sensor_discoveries row actually landed. The two
// sinks are written independently: a failed finding does not skip the inventory
// write, because that is what turns one broken INSERT into a total pipeline
// outage.
func (s *DeviceInterrogationService) materializeInterrogatedAsset(
	ctx context.Context,
	tenantID, deviceID, jobID, targetID, systemSensorID uuid.UUID,
	batchID string,
	asset *di.CryptoAsset,
	result *di.InterrogateResult,
) bool {
	details := map[string]interface{}{
		"asset_id":          deviceID.String(),
		"device_id":         deviceID.String(), // deprecated alias, same value
		"asset_type":        asset.AssetType,
		"protocol_version":  diDerefStr(asset.ProtocolVersion),
		"cipher_suite":      diDerefStr(asset.CipherSuite),
		"supported_ciphers": asset.SupportedCiphers,
		"key_size":          diDerefInt(asset.KeySize),
		"hash_algorithm":    diDerefStr(asset.HashAlgorithm),
		"tls_versions":      asset.TLSVersions,
		"certificate":       asset.Certificate,
		"certificates":      asset.Certificates,
		"ssh_info":          asset.SSHInfo,
		"service_hints":     asset.ServiceHints,
		"metadata":          asset.Metadata,
		"device_info":       result.DeviceInfo,
		"device_identity":   result.DeviceIdentity,
	}

	var hostname *string
	if asset.Hostname != "" {
		hostname = &asset.Hostname
	}
	var ipAddress *string
	if asset.IPAddress != "" {
		ipAddress = &asset.IPAddress
	}

	// Compute the certificate quality flags once and share them across both
	// sinks, exactly as ProcessJobResults does — one OCSP round trip, one
	// set of flags, identical in discovery_findings and sensor_discoveries.
	discovered := toDiscoveredAsset(asset, result.DeviceIdentity)
	certFlags, ocspStatus, ocspDetail, derivedStatus := s.resultProcessor.assetCertQualityFlags(discovered)
	mergeCertFlags(details, certFlags, ocspStatus, ocspDetail)
	if discovered.CertValidationStatus == "" && derivedStatus != "" {
		details["cert_validation_status"] = derivedStatus
	}

	confidenceScore := 0.9 // High confidence for direct device interrogation
	if _, err := s.discoveryIntegration.CreateDiscoveryFinding(
		ctx, tenantID, jobID, targetID, "device_interrogation",
		asset.Protocol, asset.Port, hostname, ipAddress,
		details, confidenceScore,
	); err != nil {
		fmt.Printf("Warning: failed to create discovery finding: %v\n", err)
		// Deliberately no early return: the sinks are independent, and skipping
		// the inventory write because the inspection record failed is what turns
		// one broken INSERT into a total pipeline outage.
	}

	if err := s.resultProcessor.writeSensorDiscovery(
		ctx, systemSensorID, tenantID, &deviceID, nil, batchID,
		discovered, certFlags, ocspStatus, ocspDetail,
	); err != nil {
		fmt.Printf("Warning: failed to write sensor discovery for device %s: %v\n", deviceID, err)
		return false
	}
	return true
}

// buildCoreDeviceInfo maps a platform device record onto the shared core's
// DeviceInfo.
func buildCoreDeviceInfo(device *models.Device, baseURL string) di.DeviceInfo {
	d := di.DeviceInfo{
		DeviceType:    device.DeviceType,
		ManagementURL: baseURL,
		Metadata:      map[string]interface{}(device.Metadata),
	}
	if device.Hostname != nil {
		d.Hostname = *device.Hostname
	}
	if device.IPAddress != nil {
		d.IPAddress = *device.IPAddress
	}
	if device.Metadata != nil {
		if siteID, ok := device.Metadata["site_id"].(string); ok {
			d.SiteID = siteID
		}
		if p, ok := device.Metadata["ssh_port"].(float64); ok {
			d.Port = int(p)
		}
	}
	return d
}

// toDiscoveredAsset maps the shared core's CryptoAsset onto the platform's
// enriched models.DiscoveredAsset — the shape every downstream materializer
// (certificate quality flags, sensor_discoveries metadata) consumes.
//
// It mirrors the standalone Interrogation Agent's convertInterrogateResult
// field for field. The two runtimes wrap the SAME shared interrogators and must
// deliver the same asset to the same sinks; the only reason this is not one
// function is that each runtime carries its own copy of the DiscoveredAsset
// struct. Change one mapping, change the other.
func toDiscoveredAsset(ca *di.CryptoAsset, identity *di.DeviceIdentity) models.DiscoveredAsset {
	asset := models.DiscoveredAsset{
		Hostname:             ca.Hostname,
		IPAddress:            ca.IPAddress,
		Port:                 ca.Port,
		Protocol:             ca.Protocol,
		AssetType:            ca.AssetType,
		SupportedCiphers:     ca.SupportedCiphers,
		TLSVersions:          ca.TLSVersions,
		CertValidationStatus: ca.CertValidationStatus,
		CertValidationError:  ca.CertValidationError,
		ProtocolVersion:      diDerefStr(ca.ProtocolVersion),
		CipherSuite:          diDerefStr(ca.CipherSuite),
		KeySize:              diDerefInt(ca.KeySize),
		KeyExchangeAlgorithm: diDerefStr(ca.KeyExchangeAlg),
		HashAlgorithm:        diDerefStr(ca.HashAlgorithm),
		Metadata:             ca.Metadata,
	}
	if ca.SSHInfo != nil {
		asset.SSHInfo = &models.SSHInfo{
			Banner:               ca.SSHInfo.Banner,
			KeyTypes:             ca.SSHInfo.KeyTypes,
			HostKeyType:          ca.SSHInfo.HostKeyType,
			HostKeyFingerprint:   ca.SSHInfo.HostKeyFingerprint,
			KexAlgorithm:         ca.SSHInfo.KexAlgorithm,
			EncryptionAlgC2S:     ca.SSHInfo.EncryptionAlgC2S,
			EncryptionAlgS2C:     ca.SSHInfo.EncryptionAlgS2C,
			MACAlgC2S:            ca.SSHInfo.MACAlgC2S,
			MACAlgS2C:            ca.SSHInfo.MACAlgS2C,
			CompressionAlgorithm: ca.SSHInfo.CompressionAlgorithm,
		}
	}
	if ca.ServiceHints != nil {
		asset.ServiceHints = &models.ServiceHints{
			ServiceName:          ca.ServiceHints.ServiceName,
			ServiceVersion:       ca.ServiceHints.ServiceVersion,
			Confidence:           ca.ServiceHints.Confidence,
			IdentificationMethod: ca.ServiceHints.IdentificationMethod,
		}
	}
	if ca.Certificate != nil {
		asset.Certificate = toModelCertificate(ca.Certificate)
	}
	if len(ca.Certificates) > 0 {
		certs := make([]models.CertificateInfo, 0, len(ca.Certificates))
		for i := range ca.Certificates {
			certs = append(certs, *toModelCertificate(&ca.Certificates[i]))
		}
		asset.Certificates = certs
	}
	if identity != nil {
		asset.DeviceInfo = &models.DeviceIdentity{
			Vendor:          identity.Vendor,
			Model:           identity.Model,
			FirmwareVersion: identity.FirmwareVersion,
			SerialNumber:    identity.SerialNumber,
			OSVersion:       identity.OSVersion,
		}
	}
	return asset
}

// toModelCertificate maps the shared/certificates canonical cert shape onto the
// platform's models.CertificateInfo.
func toModelCertificate(c *di.CertificateInfo) *models.CertificateInfo {
	serial := c.SerialNumber
	if serial == "" {
		serial = c.Serial
	}
	return &models.CertificateInfo{
		SubjectDN:               c.SubjectDN,
		IssuerDN:                c.IssuerDN,
		SerialNumber:            serial,
		NotBefore:               c.NotBefore,
		NotAfter:                c.NotAfter,
		Fingerprint:             c.FingerprintSHA256,
		FingerprintSHA256:       c.FingerprintSHA256,
		FingerprintSHA1:         c.FingerprintSHA1,
		KeyAlgorithm:            c.KeyAlgorithm,
		KeySize:                 c.KeySize,
		SignatureAlgorithm:      c.SignatureAlg,
		IsCA:                    c.IsCA,
		CertificatePEM:          c.CertificatePEM,
		SubjectAlternativeNames: c.SubjectAlternativeNames,
		KeyUsage:                c.KeyUsage,
		ExtendedKeyUsage:        c.ExtendedKeyUsage,
		ChainOrder:              c.ChainOrder,
	}
}

func diDerefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func diDerefInt(i *int) int {
	if i == nil {
		return 0
	}
	return *i
}

// getDevice retrieves a managed asset by id, scoped to tenantID.
//
// It does NOT go through DeviceService.GetDevice, which masks the password: the
// value this caller needs is the real stored ciphertext, because
// getDeviceCredentials decrypts it to log into the device. Handing it a mask is
//and the split between the two readers is what keeps the API response
// masked and the interrogator working.
func (s *DeviceInterrogationService) getDevice(ctx context.Context, tenantID, assetID uuid.UUID) (*models.Device, error) {
	query := `
		SELECT a.id, a.tenant_id, a.metadata->>'device_type',
		       a.hostname, host(a.primary_address),
		       m.management_url, m.tls_insecure_skip_verify, m.connection_status,
		       a.metadata, a.tags, a.created_at, a.updated_at,
		       c.credential_id, c.username, c.password_enc
		FROM public.assets a
		JOIN public.asset_management m ON m.tenant_id = a.tenant_id AND m.asset_id = a.id
		LEFT JOIN public.asset_credentials c ON c.tenant_id = a.tenant_id AND c.asset_id = a.id
		WHERE a.id = $1 AND a.tenant_id = $2 AND a.deleted_at IS NULL
	`

	var device models.Device
	var metadataJSON, tagsJSON []byte
	var deviceType, hostname, ipAddress, managementURL sql.NullString
	var credentialID, username, password sql.NullString

	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, assetID, tenantID).Scan(
			&device.ID, &device.TenantID, &deviceType,
			&hostname, &ipAddress,
			&managementURL, &device.TLSInsecureSkipVerify, &device.ConnectionStatus,
			&metadataJSON, &tagsJSON, &device.CreatedAt, &device.UpdatedAt,
			&credentialID, &username, &password,
		)
	})
	if err != nil {
		return nil, err
	}

	device.AssetID = device.ID
	device.DeviceType = deviceType.String
	if hostname.Valid && hostname.String != "" {
		device.Hostname = &hostname.String
	}
	if ipAddress.Valid && ipAddress.String != "" {
		device.IPAddress = &ipAddress.String
	}
	if managementURL.Valid && managementURL.String != "" {
		device.ManagementURL = &managementURL.String
	}
	if credentialID.Valid {
		id, _ := uuid.Parse(credentialID.String)
		device.CredentialID = &id
	}
	if username.Valid {
		device.Username = &username.String
	}
	if password.Valid {
		device.Password = &password.String
	}

	var meta map[string]interface{}
	if err := json.Unmarshal(metadataJSON, &meta); err != nil {
		meta = map[string]interface{}{}
	}
	// The vendor-specific addressing a collector needs (UniFi's site_id, the
	// cloud collectors' arn/region) lives under the nested device key; the rest
	// of assets.metadata is pipeline state that has no business reaching a
	// vendor client.
	if nested, ok := meta[deviceMetadataKey].(map[string]interface{}); ok {
		device.Metadata = nested
	} else {
		device.Metadata = models.JSONB{}
	}
	if err := json.Unmarshal(tagsJSON, &device.Tags); err != nil {
		device.Tags = models.JSONB{}
	}

	return &device, nil
}

// getDeviceCredentials retrieves and decrypts device credentials.
func (s *DeviceInterrogationService) getDeviceCredentials(
	ctx context.Context,
	tenantID uuid.UUID,
	device *models.Device,
) (username, password, baseURL string, insecureSkipVerify bool, err error) {
	// Priority 1: Device-embedded credentials (new approach for network devices)
	if device.Username != nil && device.Password != nil && *device.Username != "" && *device.Password != "" {
		// asset_credentials.password_enc is written by the shared credentials
		// helper and carries its `enc:v1:` tag, so the reader never has to guess
		// whether a value is encrypted. openStoredCredential branches on the tag
		// and keeps the untagged path for a value written before this release.
		password, err = openStoredCredential(s.masterKey, *device.Password)
		if err != nil {
			return "", "", "", false, fmt.Errorf("failed to decrypt device password: %w", err)
		}
		username = *device.Username

		if device.ManagementURL != nil {
			baseURL = *device.ManagementURL
		} else {
			baseURL = fmt.Sprintf("https://%s", deviceHost(device))
		}

		// Per-device explicit opt-in. Defaults to false (verify TLS).
		insecureSkipVerify = device.TLSInsecureSkipVerify
		return username, password, baseURL, insecureSkipVerify, nil
	}

	// Priority 2: Fallback to credential_id (backward compatibility, cloud resources)
	if device.CredentialID == nil {
		return "", "", "", false, fmt.Errorf("device has no credentials configured (neither embedded nor credential_id)")
	}

	query := `
		SELECT config, integration_type
		FROM platform_integrations
		WHERE id = $1
		  AND (tenant_id = $2 OR (tenant_id IS NULL AND is_shared = true))
		  AND is_active = true
		  AND deleted_at IS NULL
	`

	var configJSON string
	var integrationType string
	// RLS: credential_id may point at a shared integration visible to the tenant
	// through integrationRepository.List/Get. RLS hides NULL-tenant rows, so this
	// read uses bypassDB with the same explicit tenant-or-shared predicate.
	if err = s.bypassDB.QueryRowContext(ctx, query, device.CredentialID, tenantID).Scan(&configJSON, &integrationType); err != nil {
		return "", "", "", false, fmt.Errorf("failed to load credentials: %w", err)
	}

	enc, err := encryption.NewService(s.masterKey)
	if err != nil {
		return "", "", "", false, fmt.Errorf("failed to initialize encryption: %w", err)
	}

	var encryptedConfig map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &encryptedConfig); err != nil {
		return "", "", "", false, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	usernameEnc, _ := encryptedConfig["username"].(string)
	passwordEnc, _ := encryptedConfig["password"].(string)

	username, err = enc.Decrypt(usernameEnc)
	if err != nil {
		return "", "", "", false, fmt.Errorf("failed to decrypt username: %w", err)
	}
	password, err = enc.Decrypt(passwordEnc)
	if err != nil {
		return "", "", "", false, fmt.Errorf("failed to decrypt password: %w", err)
	}

	if device.ManagementURL != nil {
		baseURL = *device.ManagementURL
	} else if url, ok := encryptedConfig["url"].(string); ok {
		baseURL = url
	} else {
		baseURL = fmt.Sprintf("https://%s", deviceHost(device))
	}

	if skip, ok := encryptedConfig["insecure_skip_verify"].(bool); ok {
		insecureSkipVerify = skip
	}

	return username, password, baseURL, insecureSkipVerify, nil
}

// deviceHost returns the best available host string for a device.
func deviceHost(device *models.Device) string {
	if device.Hostname != nil {
		return *device.Hostname
	}
	if device.IPAddress != nil {
		return *device.IPAddress
	}
	return "localhost"
}

// updateDeviceInterrogationTime records that the device was reached, on its
// asset_management row.
func (s *DeviceInterrogationService) updateDeviceInterrogationTime(ctx context.Context, tenantID, assetID uuid.UUID) {
	now := time.Now().UTC()
	connected := "connected"
	if err := upsertManagementOwnTx(ctx, s.db, tenantID, assetID, managementUpsert{
		ConnectionStatus:        &connected,
		LastInterrogatedAt:      &now,
		ClearInterrogationError: true,
	}); err != nil {
		log.Printf("device-interrogation: failed to record interrogation time for asset %s: %v", assetID, err)
	}
}

// persistObservations writes the identity, ops facts and observed edges an
// in-cluster interrogation produced.
//
// Identical destination and identical rules to the agent path
// (ResultProcessor.recordInterrogationObservations) because they share the
// sink — the two runtimes writing the same observation two ways is the drift
// that made the sensor and its in-cluster twin diverge.
func (s *DeviceInterrogationService) persistObservations(ctx context.Context, tenantID, assetID, jobID uuid.UUID, result *di.InterrogateResult) {
	obs := InterrogationObservations{
		DeviceIdentity: result.DeviceIdentity,
		Facts:          result.Facts,
		Relationships:  result.Relationships,
	}
	if obs.Empty() {
		return
	}
	if err := s.observations.Persist(ctx, tenantID, assetID, interrogationSource(jobID), obs); err != nil {
		log.Printf("device-interrogation: failed to persist observations for asset %s: %v", assetID, err)
	}
}

// updateDeviceError records why the device could not be reached, on its
// asset_management row.
func (s *DeviceInterrogationService) updateDeviceError(ctx context.Context, tenantID, assetID uuid.UUID, errorMsg string) {
	status := "error"
	if err := upsertManagementOwnTx(ctx, s.db, tenantID, assetID, managementUpsert{
		ConnectionStatus:   &status,
		InterrogationError: &errorMsg,
	}); err != nil {
		log.Printf("device-interrogation: failed to record interrogation error for asset %s: %v", assetID, err)
	}
}

// interrogateDatabase runs the shared core's database interrogation, persists
// the encryption finding to database_encryption_states, and records a discovery
// finding for the pipeline.
func (s *DeviceInterrogationService) interrogateDatabase(
	ctx context.Context,
	tenantID uuid.UUID,
	jobID uuid.UUID,
	targetID uuid.UUID,
	device *models.Device,
	coreDevice di.DeviceInfo,
	coreCreds di.Credentials,
) (uuid.UUID, int, error) {
	finding, err := di.InterrogateDatabase(ctx, coreDevice, coreCreds)
	if err != nil {
		s.updateDeviceError(ctx, tenantID, device.ID, err.Error())
		markJobFailed(ctx, s.discoveryIntegration, jobID, err.Error())
		return uuid.Nil, 0, fmt.Errorf("database interrogation failed: %w", err)
	}

	if device.Hostname != nil {
		finding.Hostname = *device.Hostname
	}
	if device.IPAddress != nil && finding.Hostname == "" {
		finding.Hostname = *device.IPAddress
	}

	dbService := NewDatabaseInterrogationService(s.db)
	if err := dbService.StoreDatabaseEncryptionFinding(ctx, tenantID, &device.ID, finding); err != nil {
		markJobFailed(ctx, s.discoveryIntegration, jobID, err.Error())
		return uuid.Nil, 0, fmt.Errorf("failed to store database encryption finding: %w", err)
	}

	details := map[string]interface{}{
		"asset_id":                   device.ID.String(),
		"device_id":                  device.ID.String(), // deprecated alias, same value
		"db_engine":                  finding.Engine,
		"db_version":                 finding.Version,
		"ssl_enabled":                finding.SSLEnabled,
		"ssl_cipher":                 finding.SSLCipher,
		"ssl_version":                finding.SSLVersion,
		"encryption_at_rest":         finding.EncryptionAtRestEnabled,
		"password_encryption_method": finding.PasswordEncryptionMethod,
		"risk_score":                 finding.RiskScore,
		"raw_config":                 finding.RawConfig,
	}

	protocol := "TLS"
	if !finding.SSLEnabled {
		protocol = "NONE"
	}
	port := 5432
	if device.DeviceType == "mysql" {
		port = 3306
	}

	confidenceScore := 0.95
	if _, err := s.discoveryIntegration.CreateDiscoveryFinding(
		ctx, tenantID, jobID, targetID, "device_interrogation",
		protocol, port,
		&finding.Hostname, nil,
		details, confidenceScore,
	); err != nil {
		fmt.Printf("Warning: failed to create database discovery finding: %v\n", err)
	}

	s.updateDeviceInterrogationTime(ctx, tenantID, device.ID)
	if err := s.discoveryIntegration.MarkJobCompleted(ctx, jobID); err != nil {
		log.Printf("device-interrogation: failed to mark job %s completed — the job row may stay 'running': %v", jobID, err)
	}
	// One database finding per interrogation.
	return jobID, 1, nil
}
