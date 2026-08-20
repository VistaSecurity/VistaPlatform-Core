package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

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
		s.discoveryIntegration.UpdateJobStatus(ctx, jobID, "failed", stringPtr("Failed to create discovery target"))
		return uuid.Nil, 0, fmt.Errorf("failed to create discovery target: %w", err)
	}

	// Resolve + decrypt credentials, build the shared core's request shape.
	username, password, baseURL, insecureSkipVerify, err := s.getDeviceCredentials(ctx, tenantID, device)
	if err != nil {
		s.updateDeviceError(ctx, tenantID, deviceID, err.Error())
		s.discoveryIntegration.UpdateJobStatus(ctx, jobID, "failed", stringPtr(err.Error()))
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
		s.discoveryIntegration.UpdateJobStatus(ctx, jobID, "failed", stringPtr(fmt.Sprintf("Unsupported device type: %s", device.DeviceType)))
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
		_ = s.discoveryIntegration.UpdateJobStatus(ctx, jobID, "failed", stringPtr(reason))
		return uuid.Nil, 0, fmt.Errorf("%s: %w", reason, err)
	}

	result, err := interrogator.Interrogate(ctx, coreDevice, coreCreds)
	if err != nil {
		s.updateDeviceError(ctx, tenantID, deviceID, err.Error())
		s.discoveryIntegration.UpdateJobStatus(ctx, jobID, "failed", stringPtr(err.Error()))
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

	// Persist the identity the interrogator observed (vendor/model/firmware/
	// serial) back onto the device row. Without this the finding carries it
	// (see "device_identity" above) but the Devices page — which reads straight
	// off `devices` — keeps showing "—" for firmware forever, even after a
	// successful interrogation that plainly reported one (L-7).
	if result.DeviceIdentity != nil {
		s.updateDeviceIdentity(ctx, tenantID, deviceID, result.DeviceIdentity)
	}

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
		"device_id":         deviceID.String(),
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
		ctx, systemSensorID, tenantID, &deviceID, batchID,
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

// getDevice retrieves a device by ID, scoped to tenantID (devices is RLS-scoped).
func (s *DeviceInterrogationService) getDevice(ctx context.Context, tenantID, deviceID uuid.UUID) (*models.Device, error) {
	query := `
		SELECT id, tenant_id, device_type, vendor, model, hostname, ip_address,
		       management_url, serial_number, firmware_version, discovery_method,
		       credential_id, username, password, tls_insecure_skip_verify,
		       connection_status, metadata, tags, created_at, updated_at
		FROM devices
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
	`

	var device models.Device
	var metadataJSON, tagsJSON []byte
	var credentialID, username, password sql.NullString

	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, deviceID, tenantID).Scan(
			&device.ID, &device.TenantID, &device.DeviceType, &device.Vendor, &device.Model,
			&device.Hostname, &device.IPAddress, &device.ManagementURL, &device.SerialNumber,
			&device.FirmwareVersion, &device.DiscoveryMethod, &credentialID, &username, &password,
			&device.TLSInsecureSkipVerify,
			&device.ConnectionStatus, &metadataJSON, &tagsJSON, &device.CreatedAt, &device.UpdatedAt,
		)
	})
	if err != nil {
		return nil, err
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

	if err := json.Unmarshal(metadataJSON, &device.Metadata); err != nil {
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
		enc, err := encryption.NewService(s.masterKey)
		if err != nil {
			return "", "", "", false, fmt.Errorf("failed to initialize encryption: %w", err)
		}

		password, err = enc.Decrypt(*device.Password)
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

// updateDeviceInterrogationTime updates the device's last_interrogated_at
// timestamp, under the resolved tenantID (devices is RLS-scoped).
func (s *DeviceInterrogationService) updateDeviceInterrogationTime(ctx context.Context, tenantID, deviceID uuid.UUID) {
	query := `
		UPDATE devices
		SET last_interrogated_at = NOW(), connection_status = 'connected',
		    interrogation_error = NULL, updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2
	`
	_ = shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query, deviceID, tenantID)
		return e
	})
}

// updateDeviceIdentity writes the vendor/model/firmware/serial an interrogation
// observed back onto the device row, under the resolved tenantID (devices is
// RLS-scoped). Only non-empty fields are set — an interrogator that doesn't
// populate a given field must not blank out a value a prior run recorded.
func (s *DeviceInterrogationService) updateDeviceIdentity(ctx context.Context, tenantID, deviceID uuid.UUID, identity *di.DeviceIdentity) {
	setClauses, args := deviceIdentitySetClauses(identity.Vendor, identity.Model, identity.FirmwareVersion, identity.SerialNumber, 1)
	if len(setClauses) == 0 {
		return
	}
	setClauses = append(setClauses, "updated_at = NOW()")
	argIdx := len(args) + 1

	//nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
	query := fmt.Sprintf(
		"UPDATE devices SET %s WHERE id = $%d AND tenant_id = $%d",
		strings.Join(setClauses, ", "), argIdx, argIdx+1,
	)
	args = append(args, deviceID, tenantID)

	_ = shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query, args...)
		return e
	})
}

// updateDeviceError updates the device's error status, under the resolved
// tenantID (devices is RLS-scoped).
func (s *DeviceInterrogationService) updateDeviceError(ctx context.Context, tenantID, deviceID uuid.UUID, errorMsg string) {
	query := `
		UPDATE devices
		SET connection_status = 'error', interrogation_error = $1, updated_at = NOW()
		WHERE id = $2 AND tenant_id = $3
	`
	_ = shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query, errorMsg, deviceID, tenantID)
		return e
	})
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
		s.discoveryIntegration.UpdateJobStatus(ctx, jobID, "failed", stringPtr(err.Error()))
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
		s.discoveryIntegration.UpdateJobStatus(ctx, jobID, "failed", stringPtr(err.Error()))
		return uuid.Nil, 0, fmt.Errorf("failed to store database encryption finding: %w", err)
	}

	details := map[string]interface{}{
		"device_id":                  device.ID.String(),
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
	s.discoveryIntegration.MarkJobCompleted(ctx, jobID)
	// One database finding per interrogation.
	return jobID, 1, nil
}
