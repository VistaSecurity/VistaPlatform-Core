package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

// DeviceService handles device business logic
type DeviceService struct {
	db            *sql.DB
	encryptionKey string
}

// NewDeviceService creates a new device service
func NewDeviceService(db *sql.DB) *DeviceService {
	encryptionKey := os.Getenv("ENCRYPTION_MASTER_KEY")
	if encryptionKey == "" {
		// Fallback for development - in production this should fail
		encryptionKey = "dev-encryption-key-change-in-production"
	}
	return &DeviceService{
		db:            db,
		encryptionKey: encryptionKey,
	}
}

// encryptPassword encrypts a password using the master encryption key
func (s *DeviceService) encryptPassword(password string) (string, error) {
	if password == "" {
		return "", nil
	}
	enc, err := encryption.NewService(s.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to initialize encryption: %w", err)
	}
	return enc.Encrypt(password)
}

// decryptPassword decrypts a password using the master encryption key
func (s *DeviceService) decryptPassword(encrypted string) (string, error) {
	if encrypted == "" {
		return "", nil
	}
	enc, err := encryption.NewService(s.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to initialize encryption: %w", err)
	}
	return enc.Decrypt(encrypted)
}

// maskPassword masks a password for display in API responses
func maskPassword(password string) string {
	if len(password) == 0 {
		return ""
	}
	if len(password) > 8 {
		return password[:4] + "****" + password[len(password)-4:]
	}
	return "****"
}

// CreateDevice creates a new device
func (s *DeviceService) CreateDevice(ctx context.Context, tenantID uuid.UUID, req models.CreateDeviceRequest) (*models.Device, error) {
	deviceID := uuid.New()
	now := time.Now()

	// Set default discovery method if not provided
	discoveryMethod := req.DiscoveryMethod
	if discoveryMethod == "" {
		discoveryMethod = "device_interrogation"
	}

	// Encrypt password if provided
	var encryptedPassword *string
	if req.Password != nil && *req.Password != "" {
		encrypted, err := s.encryptPassword(*req.Password)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt password: %w", err)
		}
		encryptedPassword = &encrypted
	}

	// Convert metadata and tags to JSONB
	metadataJSON, _ := json.Marshal(req.Metadata)
	if metadataJSON == nil {
		metadataJSON = []byte("{}")
	}
	tagsJSON, _ := json.Marshal(req.Tags)
	if tagsJSON == nil {
		tagsJSON = []byte("{}")
	}

	// Defaults to false (verify TLS) unless the caller explicitly opts in.
	tlsInsecureSkipVerify := false
	if req.TLSInsecureSkipVerify != nil {
		tlsInsecureSkipVerify = *req.TLSInsecureSkipVerify
	}

	query := `
		INSERT INTO devices (
			id, tenant_id, device_type, vendor, model, hostname, ip_address,
			management_url, serial_number, firmware_version, discovery_method,
			credential_id, username, password, tls_insecure_skip_verify,
			connection_status, metadata, tags, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
		RETURNING id, tenant_id, device_type, vendor, model, hostname, ip_address,
			management_url, serial_number, firmware_version, discovery_method,
			credential_id, username, password, tls_insecure_skip_verify,
			connection_status, last_interrogated_at, interrogation_error,
			metadata, tags, created_at, updated_at, deleted_at
	`

	device := &models.Device{}
	var metadataJSONB, tagsJSONB []byte
	var credentialID sql.NullString
	var username, password sql.NullString

	// RLS-scoped write on `devices`: tenantID is an input → WithTenantTx.
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query,
			deviceID, tenantID, req.DeviceType, req.Vendor, req.Model, req.Hostname, req.IPAddress,
			req.ManagementURL, req.SerialNumber, req.FirmwareVersion, discoveryMethod,
			req.CredentialID, req.Username, encryptedPassword, tlsInsecureSkipVerify,
			"unknown", metadataJSON, tagsJSON, now, now,
		).Scan(
			&device.ID, &device.TenantID, &device.DeviceType, &device.Vendor, &device.Model,
			&device.Hostname, &device.IPAddress, &device.ManagementURL, &device.SerialNumber,
			&device.FirmwareVersion, &device.DiscoveryMethod, &credentialID, &username, &password,
			&device.TLSInsecureSkipVerify, &device.ConnectionStatus,
			&device.LastInterrogatedAt, &device.InterrogationError, &metadataJSONB, &tagsJSONB,
			&device.CreatedAt, &device.UpdatedAt, &device.DeletedAt,
		)
	})

	if err != nil {
		fmt.Printf("Database error creating device: %v\n", err)
		return nil, fmt.Errorf("failed to create device: %w", err)
	}

	// Parse JSONB fields
	if len(metadataJSONB) > 0 {
		_ = json.Unmarshal(metadataJSONB, &device.Metadata)
	}
	if len(tagsJSONB) > 0 {
		_ = json.Unmarshal(tagsJSONB, &device.Tags)
	}
	if credentialID.Valid {
		id, _ := uuid.Parse(credentialID.String)
		device.CredentialID = &id
	}
	if username.Valid {
		device.Username = &username.String
	}
	// Mask password in response
	if password.Valid && password.String != "" {
		masked := maskPassword(password.String)
		device.Password = &masked
	}

	return device, nil
}

// GetDevice retrieves a device by ID, scoped to tenantID. tenantID is threaded
// from the caller (handlers already hold it) so the read runs inside WithTenantTx
// (devices is RLS-scoped) and stays correct once RLS enforces; the WHERE
// tenant_id = $2 is the belt-and-suspenders primary control and the callers'
// device.TenantID != tenantID check is retained.
func (s *DeviceService) GetDevice(ctx context.Context, tenantID, deviceID uuid.UUID) (*models.Device, error) {
	query := `
		SELECT id, tenant_id, device_type, vendor, model, hostname, ip_address,
			management_url, serial_number, firmware_version, discovery_method,
			credential_id, username, password, tls_insecure_skip_verify,
			connection_status, last_interrogated_at, interrogation_error,
			metadata, tags, created_at, updated_at, deleted_at
		FROM devices
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
	`

	device := &models.Device{}
	var metadataJSONB, tagsJSONB []byte
	var credentialID, username, password sql.NullString

	found := false
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		scanErr := tx.QueryRowContext(ctx, query, deviceID, tenantID).Scan(
			&device.ID, &device.TenantID, &device.DeviceType, &device.Vendor, &device.Model,
			&device.Hostname, &device.IPAddress, &device.ManagementURL, &device.SerialNumber,
			&device.FirmwareVersion, &device.DiscoveryMethod, &credentialID, &username, &password,
			&device.TLSInsecureSkipVerify, &device.ConnectionStatus,
			&device.LastInterrogatedAt, &device.InterrogationError, &metadataJSONB, &tagsJSONB,
			&device.CreatedAt, &device.UpdatedAt, &device.DeletedAt,
		)
		if scanErr == sql.ErrNoRows {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		found = true
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get device: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("device not found")
	}

	// Parse JSONB fields
	if len(metadataJSONB) > 0 {
		_ = json.Unmarshal(metadataJSONB, &device.Metadata)
	}
	if len(tagsJSONB) > 0 {
		_ = json.Unmarshal(tagsJSONB, &device.Tags)
	}
	if credentialID.Valid {
		id, _ := uuid.Parse(credentialID.String)
		device.CredentialID = &id
	}
	if username.Valid {
		device.Username = &username.String
	}
	// Mask password in response
	if password.Valid && password.String != "" {
		masked := maskPassword(password.String)
		device.Password = &masked
	}

	return device, nil
}

// ListDevices lists all devices for a tenant
func (s *DeviceService) ListDevices(ctx context.Context, tenantID uuid.UUID) ([]*models.Device, error) {
	query := `
		SELECT id, tenant_id, device_type, vendor, model, hostname, ip_address,
			management_url, serial_number, firmware_version, discovery_method,
			credential_id, username, password, tls_insecure_skip_verify,
			connection_status, last_interrogated_at, interrogation_error,
			metadata, tags, created_at, updated_at, deleted_at
		FROM devices
		WHERE tenant_id = $1 AND deleted_at IS NULL
		ORDER BY created_at DESC
	`

	// RLS-scoped read on `devices`: WithTenantTx sets app.tenant_id; the explicit
	// WHERE tenant_id = $1 is kept as the primary control.
	var devices []*models.Device
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(ctx, query, tenantID)
		if e != nil {
			return fmt.Errorf("failed to list devices: %w", e)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			device := &models.Device{}
			var metadataJSONB, tagsJSONB []byte
			var credentialID, username, password sql.NullString

			if scanErr := rows.Scan(
				&device.ID, &device.TenantID, &device.DeviceType, &device.Vendor, &device.Model,
				&device.Hostname, &device.IPAddress, &device.ManagementURL, &device.SerialNumber,
				&device.FirmwareVersion, &device.DiscoveryMethod, &credentialID, &username, &password,
				&device.TLSInsecureSkipVerify, &device.ConnectionStatus,
				&device.LastInterrogatedAt, &device.InterrogationError, &metadataJSONB, &tagsJSONB,
				&device.CreatedAt, &device.UpdatedAt, &device.DeletedAt,
			); scanErr != nil {
				return fmt.Errorf("failed to scan device: %w", scanErr)
			}

			// Parse JSONB fields
			if len(metadataJSONB) > 0 {
				_ = json.Unmarshal(metadataJSONB, &device.Metadata)
			}
			if len(tagsJSONB) > 0 {
				_ = json.Unmarshal(tagsJSONB, &device.Tags)
			}
			if credentialID.Valid {
				id, _ := uuid.Parse(credentialID.String)
				device.CredentialID = &id
			}
			if username.Valid {
				device.Username = &username.String
			}
			// Mask password in response
			if password.Valid && password.String != "" {
				masked := maskPassword(password.String)
				device.Password = &masked
			}

			devices = append(devices, device)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	return devices, nil
}

// UpdateDevice updates a device, scoped to tenantID (devices is RLS-scoped).
func (s *DeviceService) UpdateDevice(ctx context.Context, tenantID, deviceID uuid.UUID, req models.UpdateDeviceRequest) (*models.Device, error) {
	// Build update query dynamically
	updates := []string{"updated_at = $1"}
	args := []interface{}{time.Now()}
	argIndex := 2

	if req.Vendor != nil {
		updates = append(updates, fmt.Sprintf("vendor = $%d", argIndex))
		args = append(args, *req.Vendor)
		argIndex++
	}
	if req.Model != nil {
		updates = append(updates, fmt.Sprintf("model = $%d", argIndex))
		args = append(args, *req.Model)
		argIndex++
	}
	if req.Hostname != nil {
		updates = append(updates, fmt.Sprintf("hostname = $%d", argIndex))
		args = append(args, *req.Hostname)
		argIndex++
	}
	if req.IPAddress != nil {
		updates = append(updates, fmt.Sprintf("ip_address = $%d", argIndex))
		args = append(args, *req.IPAddress)
		argIndex++
	}
	if req.ManagementURL != nil {
		updates = append(updates, fmt.Sprintf("management_url = $%d", argIndex))
		args = append(args, *req.ManagementURL)
		argIndex++
	}
	if req.SerialNumber != nil {
		updates = append(updates, fmt.Sprintf("serial_number = $%d", argIndex))
		args = append(args, *req.SerialNumber)
		argIndex++
	}
	if req.FirmwareVersion != nil {
		updates = append(updates, fmt.Sprintf("firmware_version = $%d", argIndex))
		args = append(args, *req.FirmwareVersion)
		argIndex++
	}
	if req.CredentialID != nil {
		updates = append(updates, fmt.Sprintf("credential_id = $%d", argIndex))
		args = append(args, *req.CredentialID)
		argIndex++
	}
	if req.Username != nil {
		updates = append(updates, fmt.Sprintf("username = $%d", argIndex))
		args = append(args, *req.Username)
		argIndex++
	}
	if req.Password != nil && *req.Password != "" {
		// Encrypt password before storing
		encrypted, err := s.encryptPassword(*req.Password)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt password: %w", err)
		}
		updates = append(updates, fmt.Sprintf("password = $%d", argIndex))
		args = append(args, encrypted)
		argIndex++
	}
	if req.TLSInsecureSkipVerify != nil {
		updates = append(updates, fmt.Sprintf("tls_insecure_skip_verify = $%d", argIndex))
		args = append(args, *req.TLSInsecureSkipVerify)
		argIndex++
	}
	if req.ConnectionStatus != nil {
		updates = append(updates, fmt.Sprintf("connection_status = $%d", argIndex))
		args = append(args, *req.ConnectionStatus)
		argIndex++
	}
	if req.Metadata != nil {
		metadataJSON, _ := json.Marshal(req.Metadata)
		updates = append(updates, fmt.Sprintf("metadata = $%d", argIndex))
		args = append(args, metadataJSON)
		argIndex++
	}
	if req.Tags != nil {
		tagsJSON, _ := json.Marshal(req.Tags)
		updates = append(updates, fmt.Sprintf("tags = $%d", argIndex))
		args = append(args, tagsJSON)
		argIndex++
	}

	if len(updates) == 1 {
		// Only updated_at changed, just return the device
		return s.GetDevice(ctx, tenantID, deviceID)
	}

	// Join all updates with commas
	updatesStr := ""
	for i, update := range updates {
		if i > 0 {
			updatesStr += ", "
		}
		updatesStr += update
	}

	//nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
	query := fmt.Sprintf(`
		UPDATE devices
		SET %s
		WHERE id = $%d AND tenant_id = $%d AND deleted_at IS NULL
		RETURNING id, tenant_id, device_type, vendor, model, hostname, ip_address,
			management_url, serial_number, firmware_version, discovery_method,
			credential_id, tls_insecure_skip_verify, connection_status,
			last_interrogated_at, interrogation_error,
			metadata, tags, created_at, updated_at, deleted_at
	`, updatesStr, argIndex, argIndex+1)

	args = append(args, deviceID, tenantID)

	device := &models.Device{}
	var metadataJSONB, tagsJSONB []byte
	var credentialID sql.NullString

	found := false
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		scanErr := tx.QueryRowContext(ctx, query, args...).Scan(
			&device.ID, &device.TenantID, &device.DeviceType, &device.Vendor, &device.Model,
			&device.Hostname, &device.IPAddress, &device.ManagementURL, &device.SerialNumber,
			&device.FirmwareVersion, &device.DiscoveryMethod, &credentialID,
			&device.TLSInsecureSkipVerify, &device.ConnectionStatus,
			&device.LastInterrogatedAt, &device.InterrogationError, &metadataJSONB, &tagsJSONB,
			&device.CreatedAt, &device.UpdatedAt, &device.DeletedAt,
		)
		if scanErr == sql.ErrNoRows {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		found = true
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to update device: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("device not found")
	}

	// Parse JSONB fields
	if len(metadataJSONB) > 0 {
		_ = json.Unmarshal(metadataJSONB, &device.Metadata)
	}
	if len(tagsJSONB) > 0 {
		_ = json.Unmarshal(tagsJSONB, &device.Tags)
	}
	if credentialID.Valid {
		id, _ := uuid.Parse(credentialID.String)
		device.CredentialID = &id
	}

	return device, nil
}

// DeleteDevice soft deletes a device, scoped to tenantID (devices is RLS-scoped).
func (s *DeviceService) DeleteDevice(ctx context.Context, tenantID, deviceID uuid.UUID) error {
	query := `
		UPDATE devices
		SET deleted_at = $1, updated_at = $1
		WHERE id = $2 AND tenant_id = $3 AND deleted_at IS NULL
	`

	var rowsAffected int64
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		result, e := tx.ExecContext(ctx, query, time.Now(), deviceID, tenantID)
		if e != nil {
			return e
		}
		rowsAffected, e = result.RowsAffected()
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to delete device: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("device not found")
	}

	return nil
}

// StoredDeviceCredentials carries a device's embedded credentials exactly as
// they sit in the `devices` row: username in the clear, password still
// encrypted under the platform master key.
//
// GetDevice deliberately MASKS the password before returning
// (maskPassword → "abcd****wxyz") because *models.Device is serialised straight
// into API responses. That masking is right for the API and catastrophic for
// anything that needs the real value: the interrogation handler used
// device.Password from GetDevice as the credential it shipped to the agent, so
// what a remote agent actually received was a twelve-character fragment of a
// ciphertext. Anything that needs the true stored value must come
// through here instead, and this type must never be returned from a handler.
type StoredDeviceCredentials struct {
	Username           string
	EncryptedPassword  string // master-key ciphertext, NOT plaintext
	ManagementURL      string
	DeviceType         string
	InsecureSkipVerify bool
}

// HasCredentials reports whether the device carries embedded credentials.
func (c StoredDeviceCredentials) HasCredentials() bool {
	return c.Username != "" && c.EncryptedPassword != ""
}

// GetStoredDeviceCredentials reads a device's embedded credentials unmasked,
// scoped to tenantID (devices is RLS-scoped, so the read runs in WithTenantTx
// with the WHERE tenant_id = $2 belt-and-braces the other reads use).
func (s *DeviceService) GetStoredDeviceCredentials(ctx context.Context, tenantID, deviceID uuid.UUID) (StoredDeviceCredentials, error) {
	var creds StoredDeviceCredentials
	var username, password, managementURL sql.NullString
	found := false

	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		scanErr := tx.QueryRowContext(ctx, `
			SELECT username, password, management_url, device_type, tls_insecure_skip_verify
			FROM devices
			WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		`, deviceID, tenantID).Scan(
			&username, &password, &managementURL, &creds.DeviceType, &creds.InsecureSkipVerify,
		)
		if scanErr == sql.ErrNoRows {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		found = true
		return nil
	})
	if err != nil {
		return StoredDeviceCredentials{}, fmt.Errorf("failed to read device credentials: %w", err)
	}
	if !found {
		return StoredDeviceCredentials{}, fmt.Errorf("device not found")
	}

	creds.Username = username.String
	creds.EncryptedPassword = password.String
	creds.ManagementURL = managementURL.String
	return creds, nil
}
