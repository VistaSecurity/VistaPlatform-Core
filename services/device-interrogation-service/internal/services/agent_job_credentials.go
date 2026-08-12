package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

// ErrJobHasNoCredentials reports that a device-interrogation job carries no
// credentials and the device it targets has none to fall back on.
var ErrJobHasNoCredentials = errors.New("device has no credentials configured")

// resolveJobCredentials fills in a job's credentials from the device row when
// the job was created without them.
//
// This is the credentials half of the shape: a payload that is sufficient
// for the in-cluster PlatformAgentWorker and insufficient for an agent. That
// worker calls DeviceInterrogationService.InterrogateDevice, which loads and
// decrypts credentials from the device row itself and never looks at
// job.Credentials — so SchedulerService.TriggerSchedule, which sets no
// credentials at all, produces jobs that run in-cluster and would reach an
// agent with an empty credential map. Both consumers claim the same
// `agent_id IS NULL` queue, so which one runs a scheduled interrogation is a
// race that registering a tenant's first agent decides.
//
// Resolving here rather than at creation keeps it at the single choke point
// (matching enrichJobTarget) and means the credentials are read fresh at
// hand-off instead of being frozen into device_jobs.credentials when the
// schedule fires. Credentials already on the job win — a job created with an
// explicit credential payload is the more specific intent.
//
// The result is the same stored shape the creation paths write, and goes
// straight into sealJobCredentials, which normalises and seals it for exactly
// one agent. Nothing here is persisted.
func (s *AgentService) resolveJobCredentials(ctx context.Context, tenantID uuid.UUID, job *models.Job) error {
	if len(job.Credentials) > 0 {
		return nil
	}
	if job.DeviceID == nil {
		return ErrJobHasNoCredentials
	}

	// RLS: agent-outbound — keyed by agent id, tenant is the OUTPUT → bypass
	// role, same as enrichJobTarget and sealJobCredentials. Constrained to the
	// job's own tenant so this path cannot hand one tenant's credentials to
	// another's agent.
	var credentialID, username, password, managementURL, deviceType sql.NullString
	var insecureSkipVerify sql.NullBool
	err := s.bypassDB.QueryRowContext(ctx,
		`SELECT credential_id, username, password, management_url, device_type,
		        tls_insecure_skip_verify
		   FROM devices
		  WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`,
		*job.DeviceID, tenantID,
	).Scan(&credentialID, &username, &password, &managementURL, &deviceType, &insecureSkipVerify)
	if err == sql.ErrNoRows {
		return fmt.Errorf("device %s not found", *job.DeviceID)
	}
	if err != nil {
		return fmt.Errorf("failed to resolve device credentials: %w", err)
	}

	// Precedence matches handlers.buildJobCredentials, the creation path this
	// backstops: credential_id first, embedded second. (Note that the
	// in-cluster reader, getDeviceCredentials, orders these the other way
	// round. That divergence predates this change and only shows on a device
	// carrying both.)
	if credentialID.Valid && credentialID.String != "" {
		credID, parseErr := uuid.Parse(credentialID.String)
		if parseErr != nil {
			return fmt.Errorf("device %s has an unparseable credential_id: %w", *job.DeviceID, parseErr)
		}
		creds, credErr := s.credentialsFromIntegration(ctx, tenantID, credID)
		if credErr != nil {
			return credErr
		}
		setIfAbsent(creds, "device_type", deviceType)
		setIfAbsent(creds, "management_url", managementURL)
		if _, exists := creds["insecure_skip_verify"]; !exists && insecureSkipVerify.Valid {
			creds["insecure_skip_verify"] = insecureSkipVerify.Bool
		}
		job.Credentials = creds
		return nil
	}

	if username.String == "" && password.String == "" {
		return ErrJobHasNoCredentials
	}

	// Embedded credentials: the password stays master-key ciphertext, flagged
	// so NormalizeJobCredentials decrypts it at seal time. Byte-for-byte the
	// shape handlers.buildJobCredentials writes.
	creds := map[string]interface{}{
		"username":             username.String,
		"password":             password.String, // master-key ciphertext
		"device_type":          deviceType.String,
		"insecure_skip_verify": insecureSkipVerify.Bool,
		masterEncryptedFlag:    true,
	}
	if managementURL.String != "" {
		creds["management_url"] = managementURL.String
	}
	job.Credentials = creds
	return nil
}

// credentialsFromIntegration reads a legacy platform_integrations credential
// and returns it as flat plaintext.
//
// Plaintext rather than the master-encrypted shape because the stored config
// encrypts a wider set of fields than NormalizeJobCredentials decrypts —
// notably `username`, which would otherwise reach the agent as ciphertext, the
// exact failure fixed for passwords. Decrypting here is safe: this runs
// on the platform where the master key lives, and the caller seals the result
// for one agent immediately. A field that will not decrypt is treated as
// already-plaintext legacy data, matching how the creation path reads the same
// rows.
//
// RLS: read under the job's tenant on the RLS-scoped pool, so the existing
// platform_integrations policy decides visibility (including shared rows),
// exactly as handlers.encryptCredentialsForJob does.
func (s *AgentService) credentialsFromIntegration(ctx context.Context, tenantID, credentialID uuid.UUID) (map[string]interface{}, error) {
	var configJSON string
	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT config
			  FROM platform_integrations
			 WHERE id = $1 AND is_active = true AND deleted_at IS NULL
		`, credentialID).Scan(&configJSON)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("credential %s not found: %w", credentialID, ErrJobHasNoCredentials)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load credentials: %w", err)
	}

	var stored map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &stored); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential config: %w", err)
	}

	enc, err := encryption.NewService(s.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialise master encryption: %w", err)
	}

	// Kept in sync with handlers.encryptCredentialsForJob, which writes these.
	encryptedFields := []string{
		"username", "password", "api_key", "api_token", "client_secret",
		"access_key_id", "secret_access_key",
	}

	out := make(map[string]interface{}, len(stored))
	for key, value := range stored {
		strValue, isString := value.(string)
		if !isString || !slices.Contains(encryptedFields, key) {
			out[key] = value
			continue
		}
		plaintext, decErr := enc.Decrypt(strValue)
		if decErr != nil {
			out[key] = strValue // legacy plaintext
			continue
		}
		out[key] = plaintext
	}
	if len(out) == 0 {
		return nil, ErrJobHasNoCredentials
	}
	return out, nil
}
