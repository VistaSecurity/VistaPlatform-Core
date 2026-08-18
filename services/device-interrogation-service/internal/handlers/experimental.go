package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// ExperimentalHandlers handles experimental encryption detection feature endpoints
type ExperimentalHandlers struct {
	db *sql.DB
}

// NewExperimentalHandlers creates a new ExperimentalHandlers instance
func NewExperimentalHandlers(db *sql.DB) *ExperimentalHandlers {
	return &ExperimentalHandlers{db: db}
}

// --- Local structs for JSON serialization ---

type kmsKeyRow struct {
	ID                uuid.UUID  `json:"id"`
	TenantID          uuid.UUID  `json:"tenant_id"`
	IntegrationID     uuid.UUID  `json:"integration_id"`
	Provider          string     `json:"provider"`
	KeyID             string     `json:"key_id"`
	KeyARN            *string    `json:"key_arn,omitempty"`
	KeyName           *string    `json:"key_name,omitempty"`
	Description       *string    `json:"description,omitempty"`
	KeySpec           *string    `json:"key_spec,omitempty"`
	KeyUsage          *string    `json:"key_usage,omitempty"`
	AlgorithmID       *uuid.UUID `json:"algorithm_id,omitempty"`
	KeySize           *int       `json:"key_size,omitempty"`
	KeyState          string     `json:"key_state"`
	CreationDate      *time.Time `json:"creation_date,omitempty"`
	ExpirationDate    *time.Time `json:"expiration_date,omitempty"`
	RotationEnabled   *bool      `json:"rotation_enabled,omitempty"`
	LastRotatedAt     *time.Time `json:"last_rotated_at,omitempty"`
	RotationPeriod    *int       `json:"rotation_period_days,omitempty"`
	Origin            *string    `json:"origin,omitempty"`
	KeyManager        *string    `json:"key_manager,omitempty"`
	MultiRegion       bool       `json:"multi_region"`
	HSMBacked         bool       `json:"hsm_backed"`
	RiskScore         int        `json:"risk_score"`
	DaysSinceRotation *int       `json:"days_since_rotation,omitempty"`
	Region            *string    `json:"region,omitempty"`
	AccountID         *string    `json:"account_id,omitempty"`
	DiscoveryMethod   string     `json:"discovery_method"`
	FirstDiscoveredAt time.Time  `json:"first_discovered_at"`
	LastVerifiedAt    time.Time  `json:"last_verified_at"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type dbEncryptionStateRow struct {
	ID                       uuid.UUID  `json:"id"`
	TenantID                 uuid.UUID  `json:"tenant_id"`
	DeviceID                 *uuid.UUID `json:"device_id,omitempty"`
	AssetID                  *uuid.UUID `json:"asset_id,omitempty"`
	DBEngine                 string     `json:"db_engine"`
	DBVersion                *string    `json:"db_version,omitempty"`
	Hostname                 *string    `json:"hostname,omitempty"`
	Port                     *int       `json:"port,omitempty"`
	InstanceName             *string    `json:"instance_name,omitempty"`
	SSLEnabled               *bool      `json:"ssl_enabled,omitempty"`
	SSLVersion               *string    `json:"ssl_version,omitempty"`
	SSLCipher                *string    `json:"ssl_cipher,omitempty"`
	SSLEnforced              *bool      `json:"ssl_enforced,omitempty"`
	CertificateID            *uuid.UUID `json:"certificate_id,omitempty"`
	EncryptionAtRestEnabled  *bool      `json:"encryption_at_rest_enabled,omitempty"`
	EncryptionMethod         *string    `json:"encryption_method,omitempty"`
	EncryptionAlgorithm      *string    `json:"encryption_algorithm,omitempty"`
	EncryptionKeySource      *string    `json:"encryption_key_source,omitempty"`
	PasswordEncryptionMethod *string    `json:"password_encryption_method,omitempty"`
	SSLAlgorithmID           *uuid.UUID `json:"ssl_algorithm_id,omitempty"`
	EncryptionAlgorithmID    *uuid.UUID `json:"encryption_algorithm_id,omitempty"`
	PasswordAlgorithmID      *uuid.UUID `json:"password_algorithm_id,omitempty"`
	RiskScore                int        `json:"risk_score"`
	DiscoveryMethod          string     `json:"discovery_method"`
	FirstDiscoveredAt        time.Time  `json:"first_discovered_at"`
	LastVerifiedAt           time.Time  `json:"last_verified_at"`
	CreatedAt                time.Time  `json:"created_at"`
	UpdatedAt                time.Time  `json:"updated_at"`
}

type sshKeyRow struct {
	ID                uuid.UUID  `json:"id"`
	TenantID          uuid.UUID  `json:"tenant_id"`
	AssetID           *uuid.UUID `json:"asset_id,omitempty"`
	KeyType           string     `json:"key_type"`
	KeySize           *int       `json:"key_size,omitempty"`
	FingerprintSHA256 string     `json:"fingerprint_sha256"`
	PublicKey         *string    `json:"public_key,omitempty"`
	AlgorithmID       *uuid.UUID `json:"algorithm_id,omitempty"`
	KeySource         string     `json:"key_source"`
	Username          *string    `json:"username,omitempty"`
	Hostname          *string    `json:"hostname,omitempty"`
	IPAddress         *string    `json:"ip_address,omitempty"`
	FilePath          *string    `json:"file_path,omitempty"`
	Comment           *string    `json:"comment,omitempty"`
	RiskScore         int        `json:"risk_score"`
	IsWeak            bool       `json:"is_weak"`
	DiscoveryMethod   string     `json:"discovery_method"`
	FirstDiscoveredAt time.Time  `json:"first_discovered_at"`
	LastSeenAt        time.Time  `json:"last_seen_at"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// parsePagination extracts page and page_size from query params with defaults.
func parsePagination(c *gin.Context) (page, pageSize, offset int) {
	page, _ = strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ = strconv.Atoi(c.DefaultQuery("page_size", "50"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 50
	}
	offset = (page - 1) * pageSize
	return
}

// ListKMSKeys handles GET - returns KMS keys for the tenant
func (h *ExperimentalHandlers) ListKMSKeys(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}

	page, pageSize, offset := parsePagination(c)

	query := `
		SELECT id, tenant_id, integration_id, provider, key_id, key_arn, key_name, description,
		       key_spec, key_usage, algorithm_id, key_size, key_state,
		       creation_date, expiration_date, rotation_enabled, last_rotated_at, rotation_period_days,
		       origin, key_manager, multi_region, hsm_backed,
		       risk_score, days_since_rotation, region, account_id,
		       discovery_method, first_discovered_at, last_verified_at, created_at, updated_at
		FROM kms_keys
		WHERE tenant_id = $1 AND deleted_at IS NULL
	`
	countQuery := `SELECT COUNT(*) FROM kms_keys WHERE tenant_id = $1 AND deleted_at IS NULL`
	args := []interface{}{tenantID}
	argNum := 2

	if provider := c.Query("provider"); provider != "" {
		query += " AND provider = $" + strconv.Itoa(argNum)
		countQuery += " AND provider = $" + strconv.Itoa(argNum)
		args = append(args, provider)
		argNum++
	}

	if state := c.Query("state"); state != "" {
		query += " AND key_state = $" + strconv.Itoa(argNum)
		countQuery += " AND key_state = $" + strconv.Itoa(argNum)
		args = append(args, state)
		argNum++
	}

	// Paginated query
	query += " ORDER BY created_at DESC LIMIT $" + strconv.Itoa(argNum) + " OFFSET $" + strconv.Itoa(argNum+1) //nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice

	// RLS-scoped reads on `kms_keys`: count + page run inside one WithTenantTx.
	var total int
	keys := make([]kmsKeyRow, 0)
	if err := shareddatabase.WithTenantTx(c.Request.Context(), h.db, tenantID, func(tx *sql.Tx) error {
		if e := tx.QueryRowContext(c.Request.Context(), countQuery, args...).Scan(&total); e != nil {
			return e
		}
		pageArgs := append(append([]interface{}{}, args...), pageSize, offset)
		rows, e := tx.QueryContext(c.Request.Context(), query, pageArgs...)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var k kmsKeyRow
			if scanErr := rows.Scan(
				&k.ID, &k.TenantID, &k.IntegrationID, &k.Provider, &k.KeyID, &k.KeyARN, &k.KeyName, &k.Description,
				&k.KeySpec, &k.KeyUsage, &k.AlgorithmID, &k.KeySize, &k.KeyState,
				&k.CreationDate, &k.ExpirationDate, &k.RotationEnabled, &k.LastRotatedAt, &k.RotationPeriod,
				&k.Origin, &k.KeyManager, &k.MultiRegion, &k.HSMBacked,
				&k.RiskScore, &k.DaysSinceRotation, &k.Region, &k.AccountID,
				&k.DiscoveryMethod, &k.FirstDiscoveredAt, &k.LastVerifiedAt, &k.CreatedAt, &k.UpdatedAt,
			); scanErr != nil {
				continue
			}
			keys = append(keys, k)
		}
		return rows.Err()
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query KMS keys"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"kms_keys":  keys,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// ListDatabaseEncryptionStates handles GET - returns database encryption states for the tenant
func (h *ExperimentalHandlers) ListDatabaseEncryptionStates(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}

	page, pageSize, offset := parsePagination(c)

	query := `
		SELECT id, tenant_id, device_id, asset_id,
		       db_engine, db_version, hostname, port, instance_name,
		       ssl_enabled, ssl_version, ssl_cipher, ssl_enforced, certificate_id,
		       encryption_at_rest_enabled, encryption_method, encryption_algorithm, encryption_key_source,
		       password_encryption_method,
		       ssl_algorithm_id, encryption_algorithm_id, password_algorithm_id,
		       risk_score, discovery_method,
		       first_discovered_at, last_verified_at, created_at, updated_at
		FROM database_encryption_states
		WHERE tenant_id = $1 AND deleted_at IS NULL
	`
	countQuery := `SELECT COUNT(*) FROM database_encryption_states WHERE tenant_id = $1 AND deleted_at IS NULL`
	args := []interface{}{tenantID}
	argNum := 2

	if engine := c.Query("engine"); engine != "" {
		query += " AND db_engine = $" + strconv.Itoa(argNum)
		countQuery += " AND db_engine = $" + strconv.Itoa(argNum)
		args = append(args, engine)
		argNum++
	}

	if sslEnabled := c.Query("ssl_enabled"); sslEnabled != "" {
		boolVal, err := strconv.ParseBool(sslEnabled)
		if err == nil {
			query += " AND ssl_enabled = $" + strconv.Itoa(argNum)
			countQuery += " AND ssl_enabled = $" + strconv.Itoa(argNum)
			args = append(args, boolVal)
			argNum++
		}
	}

	// Paginated query
	query += " ORDER BY created_at DESC LIMIT $" + strconv.Itoa(argNum) + " OFFSET $" + strconv.Itoa(argNum+1) //nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice

	// RLS-scoped reads on `database_encryption_states`: count + page in one WithTenantTx.
	var total int
	states := make([]dbEncryptionStateRow, 0)
	if err := shareddatabase.WithTenantTx(c.Request.Context(), h.db, tenantID, func(tx *sql.Tx) error {
		if e := tx.QueryRowContext(c.Request.Context(), countQuery, args...).Scan(&total); e != nil {
			return e
		}
		pageArgs := append(append([]interface{}{}, args...), pageSize, offset)
		rows, e := tx.QueryContext(c.Request.Context(), query, pageArgs...)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var s dbEncryptionStateRow
			if scanErr := rows.Scan(
				&s.ID, &s.TenantID, &s.DeviceID, &s.AssetID,
				&s.DBEngine, &s.DBVersion, &s.Hostname, &s.Port, &s.InstanceName,
				&s.SSLEnabled, &s.SSLVersion, &s.SSLCipher, &s.SSLEnforced, &s.CertificateID,
				&s.EncryptionAtRestEnabled, &s.EncryptionMethod, &s.EncryptionAlgorithm, &s.EncryptionKeySource,
				&s.PasswordEncryptionMethod,
				&s.SSLAlgorithmID, &s.EncryptionAlgorithmID, &s.PasswordAlgorithmID,
				&s.RiskScore, &s.DiscoveryMethod,
				&s.FirstDiscoveredAt, &s.LastVerifiedAt, &s.CreatedAt, &s.UpdatedAt,
			); scanErr != nil {
				continue
			}
			states = append(states, s)
		}
		return rows.Err()
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query database encryption states"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"database_states": states,
		"total":           total,
		"page":            page,
		"page_size":       pageSize,
	})
}

// ListSSHKeys handles GET - returns SSH keys for the tenant
func (h *ExperimentalHandlers) ListSSHKeys(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}

	page, pageSize, offset := parsePagination(c)

	query := `
		SELECT id, tenant_id, asset_id,
		       key_type, key_size, fingerprint_sha256, public_key, algorithm_id,
		       key_source, username, hostname, ip_address, file_path, comment,
		       risk_score, is_weak,
		       discovery_method, first_discovered_at, last_seen_at, created_at, updated_at
		FROM ssh_keys
		WHERE tenant_id = $1 AND deleted_at IS NULL
	`
	countQuery := `SELECT COUNT(*) FROM ssh_keys WHERE tenant_id = $1 AND deleted_at IS NULL`
	args := []interface{}{tenantID}
	argNum := 2

	if keyType := c.Query("key_type"); keyType != "" {
		query += " AND key_type = $" + strconv.Itoa(argNum)
		countQuery += " AND key_type = $" + strconv.Itoa(argNum)
		args = append(args, keyType)
		argNum++
	}

	if isWeak := c.Query("is_weak"); isWeak != "" {
		boolVal, err := strconv.ParseBool(isWeak)
		if err == nil {
			query += " AND is_weak = $" + strconv.Itoa(argNum)
			countQuery += " AND is_weak = $" + strconv.Itoa(argNum)
			args = append(args, boolVal)
			argNum++
		}
	}

	if keySource := c.Query("key_source"); keySource != "" {
		query += " AND key_source = $" + strconv.Itoa(argNum)
		countQuery += " AND key_source = $" + strconv.Itoa(argNum)
		args = append(args, keySource)
		argNum++
	}

	// Paginated query
	query += " ORDER BY created_at DESC LIMIT $" + strconv.Itoa(argNum) + " OFFSET $" + strconv.Itoa(argNum+1) //nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice

	// RLS-scoped reads on `ssh_keys`: count + page in one WithTenantTx.
	var total int
	keys := make([]sshKeyRow, 0)
	if err := shareddatabase.WithTenantTx(c.Request.Context(), h.db, tenantID, func(tx *sql.Tx) error {
		if e := tx.QueryRowContext(c.Request.Context(), countQuery, args...).Scan(&total); e != nil {
			return e
		}
		pageArgs := append(append([]interface{}{}, args...), pageSize, offset)
		rows, e := tx.QueryContext(c.Request.Context(), query, pageArgs...)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var k sshKeyRow
			if scanErr := rows.Scan(
				&k.ID, &k.TenantID, &k.AssetID,
				&k.KeyType, &k.KeySize, &k.FingerprintSHA256, &k.PublicKey, &k.AlgorithmID,
				&k.KeySource, &k.Username, &k.Hostname, &k.IPAddress, &k.FilePath, &k.Comment,
				&k.RiskScore, &k.IsWeak,
				&k.DiscoveryMethod, &k.FirstDiscoveredAt, &k.LastSeenAt, &k.CreatedAt, &k.UpdatedAt,
			); scanErr != nil {
				continue
			}
			keys = append(keys, k)
		}
		return rows.Err()
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query SSH keys"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ssh_keys":  keys,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// GetExperimentalStats handles GET - returns summary counts for the experimental features
func (h *ExperimentalHandlers) GetExperimentalStats(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}

	ctx := c.Request.Context()

	// Use a single query with sub-selects for efficiency
	statsQuery := `
		SELECT
		(SELECT COUNT(*) FROM kms_keys WHERE tenant_id = $1 AND deleted_at IS NULL),
		(SELECT COUNT(*) FROM kms_keys WHERE tenant_id = $1 AND deleted_at IS NULL AND risk_score >= 70),
		(SELECT COUNT(*) FROM kms_keys WHERE tenant_id = $1 AND deleted_at IS NULL AND rotation_enabled = false),
		(SELECT COUNT(*) FROM database_encryption_states WHERE tenant_id = $1 AND deleted_at IS NULL),
		(SELECT COUNT(*) FROM database_encryption_states WHERE tenant_id = $1 AND deleted_at IS NULL AND ssl_enabled = false),
		(SELECT COUNT(*) FROM database_encryption_states WHERE tenant_id = $1 AND deleted_at IS NULL AND risk_score >= 70),
		(SELECT COUNT(*) FROM ssh_keys WHERE tenant_id = $1 AND deleted_at IS NULL),
		(SELECT COUNT(*) FROM ssh_keys WHERE tenant_id = $1 AND deleted_at IS NULL AND is_weak = true)
	`

	var kmsCount, weakKMSKeys, unrotatedKMS int
	var dbStatesCount, sslDisabledDBs, highRiskDBs int
	var sshKeysCount, weakSSHKeys int

	err := shareddatabase.WithTenantTx(ctx, h.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, statsQuery, tenantID).Scan(
			&kmsCount, &weakKMSKeys, &unrotatedKMS,
			&dbStatesCount, &sslDisabledDBs, &highRiskDBs,
			&sshKeysCount, &weakSSHKeys,
		)
	})
	if err != nil {
		fmt.Printf("Failed to query experimental stats: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query experimental stats"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"kms_keys": gin.H{
			"total":       kmsCount,
			"weak":        weakKMSKeys,
			"no_rotation": unrotatedKMS,
		},
		"database_encryption": gin.H{
			"total":        dbStatesCount,
			"ssl_disabled": sslDisabledDBs,
			"high_risk":    highRiskDBs,
		},
		"ssh_keys": gin.H{
			"total": sshKeysCount,
			"weak":  weakSSHKeys,
		},
	})
}
