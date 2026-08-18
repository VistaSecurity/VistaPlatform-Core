package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/network"
	"golang.org/x/crypto/ssh"
)

// ExperimentalActionHandlers handles action endpoints for experimental features
type ExperimentalActionHandlers struct {
	db *sql.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) connection threaded into the KMS
	// discovery service (whose AWS-client integration lookup may resolve a shared
	// platform integration). Tenant-owned reads/writes here use WithTenantTx.
	bypassDB      *sql.DB
	encryptionKey string
}

// NewExperimentalActionHandlers creates a new ExperimentalActionHandlers. db is
// the RLS-scoped (crypto_app) connection; bypassDB is the BYPASSRLS
// (crypto_bypass) connection. Pre-flip both handles resolve to the same connection.
func NewExperimentalActionHandlers(db, bypassDB *sql.DB, encryptionKey string) *ExperimentalActionHandlers {
	return &ExperimentalActionHandlers{
		db:            db,
		bypassDB:      bypassDB,
		encryptionKey: encryptionKey,
	}
}

// --- KMS Discovery ---

type discoverKMSRequest struct {
	IntegrationID string   `json:"integration_id" binding:"required"`
	Regions       []string `json:"regions"`
}

// DiscoverKMSKeys triggers KMS key discovery for an existing AWS integration
func (h *ExperimentalActionHandlers) DiscoverKMSKeys(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}

	var req discoverKMSRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "integration_id is required"})
		return
	}

	integrationID, err := uuid.Parse(req.IntegrationID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid integration_id"})
		return
	}

	// Verify the integration belongs to this tenant and is an AWS integration.
	var integrationType string
	err = shareddatabase.WithTenantTx(c.Request.Context(), h.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(c.Request.Context(),
			`SELECT integration_type FROM platform_integrations
			 WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`,
			integrationID, tenantID,
		).Scan(&integrationType)
	})
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "integration not found"})
		return
	}
	if integrationType != "aws" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "KMS discovery requires an AWS integration"})
		return
	}

	// Run discovery using the existing KMS discovery service
	kmsService := services.NewKMSDiscoveryService(h.db, h.bypassDB, h.encryptionKey)

	findings, err := kmsService.DiscoverAWSKMSKeys(c.Request.Context(), tenantID, integrationID, req.Regions, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("KMS discovery failed: %v", err)})
		return
	}

	// Store findings
	if err := kmsService.StoreKMSKeyFindings(c.Request.Context(), tenantID, integrationID, "aws", findings); err != nil {
		log.Printf("Warning: failed to store some KMS findings: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"message":         fmt.Sprintf("Discovered %d KMS keys", len(findings)),
		"keys_discovered": len(findings),
		"regions_scanned": len(req.Regions),
	})
}

// ListAWSIntegrations returns AWS integrations for the tenant (for the integration picker)
func (h *ExperimentalActionHandlers) ListAWSIntegrations(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}

	type awsIntegration struct {
		ID              uuid.UUID `json:"id"`
		IntegrationName string    `json:"integration_name"`
		Region          *string   `json:"region,omitempty"`
		AccountID       *string   `json:"account_id,omitempty"`
		Status          string    `json:"status"`
	}

	var integrations []awsIntegration
	if err := shareddatabase.WithTenantTx(c.Request.Context(), h.db, tenantID, func(tx *sql.Tx) error {
		rows, e := tx.QueryContext(c.Request.Context(),
			`SELECT id, integration_name, region, account_id, status
			 FROM platform_integrations
			 WHERE tenant_id = $1 AND integration_type = 'aws' AND deleted_at IS NULL
			 ORDER BY integration_name`,
			tenantID,
		)
		if e != nil {
			return e
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var i awsIntegration
			if scanErr := rows.Scan(&i.ID, &i.IntegrationName, &i.Region, &i.AccountID, &i.Status); scanErr != nil {
				continue
			}
			integrations = append(integrations, i)
		}
		return rows.Err()
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list integrations"})
		return
	}

	if integrations == nil {
		integrations = []awsIntegration{}
	}

	c.JSON(http.StatusOK, gin.H{"integrations": integrations})
}

// --- Database Interrogation ---

type interrogateDatabaseRequest struct {
	Hostname string `json:"hostname" binding:"required"`
	Port     int    `json:"port"`
	Engine   string `json:"engine" binding:"required"`
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// InterrogateDatabase connects to a database and discovers its encryption configuration
func (h *ExperimentalActionHandlers) InterrogateDatabase(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}

	var req interrogateDatabaseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "hostname, engine, username, and password are required"})
		return
	}

	if req.Engine != "postgresql" && req.Engine != "mysql" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "engine must be 'postgresql' or 'mysql'"})
		return
	}

	if req.Port == 0 {
		if req.Engine == "postgresql" {
			req.Port = 5432
		} else {
			req.Port = 3306
		}
	}

	dbInterrogator := services.NewDatabaseInterrogationService(h.db)

	var connStr string
	if req.Engine == "postgresql" {
		connStr = fmt.Sprintf("postgres://%s:%s@%s:%d/postgres?sslmode=prefer&connect_timeout=10",
			req.Username, req.Password, req.Hostname, req.Port)
	} else {
		connStr = fmt.Sprintf("%s:%s@tcp(%s:%d)/?timeout=10s",
			req.Username, req.Password, req.Hostname, req.Port)
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	var finding *services.DatabaseEncryptionFinding
	var err error
	if req.Engine == "postgresql" {
		finding, err = dbInterrogator.InterrogatePostgreSQL(ctx, connStr)
	} else {
		finding, err = dbInterrogator.InterrogateMySQL(ctx, connStr)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Interrogation failed: %v", err)})
		return
	}

	finding.Hostname = req.Hostname
	finding.Port = req.Port

	// Store the finding
	if err := dbInterrogator.StoreDatabaseEncryptionFinding(ctx, tenantID, nil, finding); err != nil {
		log.Printf("Warning: failed to store database encryption finding: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"message":                    "Database interrogated successfully",
		"db_engine":                  finding.Engine,
		"db_version":                 finding.Version,
		"ssl_enabled":                finding.SSLEnabled,
		"ssl_cipher":                 finding.SSLCipher,
		"encryption_at_rest_enabled": finding.EncryptionAtRestEnabled,
		"password_encryption":        finding.PasswordEncryptionMethod,
	})
}

// --- SSH Key Scan ---

type scanSSHRequest struct {
	Hostname string `json:"hostname" binding:"required"`
	Port     int    `json:"port"`
}

// ScanSSHKeys probes an SSH host to discover its host keys
func (h *ExperimentalActionHandlers) ScanSSHKeys(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}

	var req scanSSHRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "hostname is required"})
		return
	}

	if req.Port == 0 {
		req.Port = 22
	}

	addr := fmt.Sprintf("%s:%d", req.Hostname, req.Port)

	// SSRF guard: the hostname is fully tenant-controlled, so refuse a
	// target that resolves to an internal/metadata address before probing.
	// The dial itself also goes through network.SafeDialTimeout below, which
	// re-checks at connect time (closes the resolve-then-dial TOCTOU).
	if err := network.ValidateDialAddr(addr); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "target host is not allowed"})
		return
	}

	// Probe with different key type preferences to discover all offered host keys
	keyTypePreferences := [][]string{
		{"ssh-ed25519"},
		{"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"},
		{"rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"},
		{"ssh-dss"},
	}

	type discoveredKey struct {
		KeyType     string `json:"key_type"`
		KeySize     int    `json:"key_size"`
		Fingerprint string `json:"fingerprint"`
		IsWeak      bool   `json:"is_weak"`
		RiskScore   int    `json:"risk_score"`
	}

	seen := make(map[string]bool)
	var keys []discoveredKey

	for _, prefs := range keyTypePreferences {
		var capturedKey ssh.PublicKey
		config := &ssh.ClientConfig{
			HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
				capturedKey = key
				return nil // Complete handshake once; key captured from callback
			},
			HostKeyAlgorithms: prefs,
			Timeout:           5 * time.Second,
		}

		conn, err := network.SafeDialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			// If we can't connect at all, fail immediately
			if len(keys) == 0 {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to connect to %s: %v", addr, err)})
				return
			}
			break
		}

		sshConn, _, _, err := ssh.NewClientConn(conn, addr, config)
		if err != nil {
			// Connection established but SSH handshake may fail — that's OK, try next
			conn.Close()
			continue
		}
		sshConn.Close()

		if capturedKey == nil {
			continue
		}

		keyType := capturedKey.Type()
		fingerprint := ssh.FingerprintSHA256(capturedKey)

		if seen[fingerprint] {
			continue
		}
		seen[fingerprint] = true

		keySize := estimateSSHKeySize(keyType, capturedKey)
		isWeak, riskScore := assessSSHKey(keyType, keySize)

		keys = append(keys, discoveredKey{
			KeyType:     keyType,
			KeySize:     keySize,
			Fingerprint: fingerprint,
			IsWeak:      isWeak,
			RiskScore:   riskScore,
		})

		// Store to database
		h.storeSSHKey(c.Request.Context(), tenantID, req.Hostname, req.Port, keyType, keySize, fingerprint, isWeak, riskScore)
	}

	if len(keys) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"message": "Connected but no SSH host keys could be captured",
			"keys":    []discoveredKey{},
		})
		return
	}

	weakCount := 0
	for _, k := range keys {
		if k.IsWeak {
			weakCount++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    fmt.Sprintf("Discovered %d SSH host keys", len(keys)),
		"keys":       keys,
		"total":      len(keys),
		"weak_count": weakCount,
	})
}

func (h *ExperimentalActionHandlers) storeSSHKey(
	ctx context.Context, tenantID uuid.UUID,
	hostname string, port int,
	keyType string, keySize int, fingerprint string,
	isWeak bool, riskScore int,
) {
	query := `
		INSERT INTO ssh_keys (
			tenant_id, key_type, key_size, fingerprint_sha256,
			key_source, hostname, ip_address,
			risk_score, is_weak, discovery_method,
			first_discovered_at, last_seen_at
		) VALUES (
			$1, $2, $3, $4,
			'host_key', $5, $6,
			$7, $8, 'active',
			NOW(), NOW()
		)
		ON CONFLICT (tenant_id, fingerprint_sha256) WHERE deleted_at IS NULL
		DO UPDATE SET last_seen_at = NOW(), updated_at = NOW()
	`
	var ipAddr sql.NullString
	if ip := net.ParseIP(hostname); ip != nil {
		ipAddr = sql.NullString{String: ip.String(), Valid: true}
	}
	// RLS-scoped write on `ssh_keys`: tenantID is an input → WithTenantTx.
	err := shareddatabase.WithTenantTx(ctx, h.db, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query,
			tenantID, keyType, keySize, fingerprint,
			hostname, ipAddr,
			riskScore, isWeak,
		)
		return e
	})
	if err != nil {
		log.Printf("Warning: failed to store SSH key for %s: %v", hostname, err)
	}
}

func estimateSSHKeySize(keyType string, key ssh.PublicKey) int {
	switch {
	case keyType == "ssh-ed25519":
		return 256
	case strings.Contains(keyType, "nistp256"):
		return 256
	case strings.Contains(keyType, "nistp384"):
		return 384
	case strings.Contains(keyType, "nistp521"):
		return 521
	case keyType == "ssh-dss":
		return 1024
	case strings.Contains(keyType, "rsa"):
		// Estimate RSA key size from marshaled key length
		marshaled := key.Marshal()
		bits := len(marshaled) * 8
		if bits > 3000 {
			return 4096
		}
		if bits > 1500 {
			return 2048
		}
		return 1024
	default:
		return 0
	}
}

func assessSSHKey(keyType string, keySize int) (isWeak bool, riskScore int) {
	switch {
	case keyType == "ssh-dss":
		return true, 80 // DSA deprecated, limited to 1024-bit
	case keyType == "ssh-rsa":
		return true, 60 // ssh-rsa uses SHA-1 signatures
	case strings.Contains(keyType, "rsa") && keySize < 2048:
		return true, 70 // RSA < 2048 is weak
	case keyType == "ssh-ed25519":
		return false, 10 // Ed25519 is strong
	case strings.Contains(keyType, "ecdsa"):
		return false, 15 // ECDSA is strong
	default:
		if keySize >= 2048 {
			return false, 20
		}
		return false, 30
	}
}
