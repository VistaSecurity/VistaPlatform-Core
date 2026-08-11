package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
)

// DatabaseInterrogationService is the in-cluster wrapper around the shared
// core's database interrogation. The interrogation itself (connection-string
// construction, per-engine SELECT/SHOW queries, risk scoring) lives in
// shared/deviceinterrogation; this wrapper owns only the platform-side
// persistence to the database_encryption_states table.
type DatabaseInterrogationService struct {
	db *sql.DB
}

// NewDatabaseInterrogationService creates a new database interrogation service.
func NewDatabaseInterrogationService(db *sql.DB) *DatabaseInterrogationService {
	return &DatabaseInterrogationService{db: db}
}

// DatabaseEncryptionFinding is the shared core's finding type, aliased here so
// existing call sites and tests in this package keep compiling.
type DatabaseEncryptionFinding = di.DatabaseEncryptionFinding

// InterrogatePostgreSQL interrogates a PostgreSQL instance via a connection
// string, delegating to the shared core. Retained for callers that already have
// a DSN (e.g. the experimental connection tester).
func (s *DatabaseInterrogationService) InterrogatePostgreSQL(ctx context.Context, connStr string) (*DatabaseEncryptionFinding, error) {
	return di.InterrogatePostgreSQLConn(ctx, connStr)
}

// InterrogateMySQL interrogates a MySQL instance via a connection string,
// delegating to the shared core.
func (s *DatabaseInterrogationService) InterrogateMySQL(ctx context.Context, connStr string) (*DatabaseEncryptionFinding, error) {
	return di.InterrogateMySQLConn(ctx, connStr)
}

// StoreDatabaseEncryptionFinding persists a database encryption finding to the
// database_encryption_states table.
func (s *DatabaseInterrogationService) StoreDatabaseEncryptionFinding(
	ctx context.Context,
	tenantID uuid.UUID,
	deviceID *uuid.UUID,
	finding *DatabaseEncryptionFinding,
) error {
	rawConfigJSON, err := json.Marshal(finding.RawConfig)
	if err != nil {
		rawConfigJSON = []byte("{}")
	}

	query := `
		INSERT INTO database_encryption_states (
			tenant_id, device_id, db_engine, db_version,
			hostname, port,
			ssl_enabled, ssl_version, ssl_cipher, ssl_enforced,
			encryption_at_rest_enabled, encryption_method, encryption_algorithm,
			password_encryption_method,
			risk_score, discovery_method, raw_config,
			first_discovered_at, last_verified_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6,
			$7, $8, $9, $10,
			$11, $12, $13,
			$14,
			$15, 'device_interrogation', $16,
			NOW(), NOW()
		)
	`

	riskScore := s.calculateRiskScore(finding)

	// RLS-scoped write on `database_encryption_states`: tenantID is an input → WithTenantTx.
	err = shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query,
			tenantID, deviceID, finding.Engine, finding.Version,
			finding.Hostname, finding.Port,
			finding.SSLEnabled, finding.SSLVersion, finding.SSLCipher, finding.SSLEnforced,
			finding.EncryptionAtRestEnabled, finding.EncryptionMethod, finding.EncryptionAlgorithm,
			finding.PasswordEncryptionMethod,
			riskScore, string(rawConfigJSON),
		)
		return e
	})
	if err != nil {
		return fmt.Errorf("failed to store database encryption state: %w", err)
	}
	return nil
}

// calculateRiskScore delegates to the shared core's single scoring
// implementation (kept as a method so existing tests and call sites are stable).
func (s *DatabaseInterrogationService) calculateRiskScore(finding *DatabaseEncryptionFinding) int {
	return di.CalculateDatabaseRiskScore(finding)
}
