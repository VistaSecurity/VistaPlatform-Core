package deviceinterrogation

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq" // postgres driver, registered for sql.Open("postgres", ...)
)

// DatabaseInterrogator interrogates PostgreSQL and MySQL instances for their
// in-transit (TLS) and at-rest encryption posture plus password-hashing method.
// It is the shared core of the former in-cluster
// device-interrogation-service's database interrogation: the service wrapper
// keeps the persistence side (writing to the database_encryption_states table),
// while the connection-string construction, the per-engine SELECT/SHOW
// interrogation, and the risk scoring all live here so the customer-deployed
// Interrogation Agent can carry the same capability.
//
// Entitlement gating happens at the wrapper, not here.
type DatabaseInterrogator struct{}

// SupportedDeviceTypes implements DeviceInterrogator.
func (*DatabaseInterrogator) SupportedDeviceTypes() []string {
	return []string{"postgresql", "mysql"}
}

// DatabaseEncryptionFinding represents the encryption state of a database. It is
// exported so the service wrapper can read it and persist it to the
// database_encryption_states table (persistence stays in the wrapper).
type DatabaseEncryptionFinding struct {
	Engine   string
	Version  string
	Hostname string
	Port     int

	// TLS / in-transit
	SSLEnabled  bool
	SSLVersion  string
	SSLCipher   string
	SSLEnforced bool

	// At-rest
	EncryptionAtRestEnabled bool
	EncryptionMethod        string
	EncryptionAlgorithm     string

	// Password hashing
	PasswordEncryptionMethod string

	// RiskScore is the computed 0-100 severity of this finding. The wrapper
	// persists it verbatim; it is computed here (rather than in the wrapper's
	// store path) so the standalone agent gets the same score.
	RiskScore int

	// Raw settings for reference
	RawConfig map[string]interface{}
}

// InterrogateDatabase builds a DSN from the (already-decrypted, plaintext)
// device credentials, dispatches on device.DeviceType to the per-engine
// interrogation, computes the risk score, and returns the finding with
// Hostname/Port set. Credentials are plaintext here — no encryption service is
// involved (the wrapper decrypts before calling).
func InterrogateDatabase(ctx context.Context, device DeviceInfo, creds Credentials) (*DatabaseEncryptionFinding, error) {
	connStr, port, err := dbBuildConnStr(device, creds)
	if err != nil {
		return nil, fmt.Errorf("failed to build connection string: %w", err)
	}

	var finding *DatabaseEncryptionFinding
	switch device.DeviceType {
	case "postgresql":
		finding, err = dbInterrogatePostgreSQL(ctx, connStr)
	case "mysql":
		finding, err = dbInterrogateMySQL(ctx, connStr)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", device.DeviceType)
	}
	if err != nil {
		return nil, fmt.Errorf("database interrogation failed: %w", err)
	}

	// Set hostname/port from the device record. dbBuildConnStr above already
	// resolved the same host successfully, so this cannot fail here.
	finding.Hostname, _ = deviceHost(device)
	finding.Port = port

	finding.RiskScore = dbCalculateRiskScore(finding)

	return finding, nil
}

// Interrogate implements DeviceInterrogator. It runs InterrogateDatabase and
// converts the finding into a single database CryptoAsset.
func (*DatabaseInterrogator) Interrogate(ctx context.Context, device DeviceInfo, creds Credentials) (*InterrogateResult, error) {
	finding, err := InterrogateDatabase(ctx, device, creds)
	if err != nil {
		return nil, err
	}

	protocol := "TLS"
	if !finding.SSLEnabled {
		protocol = "NONE"
	}

	asset := CryptoAsset{
		Hostname:  finding.Hostname,
		IPAddress: device.IPAddress,
		Port:      finding.Port,
		Protocol:  protocol,
		AssetType: "database",
		Metadata: map[string]interface{}{
			"db_engine":                  finding.Engine,
			"db_version":                 finding.Version,
			"ssl_enabled":                finding.SSLEnabled,
			"ssl_cipher":                 finding.SSLCipher,
			"ssl_version":                finding.SSLVersion,
			"encryption_at_rest":         finding.EncryptionAtRestEnabled,
			"password_encryption_method": finding.PasswordEncryptionMethod,
			"risk_score":                 finding.RiskScore,
			"raw_config":                 finding.RawConfig,
		},
	}

	// Only populate optional crypto fields when genuinely known — never
	// fabricate a default.
	if finding.SSLVersion != "" {
		asset.ProtocolVersion = strPtr(finding.SSLVersion)
	}
	if finding.SSLCipher != "" {
		asset.CipherSuite = strPtr(finding.SSLCipher)
	}

	return &InterrogateResult{
		Assets: []CryptoAsset{asset},
		DeviceInfo: map[string]interface{}{
			"db_engine":                  finding.Engine,
			"db_version":                 finding.Version,
			"ssl_enabled":                finding.SSLEnabled,
			"ssl_cipher":                 finding.SSLCipher,
			"ssl_version":                finding.SSLVersion,
			"encryption_at_rest":         finding.EncryptionAtRestEnabled,
			"password_encryption_method": finding.PasswordEncryptionMethod,
			"risk_score":                 finding.RiskScore,
			"raw_config":                 finding.RawConfig,
		},
	}, nil
}

// dbBuildConnStr constructs a DSN from plaintext credentials and the device
// record. It returns the DSN and the engine's default port.
func dbBuildConnStr(device DeviceInfo, creds Credentials) (string, int, error) {
	username := creds.Username
	password := creds.Password
	// deviceHost errors rather than defaulting to localhost — a DSN built
	// against the interrogating host is a scan of the wrong machine, not a
	// degraded scan of the right one.
	host, err := deviceHost(device)
	if err != nil {
		return "", 0, err
	}

	switch device.DeviceType {
	case "postgresql":
		port := 5432
		return fmt.Sprintf("postgres://%s:%s@%s:%d/postgres?sslmode=prefer", username, password, host, port), port, nil
	case "mysql":
		port := 3306
		return fmt.Sprintf("%s:%s@tcp(%s:%d)/", username, password, host, port), port, nil
	default:
		return "", 0, fmt.Errorf("unsupported database type: %s", device.DeviceType)
	}
}

// dbInterrogatePostgreSQL queries a PostgreSQL instance for its encryption settings.
func dbInterrogatePostgreSQL(ctx context.Context, connStr string) (*DatabaseEncryptionFinding, error) {
	targetDB, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}
	defer targetDB.Close()

	// Set a timeout for the connection
	targetDB.SetConnMaxLifetime(30 * time.Second)
	if err := targetDB.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping PostgreSQL: %w", err)
	}

	finding := &DatabaseEncryptionFinding{
		Engine:    "postgresql",
		RawConfig: make(map[string]interface{}),
	}

	// Get version
	var version string
	if err := targetDB.QueryRowContext(ctx, "SELECT version()").Scan(&version); err == nil {
		finding.Version = version
		finding.RawConfig["version"] = version
	}

	// Get SSL status from connection
	var sslInUse bool
	if err := targetDB.QueryRowContext(ctx, "SELECT ssl_is_used()").Scan(&sslInUse); err == nil {
		finding.SSLEnabled = sslInUse
		finding.RawConfig["ssl_is_used"] = sslInUse
	}

	// Get SSL cipher and protocol from current connection
	if sslInUse {
		var cipher sql.NullString
		row := targetDB.QueryRowContext(ctx,
			"SELECT ssl_cipher(), version()")
		if err := row.Scan(&cipher, &version); err == nil {
			if cipher.Valid {
				finding.SSLCipher = cipher.String
				finding.RawConfig["ssl_cipher"] = cipher.String
			}
		}
	}

	// Get SSL-related settings from pg_settings
	sslSettings := []string{
		"ssl", "ssl_min_protocol_version", "ssl_max_protocol_version",
		"ssl_ciphers", "ssl_prefer_server_ciphers",
		"password_encryption",
	}
	for _, setting := range sslSettings {
		var name, settingValue string
		err := targetDB.QueryRowContext(ctx,
			"SELECT name, setting FROM pg_settings WHERE name = $1", setting,
		).Scan(&name, &settingValue)
		if err == nil {
			finding.RawConfig[name] = settingValue

			switch name {
			case "ssl":
				finding.SSLEnabled = finding.SSLEnabled || settingValue == "on"
			case "ssl_min_protocol_version":
				finding.SSLVersion = settingValue
			case "password_encryption":
				finding.PasswordEncryptionMethod = settingValue
			}
		}
	}

	// Check if SSL is required (pg_hba.conf hostssl entries)
	// We can infer from ssl setting being 'on' and check if there are hostnossl entries
	var sslSetting string
	if err := targetDB.QueryRowContext(ctx,
		"SELECT setting FROM pg_settings WHERE name = 'ssl'",
	).Scan(&sslSetting); err == nil {
		finding.RawConfig["ssl_setting"] = sslSetting
	}

	return finding, nil
}

// dbInterrogateMySQL queries a MySQL instance for its encryption settings.
func dbInterrogateMySQL(ctx context.Context, connStr string) (*DatabaseEncryptionFinding, error) {
	// MySQL connections use a different driver, so we query via standard database/sql.
	// The caller should provide a mysql:// connection string.
	targetDB, err := sql.Open("mysql", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MySQL: %w", err)
	}
	defer targetDB.Close()

	targetDB.SetConnMaxLifetime(30 * time.Second)
	if err := targetDB.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping MySQL: %w", err)
	}

	finding := &DatabaseEncryptionFinding{
		Engine:    "mysql",
		RawConfig: make(map[string]interface{}),
	}

	// Get version
	var version string
	if err := targetDB.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err == nil {
		finding.Version = version
		finding.RawConfig["version"] = version
	}

	// Query SSL-related variables
	rows, err := targetDB.QueryContext(ctx,
		"SHOW VARIABLES WHERE Variable_name LIKE '%ssl%' OR Variable_name LIKE '%tls%' OR Variable_name LIKE '%encrypt%'")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var name, value string
			if err := rows.Scan(&name, &value); err == nil {
				finding.RawConfig[name] = value

				switch strings.ToLower(name) {
				case "have_ssl", "have_openssl":
					finding.SSLEnabled = finding.SSLEnabled || strings.ToUpper(value) == "YES"
				case "ssl_cipher":
					finding.SSLCipher = value
				case "tls_version":
					finding.SSLVersion = value
				case "default_table_encryption":
					finding.EncryptionAtRestEnabled = strings.ToUpper(value) == "ON"
				case "require_secure_transport":
					finding.SSLEnforced = strings.ToUpper(value) == "ON"
				}
			}
		}
	}

	// Check InnoDB encryption status
	var innodbEncryption string
	if err := targetDB.QueryRowContext(ctx,
		"SELECT @@innodb_encrypt_tables",
	).Scan(&innodbEncryption); err == nil {
		finding.RawConfig["innodb_encrypt_tables"] = innodbEncryption
		if strings.ToUpper(innodbEncryption) == "ON" || strings.ToUpper(innodbEncryption) == "FORCE" {
			finding.EncryptionAtRestEnabled = true
			finding.EncryptionMethod = "InnoDB tablespace encryption"
		}
	}

	return finding, nil
}

// InterrogatePostgreSQLConn interrogates a PostgreSQL instance reachable via the
// given connection string. Exposed for callers (e.g. the experimental
// connection tester) that already have a DSN rather than a device record.
func InterrogatePostgreSQLConn(ctx context.Context, connStr string) (*DatabaseEncryptionFinding, error) {
	return dbInterrogatePostgreSQL(ctx, connStr)
}

// InterrogateMySQLConn interrogates a MySQL instance reachable via the given
// connection string.
func InterrogateMySQLConn(ctx context.Context, connStr string) (*DatabaseEncryptionFinding, error) {
	return dbInterrogateMySQL(ctx, connStr)
}

// CalculateDatabaseRiskScore computes the 0-100 risk score for a database
// encryption finding. Exported so a wrapper can reuse the single scoring
// implementation rather than re-deriving it.
func CalculateDatabaseRiskScore(finding *DatabaseEncryptionFinding) int {
	return dbCalculateRiskScore(finding)
}

// dbCalculateRiskScore computes a 0-100 risk score for a database encryption
// finding. Ported verbatim from the service's calculateRiskScore (minus the
// log line, which depended on the service's logger).
func dbCalculateRiskScore(finding *DatabaseEncryptionFinding) int {
	score := 50 // Baseline

	// SSL disabled is high risk
	if !finding.SSLEnabled {
		score += 30
	}

	// SSL not enforced is moderate risk
	if finding.SSLEnabled && !finding.SSLEnforced {
		score += 10
	}

	// Weak password hashing
	if finding.PasswordEncryptionMethod == "md5" {
		score += 20
	}

	// No encryption at rest (informational, depends on context)
	if !finding.EncryptionAtRestEnabled {
		score += 10
	}

	// TLS version check
	if finding.SSLVersion != "" {
		ver := strings.ToLower(finding.SSLVersion)
		if strings.Contains(ver, "tlsv1.0") || strings.Contains(ver, "tlsv1.1") {
			score += 15
		}
	}

	if score > 100 {
		score = 100
	}

	return score
}
