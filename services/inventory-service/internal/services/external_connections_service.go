package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
	cryptostrength "github.com/vistasecurity/vistaplatform/shared/strength"
)

// ExternalConnectionsService manages the external_connections and
// external_connection_history tables. It is the storage layer for
// 3rd party public internet connections observed by sensors.
type ExternalConnectionsService struct {
	db                       *database.DB
	algorithms               externalAlgorithmLookup
	serviceIdentificationSvc *ServiceIdentificationService
}

// NewExternalConnectionsService creates a new service wired to the algorithm service
// for crypto strength assessment.
func NewExternalConnectionsService(db *database.DB, algorithms *AlgorithmService) *ExternalConnectionsService {
	service := &ExternalConnectionsService{db: db}
	if algorithms != nil {
		service.algorithms = algorithms
	}
	return service
}

// SetServiceIdentificationService injects the service identification dependency.
func (s *ExternalConnectionsService) SetServiceIdentificationService(svc *ServiceIdentificationService) {
	s.serviceIdentificationSvc = svc
}

// Upsert inserts or updates an external connection observation.
// Crypto strength and PQC resistance are assessed at write time using the algorithms table.
func (s *ExternalConnectionsService) Upsert(tenantID uuid.UUID, input models.ExternalConnectionUpsert) (*models.ExternalConnection, error) {
	if input.SourceIP == "" || input.DestIP == "" || input.DestPort == 0 || input.Protocol == "" {
		return nil, fmt.Errorf("source_ip, dest_ip, dest_port, and protocol are required")
	}

	// Canonicalize the protocol spelling BEFORE anything reads it. external_connections.protocol
	// is varchar, not the protocol_type enum, and it is part of the row's unique key — so an
	// "EtherNet/IP" observation and an "EtherNet_IP" observation of the same endpoint would
	// otherwise upsert into two separate rows, each with its own observation_count and history.
	// Doing it here rather than in the SQL args also means assessCrypto and the port-heuristic
	// service lookup below see the same canonical value the row stores.
	input.Protocol = cryptoparse.NormalizeProtocol(input.Protocol)

	// Ratings are computed only after merging persisted facts inside the tenant
	// transaction. Assessing the incoming fragment first can erase known weakness.
	var cryptoStrength *string
	var isPQC bool
	var weakReasonsArr, hygieneFlagsArr pq.StringArray

	// source_asset_id is resolved best-effort inside the tenant tx below (the
	// assets lookup, the external_connections upsert, and the history
	// write are all RLS-scoped and run as one unit).
	var sourceAssetID *uuid.UUID

	// --- Certificate expiry flag ---
	certIsExpired := input.CertNotAfter != nil && input.CertNotAfter.Before(time.Now())

	// --- dest_hostname + its provenance ---
	// Normalized together because they are one claim: a blank name is no claim
	// at all, and a provenance with nothing to describe would sit in the column
	// asserting something about a name that is not there.
	input.DestHostname = trimmedOrNil(input.DestHostname)
	destHostnameSourceKind := normalizeHostnameSourceKind(input.DestHostnameSourceKind)
	if input.DestHostname == nil {
		destHostnameSourceKind = nil
	}

	now := time.Now()

	var certSAN pq.StringArray
	if len(input.CertSAN) > 0 {
		certSAN = pq.StringArray(input.CertSAN)
	}

	var supportedTLSVersions pq.StringArray
	if len(input.SupportedTLSVersions) > 0 {
		supportedTLSVersions = pq.StringArray(input.SupportedTLSVersions)
	}

	// --- Upsert into external_connections ---
	// CTE captures the previous state on conflict so we can write history.
	upsertSQL := `
WITH prev AS (
    SELECT id, cipher_suite, protocol_version, crypto_strength, is_pqc_resistant, cert_fingerprint_sha256, cert_not_after
    FROM external_connections
    WHERE tenant_id = $1 AND source_ip = $2::inet AND dest_ip = $3::inet AND dest_port = $4 AND protocol = $5
),
upserted AS (
    INSERT INTO external_connections (
        tenant_id, source_ip, source_hostname, source_asset_id,
        dest_ip, dest_hostname, dest_hostname_source_kind, dest_port, protocol, protocol_version,
        cipher_suite, key_exchange_algorithm, key_size,
        supported_tls_versions,
        crypto_strength, is_pqc_resistant, weak_reasons, cert_hygiene_flags,
        cert_subject, cert_issuer, cert_san,
        cert_not_before, cert_not_after, cert_fingerprint_sha256,
        cert_public_key_algorithm, cert_public_key_size, cert_signature_algorithm,
        cert_is_expired, cert_validation_status, cert_sct_source, cert_pem,
        first_seen_at, last_seen_at, observation_count, sensor_id,
        created_at, updated_at
    ) VALUES (
        $1, $2::inet, $6, $7,
        $3::inet, $8, $33, $4, $5, $9,
        $10, $11, $12,
        $29,
        $13, $14, $30, $31,
        $15, $16, $17,
        $18, $19, $20,
        $21, $22, $23,
        $24, $25, $32, $26,
        $27, $27, 1, $28,
        $27, $27
    )
    ON CONFLICT ON CONSTRAINT uq_external_connection DO UPDATE SET
        source_hostname         = COALESCE(EXCLUDED.source_hostname, external_connections.source_hostname),
        source_asset_id         = COALESCE(EXCLUDED.source_asset_id, external_connections.source_asset_id),
        -- dest_hostname precedence: an INFERENCE never overwrites a MEASUREMENT.
        --
        -- COALESCE alone ("empty never wins") was not enough: a reverse-DNS PTR
        -- answer is a populated string, so ec2-54-163-235-119.compute-1.amazonaws.com
        -- cheerfully replaced the slack.com the sensor read out of the client's
        -- own ClientHello. The rank below is the fix — it is a total order over
        -- the three provenance states, and NULL ("producer did not say") sits
        -- between the two rather than being folded into either:
        --
        --   measured                     2  -- read off the wire (TLS SNI, DHCP/mDNS)
        --   NULL / declared / imported   1  -- unstated, or asserted by a human/import
        --   inferred                     0  -- a guess about the address (PTR)
        --
        -- The incoming value wins on >= , so like beats like (a fresh PTR may
        -- still refresh a stale PTR, a new SNI a previous SNI) while a lower
        -- rank is refused. A CASE <expr> WHEN ... form with a NULL <expr> falls
        -- to ELSE, so no NULL leaks into the comparison and turns it into NULL.
        --
        -- btrim/<> '' rather than IS NOT NULL on the incoming name: a producer
        -- that sends a pointer to "" is making no claim, and '' is not NULL.
        dest_hostname           = CASE
            WHEN COALESCE(btrim(EXCLUDED.dest_hostname), '') <> ''
             AND (external_connections.dest_hostname IS NULL
                  OR CASE EXCLUDED.dest_hostname_source_kind WHEN 'measured' THEN 2 WHEN 'inferred' THEN 0 ELSE 1 END
                     >= CASE external_connections.dest_hostname_source_kind WHEN 'measured' THEN 2 WHEN 'inferred' THEN 0 ELSE 1 END)
            THEN EXCLUDED.dest_hostname
            ELSE external_connections.dest_hostname
        END,
        dest_hostname_source_kind = CASE
            WHEN COALESCE(btrim(EXCLUDED.dest_hostname), '') <> ''
             AND (external_connections.dest_hostname IS NULL
                  OR CASE EXCLUDED.dest_hostname_source_kind WHEN 'measured' THEN 2 WHEN 'inferred' THEN 0 ELSE 1 END
                     >= CASE external_connections.dest_hostname_source_kind WHEN 'measured' THEN 2 WHEN 'inferred' THEN 0 ELSE 1 END)
            THEN EXCLUDED.dest_hostname_source_kind
            ELSE external_connections.dest_hostname_source_kind
        END,
        protocol_version        = COALESCE(EXCLUDED.protocol_version, external_connections.protocol_version),
        cipher_suite            = COALESCE(EXCLUDED.cipher_suite, external_connections.cipher_suite),
        key_exchange_algorithm  = COALESCE(EXCLUDED.key_exchange_algorithm, external_connections.key_exchange_algorithm),
        key_size                = COALESCE(EXCLUDED.key_size, external_connections.key_size),
        supported_tls_versions  = COALESCE(EXCLUDED.supported_tls_versions, external_connections.supported_tls_versions),
        crypto_strength         = EXCLUDED.crypto_strength,
        is_pqc_resistant        = EXCLUDED.is_pqc_resistant,
        weak_reasons            = EXCLUDED.weak_reasons,
        cert_hygiene_flags       = EXCLUDED.cert_hygiene_flags,
        cert_subject            = COALESCE(EXCLUDED.cert_subject, external_connections.cert_subject),
        cert_issuer             = COALESCE(EXCLUDED.cert_issuer, external_connections.cert_issuer),
        cert_san                = COALESCE(EXCLUDED.cert_san, external_connections.cert_san),
        cert_not_before         = COALESCE(EXCLUDED.cert_not_before, external_connections.cert_not_before),
        cert_not_after          = COALESCE(EXCLUDED.cert_not_after, external_connections.cert_not_after),
        cert_fingerprint_sha256 = COALESCE(EXCLUDED.cert_fingerprint_sha256, external_connections.cert_fingerprint_sha256),
        cert_public_key_algorithm = COALESCE(EXCLUDED.cert_public_key_algorithm, external_connections.cert_public_key_algorithm),
        cert_public_key_size    = COALESCE(EXCLUDED.cert_public_key_size, external_connections.cert_public_key_size),
        cert_signature_algorithm = COALESCE(EXCLUDED.cert_signature_algorithm, external_connections.cert_signature_algorithm),
        cert_is_expired         = EXCLUDED.cert_is_expired,
        cert_validation_status  = COALESCE(EXCLUDED.cert_validation_status, external_connections.cert_validation_status),
        cert_sct_source         = COALESCE(EXCLUDED.cert_sct_source, external_connections.cert_sct_source),
        cert_pem                = COALESCE(EXCLUDED.cert_pem, external_connections.cert_pem),
        last_seen_at            = EXCLUDED.last_seen_at,
        observation_count       = external_connections.observation_count + 1,
        sensor_id               = COALESCE(EXCLUDED.sensor_id, external_connections.sensor_id),
        updated_at              = EXCLUDED.updated_at
    RETURNING *
)
SELECT
    u.id, u.tenant_id,
    u.source_ip::text, u.source_hostname, u.source_asset_id,
    u.dest_ip::text, u.dest_hostname, u.dest_port,
    u.protocol, u.protocol_version, u.cipher_suite, u.key_exchange_algorithm, u.key_size,
    u.supported_tls_versions,
    u.crypto_strength, u.is_pqc_resistant, u.weak_reasons, u.cert_hygiene_flags,
    u.cert_subject, u.cert_issuer, u.cert_san,
    u.cert_not_before, u.cert_not_after, u.cert_fingerprint_sha256,
    u.cert_public_key_algorithm, u.cert_public_key_size, u.cert_signature_algorithm,
    u.cert_is_expired, u.cert_validation_status, u.cert_sct_source, u.cert_pem,
    u.first_seen_at, u.last_seen_at, u.observation_count, u.sensor_id,
    u.created_at, u.updated_at,
    (prev.id IS NULL) AS is_new,
    prev.cipher_suite AS prev_cipher_suite,
    prev.protocol_version AS prev_protocol_version,
    prev.crypto_strength AS prev_crypto_strength,
    prev.is_pqc_resistant AS prev_is_pqc_resistant,
    prev.cert_fingerprint_sha256 AS prev_cert_fingerprint,
    prev.cert_not_after AS prev_cert_not_after
FROM upserted u
LEFT JOIN prev ON true
`

	var conn models.ExternalConnection
	var isNew bool
	var prevCipherSuite, prevProtocolVersion, prevCryptoStrength, prevCertFingerprint sql.NullString
	var prevIsPQC sql.NullBool
	var prevCertNotAfter sql.NullTime
	var scanCertSAN pq.StringArray
	var scanSupportedTLSVersions pq.StringArray
	var scanWeakReasons pq.StringArray
	var scanCertHygieneFlags pq.StringArray

	// RLS-scoped unit: resolve source_asset_id (assets), upsert the row
	// (external_connections), and write the history row (external_connection_history)
	// all inside one WithTenantTx so app.tenant_id is set for every statement and
	// the upsert + its history land atomically.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		// Serialize this observation tuple, including the first insert: a
		// row lock alone does not protect two concurrent first observations.
		if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtextextended($1::text||':'||$2::inet::text||':'||$3::inet::text||':'||$4::text||':'||$5,1616))`, tenantID, input.SourceIP, input.DestIP, input.DestPort, input.Protocol); err != nil {
			return err
		}
		freshComplete := completeExternalObservation(input)
		measuredExchange := input.KeyExchangeAlgorithm != nil && strings.TrimSpace(*input.KeyExchangeAlgorithm) != "" && input.KeySize != nil && *input.KeySize > 0
		var priorJSON []byte
		var prior models.ExternalConnection
		err := tx.QueryRow(`SELECT to_jsonb(ec) FROM external_connections ec WHERE tenant_id=$1 AND source_ip=$2::inet AND dest_ip=$3::inet AND dest_port=$4 AND protocol=$5 FOR UPDATE`, tenantID, input.SourceIP, input.DestIP, input.DestPort, input.Protocol).Scan(&priorJSON)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		if err == nil {
			if err := json.Unmarshal(priorJSON, &prior); err != nil {
				return err
			}
			var stored struct {
				Strength *string `json:"crypto_strength"`
			}
			if err := json.Unmarshal(priorJSON, &stored); err != nil {
				return err
			}
			prior.Strength = stored.Strength
			var facts models.ExternalConnectionUpsert
			if err := json.Unmarshal(priorJSON, &facts); err != nil {
				return err
			}
			input = mergeExternalObservation(input, facts)
		}
		assessmentInput, priorReasons := prepareExternalAssessment(input, prior.WeakReasons, measuredExchange)
		rating, pqcRating, parsedKEX, reasons, hygiene := assessExternalCryptoTx(context.Background(), tx, assessmentInput)
		if input.KeyExchangeAlgorithm == nil && parsedKEX != "" {
			input.KeyExchangeAlgorithm = &parsedKEX
		}
		rating, reasons = preserveExternalAssessment(rating, reasons, prior.Strength, priorReasons, freshComplete && rating != "")
		cryptoStrength = nullableStrength(rating)
		isPQC = pqcRating
		weakReasonsArr = pq.StringArray(reasons)
		hygieneFlagsArr = pq.StringArray(appendUnique(hygiene, prior.CertHygieneFlags...))
		certIsExpired = input.CertNotAfter != nil && input.CertNotAfter.Before(now)
		certSAN = pq.StringArray(input.CertSAN)
		supportedTLSVersions = pq.StringArray(input.SupportedTLSVersions)
		// --- Resolve source_asset_id best-effort ---
		{
			var id uuid.UUID
			if input.SourceAssetID != nil {
				if e := tx.QueryRow(`SELECT id FROM assets WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL`, tenantID, *input.SourceAssetID).Scan(&id); e == nil {
					sourceAssetID = &id
				}
			}
			// host() rather than ::text: casting inet to text renders the netmask
			// ("10.0.0.5/32"), which never equals a bare source IP — this lookup
			// matched nothing for as long as the ::text form was here.
			// The address may be the asset's primary_address or any of its
			// endpoints' — a host with three interfaces originates from all
			// three, and only one of them is the primary.
			q := `
				SELECT a.id FROM assets a
				LEFT JOIN asset_endpoints e ON e.tenant_id = a.tenant_id AND e.asset_id = a.id
				WHERE a.tenant_id = $1
				  AND (host(a.primary_address) = $2 OR host(e.address) = $2)
				  AND a.deleted_at IS NULL
				LIMIT 1`
			if sourceAssetID == nil {
				if e := tx.QueryRow(q, tenantID, input.SourceIP).Scan(&id); e == nil {
					sourceAssetID = &id
				}
			}
		}

		if e := tx.QueryRow(upsertSQL,
			// $1-$5: unique key
			tenantID, input.SourceIP, input.DestIP, input.DestPort, input.Protocol,
			// $6-$28: columns
			input.SourceHostname, sourceAssetID,
			input.DestHostname, input.ProtocolVersion,
			input.CipherSuite, input.KeyExchangeAlgorithm, input.KeySize,
			cryptoStrength, isPQC,
			input.CertSubject, input.CertIssuer, certSAN,
			input.CertNotBefore, input.CertNotAfter, input.CertFingerprintSHA256,
			input.CertPublicKeyAlgorithm, input.CertPublicKeySize, input.CertSignatureAlgorithm,
			certIsExpired, input.CertValidationStatus, input.CertPEM,
			now, input.SensorID,
			// $29: supported_tls_versions
			supportedTLSVersions,
			// $30: weak_reasons
			weakReasonsArr,
			// $31: cert_hygiene_flags
			hygieneFlagsArr,
			// $32: cert_sct_source
			input.CertSCTSource,
			// $33: dest_hostname_source_kind
			destHostnameSourceKind,
		).Scan(
			&conn.ID, &conn.TenantID,
			&conn.SourceIP, &conn.SourceHostname, &conn.SourceAssetID,
			&conn.DestIP, &conn.DestHostname, &conn.DestPort,
			&conn.Protocol, &conn.ProtocolVersion, &conn.CipherSuite, &conn.KeyExchangeAlgorithm, &conn.KeySize,
			&scanSupportedTLSVersions,
			&conn.Strength, &conn.IsPQCResistant, &scanWeakReasons, &scanCertHygieneFlags,
			&conn.CertSubject, &conn.CertIssuer, &scanCertSAN,
			&conn.CertNotBefore, &conn.CertNotAfter, &conn.CertFingerprintSHA256,
			&conn.CertPublicKeyAlgorithm, &conn.CertPublicKeySize, &conn.CertSignatureAlgorithm,
			&conn.CertIsExpired, &conn.CertValidationStatus, &conn.CertSCTSource, &conn.CertPEM,
			&conn.FirstSeenAt, &conn.LastSeenAt, &conn.ObservationCount, &conn.SensorID,
			&conn.CreatedAt, &conn.UpdatedAt,
			&isNew,
			&prevCipherSuite, &prevProtocolVersion, &prevCryptoStrength, &prevIsPQC,
			&prevCertFingerprint, &prevCertNotAfter,
		); e != nil {
			return fmt.Errorf("upsert external connection: %w", e)
		}
		if len(scanWeakReasons) > 0 {
			conn.WeakReasons = []string(scanWeakReasons)
		}
		if len(scanCertHygieneFlags) > 0 {
			conn.CertHygieneFlags = []string(scanCertHygieneFlags)
		}
		if len(scanCertSAN) > 0 {
			conn.CertSAN = []string(scanCertSAN)
		}
		if len(scanSupportedTLSVersions) > 0 {
			conn.SupportedTLSVersions = []string(scanSupportedTLSVersions)
		}

		// --- Write history row ---
		changeType, shouldRecord := s.determineChangeType(isNew,
			prevCipherSuite.String, prevProtocolVersion.String,
			prevCryptoStrength.String, prevIsPQC.Bool,
			prevCertFingerprint.String, prevCertNotAfter,
			&conn,
		)
		if shouldRecord {
			var prevPQC *bool
			if prevIsPQC.Valid {
				b := prevIsPQC.Bool
				prevPQC = &b
			}
			var prevCA *time.Time
			if prevCertNotAfter.Valid {
				t := prevCertNotAfter.Time
				prevCA = &t
			}

			var histPrevCipher, histPrevProto, histPrevStrength, histPrevFP *string
			if prevCipherSuite.Valid {
				histPrevCipher = &prevCipherSuite.String
			}
			if prevProtocolVersion.Valid {
				histPrevProto = &prevProtocolVersion.String
			}
			if prevCryptoStrength.Valid {
				histPrevStrength = &prevCryptoStrength.String
			}
			if prevCertFingerprint.Valid {
				histPrevFP = &prevCertFingerprint.String
			}

			newCS := conn.Strength
			_, historyErr := tx.Exec(`
				INSERT INTO external_connection_history (
					id, external_connection_id, tenant_id, change_type, strength_vocabulary_version,
					previous_protocol_version, previous_cipher_suite, previous_crypto_strength,
					previous_is_pqc_resistant, previous_cert_fingerprint_sha256, previous_cert_not_after,
					new_protocol_version, new_cipher_suite, new_crypto_strength,
					new_is_pqc_resistant, new_cert_fingerprint_sha256, new_cert_not_after,
					created_at
				) VALUES (
					gen_random_uuid(), $1, $2, $3, 2,
					$4, $5, $6, $7, $8, $9,
					$10, $11, $12, $13, $14, $15,
					NOW()
				)`,
				conn.ID, tenantID, changeType,
				histPrevProto, histPrevCipher, histPrevStrength, prevPQC, histPrevFP, prevCA,
				conn.ProtocolVersion, conn.CipherSuite, newCS, &conn.IsPQCResistant,
				conn.CertFingerprintSHA256, conn.CertNotAfter,
			)
			if historyErr != nil {
				return fmt.Errorf("record external connection history: %w", historyErr)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// --- Service identification ---
	// IdentifyService runs on the ServiceIdentificationService's own db handle
	// against the non-RLS service_identification_rules table, so it stays outside
	// the tenant tx; only the resulting external_connections UPDATE is RLS-scoped.
	if s.serviceIdentificationSvc != nil {
		hints := s.serviceIdentificationSvc.IdentifyService(tenantID, input.DestPort, input.Protocol, nil)
		if hints != nil {
			ver := hints.ServiceVersion
			_ = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
				_, _ = tx.Exec(`
					UPDATE external_connections SET service_name = $1, service_version = NULLIF($2, ''),
						service_confidence = $3, service_identification_method = $4, updated_at = NOW()
					WHERE id = $5 AND tenant_id = $6`,
					hints.ServiceName, ver, hints.Confidence, hints.IdentificationMethod, conn.ID, tenantID)
				return nil
			})
			conn.ServiceName = &hints.ServiceName
			if ver != "" {
				conn.ServiceVersion = &ver
			}
			conn.ServiceConfidence = &hints.Confidence
			conn.ServiceIdentificationMethod = &hints.IdentificationMethod
		}
	}

	// freshness guard: if this connection has been elevated to a managed
	// asset, keep that asset's last_seen current on every re-observation so
	// continuous vendor monitoring doesn't let the promoted asset go stale. The
	// join is a no-op for the (vast majority) non-elevated connections. This is
	// the passive-path counterpart to the in-place refresh in IngestFindings;
	// both the manual route and the sensor BatchProcessor reach external_connections
	// through this Upsert, so the freshness logic lives here once.
	// (Re-materializing a rotated cert into the managed asset is a follow-up — it
	// needs idempotent crypto handling to avoid duplicate crypto_implementations.)
	// RLS-scoped write over assets (and reads external_connections).
	_ = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, _ = tx.Exec(`
			UPDATE assets na
			SET last_seen_at = NOW(), updated_at = NOW()
			FROM external_connections ec
			WHERE ec.id = $1 AND ec.tenant_id = $2
			  AND ec.elevated_asset_id = na.id AND na.tenant_id = $2`,
			conn.ID, tenantID)
		return nil
	})

	return &conn, nil
}

// normalizeCipherComponent strips operating-mode suffixes from a cipher component
// name, then removes formatting hyphens and spaces so the result matches the
// algorithms.code format (e.g. "AES-256-GCM" → "AES256", "CHACHA20-POLY1305" →
// "CHACHA20", "TLS 1.2" → "TLS1.2"). For codes that already match (key exchange,
// hash), this is a no-op.
//
// The rules live in shared/cryptoparse alongside the parser that produces the
// values being normalized; this wrapper keeps the call sites short.
func normalizeCipherComponent(parsed string) string {
	return cryptoparse.NormalizeComponentCode(parsed)
}

// resolveAlgorithmForComponent looks up a cipher component (key exchange, symmetric,
// hash, signature) in the algorithms table using DB-driven matching only — no
// strength values are hardcoded here.
//
// Lookup order:
//  1. Case-insensitive exact code match (handles ECDHE, SHA384, etc.)
//  2. Normalize the component (strip mode suffix, remove hyphens) and retry
//     (handles AES-256-GCM → AES256, CHACHA20-POLY1305 → ChaCha20, etc.)
//
// Returns nil without error if no matching row exists; that component is simply
// represented as unassessed rather than silently counted as healthy.
func (s *ExternalConnectionsService) resolveAlgorithmForComponent(parsed string) (*Algorithm, error) {
	if strings.TrimSpace(parsed) == "" {
		return nil, nil
	}

	alg, err := s.algorithms.GetAlgorithmByCodeCI(parsed)
	if err != nil {
		return nil, err
	}
	if alg != nil {
		return alg, nil
	}

	normalized := normalizeCipherComponent(parsed)
	if normalized == parsed {
		return nil, nil
	}
	return s.algorithms.GetAlgorithmByCodeCI(normalized)
}

// assessCrypto evaluates the cipher suite and protocol against the algorithms
// table and returns (cryptoStrength, isPQCResistant, parsedKEX, weakReasons,
// hygieneFlags). weakReasons drives crypto_strength and reflects ONLY
// protocol version, cipher suite, key exchange, key size and signature
// algorithm — the things the algorithms catalogue rates (CLAUDE.md "Crypto
// Assessment Source of Truth"). Certificate-hygiene observations (CT logging,
// chain trust, missing Subject DN) are returned separately in hygieneFlags
// and never influence crypto_strength — see assessCertHygiene.
func (s *ExternalConnectionsService) assessCrypto(input models.ExternalConnectionUpsert) (rating string, isPQC bool, kex string, weakReasons []string, hygieneFlags []string) {
	hygieneFlags = assessCertHygiene(input)
	hygieneFlags = append(hygieneFlags, assessCertValidationStatus(input)...)
	hygieneFlags = append(hygieneFlags, assessSensorCertFlags(input)...)
	var values []string
	if input.CipherSuite == nil && input.KeyExchangeAlgorithm == nil && input.CertPublicKeyAlgorithm == nil && input.CertSignatureAlgorithm == nil {
		values = append(values, "")
	}
	add := func(code, role string) {
		if strings.TrimSpace(code) == "" {
			return
		}
		var alg *Algorithm
		if s.algorithms != nil {
			alg, _ = s.resolveAlgorithmForComponent(code)
		}
		if alg == nil {
			values = append(values, "")
			return
		}
		values = append(values, alg.Strength)
		if alg.Strength == "weak" {
			weakReasons = append(weakReasons, fmt.Sprintf("Weak %s: %s", role, code))
		}
		if alg.IsPQC && alg.PQCStandardizationStatus == "standardized" {
			isPQC = true
		}
	}
	value := func(v *string) string {
		if v == nil {
			return ""
		}
		return *v
	}
	if input.ProtocolVersion != nil {
		code := externalProtocolCode(input.Protocol, *input.ProtocolVersion)
		add(code, "protocol version")
	}
	for _, v := range input.SupportedTLSVersions {
		code := externalProtocolCode(input.Protocol, v)
		add(code, "offered protocol version")
	}
	if input.CipherSuite != nil && strings.TrimSpace(*input.CipherSuite) != "" {
		components, _ := cryptoparse.ParseCipherSuite(*input.CipherSuite)
		// A whole-suite row contributes, but never short-circuits the individual
		// components or an explicitly observed key/certificate below.
		var suite *Algorithm
		if s.algorithms != nil {
			suite, _ = s.algorithms.GetAlgorithmByCodeCI(*input.CipherSuite)
		}
		if suite != nil {
			add(*input.CipherSuite, "cipher suite")
		} else if components == nil {
			values = append(values, "")
		}
		if components != nil {
			kex = components.KeyExchange
			for _, part := range []struct{ code, role string }{{components.KeyExchange, "key exchange"}, {components.Signature, "signature"}, {components.Symmetric, "symmetric"}, {components.Hash, "hash"}} {
				if part.role == "signature" && cryptoparse.KeyAlgorithmFamily(part.code) == cryptoparse.KexFamilyFiniteField {
					// RSA authentication is a certificate key, not static RSA
					// key transport. Only a measured matching leaf key can
					// resolve this inferred role through the sized-key path.
					if input.CertPublicKeyAlgorithm == nil || !strings.EqualFold(part.code, *input.CertPublicKeyAlgorithm) || input.CertPublicKeySize == nil {
						values = append(values, "")
					}
					continue
				}
				add(part.code, part.role)
			}
		}
	}
	add(value(input.KeyExchangeAlgorithm), "observed key exchange")
	if input.KeyExchangeAlgorithm == nil && kex != "" {
		input.KeyExchangeAlgorithm = &kex
	}
	if input.CertPublicKeyAlgorithm != nil {
		key := *input.CertPublicKeyAlgorithm
		if cryptoparse.KeyAlgorithmFamily(key) == cryptoparse.KexFamilyFiniteField {
			var alg *Algorithm
			if input.CertPublicKeySize != nil && s.algorithms != nil {
				alg, _ = s.algorithms.GetAlgorithmByCodeCI(fmt.Sprintf("%s-%d", strings.ToUpper(key), *input.CertPublicKeySize))
			}
			if alg != nil {
				add(alg.Code, "certificate public key")
			} else {
				// A bare RSA key-transport row is not a certificate-key assessment.
				if s.algorithms != nil {
					alg, _ = s.resolveAlgorithmForComponent(key)
				}
				if alg != nil && alg.Category != "key_exchange" {
					add(alg.Code, "certificate public key")
				} else {
					values = append(values, "")
				}
			}
		} else {
			add(key, "certificate public key")
		}
	}
	add(value(input.CertSignatureAlgorithm), "certificate signature")
	if isWeakProtocol(input.Protocol, input.ProtocolVersion) {
		weakReasons = append(weakReasons, "Weak protocol: "+input.Protocol+" "+value(input.ProtocolVersion))
	}
	if hasWeakTLSVersion(input.SupportedTLSVersions) {
		weakReasons = append(weakReasons, "Server accepts legacy TLS: "+strings.Join(legacyTLSVersions(input.SupportedTLSVersions), ", "))
	}
	weakReasons = append(weakReasons, s.assessKeyExchangeSize(input)...)
	weakReasons = append(weakReasons, assessCertPublicKeySize(input)...)
	weakReasons = append(weakReasons, assessCertSignatureAlgorithm(input)...)
	for _, key := range []struct {
		alg  *string
		bits *int
	}{{input.KeyExchangeAlgorithm, input.KeySize}, {input.CertPublicKeyAlgorithm, input.CertPublicKeySize}} {
		if key.alg != nil && (key.bits == nil || *key.bits <= 0) {
			family := cryptoparse.KeyAlgorithmFamily(*key.alg)
			if family == cryptoparse.KexFamilyFiniteField || family == cryptoparse.KexFamilyEllipticCurve {
				values = append(values, "")
			}
		}
	}
	if len(weakReasons) > 0 {
		return "weak", isPQC, kex, weakReasons, hygieneFlags
	}
	rating, complete := cryptostrength.Weakest(values...)
	if !complete {
		rating = ""
	}
	return rating, isPQC, kex, weakReasons, hygieneFlags
}

// assessKeyExchangeSize checks the key exchange key size against NIST thresholds.
// Returns weak reasons for sub-standard key sizes on DH and RSA key exchanges.
func (s *ExternalConnectionsService) assessKeyExchangeSize(input models.ExternalConnectionUpsert) []string {
	if input.KeyExchangeAlgorithm == nil || input.KeySize == nil {
		return nil
	}
	if severity := cryptoparse.WeakKeySizeSeverity(*input.KeyExchangeAlgorithm, *input.KeySize); severity != "" {
		label := "Weak"
		if severity == cryptoparse.SeverityCritical {
			label = "Critical"
		}
		return []string{fmt.Sprintf(label+" key exchange: %s %d-bit key is below the NIST SP 800-131A floor", *input.KeyExchangeAlgorithm, *input.KeySize)}
	}
	return nil
}

// legacyTLSVersions extracts the weak versions from a supported versions list.
func legacyTLSVersions(versions []string) []string {
	var legacy []string
	for _, v := range versions {
		if isLegacyProtocolVersion(v) {
			legacy = append(legacy, v)
		}
	}
	return legacy
}

// assessCertPublicKeySize checks the certificate's public key size against NIST thresholds.
func assessCertPublicKeySize(input models.ExternalConnectionUpsert) []string {
	if input.CertPublicKeyAlgorithm == nil || input.CertPublicKeySize == nil {
		return nil
	}
	if severity := cryptoparse.WeakKeySizeSeverity(*input.CertPublicKeyAlgorithm, *input.CertPublicKeySize); severity != "" {
		label := "Weak"
		if severity == cryptoparse.SeverityCritical {
			label = "Critical"
		}
		return []string{fmt.Sprintf(label+" certificate public key: %s %d bits is below the NIST SP 800-131A floor", *input.CertPublicKeyAlgorithm, *input.CertPublicKeySize)}
	}
	return nil
}

func assessCertSignatureAlgorithm(input models.ExternalConnectionUpsert) []string {
	if input.CertSignatureAlgorithm != nil && cryptoparse.WeakHashSeverity(*input.CertSignatureAlgorithm) != "" {
		name := *input.CertSignatureAlgorithm
		if cryptoparse.WeakHashSeverity(name) == cryptoparse.SeverityHigh {
			name = "SHA-1 (" + name + ")"
		}
		return []string{"Weak certificate signature hash: " + name}
	}
	return nil
}

// assessCertValidationStatus reports certificate trust issues as hygiene.
//
// "untrusted_ca" and "incomplete_chain" are deliberately NOT here: neither
// says anything about protocol version, cipher suite, key exchange, key size
// or signature algorithm — the things crypto_strength must reflect (CLAUDE.md
// "Crypto Assessment Source of Truth"). A service that pins its own CA (e.g.
// Signal) validates as "untrusted_ca" even over TLS 1.3/AES-256-GCM, and
// counting that as "weak crypto" is exactly the bug this split fixes. Those
// two are certificate-HYGIENE observations, reported separately by
// assessCertHygiene so the information isn't lost — just not conflated with
// cryptographic weakness.
func assessCertValidationStatus(input models.ExternalConnectionUpsert) []string {
	if input.CertValidationStatus == nil {
		return nil
	}
	status := strings.ToLower(strings.TrimSpace(*input.CertValidationStatus))
	if status == "" || status == "valid" {
		return nil
	}

	var reasons []string
	switch status {
	case "self_signed":
		reasons = append(reasons, "Certificate is self-signed (not issued by a trusted CA)")
	case "expired":
		reasons = append(reasons, "Certificate has expired or is not yet valid")
	case "hostname_mismatch":
		reasons = append(reasons, "Certificate hostname does not match the server")
	case "revoked":
		reasons = append(reasons, "Certificate has been revoked")
	case "untrusted_ca", "incomplete_chain":
		// Certificate hygiene, not crypto weakness — see assessCertHygiene.
	default:
		reasons = append(reasons, fmt.Sprintf("Certificate validation issue: %s", status))
	}
	return reasons
}

// assessCertHygiene reports certificate-hygiene observations: signals that
// affect confidence in the certificate chain (CT logging, a self-issued or
// pinned trust root, an incomplete chain, a missing Subject DN) but say
// nothing about cryptographic strength — protocol version, cipher suite, key
// exchange, key size, signature algorithm (the things the algorithms
// catalogue rates). These are recorded on CertHygieneFlags, separate from
// WeakReasons/CryptoStrength, so a TLS 1.3 / AES-256-GCM connection with a
// missing SCT is not counted as "weak crypto" on the dashboard (CLAUDE.md
// "Certificate quality flags" / "Crypto Assessment Source of Truth").
func assessCertHygiene(input models.ExternalConnectionUpsert) []string {
	var flags []string

	if input.CertHasSCT != nil && !*input.CertHasSCT {
		flags = append(flags, "Certificate missing Signed Certificate Timestamps (SCTs) — not logged in Certificate Transparency")
	}

	if input.CertNoSubject {
		flags = append(flags, "Certificate has no Subject DN")
	} else if input.CertNoCommonName {
		flags = append(flags, "Certificate has no Common Name in Subject DN")
	}

	if input.CertValidationStatus != nil {
		switch strings.ToLower(strings.TrimSpace(*input.CertValidationStatus)) {
		case "untrusted_ca":
			flags = append(flags, "Certificate signed by an untrusted certificate authority (not in the system trust store — may be a private or pinned CA)")
		case "incomplete_chain":
			flags = append(flags, "Incomplete certificate chain (missing intermediate certificates)")
		}
	}

	return flags
}

// assessSensorCertFlags checks sensor-level certificate quality flags that
// indicate genuine risk — a known-malicious CA in the chain, OCSP-confirmed
// revocation — and produces weak_reasons for issues the structured field
// checks above can't detect. Certificate-hygiene flags (missing SCT, no
// Subject DN, untrusted/pinned CA, incomplete chain) are handled by
// assessCertHygiene instead; they are not cryptographic weakness.
func assessSensorCertFlags(input models.ExternalConnectionUpsert) []string {
	var reasons []string

	if input.CertKnownBadCA != nil && *input.CertKnownBadCA != "" {
		reasons = append(reasons, fmt.Sprintf("Critical: certificate chain includes known-bad CA: %s", *input.CertKnownBadCA))
	}

	if input.OCSPStatus != nil && *input.OCSPStatus == "revoked" {
		vs := ""
		if input.CertValidationStatus != nil {
			vs = strings.ToLower(strings.TrimSpace(*input.CertValidationStatus))
		}
		if vs != "revoked" {
			reasons = append(reasons, "Certificate has been revoked (OCSP)")
		}
	}

	return reasons
}

// isWeakProtocol returns true if the protocol version is known-weak (SSLv2/3, TLS 1.0/1.1).
// IKE is handled as a protocol name (not "IPsec/IKE") — no SSL check needed.
func isWeakProtocol(protocol string, version *string) bool {
	p := strings.ToUpper(strings.TrimSpace(protocol))
	if strings.Contains(p, "SSL") {
		return true
	}
	// The version half is compared through the shared fold, not against a bare
	// "1.0": every producer writes the spaced "TLS 1.0", so the old literal
	// comparison never matched a stored value and the "weak protocol" reason
	// never appeared on any external connection.
	if p == "TLS" && version != nil {
		return isLegacyProtocolVersion(*version)
	}
	return false
}

// hasWeakTLSVersion returns true if the enumerated supported TLS versions list
// contains any weak version (TLS 1.0, TLS 1.1, or any SSL variant). This catches
// servers that negotiate TLS 1.2+ but still accept legacy versions.
func hasWeakTLSVersion(versions []string) bool {
	for _, v := range versions {
		if isLegacyProtocolVersion(v) {
			return true
		}
	}
	return false
}

// determineChangeType figures out what kind of history row to write.
// Returns (changeType, shouldRecord).
func (s *ExternalConnectionsService) determineChangeType(
	isNew bool,
	prevCipher, prevProto, prevStrength string, prevIsPQC bool,
	prevFingerprint string, prevCertNotAfter sql.NullTime,
	conn *models.ExternalConnection,
) (string, bool) {
	if isNew {
		return "first_seen", true
	}

	// Cert rotation: fingerprint changed and we have a new one
	newFP := ""
	if conn.CertFingerprintSHA256 != nil {
		newFP = *conn.CertFingerprintSHA256
	}
	if newFP != "" && prevFingerprint != "" && newFP != prevFingerprint {
		return "cert_rotated", true
	}

	// Cipher suite changed
	newCS := ""
	if conn.CipherSuite != nil {
		newCS = *conn.CipherSuite
	}
	if newCS != "" && prevCipher != "" && newCS != prevCipher {
		return "cipher_changed", true
	}

	// Protocol version changed
	newPV := ""
	if conn.ProtocolVersion != nil {
		newPV = *conn.ProtocolVersion
	}
	if newPV != "" && prevProto != "" && newPV != prevProto {
		if isVersionUpgrade(prevProto, newPV) {
			return "protocol_upgraded", true
		}
		return "protocol_downgraded", true
	}

	// Crypto strength changed
	if stringValue(conn.Strength) != prevStrength {
		return "crypto_strength_changed", true
	}

	return "", false
}

// isVersionUpgrade returns true if newVersion is numerically higher than prevVersion.
func isVersionUpgrade(prev, next string) bool {
	parseTLSVer := func(v string) float64 {
		v = strings.TrimPrefix(strings.ToUpper(v), "TLS")
		v = strings.TrimSpace(v)
		var f float64
		_, _ = fmt.Sscanf(v, "%f", &f)
		return f
	}
	return parseTLSVer(next) > parseTLSVer(prev)
}

// List returns paginated external connections for the tenant.
func (s *ExternalConnectionsService) List(tenantID uuid.UUID, f models.ExternalConnectionFilters) ([]models.ExternalConnection, int, error) {
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 {
		f.PageSize = 20
	}
	if f.PageSize > 100 {
		f.PageSize = 100
	}
	if f.SortOrder != "asc" && f.SortOrder != "desc" {
		f.SortOrder = "desc"
	}
	sortCol := "last_seen_at"
	switch f.SortBy {
	case "strength":
		sortCol = externalStrengthSortSQL()
	case "last_seen_at", "dest_hostname", "dest_ip", "source_ip", "protocol", "observation_count":
		sortCol = f.SortBy
	}
	sortOrder := "DESC"
	if strings.ToUpper(f.SortOrder) == "ASC" {
		sortOrder = "ASC"
	}

	if f.SortBy == "strength" {
		sortOrder += " NULLS LAST, id"
	}

	args := []interface{}{tenantID}
	argIdx := 2
	where := []string{"tenant_id = $1"}

	if f.Search != "" {
		where = append(where, fmt.Sprintf("(dest_hostname ILIKE $%d OR dest_ip::text ILIKE $%d)", argIdx, argIdx))
		args = append(args, "%"+f.Search+"%")
		argIdx++
	}
	if f.Strength == "unassessed" {
		where = append(where, "crypto_strength IS NULL")
	} else if f.Strength != "" {
		where = append(where, fmt.Sprintf("crypto_strength = $%d", argIdx))
		args = append(args, f.Strength)
		argIdx++
	}
	if f.IsPQCResistant != nil {
		where = append(where, fmt.Sprintf("is_pqc_resistant = $%d", argIdx))
		args = append(args, *f.IsPQCResistant)
		argIdx++
	}
	if f.CertExpired != nil {
		where = append(where, fmt.Sprintf("cert_is_expired = $%d", argIdx))
		args = append(args, *f.CertExpired)
		argIdx++
	}
	if f.CertTrustIssue != nil && *f.CertTrustIssue {
		where = append(where, "(cert_validation_status IS NOT NULL AND LOWER(TRIM(cert_validation_status)) <> 'valid')")
	}
	if f.HasLegacyTLS != nil && *f.HasLegacyTLS {
		where = append(where, legacyTLSVersionsArraySQL("supported_tls_versions"))
	}
	if f.SourceAssetID != nil {
		where = append(where, fmt.Sprintf("source_asset_id = $%d", argIdx))
		args = append(args, *f.SourceAssetID)
		argIdx++
	}

	whereSQL := strings.Join(where, " AND ")
	offset := (f.Page - 1) * f.PageSize

	// Snapshot the count args before pagination params are appended; the count
	// and the page run together inside one tenant tx below.
	countArgs := append([]interface{}{}, args...)

	args = append(args, f.PageSize, offset)
	listSQL := fmt.Sprintf(`
		SELECT
			id, tenant_id,
			source_ip::text, source_hostname, source_asset_id,
			dest_ip::text, dest_hostname, dest_port,
			protocol, protocol_version, cipher_suite, key_exchange_algorithm, key_size,
			supported_tls_versions,
			crypto_strength, is_pqc_resistant, weak_reasons, cert_hygiene_flags,
			cert_subject, cert_issuer, cert_san,
			cert_not_before, cert_not_after, cert_fingerprint_sha256,
			cert_public_key_algorithm, cert_public_key_size, cert_signature_algorithm,
			cert_is_expired, cert_validation_status, cert_sct_source, cert_pem,
			first_seen_at, last_seen_at, observation_count, sensor_id,
			created_at, updated_at, elevated_asset_id
		FROM external_connections
		WHERE %s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d`,
		whereSQL, sortCol, sortOrder, argIdx, argIdx+1)

	// RLS-scoped reads over external_connections — count + page in one tenant tx.
	var total int
	var list []models.ExternalConnection
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		if e := tx.QueryRow("SELECT COUNT(*) FROM external_connections WHERE "+whereSQL, countArgs...).Scan(&total); e != nil {
			return fmt.Errorf("count external connections: %w", e)
		}

		rows, e := tx.Query(listSQL, args...)
		if e != nil {
			return fmt.Errorf("list external connections: %w", e)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var conn models.ExternalConnection
			var certSAN pq.StringArray
			var scanSTV pq.StringArray
			var scanWR pq.StringArray
			var scanCHF pq.StringArray
			if e := rows.Scan(
				&conn.ID, &conn.TenantID,
				&conn.SourceIP, &conn.SourceHostname, &conn.SourceAssetID,
				&conn.DestIP, &conn.DestHostname, &conn.DestPort,
				&conn.Protocol, &conn.ProtocolVersion, &conn.CipherSuite, &conn.KeyExchangeAlgorithm, &conn.KeySize,
				&scanSTV,
				&conn.Strength, &conn.IsPQCResistant, &scanWR, &scanCHF,
				&conn.CertSubject, &conn.CertIssuer, &certSAN,
				&conn.CertNotBefore, &conn.CertNotAfter, &conn.CertFingerprintSHA256,
				&conn.CertPublicKeyAlgorithm, &conn.CertPublicKeySize, &conn.CertSignatureAlgorithm,
				&conn.CertIsExpired, &conn.CertValidationStatus, &conn.CertSCTSource, &conn.CertPEM,
				&conn.FirstSeenAt, &conn.LastSeenAt, &conn.ObservationCount, &conn.SensorID,
				&conn.CreatedAt, &conn.UpdatedAt, &conn.ElevatedAssetID,
			); e != nil {
				return fmt.Errorf("scan external connection: %w", e)
			}
			if len(certSAN) > 0 {
				conn.CertSAN = []string(certSAN)
			}
			if len(scanSTV) > 0 {
				conn.SupportedTLSVersions = []string(scanSTV)
			}
			if len(scanWR) > 0 {
				conn.WeakReasons = []string(scanWR)
			}
			if len(scanCHF) > 0 {
				conn.CertHygieneFlags = []string(scanCHF)
			}
			list = append(list, conn)
		}
		if e := rows.Err(); e != nil {
			return fmt.Errorf("rows error: %w", e)
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return list, total, nil
}

// GetByID retrieves a single external connection.
func (s *ExternalConnectionsService) GetByID(tenantID, id uuid.UUID) (*models.ExternalConnection, error) {
	var conn models.ExternalConnection
	var certSAN pq.StringArray
	var scanSTV pq.StringArray
	var scanWR pq.StringArray
	var scanCHF pq.StringArray
	// RLS-scoped read over external_connections — WithTenantTx returns fn's error
	// verbatim, so the sql.ErrNoRows check below still works.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`
			SELECT
				id, tenant_id,
				-- host(), not ::text. An inet renders as 203.0.113.40/32, and
				-- that is NOT an IP address: identity normalisation rejects it,
				-- so an elevated connection was created with no ip_address
				-- identifier at all — the one identifier that would let the next
				-- sighting of that endpoint match it instead of minting a
				-- duplicate beside it. The rejection was logged and dropped, so
				-- nothing surfaced.
				host(source_ip), source_hostname, source_asset_id,
				host(dest_ip), dest_hostname, dest_port,
				protocol, protocol_version, cipher_suite, key_exchange_algorithm, key_size,
				supported_tls_versions,
				crypto_strength, is_pqc_resistant, weak_reasons, cert_hygiene_flags,
				cert_subject, cert_issuer, cert_san,
				cert_not_before, cert_not_after, cert_fingerprint_sha256,
				cert_public_key_algorithm, cert_public_key_size, cert_signature_algorithm,
				cert_is_expired, cert_validation_status, cert_sct_source, cert_pem,
				first_seen_at, last_seen_at, observation_count, sensor_id,
				created_at, updated_at, elevated_asset_id
			FROM external_connections
			WHERE id = $1 AND tenant_id = $2`,
			id, tenantID,
		).Scan(
			&conn.ID, &conn.TenantID,
			&conn.SourceIP, &conn.SourceHostname, &conn.SourceAssetID,
			&conn.DestIP, &conn.DestHostname, &conn.DestPort,
			&conn.Protocol, &conn.ProtocolVersion, &conn.CipherSuite, &conn.KeyExchangeAlgorithm, &conn.KeySize,
			&scanSTV,
			&conn.Strength, &conn.IsPQCResistant, &scanWR, &scanCHF,
			&conn.CertSubject, &conn.CertIssuer, &certSAN,
			&conn.CertNotBefore, &conn.CertNotAfter, &conn.CertFingerprintSHA256,
			&conn.CertPublicKeyAlgorithm, &conn.CertPublicKeySize, &conn.CertSignatureAlgorithm,
			&conn.CertIsExpired, &conn.CertValidationStatus, &conn.CertSCTSource, &conn.CertPEM,
			&conn.FirstSeenAt, &conn.LastSeenAt, &conn.ObservationCount, &conn.SensorID,
			&conn.CreatedAt, &conn.UpdatedAt, &conn.ElevatedAssetID,
		)
	})
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get external connection by id: %w", err)
	}
	if len(certSAN) > 0 {
		conn.CertSAN = []string(certSAN)
	}
	if len(scanSTV) > 0 {
		conn.SupportedTLSVersions = []string(scanSTV)
	}
	if len(scanWR) > 0 {
		conn.WeakReasons = []string(scanWR)
	}
	if len(scanCHF) > 0 {
		conn.CertHygieneFlags = []string(scanCHF)
	}
	return &conn, nil
}

// MarkElevated links a 3rd-party connection to the managed asset a tenant
// elevated it into. Tenant-scoped; returns an error if no row matched.
func (s *ExternalConnectionsService) MarkElevated(tenantID, connID, assetID uuid.UUID) error {
	// RLS-scoped write over external_connections.
	var rowsAffected int64
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		res, e := tx.Exec(
			`UPDATE external_connections SET elevated_asset_id = $1, updated_at = NOW()
			 WHERE id = $2 AND tenant_id = $3`,
			assetID, connID, tenantID)
		if e != nil {
			return e
		}
		rowsAffected, _ = res.RowsAffected()
		return nil
	})
	if err != nil {
		return fmt.Errorf("mark connection elevated: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("external connection %s not found", connID)
	}
	return nil
}

// GetHistory returns paginated history for a single external connection.
func (s *ExternalConnectionsService) GetHistory(tenantID, connectionID uuid.UUID, page, pageSize int) ([]models.ExternalConnectionHistory, int, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 20
	}

	offset := (page - 1) * pageSize

	// RLS-scoped reads over external_connection_history — count + page in one tenant tx.
	var total int
	var history []models.ExternalConnectionHistory
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		if e := tx.QueryRow(
			`SELECT COUNT(*) FROM external_connection_history WHERE external_connection_id = $1 AND tenant_id = $2`,
			connectionID, tenantID,
		).Scan(&total); e != nil {
			return fmt.Errorf("count history: %w", e)
		}

		rows, e := tx.Query(`
			SELECT
				id, external_connection_id, tenant_id, change_type,
				previous_protocol_version, previous_cipher_suite, previous_crypto_strength,
				previous_is_pqc_resistant, previous_cert_fingerprint_sha256, previous_cert_not_after,
				new_protocol_version, new_cipher_suite, new_crypto_strength,
				new_is_pqc_resistant, new_cert_fingerprint_sha256, new_cert_not_after,
                strength_vocabulary_version, created_at
			FROM external_connection_history
			WHERE external_connection_id = $1 AND tenant_id = $2
			ORDER BY created_at DESC
			LIMIT $3 OFFSET $4`,
			connectionID, tenantID, pageSize, offset,
		)
		if e != nil {
			return fmt.Errorf("list history: %w", e)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var h models.ExternalConnectionHistory
			if e := rows.Scan(
				&h.ID, &h.ExternalConnectionID, &h.TenantID, &h.ChangeType,
				&h.PreviousProtocolVersion, &h.PreviousCipherSuite, &h.PreviousStrength,
				&h.PreviousIsPQCResistant, &h.PreviousCertFingerprintSHA256, &h.PreviousCertNotAfter,
				&h.NewProtocolVersion, &h.NewCipherSuite, &h.NewStrength,
				&h.NewIsPQCResistant, &h.NewCertFingerprintSHA256, &h.NewCertNotAfter,
				&h.StrengthVocabularyVersion, &h.CreatedAt,
			); e != nil {
				return fmt.Errorf("scan history: %w", e)
			}
			if h.StrengthVocabularyVersion != 2 {
				h.PreviousStrengthLegacy, h.NewStrengthLegacy = h.PreviousStrength, h.NewStrength
				h.PreviousStrength, h.NewStrength = nil, nil
			}
			history = append(history, h)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, err
	}
	return history, total, nil
}

// GetSummary returns aggregate counts for the summary card row.
func (s *ExternalConnectionsService) GetSummary(tenantID uuid.UUID) (*models.ExternalConnectionsSummary, error) {
	var summary models.ExternalConnectionsSummary
	// RLS-scoped read over external_connections.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`
			SELECT
				COUNT(*) AS total,
				COUNT(*) FILTER (WHERE crypto_strength = 'weak') AS weak_crypto,
				COUNT(*) FILTER (WHERE (crypto_strength IS NULL AND cardinality(weak_reasons)>0)
					OR $2 = ANY(weak_reasons) OR $3 = ANY(weak_reasons)) AS reassessment_required,
				COUNT(*) FILTER (WHERE is_pqc_resistant = true) AS pqc_resistant,
				COUNT(*) FILTER (WHERE cert_is_expired = true) AS expired_certs,
				COUNT(*) FILTER (WHERE `+legacyTLSVersionsArraySQL("supported_tls_versions")+`) AS legacy_tls,
				COUNT(DISTINCT source_ip) AS source_hosts
			FROM external_connections
			WHERE tenant_id = $1`,
			tenantID, externalReassessmentReason, externalKeySizeRoleReason,
		).Scan(&summary.Total, &summary.WeakCrypto, &summary.ReassessmentRequired, &summary.PQCResistant, &summary.ExpiredCerts, &summary.LegacyTLS, &summary.SourceHosts)
	})
	if err != nil {
		return nil, fmt.Errorf("get external connections summary: %w", err)
	}
	return &summary, nil
}

// Delete hard-deletes an external connection (history cascades via FK).
func (s *ExternalConnectionsService) Delete(tenantID, id uuid.UUID) error {
	// RLS-scoped delete over external_connections (history cascades via FK).
	var rowsAffected int64
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		result, e := tx.Exec(
			`DELETE FROM external_connections WHERE id = $1 AND tenant_id = $2`,
			id, tenantID,
		)
		if e != nil {
			return e
		}
		rowsAffected, _ = result.RowsAffected()
		return nil
	})
	if err != nil {
		return fmt.Errorf("delete external connection: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("external connection not found")
	}
	return nil
}
