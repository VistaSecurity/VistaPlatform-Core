// Package services: crypto implementation and library queries.
package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// GetCryptoImplementations retrieves crypto configurations for an asset.
func (s *AssetService) GetCryptoImplementations(tenantID, assetID uuid.UUID) ([]models.CryptoImplementation, error) {
	query := `
		SELECT
			id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
			key_exchange_algorithm, signature_algorithm, symmetric_encryption,
			hash_algorithm, key_size, certificate_id, discovery_method,
			confidence_score, source_sensor_id, raw_data, risk_score,
			compliance_status, first_discovered_at, last_verified_at,
			created_at, updated_at, deleted_at
		FROM crypto_implementations
		WHERE asset_id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		ORDER BY risk_score DESC, created_at DESC
	`
	var cryptoImpls []models.CryptoImplementation
	// RLS-scoped read over crypto_implementations.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.Select(&cryptoImpls, query, assetID, tenantID)
	}); err != nil {
		return nil, fmt.Errorf("failed to get crypto implementations: %w", err)
	}
	for i := range cryptoImpls {
		riskScore := 0
		if cryptoImpls[i].RiskScore != nil {
			riskScore = *cryptoImpls[i].RiskScore
		}
		cryptoImpls[i].RiskLevel = models.GetRiskLevel(riskScore)
		cryptoImpls[i].RiskFactors = s.AnalyzeCryptoRisk(&cryptoImpls[i])
	}
	if err := enrichCryptoImplementationsWithRelations(s.db, tenantID, cryptoImpls); err != nil {
		return nil, err
	}
	return cryptoImpls, nil
}

// legacyTLSVersionsFromRawData pulls the enumerated accepted-version list out
// of a crypto configuration's raw_data and returns just the legacy entries, in
// the spelling they were observed in.
//
// The value arrives as a JSON array, so after a JSONB scan it is
// []interface{} of strings; a []string is accepted too for callers that build
// the map in Go. Anything else yields no versions rather than an error — a
// missing or malformed enumeration means "not measured", never "clean".
func legacyTLSVersionsFromRawData(raw models.JSONB) []string {
	if raw == nil {
		return nil
	}
	var observed []string
	switch v := raw["tls_versions"].(type) {
	case []string:
		observed = v
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				observed = append(observed, s)
			}
		}
	default:
		return nil
	}
	var legacy []string
	for _, ver := range observed {
		if isLegacyProtocolVersion(ver) {
			legacy = append(legacy, ver)
		}
	}
	return legacy
}

// AnalyzeCryptoRisk analyzes crypto configuration and returns risk factors.
func (s *AssetService) AnalyzeCryptoRisk(crypto *models.CryptoImplementation) []string {
	var riskFactors []string
	if crypto.CipherSuite != nil {
		cipherSuite := strings.ToUpper(*crypto.CipherSuite)
		if strings.Contains(cipherSuite, "RC4") || strings.Contains(cipherSuite, "DES") || strings.Contains(cipherSuite, "MD5") {
			riskFactors = append(riskFactors, "Weak cipher suite")
		}
	}
	if crypto.ProtocolVersion != nil {
		version := *crypto.ProtocolVersion
		switch crypto.Protocol {
		case "TLS":
			// Folded comparison, not `version < "1.2"`: producers write the
			// spaced "TLS 1.0", and "TLS 1.0" < "1.2" is false in Go's byte
			// ordering, so the lexicographic test never fired for any value
			// actually stored.
			if isLegacyProtocolVersion(version) {
				riskFactors = append(riskFactors, "Outdated TLS version")
			}
		case "SSH":
			if version < "2.0" {
				riskFactors = append(riskFactors, "Outdated SSH version")
			}
		}
	}
	// The enumerated accepted-version set is what catches a server that
	// negotiates TLS 1.3 but still ACCEPTS TLS 1.0/1.1. Both probing runtimes
	// write it into raw_data as "tls_versions"; the external-connection path
	// already scores it (hasWeakTLSVersion), the managed-asset path read it
	// nowhere.
	if legacy := legacyTLSVersionsFromRawData(crypto.RawData); len(legacy) > 0 {
		riskFactors = append(riskFactors, "Server accepts legacy TLS: "+strings.Join(legacy, ", "))
	}
	if crypto.KeySize != nil && *crypto.KeySize < 2048 {
		riskFactors = append(riskFactors, "Weak key size")
	}
	if crypto.HashAlgorithm != nil {
		hash := strings.ToUpper(*crypto.HashAlgorithm)
		if strings.Contains(hash, "MD5") || strings.Contains(hash, "SHA1") {
			riskFactors = append(riskFactors, "Weak hash algorithm")
		}
	}
	if crypto.ConfidenceScore != nil && *crypto.ConfidenceScore < 70 {
		riskFactors = append(riskFactors, "Low confidence detection")
	}
	return riskFactors
}

// keyColumns is the canonical select list for key reads, shared by the list and
// single-key queries so they can't drift. keyDeploymentCountSubquery is appended
// separately (it references the outer `keys` row). Columns are qualified with
// `keys.` because the reads LEFT JOIN `algorithms` (ambiguous id/created_at).
// algorithm_ref is the joined algorithm name and secured_by is the schema's
// secured_by_mechanism — both aliased back to the field names the model/frontend
// expect (the `keys` table has no algorithm_ref/secured_by columns).
const keyColumns = `keys.id, keys.tenant_id, keys.key_type, keys.key_usage, keys.public_fingerprint, keys.jwk_thumbprint, keys.size_bits, keys.curve, keys.created_at, keys.rotated_at, keys.expires_at, keys.provenance, keys.metadata, keys.material_type, keys.state, keys.state_reason, keys.format, alg.name AS algorithm_ref, keys.secured_by_mechanism AS secured_by, keys.activation_date, keys.deactivation_date, keys.destruction_date`

// keyJoin resolves the algorithm name for algorithm_ref. LEFT JOIN so keys with
// a NULL algorithm_id (or none) still return.
const keyJoin = ` LEFT JOIN algorithms alg ON alg.id = keys.algorithm_id`

// keyDeploymentCountSubquery counts the distinct non-deleted assets that use a
// key via implementation_keys → crypto_implementations. Mirrors the certificate
// deployment_count pattern so the Keys lens can show "used by N assets" /
// "Unlinked" without a second round-trip per key.
const keyDeploymentCountSubquery = `
	(SELECT COUNT(DISTINCT ci.asset_id)
	   FROM implementation_keys ik
	   JOIN crypto_implementations ci ON ci.id = ik.implementation_id
	   JOIN network_assets na ON na.id = ci.asset_id
	  WHERE ik.key_id = keys.id
	    AND ci.tenant_id = keys.tenant_id
	    AND ci.deleted_at IS NULL
	    AND na.deleted_at IS NULL) AS deployment_count`

// ListKeys returns keys for a tenant, each annotated with deployment_count.
func (s *AssetService) ListKeys(tenantID uuid.UUID) ([]models.Key, error) {
	query := `SELECT ` + keyColumns + `, ` + keyDeploymentCountSubquery + ` FROM keys` + keyJoin + ` WHERE keys.tenant_id = $1 ORDER BY keys.expires_at ASC NULLS LAST, keys.created_at DESC NULLS LAST`
	var rows []keyListRow
	// RLS-scoped read over keys (LEFT JOIN algorithms; deployment_count subquery over
	// implementation_keys / crypto_implementations / network_assets).
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.Select(&rows, query, tenantID)
	}); err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	keys := make([]models.Key, len(rows))
	for i, r := range rows {
		keys[i] = r.toKey()
	}
	return keys, nil
}

// GetKeyByID returns a single key (with deployment_count) scoped to the tenant.
func (s *AssetService) GetKeyByID(tenantID, keyID uuid.UUID) (*models.Key, error) {
	query := `SELECT ` + keyColumns + `, ` + keyDeploymentCountSubquery + ` FROM keys` + keyJoin + ` WHERE keys.id = $1 AND keys.tenant_id = $2`
	var row keyListRow
	// RLS-scoped read over keys (LEFT JOIN algorithms).
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.Get(&row, query, keyID, tenantID)
	}); err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}
	key := row.toKey()
	return &key, nil
}

// keyListRow scans the keyColumns projection with driver-safe types: key_usage
// (text[]) needs pq.StringArray and metadata (jsonb) needs []byte — sqlx cannot
// scan either directly into models.Key's []string / map[string]interface{}
// fields (it fails "unsupported Scan, storing []uint8 into ..."). Mirrors the
// implementationKeyRow pattern in crypto_implementation_relations.go.
type keyListRow struct {
	ID                uuid.UUID      `db:"id"`
	TenantID          uuid.UUID      `db:"tenant_id"`
	KeyType           string         `db:"key_type"`
	KeyUsage          pq.StringArray `db:"key_usage"`
	PublicFingerprint *string        `db:"public_fingerprint"`
	JWKThumbprint     *string        `db:"jwk_thumbprint"`
	SizeBits          *int           `db:"size_bits"`
	Curve             *string        `db:"curve"`
	CreatedAt         *time.Time     `db:"created_at"`
	RotatedAt         *time.Time     `db:"rotated_at"`
	ExpiresAt         *time.Time     `db:"expires_at"`
	Provenance        *string        `db:"provenance"`
	Metadata          []byte         `db:"metadata"`
	MaterialType      *string        `db:"material_type"`
	State             *string        `db:"state"`
	StateReason       *string        `db:"state_reason"`
	Format            *string        `db:"format"`
	AlgorithmRef      *string        `db:"algorithm_ref"`
	SecuredBy         *string        `db:"secured_by"`
	ActivationDate    *time.Time     `db:"activation_date"`
	DeactivationDate  *time.Time     `db:"deactivation_date"`
	DestructionDate   *time.Time     `db:"destruction_date"`
	DeploymentCount   *int           `db:"deployment_count"`
}

func (r keyListRow) toKey() models.Key {
	k := models.Key{
		ID:                r.ID,
		TenantID:          r.TenantID,
		KeyType:           r.KeyType,
		KeyUsage:          []string(r.KeyUsage),
		PublicFingerprint: r.PublicFingerprint,
		JWKThumbprint:     r.JWKThumbprint,
		SizeBits:          r.SizeBits,
		Curve:             r.Curve,
		CreatedAt:         r.CreatedAt,
		RotatedAt:         r.RotatedAt,
		ExpiresAt:         r.ExpiresAt,
		Provenance:        r.Provenance,
		Metadata:          map[string]interface{}{},
		StateReason:       r.StateReason,
		Format:            r.Format,
		AlgorithmRef:      r.AlgorithmRef,
		SecuredBy:         r.SecuredBy,
		ActivationDate:    r.ActivationDate,
		DeactivationDate:  r.DeactivationDate,
		DestructionDate:   r.DestructionDate,
		DeploymentCount:   r.DeploymentCount,
	}
	if r.MaterialType != nil {
		k.MaterialType = *r.MaterialType
	}
	if r.State != nil {
		k.State = *r.State
	}
	if len(r.Metadata) > 0 {
		_ = json.Unmarshal(r.Metadata, &k.Metadata)
	}
	return k
}

// GetKeyImplementations returns the crypto configurations that reference a key,
// with the asset context the Keys-lens drawer needs to render rows and push the
// asset drawer. Tenant-scoped via the implementation join.
func (s *AssetService) GetKeyImplementations(tenantID, keyID uuid.UUID) ([]models.KeyImplementation, error) {
	query := `
		SELECT ci.id AS implementation_id, ci.asset_id, na.hostname AS asset_hostname,
		       ci.protocol::text AS protocol, ci.protocol_version
		  FROM implementation_keys ik
		  JOIN crypto_implementations ci ON ci.id = ik.implementation_id
		  JOIN network_assets na ON na.id = ci.asset_id
		 WHERE ik.key_id = $1
		   AND ci.tenant_id = $2
		   AND ci.deleted_at IS NULL
		   AND na.deleted_at IS NULL
		 ORDER BY na.hostname ASC NULLS LAST`
	var impls []models.KeyImplementation
	// RLS-scoped read over crypto_implementations / network_assets (JOIN implementation_keys).
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.Select(&impls, query, keyID, tenantID)
	}); err != nil {
		return nil, fmt.Errorf("failed to get key implementations: %w", err)
	}
	return impls, nil
}

// ListLibraries returns crypto libraries for a tenant.
func (s *AssetService) ListLibraries(tenantID uuid.UUID) ([]models.CryptoLibrary, error) {
	query := `SELECT id, tenant_id, name, version, vendor, cpe, build_metadata, known_vulnerabilities, created_at, updated_at, purl, certification_level FROM crypto_libraries WHERE tenant_id = $1`
	var libs []models.CryptoLibrary
	// RLS-scoped read over crypto_libraries.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.Select(&libs, query, tenantID)
	}); err != nil {
		return nil, fmt.Errorf("failed to list libraries: %w", err)
	}
	return libs, nil
}

// GetExternalMappings retrieves external mappings for a local entity.
func (s *AssetService) GetExternalMappings(tenantID uuid.UUID, localType string, localID uuid.UUID) ([]models.ExternalAssetMapping, error) {
	query := `SELECT id, tenant_id, local_type, local_id, external_system, external_id, sync_status, last_synced_at, last_sync_error, created_at, updated_at FROM external_asset_mappings WHERE tenant_id = $1 AND local_type = $2 AND local_id = $3`
	var maps []models.ExternalAssetMapping
	// RLS-scoped read over external_asset_mappings.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.Select(&maps, query, tenantID, localType, localID)
	}); err != nil {
		return nil, fmt.Errorf("failed to get mappings: %w", err)
	}
	return maps, nil
}

// AttachLibrary attaches a library to a crypto configuration.
func (s *AssetService) AttachLibrary(tenantID uuid.UUID, implementationID uuid.UUID, libraryID uuid.UUID) error {
	query := `INSERT INTO implementation_libraries (implementation_id, library_id)
              SELECT $1, $2
              WHERE EXISTS (SELECT 1 FROM crypto_implementations WHERE id = $1 AND tenant_id = $3 AND deleted_at IS NULL)
                AND EXISTS (SELECT 1 FROM crypto_libraries WHERE id = $2 AND tenant_id = $3)`
	// RLS-scoped write over implementation_libraries (guarded by crypto_implementations /
	// crypto_libraries existence subqueries).
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(query, implementationID, libraryID, tenantID)
		return e
	}); err != nil {
		return fmt.Errorf("failed to attach library: %w", err)
	}
	return nil
}

// AttachKey attaches a key to a crypto configuration.
func (s *AssetService) AttachKey(tenantID uuid.UUID, implementationID uuid.UUID, keyID uuid.UUID) error {
	query := `INSERT INTO implementation_keys (implementation_id, key_id)
              SELECT $1, $2
              WHERE EXISTS (SELECT 1 FROM crypto_implementations WHERE id = $1 AND tenant_id = $3 AND deleted_at IS NULL)
                AND EXISTS (SELECT 1 FROM keys WHERE id = $2 AND tenant_id = $3)`
	// RLS-scoped write over implementation_keys (guarded by crypto_implementations /
	// keys existence subqueries).
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(query, implementationID, keyID, tenantID)
		return e
	}); err != nil {
		return fmt.Errorf("failed to attach key: %w", err)
	}
	return nil
}

// CreateLibrary inserts a new crypto library record.
func (s *AssetService) CreateLibrary(tenantID uuid.UUID, input models.CryptoLibrary) (*models.CryptoLibrary, error) {
	if input.Name == "" || input.Version == "" {
		return nil, fmt.Errorf("name and version are required")
	}
	input.TenantID = tenantID
	insert := `INSERT INTO crypto_libraries (tenant_id, name, version, vendor, cpe, build_metadata, known_vulnerabilities)
               VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, created_at, updated_at`
	buildJSON, _ := json.Marshal(input.BuildMetadata)
	vulnsJSON, _ := json.Marshal(input.KnownVulnerabilities)
	// RLS-scoped write over crypto_libraries — WithTenantTx sets app.tenant_id so the
	// INSERT's tenant_id satisfies the policy WITH CHECK.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(insert, tenantID, input.Name, input.Version, input.Vendor, input.CPE, buildJSON, vulnsJSON).Scan(&input.ID, &input.CreatedAt, &input.UpdatedAt)
	}); err != nil {
		return nil, fmt.Errorf("failed to create library: %w", err)
	}
	return &input, nil
}

// derivedCipherColumns holds the per-component values written to the
// crypto_implementations row at ingest. They carry the parser vocabulary
// (catalogue codes — see the vocabulary note in algorithm_service.go), because
// the compliance engine's seeded measurement predicates match these columns
// literally.
type derivedCipherColumns struct {
	// ProtocolVersion is normally the finding's own protocol_version, passed
	// through. SSH is the exception: nothing in an SSH finding carries a
	// protocol_version field, so it is derived from the identification-string
	// banner here rather than staying NULL.
	ProtocolVersion *string
	KeyExchange     *string
	Signature       *string
	Symmetric       *string
	Hash            *string
}

// deriveCipherComponents fills the component columns of a crypto configuration
// from the negotiated cipher suite.
//
// A value the finding states explicitly always wins: the sensor reports the
// real key exchange for TLS 1.3 and for post-quantum/hybrid groups, neither of
// which is derivable from the suite name. Derivation only fills a gap.
func (s *AssetService) deriveCipherComponents(f IngestFinding) derivedCipherColumns {
	out := derivedCipherColumns{
		ProtocolVersion: trimmedOrNil(f.ProtocolVersion),
		KeyExchange:     trimmedOrNil(f.KeyExchangeAlgorithm),
		Hash:            trimmedOrNil(f.HashAlgorithm),
	}

	// SSH carries its components in raw metadata under names nothing else uses,
	// so it fills the gaps before the cipher-suite path (which has nothing to
	// work with for SSH — there is no cipher_suite field). Values the finding
	// stated explicitly still win: only empty slots are filled.
	if obs := sshObservationFromFinding(f); obs.Present {
		sshCols := obs.sshDerivedColumns()
		fillPtr(&out.ProtocolVersion, sshCols.ProtocolVersion)
		fillPtr(&out.KeyExchange, sshCols.KeyExchange)
		fillPtr(&out.Signature, sshCols.Signature)
		fillPtr(&out.Symmetric, sshCols.Symmetric)
		fillPtr(&out.Hash, sshCols.Hash)
	}

	if s.algorithmService == nil || f.CipherSuite == nil || strings.TrimSpace(*f.CipherSuite) == "" {
		return out
	}
	components, err := s.algorithmService.ParseCipherSuite(*f.CipherSuite)
	if err != nil || components == nil {
		return out
	}

	fill := func(dst **string, v string) {
		if *dst != nil || v == "" {
			return
		}
		val := v
		*dst = &val
	}
	fill(&out.KeyExchange, components.KeyExchange)
	fill(&out.Signature, components.Signature)
	fill(&out.Symmetric, components.Symmetric)
	fill(&out.Hash, components.Hash)

	return out
}

// trimmedOrNil returns nil for a nil or blank string pointer, so a blank
// finding field is stored as SQL NULL rather than an empty string that would
// read as "measured, and it is nothing".
// fillPtr assigns src into *dst only when *dst is still empty, so an
// explicitly reported value is never overwritten by a derived one.
func fillPtr(dst **string, src *string) {
	if *dst != nil || src == nil {
		return
	}
	*dst = src
}

func trimmedOrNil(s *string) *string {
	if s == nil || strings.TrimSpace(*s) == "" {
		return nil
	}
	v := strings.TrimSpace(*s)
	return &v
}

// classifyAndLinkAlgorithms classifies algorithms from a finding and links them to crypto configuration.
func (s *AssetService) classifyAndLinkAlgorithms(implID uuid.UUID, finding IngestFinding) {
	// SSH first: its components come from raw metadata, and linking the
	// measured ones before anything else means an algorithm that is both
	// negotiated and merely offered keeps its is_inferred=false row.
	s.classifyAndLinkSSH(implID, sshObservationFromFinding(finding))

	if finding.ProtocolVersion != nil && *finding.ProtocolVersion != "" {
		alg, err := s.algorithmService.ClassifyAlgorithm(*finding.ProtocolVersion, "protocol_version")
		if err == nil && alg != nil {
			_ = s.algorithmService.LinkAlgorithmToImplementation(implID, alg.ID, "protocol_version", false)
		}
	}
	if finding.CipherSuite != nil && *finding.CipherSuite != "" {
		alg, err := s.algorithmService.ClassifyAlgorithm(*finding.CipherSuite, "cipher_suite")
		if err == nil && alg != nil {
			_ = s.algorithmService.LinkAlgorithmToImplementation(implID, alg.ID, "cipher_suite", false)
		}
		components, err := s.algorithmService.ParseCipherSuite(*finding.CipherSuite)
		if err == nil && components != nil {
			// An observed key exchange beats one inferred from the suite name.
			// TLS 1.3 suites name no key exchange, so ParseCipherSuite infers a
			// classical ECDHE — which is exactly wrong when the handshake actually
			// negotiated a post-quantum or hybrid group and reported it separately.
			// Linking both made every PQC endpoint look like it still used ECDHE.
			if components.KeyExchange != "" && (finding.KeyExchangeAlgorithm == nil || *finding.KeyExchangeAlgorithm == "") {
				alg, err := s.algorithmService.ClassifyAlgorithm(components.KeyExchange, "key_exchange")
				if err == nil && alg != nil {
					_ = s.algorithmService.LinkAlgorithmToImplementation(implID, alg.ID, "key_exchange", components.IsInferred)
				}
			}
			if components.Signature != "" {
				alg, err := s.algorithmService.ClassifyAlgorithm(components.Signature, "signature")
				if err == nil && alg != nil {
					_ = s.algorithmService.LinkAlgorithmToImplementation(implID, alg.ID, "signature", components.IsInferred)
				}
			}
			if components.Symmetric != "" {
				alg, err := s.algorithmService.ClassifyAlgorithm(components.Symmetric, "symmetric")
				if err == nil && alg != nil {
					_ = s.algorithmService.LinkAlgorithmToImplementation(implID, alg.ID, "symmetric", components.IsInferred)
				}
			}
			if components.Hash != "" {
				alg, err := s.algorithmService.ClassifyAlgorithm(components.Hash, "hash")
				if err == nil && alg != nil {
					_ = s.algorithmService.LinkAlgorithmToImplementation(implID, alg.ID, "hash", components.IsInferred)
				}
			}
		}
	}
	// The explicitly-reported key exchange. This is NOT derivable from the cipher
	// suite for modern handshakes: TLS 1.3 suite names carry no
	// key-exchange component at all, and a post-quantum or hybrid group
	// (ML-KEM-768, X25519MLKEM768) is negotiated separately and reported here.
	// Without linking them, an implementation using PQC key establishment looked
	// exactly like one using RSA, so post-quantum readiness could never see a PQC
	// key exchange in discovered data.
	if finding.KeyExchangeAlgorithm != nil && *finding.KeyExchangeAlgorithm != "" {
		alg, err := s.algorithmService.ClassifyAlgorithm(*finding.KeyExchangeAlgorithm, "key_exchange")
		if err == nil && alg != nil {
			_ = s.algorithmService.LinkAlgorithmToImplementation(implID, alg.ID, "key_exchange", false)
		}
	}
	if finding.HashAlgorithm != nil && *finding.HashAlgorithm != "" {
		alg, err := s.algorithmService.ClassifyAlgorithm(*finding.HashAlgorithm, "hash")
		if err == nil && alg != nil {
			_ = s.algorithmService.LinkAlgorithmToImplementation(implID, alg.ID, "hash", false)
		}
	}
}
