package services

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// WeakCryptoSeverity represents the severity of a weak crypto issue
type WeakCryptoSeverity string

const (
	SeverityCritical WeakCryptoSeverity = "critical"
	SeverityHigh     WeakCryptoSeverity = "high"
	SeverityMedium   WeakCryptoSeverity = "medium"
	// SeverityLow scores into the CVSS Low band (1-39). It was named
	// "informational" while mapping to 20, which bands as Low — a label that
	// disagreed with what the UI would render. No rule assigns it today; the
	// name is corrected so it cannot ship a contradiction if one ever does.
	SeverityLow WeakCryptoSeverity = "low"
)

// Key-size floors, in bits. Single source for every classifier that judges a
// key by its length: the detector below and the Crypto Risks classifier in
// crypto_risks_service.go. RSA/DSA/DH per NIST SP 800-131A Rev 2 (112-bit
// security ⇒ 2048-bit modulus); EC per the same table (256-bit curve).
const (
	minRSAKeySizeBits = 2048
	minECCKeySizeBits = 256
)

// WeakCryptoCategory represents the category of a weak crypto issue
type WeakCryptoCategory string

const (
	CategoryProtocol    WeakCryptoCategory = "protocol"
	CategoryAlgorithm   WeakCryptoCategory = "algorithm"
	CategoryCertificate WeakCryptoCategory = "certificate"
	CategoryKeySize     WeakCryptoCategory = "key_size"
)

// WeakCryptoIssue represents a detected weak cryptography issue
type WeakCryptoIssue struct {
	ID                     uuid.UUID          `json:"id"`
	TenantID               uuid.UUID          `json:"tenant_id"`
	AssetID                uuid.UUID          `json:"asset_id"`
	CryptoImplementationID uuid.UUID          `json:"crypto_implementation_id"`
	Severity               WeakCryptoSeverity `json:"severity"`
	Category               WeakCryptoCategory `json:"category"`
	IssueType              string             `json:"issue_type"`
	CurrentValue           string             `json:"current_value"`
	Description            string             `json:"description"`
	Recommendation         string             `json:"recommendation"`
	DetectedAt             time.Time          `json:"detected_at"`
}

// WeakCryptoDetector performs fast weak crypto detection during asset import
type WeakCryptoDetector struct {
	// Critical protocols (immediate risk)
	criticalProtocols []string
	// High-risk protocols (should be deprecated)
	highRiskProtocols []string
	// Weak/deprecated algorithms
	criticalAlgorithms []string
	highRiskAlgorithms []string
	// Minimum acceptable key sizes
	minRSAKeySize int
	minECCKeySize int
	// Event publisher for notifications
	eventPublisher *EventPublisherService
}

// NewWeakCryptoDetector creates a new weak crypto detector
func NewWeakCryptoDetector(eventPublisher *EventPublisherService) *WeakCryptoDetector {
	return &WeakCryptoDetector{
		// Critical: Known vulnerable, should never be used
		criticalProtocols: []string{
			"SSLv2", "SSLv3", "SSL2", "SSL3",
			"TLSv1.0", "TLS1.0", "TLS 1.0",
		},
		// High: Deprecated, should be phased out
		highRiskProtocols: []string{
			"TLSv1.1", "TLS1.1", "TLS 1.1",
			"SSH1", "SSH-1",
		},
		// Critical algorithms: Known broken
		criticalAlgorithms: []string{
			"RC4", "DES", "MD5", "MD4", "MD2",
			"NULL", "EXPORT", "anon",
		},
		// High-risk algorithms: Deprecated
		highRiskAlgorithms: []string{
			"3DES", "SHA1", "SHA-1",
			"IDEA", "RC2",
		},
		// Minimum key sizes (NIST recommendations)
		minRSAKeySize:  minRSAKeySizeBits,
		minECCKeySize:  minECCKeySizeBits,
		eventPublisher: eventPublisher,
	}
}

// AnalyzeCryptoImplementation analyzes a crypto implementation and returns detected issues
func (d *WeakCryptoDetector) AnalyzeCryptoImplementation(tenantID, assetID uuid.UUID, impl *models.CryptoImplementation) []WeakCryptoIssue {
	var issues []WeakCryptoIssue
	now := time.Now()

	// Check protocol version
	if impl.ProtocolVersion != nil && *impl.ProtocolVersion != "" {
		version := strings.ToUpper(*impl.ProtocolVersion)

		// Critical protocols
		for _, criticalProto := range d.criticalProtocols {
			if strings.Contains(version, strings.ToUpper(criticalProto)) {
				issues = append(issues, WeakCryptoIssue{
					ID:                     uuid.New(),
					TenantID:               tenantID,
					AssetID:                assetID,
					CryptoImplementationID: impl.ID,
					Severity:               SeverityCritical,
					Category:               CategoryProtocol,
					IssueType:              "weak_protocol",
					CurrentValue:           *impl.ProtocolVersion,
					Description:            "Using a critically vulnerable protocol version that has known security exploits",
					Recommendation:         "Upgrade to TLS 1.2 or TLS 1.3 immediately",
					DetectedAt:             now,
				})
				break
			}
		}

		// High-risk protocols
		for _, highRiskProto := range d.highRiskProtocols {
			if strings.Contains(version, strings.ToUpper(highRiskProto)) {
				issues = append(issues, WeakCryptoIssue{
					ID:                     uuid.New(),
					TenantID:               tenantID,
					AssetID:                assetID,
					CryptoImplementationID: impl.ID,
					Severity:               SeverityHigh,
					Category:               CategoryProtocol,
					IssueType:              "deprecated_protocol",
					CurrentValue:           *impl.ProtocolVersion,
					Description:            "Using a deprecated protocol version that should be phased out",
					Recommendation:         "Upgrade to TLS 1.2 or TLS 1.3",
					DetectedAt:             now,
				})
				break
			}
		}
	}

	// Check cipher suite
	if impl.CipherSuite != nil && *impl.CipherSuite != "" {
		cipherSuite := strings.ToUpper(*impl.CipherSuite)

		// Critical algorithms in cipher suite.
		//
		// "DES" is a substring of "3DES", so every triple-DES suite matched here
		// and was reported as the broken single-DES cipher: severity Critical,
		// score 90, overriding the catalogue's curated 70 for 3DES (worse of the
		// two wins). 3DES is deprecated, not broken, and it is already covered by
		// the high-risk list below. The sibling classifier in
		// crypto_risks_service.go already carried this exclusion.
		for _, criticalAlgo := range d.criticalAlgorithms {
			if criticalAlgo == "DES" && !isSingleDES(cipherSuite) {
				continue
			}
			if strings.Contains(cipherSuite, strings.ToUpper(criticalAlgo)) {
				issues = append(issues, WeakCryptoIssue{
					ID:                     uuid.New(),
					TenantID:               tenantID,
					AssetID:                assetID,
					CryptoImplementationID: impl.ID,
					Severity:               SeverityCritical,
					Category:               CategoryAlgorithm,
					IssueType:              "weak_cipher",
					CurrentValue:           *impl.CipherSuite,
					Description:            "Using a weak or broken cipher algorithm (" + criticalAlgo + ")",
					Recommendation:         "Use AES-GCM or ChaCha20-Poly1305 cipher suites",
					DetectedAt:             now,
				})
				break
			}
		}

		// High-risk algorithms in cipher suite
		for _, highRiskAlgo := range d.highRiskAlgorithms {
			if strings.Contains(cipherSuite, strings.ToUpper(highRiskAlgo)) {
				issues = append(issues, WeakCryptoIssue{
					ID:                     uuid.New(),
					TenantID:               tenantID,
					AssetID:                assetID,
					CryptoImplementationID: impl.ID,
					Severity:               SeverityHigh,
					Category:               CategoryAlgorithm,
					IssueType:              "deprecated_cipher",
					CurrentValue:           *impl.CipherSuite,
					Description:            "Using a deprecated cipher algorithm (" + highRiskAlgo + ")",
					Recommendation:         "Use AES-GCM or ChaCha20-Poly1305 cipher suites",
					DetectedAt:             now,
				})
				break
			}
		}
	}

	// Check hash algorithm
	if impl.HashAlgorithm != nil && *impl.HashAlgorithm != "" {
		hashAlgo := strings.ToUpper(*impl.HashAlgorithm)

		// Critical hash algorithms
		if strings.Contains(hashAlgo, "MD5") || strings.Contains(hashAlgo, "MD4") || strings.Contains(hashAlgo, "MD2") {
			issues = append(issues, WeakCryptoIssue{
				ID:                     uuid.New(),
				TenantID:               tenantID,
				AssetID:                assetID,
				CryptoImplementationID: impl.ID,
				Severity:               SeverityCritical,
				Category:               CategoryAlgorithm,
				IssueType:              "weak_hash",
				CurrentValue:           *impl.HashAlgorithm,
				Description:            "Using a cryptographically broken hash algorithm",
				Recommendation:         "Use SHA-256 or SHA-384 for hashing",
				DetectedAt:             now,
			})
		} else if strings.Contains(hashAlgo, "SHA1") || strings.Contains(hashAlgo, "SHA-1") {
			issues = append(issues, WeakCryptoIssue{
				ID:                     uuid.New(),
				TenantID:               tenantID,
				AssetID:                assetID,
				CryptoImplementationID: impl.ID,
				Severity:               SeverityHigh,
				Category:               CategoryAlgorithm,
				IssueType:              "deprecated_hash",
				CurrentValue:           *impl.HashAlgorithm,
				Description:            "Using a deprecated hash algorithm (SHA-1)",
				Recommendation:         "Use SHA-256 or SHA-384 for hashing",
				DetectedAt:             now,
			})
		}
	}

	// Check key size
	if impl.KeySize != nil && *impl.KeySize > 0 {
		keySize := *impl.KeySize

		// A bit-length floor only means something for the algorithm family it was
		// derived for. Classify before comparing.
		//
		// This used to be `strings.Contains(kex, "EC")`, which does not match
		// X25519, X448, ML-KEM-* or HQC-* — so their legitimate 256-bit keys fell
		// into the RSA branch and tripped the "below 1024 bits" rule as CRITICAL.
		// That penalised exactly the modern and post-quantum configurations the
		// product should be rewarding, and it was the single largest source of
		// false Criticals in a realistic dataset.
		family := keyExchangeFamily(impl.KeyExchangeAlgorithm)
		switch family {
		case kexFamilyUnknown, kexFamilyPostQuantum:
			// Unknown: a bare 256 could be an EC key (healthy) or an RSA modulus
			// (catastrophic), and guessing wrong in either direction is worse than
			// staying quiet — a genuinely weak RSA key exchange is still caught by
			// its catalogue entry (RSA-512, RSA-1024) when one is reported.
			// Post-quantum: key sizes are not comparable to either floor.
		case kexFamilyEllipticCurve:
			if keySize < d.minECCKeySize {
				issues = append(issues, WeakCryptoIssue{
					ID:                     uuid.New(),
					TenantID:               tenantID,
					AssetID:                assetID,
					CryptoImplementationID: impl.ID,
					Severity:               SeverityHigh,
					Category:               CategoryKeySize,
					IssueType:              "weak_key_size",
					CurrentValue:           strconv.Itoa(keySize),
					Description:            "ECC key size is below recommended minimum (256 bits)",
					Recommendation:         "Use at least 256-bit ECC keys",
					DetectedAt:             now,
				})
			}
		case kexFamilyFiniteField:
			// RSA/DSA/DH moduli
			if keySize < 1024 {
				issues = append(issues, WeakCryptoIssue{
					ID:                     uuid.New(),
					TenantID:               tenantID,
					AssetID:                assetID,
					CryptoImplementationID: impl.ID,
					Severity:               SeverityCritical,
					Category:               CategoryKeySize,
					IssueType:              "critically_weak_key_size",
					CurrentValue:           strconv.Itoa(keySize),
					Description:            "RSA key size is critically weak (below 1024 bits)",
					Recommendation:         "Use at least 2048-bit RSA keys, preferably 3072 or 4096 bits",
					DetectedAt:             now,
				})
			} else if keySize < d.minRSAKeySize {
				issues = append(issues, WeakCryptoIssue{
					ID:                     uuid.New(),
					TenantID:               tenantID,
					AssetID:                assetID,
					CryptoImplementationID: impl.ID,
					Severity:               SeverityHigh,
					Category:               CategoryKeySize,
					IssueType:              "weak_key_size",
					CurrentValue:           strconv.Itoa(keySize),
					Description:            "RSA key size is below recommended minimum (2048 bits)",
					Recommendation:         "Use at least 2048-bit RSA keys, preferably 3072 or 4096 bits",
					DetectedAt:             now,
				})
			}
		}
	}

	return issues
}

// AnalyzeAndNotify analyzes a crypto implementation and publishes events for critical issues
func (d *WeakCryptoDetector) AnalyzeAndNotify(ctx context.Context, tenantID, assetID uuid.UUID, impl *models.CryptoImplementation) []WeakCryptoIssue {
	issues := d.AnalyzeCryptoImplementation(tenantID, assetID, impl)

	if len(issues) > 0 {
		// Log the detection
		criticalCount := 0
		highCount := 0
		for _, issue := range issues {
			switch issue.Severity {
			case SeverityCritical:
				criticalCount++
			case SeverityHigh:
				highCount++
			}
		}

		if criticalCount > 0 || highCount > 0 {
			log.Printf("[WeakCryptoDetector] Detected %d critical and %d high severity issues for asset %s",
				criticalCount, highCount, assetID)
		}

		// Publish asset changed event to trigger compliance evaluation
		// This is done by the caller in ImportDiscoveryFindings, so we don't duplicate here
	}

	return issues
}

// isSingleDES reports whether a cipher-suite name names the BROKEN single-DES
// cipher rather than triple DES. Both the IANA spelling
// (TLS_RSA_WITH_3DES_EDE_CBC_SHA) and the OpenSSL one (DES-CBC3-SHA) contain
// the substring "DES", which is why a plain Contains check reported every
// triple-DES endpoint as running 56-bit DES.
func isSingleDES(cipherSuite string) bool {
	cs := strings.ToUpper(cipherSuite)
	if !strings.Contains(cs, "DES") {
		return false
	}
	for _, triple := range []string{"3DES", "CBC3", "DES_EDE", "DES-EDE"} {
		if strings.Contains(cs, triple) {
			return false
		}
	}
	return true
}

// keyExchangeFamily buckets a key-exchange algorithm by the kind of size floor
// that applies to it. Finite-field (RSA/DSA/DH) moduli are measured in thousands
// of bits, elliptic-curve keys in hundreds, and post-quantum key sizes are not
// comparable to either.
type kexFamily int

const (
	kexFamilyUnknown kexFamily = iota
	kexFamilyFiniteField
	kexFamilyEllipticCurve
	kexFamilyPostQuantum
)

// Family tokens. Package-level so the SQL predicates below are generated from
// the SAME lists the Go classifier uses — the two ran on hand-written,
// divergent rules before, and the list view disagreed with the facet filter
// that was supposed to select it.
var (
	kexPostQuantumTokens   = []string{"ML-KEM", "MLKEM", "HQC", "ML-DSA", "MLDSA", "SLH-DSA", "FN-DSA", "KYBER", "DILITHIUM"}
	kexEllipticCurveTokens = []string{"ECDH", "ECDSA", "X25519", "X448", "CURVE25519", "SECP", "DH-ECP", "PRIME256", "ED25519", "ED448"}
	kexFiniteFieldTokens   = []string{"RSA", "DSA", "DH", "DHE"}
)

func containsAnyToken(k string, tokens []string) bool {
	for _, p := range tokens {
		if strings.Contains(k, p) {
			return true
		}
	}
	return false
}

func keyExchangeFamily(kex *string) kexFamily {
	if kex == nil || *kex == "" {
		return kexFamilyUnknown
	}
	k := strings.ToUpper(strings.TrimSpace(*kex))
	// Post-quantum first: SecP256r1MLKEM768 contains both "EC" and "MLKEM", and
	// the post-quantum reading is the correct one.
	switch {
	case containsAnyToken(k, kexPostQuantumTokens):
		return kexFamilyPostQuantum
	case containsAnyToken(k, kexEllipticCurveTokens):
		return kexFamilyEllipticCurve
	case containsAnyToken(k, kexFiniteFieldTokens):
		return kexFamilyFiniteField
	}
	return kexFamilyUnknown
}

// kexFamilyTokenSQL renders "column matches any of these tokens" for SQL.
func kexFamilyTokenSQL(col string, tokens []string) string {
	parts := make([]string, 0, len(tokens))
	for _, t := range tokens {
		parts = append(parts, fmt.Sprintf("UPPER(COALESCE(%s, '')) LIKE '%%%s%%'", col, t))
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

// kexFamilySQL is the SQL twin of keyExchangeFamily: it reproduces the same
// precedence (post-quantum wins over elliptic-curve wins over finite-field) so
// a row selected by a query lands in the same family the Go classifier assigns.
func kexFamilySQL(col string, fam kexFamily) string {
	pq := kexFamilyTokenSQL(col, kexPostQuantumTokens)
	ec := kexFamilyTokenSQL(col, kexEllipticCurveTokens)
	ff := kexFamilyTokenSQL(col, kexFiniteFieldTokens)
	switch fam {
	case kexFamilyPostQuantum:
		return pq
	case kexFamilyEllipticCurve:
		return "(NOT " + pq + " AND " + ec + ")"
	case kexFamilyFiniteField:
		return "(NOT " + pq + " AND NOT " + ec + " AND " + ff + ")"
	default:
		return "(NOT " + pq + " AND NOT " + ec + " AND NOT " + ff + ")"
	}
}

// Key-size risk predicates, family-aware, generated from the classifier's own
// token lists. `keySizeCol < 2048` on its own — which is what these filters
// used to say — labels every healthy 256-bit EC key a critically weak RSA key.
func criticallyWeakKeySizeSQL(keySizeCol, kexCol string) string {
	return fmt.Sprintf("(%s IS NOT NULL AND %s < 1024 AND %s)",
		keySizeCol, keySizeCol, kexFamilySQL(kexCol, kexFamilyFiniteField))
}

func highRiskKeySizeSQL(keySizeCol, kexCol string) string {
	return fmt.Sprintf("((%s IS NOT NULL AND %s >= 1024 AND %s < %d AND %s) OR (%s IS NOT NULL AND %s < %d AND %s))",
		keySizeCol, keySizeCol, keySizeCol, minRSAKeySizeBits, kexFamilySQL(kexCol, kexFamilyFiniteField),
		keySizeCol, keySizeCol, minECCKeySizeBits, kexFamilySQL(kexCol, kexFamilyEllipticCurve))
}

// singleDESSQL is the SQL twin of isSingleDES: matches broken single DES while
// excluding both spellings of triple DES ("3DES", OpenSSL's "CBC3").
func singleDESSQL(col string) string {
	c := fmt.Sprintf("UPPER(COALESCE(%s, ''))", col)
	return fmt.Sprintf("(%s LIKE '%%DES%%' AND %s NOT LIKE '%%3DES%%' AND %s NOT LIKE '%%CBC3%%')", c, c, c)
}

// tripleDESSQL matches triple DES in either spelling.
func tripleDESSQL(col string) string {
	c := fmt.Sprintf("UPPER(COALESCE(%s, ''))", col)
	return fmt.Sprintf("(%s LIKE '%%3DES%%' OR %s LIKE '%%CBC3%%')", c, c)
}

// anyWeakKeySizeSQL matches every key the classifier would flag for its size,
// at any severity.
func anyWeakKeySizeSQL(keySizeCol, kexCol string) string {
	return "(" + criticallyWeakKeySizeSQL(keySizeCol, kexCol) + " OR " + highRiskKeySizeSQL(keySizeCol, kexCol) + ")"
}

// foldProtocolVersion folds an observed protocol-version string onto a
// separator-free upper-case form, so the several spellings producers actually
// emit compare equal: "TLS 1.0", "TLSv1.0", "TLS1.0" and "tls-1.0" all fold to
// "TLS1.0".
//
// It is deliberately the SQL-expressible subset of
// cryptoparse.NormalizeComponentCode (upper-case + drop spaces and hyphens) and
// NOT that function itself: NormalizeComponentCode additionally strips cipher
// mode suffixes ("-GCM", "-128", …), which has no SQL twin. Keeping the fold
// small is what lets foldProtocolVersionSQL below stay provably identical.
func foldProtocolVersion(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	v = strings.ReplaceAll(v, " ", "")
	return strings.ReplaceAll(v, "-", "")
}

// foldProtocolVersionSQL is the SQL twin of foldProtocolVersion.
func foldProtocolVersionSQL(col string) string {
	return fmt.Sprintf("REPLACE(REPLACE(UPPER(TRIM(COALESCE(%s, ''))), ' ', ''), '-', '')", col)
}

// legacyProtocolVersionCodes are the folded protocol-version spellings that name
// a version RFC 8996 deprecates outright (TLS 1.0 / TLS 1.1). AWS renders TLS
// 1.0 as the bare "TLSv1", and the passive path sometimes carries only the
// version half ("1.0"), so both shapes are listed.
//
// Any SSL version is weak regardless of spelling and is matched by prefix
// instead, so SSLv2/SSLv3/"SSL 3.0" need no entries here.
var legacyProtocolVersionCodes = []string{
	"TLS1.0", "TLSV1.0", "TLS1", "TLSV1", "1.0", "1",
	"TLS1.1", "TLSV1.1", "1.1",
}

// isLegacyProtocolVersion reports whether an observed protocol-version string
// names SSL (any version) or TLS 1.0/1.1.
//
// Every producer in the tree writes the SPACED form ("TLS 1.0") — the sensor's
// packet capture and TLS enricher, the shared active probers, the F5 and Cisco
// interrogators. Comparisons against a bare "1.0" or against 'TLSv1.0' were
// therefore dead code: they matched nothing that is ever stored.
func isLegacyProtocolVersion(version string) bool {
	folded := foldProtocolVersion(version)
	if folded == "" {
		return false
	}
	if strings.HasPrefix(folded, "SSL") {
		return true
	}
	for _, code := range legacyProtocolVersionCodes {
		if folded == code {
			return true
		}
	}
	return false
}

// legacyProtocolVersionSQL is the SQL twin of isLegacyProtocolVersion.
// TestLegacyProtocolVersionSQL_MatchesGo pins the two against each other over
// every spelling either side claims to handle.
func legacyProtocolVersionSQL(col string) string {
	folded := foldProtocolVersionSQL(col)
	quoted := make([]string, 0, len(legacyProtocolVersionCodes))
	for _, code := range legacyProtocolVersionCodes {
		quoted = append(quoted, "'"+code+"'")
	}
	return fmt.Sprintf("(%s LIKE 'SSL%%' OR %s IN (%s))",
		folded, folded, strings.Join(quoted, ", "))
}

// legacyTLSVersionsArraySQL is the SQL twin of hasWeakTLSVersion: it matches a
// text[] column of enumerated accepted versions containing any legacy one. The
// filter and the facet counter used a literal `&& ARRAY['TLS 1.0','TLS 1.1']`,
// which silently missed every other spelling the enumerators can produce
// (SSLv3, 'TLSv1.1' from a cloud SSL policy).
func legacyTLSVersionsArraySQL(arrayCol string) string {
	return fmt.Sprintf(
		"EXISTS (SELECT 1 FROM unnest(COALESCE(%s, ARRAY[]::text[])) AS legacy_tls_v WHERE %s)",
		arrayCol, legacyProtocolVersionSQL("legacy_tls_v"))
}

// deprecatedAlgorithmsSQL is the shared `?uses_deprecated_algorithms=true`
// predicate. It lived inline at three call sites with two independent defects:
// it compared protocol_version against 'TLSv1.0'/'TLSv1.1' (a spelling no
// producer writes, so the real TLS 1.0/1.1 rows were skipped), and it used a
// family-blind `key_size < 2048`, which labels every healthy 256-bit EC key
// deprecated — the exact bug anyWeakKeySizeSQL already fixed elsewhere.
//
// prefix qualifies the columns (e.g. "ci.").
func deprecatedAlgorithmsSQL(prefix string) string {
	return "(" +
		legacyProtocolVersionSQL(prefix+"protocol_version") +
		" OR UPPER(COALESCE(" + prefix + "hash_algorithm, '')) IN ('SHA1', 'SHA-1', 'MD5')" +
		" OR " + anyWeakKeySizeSQL(prefix+"key_size", prefix+"key_exchange_algorithm") +
		")"
}

// CalculateRiskScore calculates an overall risk score based on detected issues
func (d *WeakCryptoDetector) CalculateRiskScore(issues []WeakCryptoIssue) int {
	if len(issues) == 0 {
		return 0
	}

	maxScore := 0
	for _, issue := range issues {
		score := 0
		switch issue.Severity {
		case SeverityCritical:
			score = 90
		case SeverityHigh:
			score = 70
		case SeverityMedium:
			score = 50
		case SeverityLow:
			score = 20
		}
		if score > maxScore {
			maxScore = score
		}
	}

	return maxScore
}

// GetRiskFactors returns a list of risk factor descriptions from detected issues
func (d *WeakCryptoDetector) GetRiskFactors(issues []WeakCryptoIssue) []string {
	var factors []string
	seen := make(map[string]bool)

	for _, issue := range issues {
		factor := issue.Description
		if !seen[factor] {
			factors = append(factors, factor)
			seen[factor] = true
		}
	}

	return factors
}

// WeakCryptoDetectedEvent represents a weak crypto detection event for NATS
type WeakCryptoDetectedEvent struct {
	EventID   uuid.UUID         `json:"event_id"`
	EventType events.EventType  `json:"event_type"`
	TenantID  uuid.UUID         `json:"tenant_id"`
	AssetID   uuid.UUID         `json:"asset_id"`
	Issues    []WeakCryptoIssue `json:"issues"`
	Timestamp time.Time         `json:"timestamp"`
	Source    string            `json:"source"`
}

// NewWeakCryptoDetectedEvent creates a new weak crypto detected event
func NewWeakCryptoDetectedEvent(tenantID, assetID uuid.UUID, issues []WeakCryptoIssue, source string) *WeakCryptoDetectedEvent {
	return &WeakCryptoDetectedEvent{
		EventID:   uuid.New(),
		EventType: "weak_crypto.detected",
		TenantID:  tenantID,
		AssetID:   assetID,
		Issues:    issues,
		Timestamp: time.Now(),
		Source:    source,
	}
}
