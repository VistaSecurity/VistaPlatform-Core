package services

// A crypto risk is measured on an ENDPOINT, and the row says so.
//
// `ci.endpoint_id` names the exact socket a configuration was observed on, so
// the address and port a risk row carries are that endpoint's, never the host's
// primary address COALESCEd in. The JSON field names stay `asset_ip_address` /
// `asset_port` for the consumers that already read them, with `endpoint_id` and
// `endpoint_address` alongside: an asset with two TLS endpoints has two rows
// here and they are different sockets, which the old flattening could not say.

import (
	"container/heap"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/cryptoassess"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/riskbands"
	"github.com/vistasecurity/vistaplatform/shared/severity"
)

// CryptoRisksSummary represents aggregated crypto risk statistics
type CryptoRisksSummary struct {
	Critical          int `json:"critical"`
	High              int `json:"high"`
	Medium            int `json:"medium"`
	Low               int `json:"low"`
	Unscored          int `json:"unscored"`
	Informational     int `json:"informational"`
	TotalAffected     int `json:"total_assets_affected"`
	ProtocolIssues    int `json:"protocol_issues"`
	AlgorithmIssues   int `json:"algorithm_issues"`
	CertificateIssues int `json:"certificate_issues"`
	KeySizeIssues     int `json:"key_size_issues"`
}

// CryptoRisk represents a detected cryptographic risk
type CryptoRisk struct {
	ID                     uuid.UUID `json:"id" db:"id"`
	TenantID               uuid.UUID `json:"tenant_id" db:"tenant_id"`
	AssetID                uuid.UUID `json:"asset_id" db:"asset_id"`
	CryptoImplementationID uuid.UUID `json:"crypto_implementation_id" db:"crypto_implementation_id"`
	Severity               *string   `json:"severity"`
	RiskScore              *int      `json:"risk_score"`
	AssessmentBasis        string    `json:"assessment_basis"`
	AssessmentLimitations  []string  `json:"assessment_limitations"`
	ScoreSources           []string  `json:"score_sources"`
	Categories             []string  `json:"categories,omitempty"`
	Category               string    `json:"category"`
	IssueType              string    `json:"issue_type"`
	CurrentValue           string    `json:"current_value"`
	Description            string    `json:"description"`
	Recommendation         string    `json:"recommendation"`
	DetectedAt             time.Time `json:"detected_at"`
	// Asset info
	AssetHostname *string `json:"asset_hostname,omitempty" db:"hostname"`
	// AssetIPAddress is the ASSET's primary address — the one to show when
	// there is room for one. It is NOT the endpoint's; the two differ on a
	// multi-homed host, and COALESCEing one onto the other (which this row used
	// to do) reported an address nobody measured this configuration on.
	AssetIPAddress *string `json:"asset_ip_address,omitempty" db:"ip_address"`
	// EndpointID, EndpointAddress and EndpointPort are the socket the
	// configuration was actually measured on. All three are nil for a
	// configuration with no endpoint — an at-rest resource, which is a real
	// answer and is what retired the "AT-REST" port sentinel.
	EndpointID      *uuid.UUID `json:"endpoint_id,omitempty" db:"endpoint_id"`
	EndpointAddress *string    `json:"endpoint_address,omitempty" db:"endpoint_address"`
	EndpointPort    *int       `json:"endpoint_port,omitempty" db:"endpoint_port"`
	// AssetPort is EndpointPort under its pre-endpoint name, kept for consumers
	// that already read it.
	AssetPort *int `json:"asset_port,omitempty" db:"port"`
	// AssetClassKey is the owning asset's class (ADR-0002 D2). Renamed with
	// the value: an asset the old enum called "appliance" is now `hardware`,
	// `switch` or `firewall`.
	AssetClassKey string `json:"asset_class_key,omitempty" db:"class_key"`
	// Crypto implementation info
	Protocol        string  `json:"protocol,omitempty" db:"protocol"`
	ProtocolVersion *string `json:"protocol_version,omitempty" db:"protocol_version"`
	CipherSuite     *string `json:"cipher_suite,omitempty" db:"cipher_suite"`
}

// CryptoRiskFilters defines filters for crypto risk queries
type CryptoRiskFilters struct {
	Severity  []string `json:"severity" form:"severity"` // critical, high, medium, low, informational; unscored selects NULL
	Category  []string `json:"category" form:"category"` // protocol, algorithm, certificate, key_size
	Search    string   `json:"search" form:"search"`
	Page      int      `json:"page" form:"page"`
	PageSize  int      `json:"page_size" form:"page_size"`
	SortBy    string   `json:"sort_by" form:"sort_by"`
	SortOrder string   `json:"sort_order" form:"sort_order"`
}

// CryptoRisksResponse represents the paginated response for crypto risks
// MaxCryptoRiskPageSize is the largest page a single ListRisks call will
// return. List endpoints clamp to it; export selects up to 50k rows in one pass.
const MaxCryptoRiskPageSize = 100

type CryptoRisksResponse struct {
	Risks      []CryptoRisk `json:"risks"`
	Total      int          `json:"total"`
	Page       int          `json:"page"`
	PageSize   int          `json:"page_size"`
	TotalPages int          `json:"total_pages"`
}

// CryptoRisksService handles crypto risk queries and analysis
type CryptoRisksService struct {
	db *database.DB
}

// NewCryptoRisksService creates a new crypto risks service
func NewCryptoRisksService(db *database.DB) *CryptoRisksService {
	return &CryptoRisksService{db: db}
}

// readRisks streams candidates in one tenant transaction. SQL restricts identity,
// lifecycle and search; the same pure judge used by CryptoProducer determines
// eligibility before filtering/counting/paging. No producer writes occur on GET.
func (s *CryptoRisksService) readRisks(tenant uuid.UUID, id *uuid.UUID, search string, visit func(CryptoRisk)) error {
	return database.WithTenantTx(context.Background(), s.db, tenant, func(tx *sqlx.Tx) error {
		query := `SELECT ci.id, ci.tenant_id, a.id, ci.protocol::text,
    ci.protocol_version, ci.cipher_suite, COALESCE(ci.key_exchange_algorithm,''),
    COALESCE(ci.key_size,0), COALESCE(ci.hash_algorithm,''), COALESCE(ci.signature_algorithm,''),
    COALESCE(ci.symmetric_encryption,''), COALESCE(ci.risk_score,0), ci.created_at,
    a.hostname, host(a.primary_address), a.class_key, e.id, host(e.address), e.port,
    cat.max_risk, COALESCE(cat.components,'[]'::jsonb)::text, cert.expiry, COALESCE(prior.fact,'null'::jsonb)::text
   FROM crypto_implementations ci
   LEFT JOIN asset_endpoints e ON e.id=ci.endpoint_id AND e.tenant_id=ci.tenant_id
   JOIN assets a ON a.id=` + findings.ConfigurationAssetSQL("ci", "e") + ` AND a.tenant_id=ci.tenant_id
    AND a.deleted_at IS NULL AND a.asset_status='monitoring'
   LEFT JOIN LATERAL (
    SELECT MAX(alg.risk_score) AS max_risk,
     jsonb_agg(jsonb_build_object('code',alg.code,'role',cia.algorithm_type,
      'strength',alg.strength,'risk_score',alg.risk_score) ORDER BY alg.code,cia.algorithm_type) AS components
    FROM crypto_implementation_algorithms cia JOIN algorithms alg ON alg.id=cia.algorithm_id
    WHERE cia.crypto_implementation_id=ci.id AND cia.algorithm_type=ANY($2)
   ) cat ON true
   LEFT JOIN LATERAL (
    SELECT MIN(c.not_after) FILTER (WHERE c.not_after>NOW()) AS expiry
    FROM crypto_implementation_certificates cic JOIN certificates c ON c.id=cic.certificate_id AND c.tenant_id=ci.tenant_id
    WHERE cic.crypto_implementation_id=ci.id
   ) cert ON true
   LEFT JOIN LATERAL (
    SELECT jsonb_build_object('score',f.score,'summary',f.summary,'evidence',f.evidence) AS fact
    FROM findings f WHERE f.tenant_id=ci.tenant_id AND f.subject_id=ci.id
     AND f.subject_type='crypto_configuration' AND f.producer='crypto'
     AND f.kind='weak_configuration' AND f.detection_state='ACTIVE'
    ORDER BY f.last_seen DESC,f.id LIMIT 1
   ) prior ON true
   WHERE ci.tenant_id=$1 AND ci.deleted_at IS NULL
    AND ($3::uuid IS NULL OR ci.id=$3)
    AND ($4='' OR a.hostname ILIKE $5 OR host(a.primary_address) ILIKE $5
     OR host(e.address) ILIKE $5 OR ci.protocol::text ILIKE $5 OR ci.cipher_suite ILIKE $5)`
		rows, err := tx.Query(query, tenant, pq.Array(cryptoassess.CatalogueRiskRoles), id, search, "%"+search+"%")
		if err != nil {
			return fmt.Errorf("query crypto risks: %w", err)
		}
		defer func() { _ = rows.Close() }()
		now := time.Now()
		for rows.Next() {
			var r CryptoRisk
			var c cryptoassess.Configuration
			var components, previous string
			var expiry *time.Time
			if err := rows.Scan(&r.ID, &r.TenantID, &r.AssetID, &r.Protocol, &r.ProtocolVersion, &r.CipherSuite,
				&c.KeyAlgorithm, &c.KeyBits, &c.Hash, &c.Signature, &c.Symmetric, &c.StoredRisk, &r.DetectedAt,
				&r.AssetHostname, &r.AssetIPAddress, &r.AssetClassKey, &r.EndpointID, &r.EndpointAddress, &r.EndpointPort,
				&c.CatalogueRisk, &components, &expiry, &previous); err != nil {
				return err
			}
			r.CryptoImplementationID = r.ID
			r.AssetPort = r.EndpointPort
			if r.ProtocolVersion != nil {
				c.Version = *r.ProtocolVersion
			}
			if r.CipherSuite != nil {
				c.Suite = *r.CipherSuite
			}
			c.Components = []byte(components)
			var priorInput struct {
				Score    *int            `json:"score"`
				Evidence json.RawMessage `json:"evidence"`
			}
			if json.Unmarshal([]byte(previous), &priorInput) == nil {
				c.PreviousEvidence = priorInput.Evidence
				c.PreviousScore = priorInput.Score
			}
			historical := r
			retained := retainCryptoRisk(&historical, c, previous)
			current := classifyConfigurationRisk(&r, c, expiry, now)
			if retained {
				if !current {
					r = historical
				} else {
					categories := append(append([]string{}, r.Categories...), historical.Categories...)
					description := r.Description + "; " + historical.Description
					limitations := historical.AssessmentLimitations
					if cryptoRiskRank(historical.Severity) > cryptoRiskRank(r.Severity) {
						r = historical
					}
					r.Categories = categories
					r.Description = description
					r.AssessmentLimitations = limitations
				}
			}
			if current || retained {
				slices.Sort(r.Categories)
				r.Categories = slices.Compact(r.Categories)
				visit(r)
			}
		}
		return rows.Err()
	})
}

// cryptoRiskSeverity returns a canonical wire value; NULL represents no numeric assessment.
func cryptoRiskSeverity(value severity.Severity) *string { wire := string(value); return &wire }
func cryptoRiskRank(value *string) int {
	if value == nil {
		return 0
	}
	wire := *value
	if wire == "informational" {
		wire = string(severity.Info)
	}
	canonical, err := severity.Parse(wire)
	if err != nil {
		return 0
	}
	rank, _ := severity.Rank(canonical)
	return rank
}

// certificateExpirySeverity is lifecycle policy, not a numeric crypto score.
// The legacy feed surfaces future expiry within 90 days; the 30-day window is
// Medium, the remaining window Informational. Expired certificates continue in
// the separate certificate-expiring alert domain, not weak-configuration rules.
func certificateExpirySeverity(expiry *time.Time, now time.Time) *string {
	if expiry == nil || !expiry.After(now) || expiry.After(now.Add(90*24*time.Hour)) {
		return nil
	}
	if !expiry.After(now.Add(30 * 24 * time.Hour)) {
		return cryptoRiskSeverity(severity.Medium)
	}
	return cryptoRiskSeverity(severity.Info)
}

func classifyConfigurationRisk(r *CryptoRisk, c cryptoassess.Configuration, expiry *time.Time, now time.Time) bool {
	judgment := c.Judge()
	lifecycle := certificateExpirySeverity(expiry, now)
	if !judgment.Emit() && lifecycle == nil {
		return false
	}
	r.AssessmentLimitations = append([]string{}, judgment.Limitations...)
	r.RiskScore = c.Score()
	r.ScoreSources = []string{}
	if r.RiskScore != nil {
		r.ScoreSources = append(r.ScoreSources, c.ScoreSources(*r.RiskScore)...)
	}
	r.AssessmentBasis = "configuration"
	if c.RetainsNumericHistory() && r.RiskScore != nil && *r.RiskScore == *c.PreviousScore {
		r.AssessmentBasis = "retained_finding"
	}
	if judgment.Emit() {
		if r.RiskScore != nil {
			r.Severity = cryptoRiskSeverity(riskbands.Severity(*r.RiskScore))
		}
		r.Description = "Configuration " + judgment.Detail()
		r.Recommendation = "Review the cited catalogue components and deployment rule failures"
		r.IssueType = "acceptable_configuration"
		if len(judgment.Weak)+len(judgment.Rules) > 0 {
			r.IssueType = "weak_configuration"
		}
		for _, rule := range judgment.Rules {
			category := "algorithm"
			if rule.Rule == "key_size" {
				category = "key_size"
			}
			r.Categories = append(r.Categories, category)
			if len(r.Categories) == 1 {
				r.Category = category
				r.IssueType = "weak_hash"
				r.CurrentValue = rule.Algorithm
				if rule.Rule == "key_size" {
					r.IssueType = "weak_key_size"
					r.CurrentValue = fmt.Sprintf("%s %d bits", rule.Algorithm, rule.Bits)
					if riskbands.Severity(rule.Score) == severity.Critical {
						r.IssueType = "critically_weak_key_size"
					}
				}
			}
		}
		weakRepresentative := len(judgment.Rules) > 0
		var components []cryptoassess.Component
		_ = json.Unmarshal(c.Components, &components) // Judge reports unreadable evidence.
		for _, component := range components {
			if component.Strength != "weak" && component.Strength != "acceptable" {
				continue
			}
			category := "algorithm"
			if component.Role == "protocol_version" {
				category = "protocol"
			}
			r.Categories = append(r.Categories, category)
			if len(r.Categories) == 1 || component.Strength == "weak" && !weakRepresentative {
				weakRepresentative = component.Strength == "weak"
				r.Category = category
				factor := component.Role
				if factor == "protocol_version" {
					factor = "protocol"
				}
				if factor == "cipher_suite" {
					factor = "cipher"
				}
				r.IssueType = component.Strength + "_" + factor
			}
			if r.CurrentValue != "" {
				r.CurrentValue += "; "
			}
			r.CurrentValue += component.Code + " [" + component.Role + "]"
		}
	}
	if lifecycle != nil {
		r.Categories = append(r.Categories, "certificate")
		days := int(expiry.Sub(now).Hours() / 24)
		description := fmt.Sprintf("Certificate expires in %d days (certificate lifecycle policy)", days)
		if !judgment.Emit() || cryptoRiskRank(lifecycle) > cryptoRiskRank(r.Severity) {
			r.Severity = lifecycle
			r.Category = "certificate"
			r.IssueType = "expiring_certificate"
			r.CurrentValue = expiry.UTC().Format(time.RFC3339)
			r.AssessmentBasis = "certificate_lifecycle"
			r.Recommendation = "Renew the certificate before expiration"
		}
		if r.Description != "" {
			r.Description += "; "
		}
		r.Description += description
	}
	return true
}

func matchesCryptoRisk(r CryptoRisk, f CryptoRiskFilters) bool {
	if len(f.Severity) > 0 {
		matched := false
		for _, value := range f.Severity {
			value = strings.ToLower(value)
			if value == "informational" {
				value = "info"
			}
			if r.Severity == nil && value == "unscored" || r.Severity != nil && *r.Severity == value {
				matched = true
			}
		}
		if !matched {
			return false
		}
	}
	if len(f.Category) > 0 {
		matched := false
		for _, category := range f.Category {
			if slices.Contains(r.Categories, strings.ToLower(category)) {
				matched = true
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// cryptoRiskBefore always ends with the stable configuration ID tie-breaker, so
// rows with equal scores/timestamps cannot move between pages or duplicate CSV.
func cryptoRiskBefore(a, b CryptoRisk, f CryptoRiskFilters) bool {
	comparison := 0
	switch f.SortBy {
	case "hostname":
		if a.AssetHostname == nil || b.AssetHostname == nil {
			if a.AssetHostname == nil && b.AssetHostname != nil {
				return false
			}
			if a.AssetHostname != nil && b.AssetHostname == nil {
				return true
			}
		} else {
			comparison = strings.Compare(*a.AssetHostname, *b.AssetHostname)
		}
	case "protocol":
		comparison = strings.Compare(a.Protocol, b.Protocol)
	case "detected_at":
		comparison = a.DetectedAt.Compare(b.DetectedAt)
	default:
		if a.Severity == nil || b.Severity == nil {
			if a.Severity == nil && b.Severity != nil {
				return false
			}
			if a.Severity != nil && b.Severity == nil {
				return true
			}
		}
		comparison = cryptoRiskRank(a.Severity) - cryptoRiskRank(b.Severity)
	}
	desc := strings.EqualFold(f.SortOrder, "DESC") || f.SortBy == ""
	if comparison != 0 {
		if desc {
			return comparison > 0
		}
		return comparison < 0
	}
	return a.ID.String() < b.ID.String()
}

type cryptoRiskSelection struct {
	rows    []CryptoRisk
	filters CryptoRiskFilters
}

func (h cryptoRiskSelection) Len() int { return len(h.rows) }
func (h cryptoRiskSelection) Less(i, j int) bool {
	return cryptoRiskBefore(h.rows[j], h.rows[i], h.filters)
}
func (h cryptoRiskSelection) Swap(i, j int) { h.rows[i], h.rows[j] = h.rows[j], h.rows[i] }
func (h *cryptoRiskSelection) Push(v any)   { h.rows = append(h.rows, v.(CryptoRisk)) }
func (h *cryptoRiskSelection) Pop() any {
	n := len(h.rows) - 1
	v := h.rows[n]
	h.rows = h.rows[:n]
	return v
}

func (s *CryptoRisksService) selectRisks(tenant uuid.UUID, f CryptoRiskFilters, keep int) ([]CryptoRisk, int, error) {
	selected := &cryptoRiskSelection{filters: f}
	total := 0
	err := s.readRisks(tenant, nil, f.Search, func(r CryptoRisk) {
		if !matchesCryptoRisk(r, f) {
			return
		}
		total++
		if len(selected.rows) < keep {
			heap.Push(selected, r)
		} else if keep > 0 && cryptoRiskBefore(r, selected.rows[0], f) {
			selected.rows[0] = r
			heap.Fix(selected, 0)
		}
	})
	sort.Slice(selected.rows, func(i, j int) bool { return cryptoRiskBefore(selected.rows[i], selected.rows[j], f) })
	return selected.rows, total, err
}

func (s *CryptoRisksService) ListRisks(tenant uuid.UUID, f CryptoRiskFilters) (*CryptoRisksResponse, error) {
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize < 1 {
		f.PageSize = 20
	} else if f.PageSize > MaxCryptoRiskPageSize {
		f.PageSize = MaxCryptoRiskPageSize
	}
	keep := 0
	if f.Page <= math.MaxInt/f.PageSize {
		keep = f.Page * f.PageSize
	}
	rows, total, err := s.selectRisks(tenant, f, keep)
	if err != nil {
		return nil, err
	}
	start := len(rows)
	if keep > 0 {
		start = min((f.Page-1)*f.PageSize, len(rows))
	}
	page := append([]CryptoRisk{}, rows[start:]...)
	return &CryptoRisksResponse{Risks: page, Total: total, Page: f.Page, PageSize: f.PageSize, TotalPages: (total + f.PageSize - 1) / f.PageSize}, nil
}

// ExportRisks evaluates once rather than repeating a tenant scan for every page.
func (s *CryptoRisksService) ExportRisks(tenant uuid.UUID, f CryptoRiskFilters) ([]CryptoRisk, error) {
	rows, _, err := s.selectRisks(tenant, f, 50000)
	return rows, err
}
func (s *CryptoRisksService) GetRiskByID(tenant, id uuid.UUID) (*CryptoRisk, error) {
	var result *CryptoRisk
	err := s.readRisks(tenant, &id, "", func(r CryptoRisk) { result = &r })
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, sql.ErrNoRows
	}
	return result, nil
}
func (s *CryptoRisksService) GetSummary(tenant uuid.UUID) (*CryptoRisksSummary, error) {
	result := &CryptoRisksSummary{}
	assets := map[uuid.UUID]*string{}
	err := s.readRisks(tenant, nil, "", func(r CryptoRisk) {
		prior, seen := assets[r.AssetID]
		if !seen || cryptoRiskRank(r.Severity) > cryptoRiskRank(prior) {
			assets[r.AssetID] = r.Severity
		}
		if slices.Contains(r.Categories, "protocol") {
			result.ProtocolIssues++
		}
		if slices.Contains(r.Categories, "algorithm") {
			result.AlgorithmIssues++
		}
		if slices.Contains(r.Categories, "key_size") {
			result.KeySizeIssues++
		}
	})
	if err != nil {
		return nil, err
	}
	for _, band := range assets {
		result.TotalAffected++
		if band == nil {
			result.Unscored++
			continue
		}
		switch *band {
		case string(severity.Critical):
			result.Critical++
		case string(severity.High):
			result.High++
		case string(severity.Medium):
			result.Medium++
		case string(severity.Low):
			result.Low++
		case string(severity.Info):
			result.Informational++
		}
	}
	// Preserve the existing certificate inventory counter (certificates, not
	// configuration rows); the mixed feed's expiry facet uses linked rows only.
	err = database.WithTenantTx(context.Background(), s.db, tenant, func(tx *sqlx.Tx) error {
		return tx.Get(&result.CertificateIssues, `SELECT COUNT(*) FROM certificates c WHERE c.tenant_id=$1 AND
   ((c.not_after IS NOT NULL AND c.not_after BETWEEN NOW() AND NOW()+INTERVAL '90 days')
    OR `+anyWeakKeySizeSQL("c.public_key_size", "c.public_key_algorithm")+`)`, tenant)
	})
	return result, err
}

// Retention requires an actual previous active finding, never just a positive
// legacy score. This read-only projection names its historical basis and does
// not extend producer lifecycle or write a new finding.
func retainCryptoRisk(r *CryptoRisk, c cryptoassess.Configuration, previous string) bool {
	judgment := c.Judge()
	if judgment.Emit() || len(judgment.Limitations) == 0 {
		return false
	}
	var prior *struct {
		Score    int    `json:"score"`
		Summary  string `json:"summary"`
		Evidence struct {
			Sources []string `json:"score_sources"`
		} `json:"evidence"`
	}
	if json.Unmarshal([]byte(previous), &prior) != nil || prior == nil {
		return false
	}
	r.AssessmentBasis = "retained_finding"
	r.AssessmentLimitations = append(append([]string{}, judgment.Limitations...), "Previously detected issue retained because current evidence cannot refute the prior assessment")
	r.Description = "Previous assessment: " + prior.Summary + ". Current evidence is insufficient to reassess this issue."
	r.Category = "algorithm"
	r.Categories = []string{"algorithm"}
	r.IssueType = "retained_configuration"
	r.Recommendation = "Refresh the configuration evidence to reassess the previously detected issue"
	r.ScoreSources = []string{}
	// Positive historical scores are retained as historical numbers; a legacy
	// zero without recorded numeric sources does not establish measured zero.
	if prior.Score > 0 || len(prior.Evidence.Sources) > 0 {
		r.RiskScore = &prior.Score
		r.Severity = cryptoRiskSeverity(riskbands.Severity(prior.Score))
		r.ScoreSources = []string{"retained finding score (historical assessment, not a current rule inference)"}
	}
	return true
}
