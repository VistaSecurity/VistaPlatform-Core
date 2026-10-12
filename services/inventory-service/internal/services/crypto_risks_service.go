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
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/cryptoassess"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
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
