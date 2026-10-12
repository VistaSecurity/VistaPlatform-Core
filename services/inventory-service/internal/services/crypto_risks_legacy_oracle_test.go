package services

// The pre- implementation of the Crypto Risks readers, kept verbatim as
// the ORACLE the persisted-judgement readers are diffed against: one query over
// every configuration of the tenant, every row judged in Go, filtered, sorted
// and paged in memory. It is test-only on purpose; production reads the
// persisted judgement (crypto_risk_judgments).

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
	"github.com/vistasecurity/vistaplatform/shared/severity"
)

// legacyReadRisks streams candidates in one tenant transaction. SQL restricts identity,
// lifecycle and search; the same pure judge used by CryptoProducer determines
// eligibility before filtering/counting/paging. No producer writes occur on GET.
func (s *CryptoRisksService) legacyReadRisks(tenant uuid.UUID, id *uuid.UUID, search string, visit func(CryptoRisk)) error {
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

func legacyMatches(r CryptoRisk, f CryptoRiskFilters) bool {
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

// legacyBefore always ends with the stable configuration ID tie-breaker, so
// rows with equal scores/timestamps cannot move between pages or duplicate CSV.
func legacyBefore(a, b CryptoRisk, f CryptoRiskFilters) bool {
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

type legacySelection struct {
	rows    []CryptoRisk
	filters CryptoRiskFilters
}

func (h legacySelection) Len() int { return len(h.rows) }
func (h legacySelection) Less(i, j int) bool {
	return legacyBefore(h.rows[j], h.rows[i], h.filters)
}
func (h legacySelection) Swap(i, j int) { h.rows[i], h.rows[j] = h.rows[j], h.rows[i] }
func (h *legacySelection) Push(v any)   { h.rows = append(h.rows, v.(CryptoRisk)) }
func (h *legacySelection) Pop() any {
	n := len(h.rows) - 1
	v := h.rows[n]
	h.rows = h.rows[:n]
	return v
}

func (s *CryptoRisksService) legacySelectRisks(tenant uuid.UUID, f CryptoRiskFilters, keep int) ([]CryptoRisk, int, error) {
	selected := &legacySelection{filters: f}
	total := 0
	err := s.legacyReadRisks(tenant, nil, f.Search, func(r CryptoRisk) {
		if !legacyMatches(r, f) {
			return
		}
		total++
		if len(selected.rows) < keep {
			heap.Push(selected, r)
		} else if keep > 0 && legacyBefore(r, selected.rows[0], f) {
			selected.rows[0] = r
			heap.Fix(selected, 0)
		}
	})
	sort.Slice(selected.rows, func(i, j int) bool { return legacyBefore(selected.rows[i], selected.rows[j], f) })
	return selected.rows, total, err
}

func (s *CryptoRisksService) legacyListRisks(tenant uuid.UUID, f CryptoRiskFilters) (*CryptoRisksResponse, error) {
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
	rows, total, err := s.legacySelectRisks(tenant, f, keep)
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

// legacyExportRisks evaluates once rather than repeating a tenant scan for every page.
func (s *CryptoRisksService) legacyExportRisks(tenant uuid.UUID, f CryptoRiskFilters) ([]CryptoRisk, error) {
	rows, _, err := s.legacySelectRisks(tenant, f, 50000)
	return rows, err
}
func (s *CryptoRisksService) legacyGetRiskByID(tenant, id uuid.UUID) (*CryptoRisk, error) {
	var result *CryptoRisk
	err := s.legacyReadRisks(tenant, &id, "", func(r CryptoRisk) { result = &r })
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, sql.ErrNoRows
	}
	return result, nil
}
func (s *CryptoRisksService) legacyGetSummary(tenant uuid.UUID) (*CryptoRisksSummary, error) {
	result := &CryptoRisksSummary{}
	assets := map[uuid.UUID]*string{}
	err := s.legacyReadRisks(tenant, nil, "", func(r CryptoRisk) {
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
