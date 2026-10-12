package services

// The Crypto Risks readers over the persisted judgement.
//
// Every method opens ONE tenant transaction, re-judges the tenant's stale and
// due rows (normally none: the triggers mark only what changed and the
// background sweep keeps ahead), then reads crypto_risk_judgments joined to the
// live configuration, endpoint and asset rows. Filtering, ordering and paging
// are SQL; nothing here judges. The ordering and the filters reproduce the
// previous in-memory ones exactly -- crypto_risks_legacy_oracle_test.go keeps
// that implementation as the oracle and diffs it against these.

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/severity"
)

// maxCryptoRiskExport bounds one CSV export.
const maxCryptoRiskExport = 50000

// feedFromSQL is the visible feed: a judged, emitted configuration whose asset
// is live and monitored. Hostname, addresses, class and visibility come from
// the live rows, so asset edits need no invalidation of the judgement.
var feedFromSQL = ` FROM crypto_risk_judgments j
 JOIN crypto_implementations ci ON ci.id=j.crypto_implementation_id AND ci.tenant_id=j.tenant_id AND ci.deleted_at IS NULL
 LEFT JOIN asset_endpoints e ON e.id=ci.endpoint_id AND e.tenant_id=ci.tenant_id
 JOIN assets a ON a.id=` + findings.ConfigurationAssetSQL("ci", "e") + ` AND a.tenant_id=ci.tenant_id
  AND a.deleted_at IS NULL AND a.asset_status='monitoring'`

// feedWhere builds the WHERE clause and its arguments ($1 is the tenant).
func feedWhere(f CryptoRiskFilters, id *uuid.UUID) (string, []any) {
	args := []any{uuid.Nil}
	arg := func(v any) string { args = append(args, v); return fmt.Sprintf("$%d", len(args)) }
	where := " WHERE j.tenant_id=$1 AND j.emitted AND NOT j.stale"
	if id != nil {
		where += " AND j.crypto_implementation_id=" + arg(*id)
	}
	if len(f.Severity) > 0 {
		var wire []string
		unscored := false
		for _, value := range f.Severity {
			value = strings.ToLower(value)
			if value == "informational" {
				value = "info"
			}
			if value == "unscored" {
				unscored = true
			}
			wire = append(wire, value)
		}
		clause := "j.severity = ANY(" + arg(pq.Array(wire)) + ")"
		if unscored {
			clause += " OR j.severity IS NULL"
		}
		where += " AND (" + clause + ")"
	}
	if len(f.Category) > 0 {
		var categories []string
		for _, category := range f.Category {
			categories = append(categories, strings.ToLower(category))
		}
		where += " AND j.categories && " + arg(pq.Array(categories)) + "::text[]"
	}
	if f.Search != "" {
		// Each branch is a single-table ILIKE the trigram indexes serve; the
		// OR combines their (small) id sets instead of an OR across joined
		// tables, which no index can serve. Protocol is an enum, so its
		// matching labels are resolved first.
		pattern := arg("%" + f.Search + "%")
		where += ` AND (a.id IN (SELECT s.id FROM assets s WHERE s.tenant_id=$1 AND (s.hostname ILIKE ` + pattern + ` OR host(s.primary_address) ILIKE ` + pattern + `))
   OR e.id IN (SELECT s.id FROM asset_endpoints s WHERE s.tenant_id=$1 AND host(s.address) ILIKE ` + pattern + `)
   OR ci.id IN (SELECT s.id FROM crypto_implementations s WHERE s.tenant_id=$1 AND s.cipher_suite ILIKE ` + pattern + `)
   OR ci.protocol::text IN (SELECT t.enumlabel::text FROM pg_enum t WHERE t.enumtypid='protocol_type'::regtype AND t.enumlabel::text ILIKE ` + pattern + `))`
	}
	return where, args
}

// feedOrder reproduces the established ordering: a stable configuration id
// tie-breaker always last, unscored severity and missing hostnames always after
// scored/named rows whatever the direction, strings compared bytewise (as the
// previous in-memory comparison did), and a descending default.
func feedOrder(f CryptoRiskFilters) string {
	desc := strings.EqualFold(f.SortOrder, "DESC") || f.SortBy == ""
	dir := "ASC"
	if desc {
		dir = "DESC"
	}
	switch f.SortBy {
	case "hostname":
		return `a.hostname COLLATE "C" ` + dir + ` NULLS LAST, j.crypto_implementation_id`
	case "protocol":
		return `ci.protocol::text COLLATE "C" ` + dir + `, j.crypto_implementation_id`
	case "detected_at":
		return `ci.created_at ` + dir + `, j.crypto_implementation_id`
	}
	if desc {
		return `j.severity_rank DESC, j.crypto_implementation_id` // unscored is rank 0: last
	}
	return `(j.severity IS NULL), j.severity_rank ASC, j.crypto_implementation_id`
}

const feedColumnsSQL = `SELECT ci.id, ci.tenant_id, a.id, ci.protocol::text, ci.protocol_version, ci.cipher_suite, ci.created_at,
    a.hostname, host(a.primary_address), a.class_key, e.id, host(e.address), e.port,
    j.severity, j.risk_score, j.assessment_basis, j.assessment_limitations, j.score_sources, j.categories,
    j.category, j.issue_type, j.current_value, j.description, j.recommendation`

func scanFeedRow(rows *sql.Rows) (CryptoRisk, error) {
	var r CryptoRisk
	var limitations, sources, categories pq.StringArray
	if err := rows.Scan(&r.ID, &r.TenantID, &r.AssetID, &r.Protocol, &r.ProtocolVersion, &r.CipherSuite, &r.DetectedAt,
		&r.AssetHostname, &r.AssetIPAddress, &r.AssetClassKey, &r.EndpointID, &r.EndpointAddress, &r.EndpointPort,
		&r.Severity, &r.RiskScore, &r.AssessmentBasis, &limitations, &sources, &categories,
		&r.Category, &r.IssueType, &r.CurrentValue, &r.Description, &r.Recommendation); err != nil {
		return r, err
	}
	r.CryptoImplementationID = r.ID
	r.AssetPort = r.EndpointPort
	r.AssessmentLimitations = append([]string{}, limitations...)
	r.ScoreSources = append([]string{}, sources...)
	if len(categories) > 0 {
		r.Categories = append([]string{}, categories...)
	}
	return r, nil
}

// withFreshJudgments runs fn in a tenant transaction after re-judging whatever
// is stale or due (only `only` when set).
func (s *CryptoRisksService) withFreshJudgments(tenant uuid.UUID, only *uuid.UUID, fn func(*sqlx.Tx) error) error {
	return database.WithTenantTx(context.Background(), s.db, tenant, func(tx *sqlx.Tx) error {
		if _, err := refreshJudgments(tx, tenant, only, 0, time.Now()); err != nil {
			return err
		}
		return fn(tx)
	})
}

func (s *CryptoRisksService) page(tx *sqlx.Tx, tenant uuid.UUID, f CryptoRiskFilters, id *uuid.UUID, limit, offset int64) ([]CryptoRisk, error) {
	where, args := feedWhere(f, id)
	args[0] = tenant
	query := feedColumnsSQL + feedFromSQL + where + " ORDER BY " + feedOrder(f) +
		fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	rows, err := tx.Query(query, append(args, limit, offset)...)
	if err != nil {
		return nil, fmt.Errorf("query crypto risks: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []CryptoRisk{}
	for rows.Next() {
		r, err := scanFeedRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
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
	resp := &CryptoRisksResponse{Risks: []CryptoRisk{}, Page: f.Page, PageSize: f.PageSize}
	err := s.withFreshJudgments(tenant, nil, func(tx *sqlx.Tx) error {
		where, args := feedWhere(f, nil)
		args[0] = tenant
		if err := tx.Get(&resp.Total, `SELECT count(*)`+feedFromSQL+where, args...); err != nil {
			return fmt.Errorf("count crypto risks: %w", err)
		}
		if f.Page > math.MaxInt64/f.PageSize { // beyond any row: an empty page, as before
			return nil
		}
		rows, err := s.page(tx, tenant, f, nil, int64(f.PageSize), int64(f.Page-1)*int64(f.PageSize))
		resp.Risks = rows
		return err
	})
	if err != nil {
		return nil, err
	}
	resp.TotalPages = (resp.Total + f.PageSize - 1) / f.PageSize
	return resp, nil
}

// ExportRisks returns the filtered feed in list order, up to maxCryptoRiskExport rows.
func (s *CryptoRisksService) ExportRisks(tenant uuid.UUID, f CryptoRiskFilters) ([]CryptoRisk, error) {
	var out []CryptoRisk
	err := s.withFreshJudgments(tenant, nil, func(tx *sqlx.Tx) error {
		var err error
		out, err = s.page(tx, tenant, f, nil, maxCryptoRiskExport, 0)
		return err
	})
	return out, err
}

func (s *CryptoRisksService) GetRiskByID(tenant, id uuid.UUID) (*CryptoRisk, error) {
	var result *CryptoRisk
	err := s.withFreshJudgments(tenant, &id, func(tx *sqlx.Tx) error {
		rows, err := s.page(tx, tenant, CryptoRiskFilters{}, &id, 1, 0)
		if len(rows) > 0 {
			result = &rows[0]
		}
		return err
	})
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
	err := s.withFreshJudgments(tenant, nil, func(tx *sqlx.Tx) error {
		// An asset is banded by its worst configuration; unscored (rank 0) is
		// below every scored rank, so it only counts when nothing else does.
		rows, err := tx.Query(`SELECT r, count(*) FROM (SELECT a.id, max(j.severity_rank) AS r`+feedFromSQL+
			` WHERE j.tenant_id=$1 AND j.emitted AND NOT j.stale GROUP BY a.id) per_asset GROUP BY r`, tenant)
		if err != nil {
			return fmt.Errorf("summarise crypto risks: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var rank, n int
			if err := rows.Scan(&rank, &n); err != nil {
				return err
			}
			result.TotalAffected += n
			switch rank {
			case 0:
				result.Unscored += n
			default:
				for _, d := range severity.Definitions() {
					if d.Rank != rank {
						continue
					}
					switch d.Value {
					case severity.Critical:
						result.Critical += n
					case severity.High:
						result.High += n
					case severity.Medium:
						result.Medium += n
					case severity.Low:
						result.Low += n
					case severity.Info:
						result.Informational += n
					}
				}
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		_ = rows.Close()
		if err := tx.QueryRow(`SELECT
   count(*) FILTER (WHERE 'protocol' = ANY(j.categories)),
   count(*) FILTER (WHERE 'algorithm' = ANY(j.categories)),
   count(*) FILTER (WHERE 'key_size' = ANY(j.categories))`+feedFromSQL+
			` WHERE j.tenant_id=$1 AND j.emitted AND NOT j.stale`, tenant).
			Scan(&result.ProtocolIssues, &result.AlgorithmIssues, &result.KeySizeIssues); err != nil {
			return fmt.Errorf("count crypto risk categories: %w", err)
		}
		// Preserve the existing certificate inventory counter (certificates, not
		// configuration rows); the mixed feed's expiry facet uses linked rows only.
		return tx.Get(&result.CertificateIssues, `SELECT COUNT(*) FROM certificates c WHERE c.tenant_id=$1 AND
   ((c.not_after IS NOT NULL AND c.not_after BETWEEN NOW() AND NOW()+INTERVAL '90 days')
    OR `+anyWeakKeySizeSQL("c.public_key_size", "c.public_key_algorithm")+`)`, tenant)
	})
	return result, err
}
