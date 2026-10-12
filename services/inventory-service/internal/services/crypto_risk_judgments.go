package services

// The persisted crypto risk judgement.
//
// `crypto_risk_judgments` keeps, per configuration, what the Go judge
// (cryptoassess.Configuration.Judge plus certificate lifecycle policy) decided,
// so the Crypto Risks list, summary and export page, sort and filter in SQL
// instead of re-judging the tenant's whole estate on every request.
//
// The table is derived and self-invalidating. Database triggers mark a row
// stale when ANY input of the judge changes (the configuration, its catalogue
// components, the catalogue rows themselves, its certificates, the prior crypto
// finding), and valid_until marks the next instant a certificate-lifecycle
// boundary or the "expires in N days" text would change. Every reader re-judges
// the stale and due rows first, inside its own transaction, so a read is
// always current; the background sweep only makes that normally a no-op.
//
// The judge itself is UNCHANGED and shared: judgeConfiguration is the code the
// per-request readers used to run, now run on the write side.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/cryptoassess"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/severity"
)

// judgedConfigurations counts judgeConfiguration calls, so a test can show that a
// warm read judges nothing and a changed configuration is judged once.
var judgedConfigurations atomic.Int64

// cryptoRiskRefreshBatch is how many stale rows one re-judge statement set covers.
const cryptoRiskRefreshBatch = 500

// judgeInputsSQL reads every input of the judge for the configurations in $4.
// $1 tenant, $2 catalogue roles, $3 the judge's clock (certificate expiry is
// "the earliest not_after after $3").
const judgeInputsSQL = `SELECT ci.id, ci.tenant_id, ci.protocol::text,
    ci.protocol_version, ci.cipher_suite, COALESCE(ci.key_exchange_algorithm,''),
    COALESCE(ci.key_size,0), COALESCE(ci.hash_algorithm,''), COALESCE(ci.signature_algorithm,''),
    COALESCE(ci.symmetric_encryption,''), COALESCE(ci.risk_score,0),
    cat.max_risk, COALESCE(cat.components,'[]'::jsonb)::text, cert.expiry, COALESCE(prior.fact,'null'::jsonb)::text
   FROM crypto_implementations ci
   LEFT JOIN LATERAL (
    SELECT MAX(alg.risk_score) AS max_risk,
     jsonb_agg(jsonb_build_object('code',alg.code,'role',cia.algorithm_type,
      'strength',alg.strength,'risk_score',alg.risk_score) ORDER BY alg.code,cia.algorithm_type) AS components
    FROM crypto_implementation_algorithms cia JOIN algorithms alg ON alg.id=cia.algorithm_id
    WHERE cia.crypto_implementation_id=ci.id AND cia.algorithm_type=ANY($2)
   ) cat ON true
   LEFT JOIN LATERAL (
    SELECT MIN(c.not_after) FILTER (WHERE c.not_after>$3) AS expiry
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
   WHERE ci.tenant_id=$1 AND ci.deleted_at IS NULL AND ci.id = ANY($4)`

// judgeInputs is one configuration's judge inputs, as judgeInputsSQL reads them.
type judgeInputs struct {
	ID, Tenant      uuid.UUID
	Protocol        string
	ProtocolVersion *string
	CipherSuite     *string
	Config          cryptoassess.Configuration
	Components      string
	Expiry          *time.Time
	Previous        string
}

func (in *judgeInputs) scanTargets() []any {
	return []any{&in.ID, &in.Tenant, &in.Protocol, &in.ProtocolVersion, &in.CipherSuite,
		&in.Config.KeyAlgorithm, &in.Config.KeyBits, &in.Config.Hash, &in.Config.Signature,
		&in.Config.Symmetric, &in.Config.StoredRisk, &in.Config.CatalogueRisk, &in.Components, &in.Expiry, &in.Previous}
}

// readJudgeInputs loads the inputs for ids (live configurations only).
func readJudgeInputs(tx *sqlx.Tx, tenant uuid.UUID, ids []uuid.UUID, now time.Time) ([]judgeInputs, error) {
	rows, err := tx.Query(judgeInputsSQL, tenant, pq.Array(cryptoassess.CatalogueRiskRoles), now, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("read crypto risk judge inputs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []judgeInputs
	for rows.Next() {
		var in judgeInputs
		if err := rows.Scan(in.scanTargets()...); err != nil {
			return nil, err
		}
		if in.ProtocolVersion != nil {
			in.Config.Version = *in.ProtocolVersion
		}
		if in.CipherSuite != nil {
			in.Config.Suite = *in.CipherSuite
		}
		in.Config.Components = []byte(in.Components)
		var prior struct {
			Score    *int            `json:"score"`
			Evidence json.RawMessage `json:"evidence"`
		}
		if json.Unmarshal([]byte(in.Previous), &prior) == nil {
			in.Config.PreviousEvidence = prior.Evidence
			in.Config.PreviousScore = prior.Score
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// judgeConfiguration is THE judge of one configuration at `now`: the current
// assessment, the retained historical one, and their merge. It sets only the
// judged fields of the returned CryptoRisk; ok is false when the configuration
// is not in the feed at all.
func judgeConfiguration(in judgeInputs, now time.Time) (r CryptoRisk, ok bool) {
	judgedConfigurations.Add(1)
	r.ID = in.ID
	r.CryptoImplementationID = in.ID
	r.TenantID = in.Tenant
	historical := r
	retained := retainCryptoRisk(&historical, in.Config, in.Previous)
	current := classifyConfigurationRisk(&r, in.Config, in.Expiry, now)
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
		return r, true
	}
	return r, false
}

// judgmentValidUntil is the first instant after now at which re-judging the
// configuration could give a different answer without any input changing: the
// certificate lifecycle windows (90 and 30 days) and the whole-day count in the
// "expires in N days" text all turn at expiry - k*24h. nil when no unexpired
// certificate makes the judgement time-dependent.
func judgmentValidUntil(expiry *time.Time, now time.Time) *time.Time {
	if expiry == nil || !expiry.After(now) {
		return nil
	}
	remaining := expiry.Sub(now)
	var next time.Time
	if remaining > 90*24*time.Hour {
		next = expiry.Add(-90 * 24 * time.Hour)
	} else {
		days := int(remaining.Hours() / 24)
		next = expiry.Add(-time.Duration(days) * 24 * time.Hour)
	}
	if !next.After(now) {
		next = now.Add(time.Second)
	}
	return &next
}

const persistJudgmentSQL = `UPDATE crypto_risk_judgments SET stale=false, judged_at=$2, valid_until=$3,
    emitted=$4, severity=$5, severity_rank=$6, risk_score=$7, assessment_basis=$8,
    assessment_limitations=$9, score_sources=$10, categories=$11, category=$12, issue_type=$13,
    current_value=$14, description=$15, recommendation=$16
 WHERE crypto_implementation_id=$1`

func persistJudgment(tx *sqlx.Tx, id uuid.UUID, r CryptoRisk, emitted bool, validUntil *time.Time, now time.Time) error {
	rank := 0
	if r.Severity != nil {
		if canonical, err := severity.Parse(*r.Severity); err == nil {
			rank, _ = severity.Rank(canonical)
		}
	}
	nonNil := func(s []string) []string {
		if s == nil {
			return []string{}
		}
		return s
	}
	_, err := tx.Exec(persistJudgmentSQL, id, now, validUntil, emitted, r.Severity, rank, r.RiskScore,
		r.AssessmentBasis, pq.Array(nonNil(r.AssessmentLimitations)), pq.Array(nonNil(r.ScoreSources)),
		pq.Array(nonNil(r.Categories)), r.Category, r.IssueType, r.CurrentValue, r.Description, r.Recommendation)
	return err
}

// refreshJudgments re-judges, inside tx, the tenant's stale and due rows (only
// `only` when set), at most limit rows (0 = all), and returns how many it
// judged. It takes the rows' locks BEFORE it reads the inputs, in separate
// statements: an input change commits together with the trigger that marks its
// row stale, and that UPDATE queues behind this transaction's lock, so a change
// that lands after the inputs were read is marked stale again afterwards instead
// of being overwritten as fresh.
func refreshJudgments(tx *sqlx.Tx, tenant uuid.UUID, only *uuid.UUID, limit int, now time.Time) (int, error) {
	if only == nil {
		if _, err := tx.Exec(`UPDATE crypto_risk_judgments SET stale=true
 WHERE tenant_id=$1 AND valid_until IS NOT NULL AND valid_until <= $2 AND NOT stale`, tenant, now); err != nil {
			return 0, fmt.Errorf("mark due crypto risk judgments: %w", err)
		}
	} else if _, err := tx.Exec(`UPDATE crypto_risk_judgments SET stale=true
 WHERE tenant_id=$1 AND crypto_implementation_id=$3 AND valid_until IS NOT NULL AND valid_until <= $2 AND NOT stale`,
		tenant, now, *only); err != nil {
		return 0, fmt.Errorf("mark due crypto risk judgment: %w", err)
	}
	total := 0
	for limit == 0 || total < limit {
		batch := cryptoRiskRefreshBatch
		if limit > 0 && limit-total < batch {
			batch = limit - total
		}
		var only2 uuid.UUID
		if only != nil {
			only2 = *only
		}
		var ids []uuid.UUID
		err := tx.Select(&ids, `SELECT crypto_implementation_id FROM crypto_risk_judgments
 WHERE tenant_id=$1 AND stale AND ($3::uuid IS NULL OR crypto_implementation_id=$3)
 ORDER BY crypto_implementation_id LIMIT $2 FOR UPDATE`, tenant, batch, judgmentOnlyArg(only2))
		if err != nil {
			return total, fmt.Errorf("lock stale crypto risk judgments: %w", err)
		}
		if len(ids) == 0 {
			return total, nil
		}
		inputs, err := readJudgeInputs(tx, tenant, ids, now)
		if err != nil {
			return total, err
		}
		seen := make(map[uuid.UUID]bool, len(inputs))
		for _, in := range inputs {
			seen[in.ID] = true
			r, emitted := judgeConfiguration(in, now)
			if err := persistJudgment(tx, in.ID, r, emitted, judgmentValidUntil(in.Expiry, now), now); err != nil {
				return total, fmt.Errorf("persist crypto risk judgment: %w", err)
			}
		}
		for _, id := range ids {
			if !seen[id] { // soft-deleted or gone: nothing to judge, nothing to show
				if err := persistJudgment(tx, id, CryptoRisk{}, false, nil, now); err != nil {
					return total, fmt.Errorf("persist crypto risk judgment: %w", err)
				}
			}
		}
		total += len(ids)
		if len(ids) < batch {
			return total, nil
		}
	}
	return total, nil
}

// SweepJudgments re-judges up to limit of the tenant's stale or due rows, one
// bounded transaction per batch, and reports how many it judged. It is what the
// background job runs (it also back-fills every row the schema upgrade created
// stale), so the request path normally finds nothing left to do.
func (s *CryptoRisksService) SweepJudgments(ctx context.Context, tenant uuid.UUID, limit int) (int, error) {
	done := 0
	for done < limit {
		n := 0
		err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sqlx.Tx) error {
			var err error
			n, err = refreshJudgments(tx, tenant, nil, min(cryptoRiskRefreshBatch, limit-done), time.Now())
			return err
		})
		if err != nil {
			return done, err
		}
		done += n
		if n == 0 {
			break
		}
	}
	if done > 0 {
		slog.Info("crypto risk judgments refreshed", "tenant", tenant, "rows", done)
	}
	return done, nil
}

func judgmentOnlyArg(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}
