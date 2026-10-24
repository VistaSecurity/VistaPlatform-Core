package producers

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"

	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer"
	"github.com/vistasecurity/vistaplatform/shared/riskbands"
)

// AtRestProducer raises `crypto/unencrypted_at_rest` and claims crypto
// coverage for the assets whose cryptography is entirely at rest.
//
// Its input is `crypto_applications` (encryption_context `at_rest`): one row per
// cloud storage or database resource, written at ingest by
// produceAtRestApplication with the measured posture in configuration_data —
// `encryption_determined` and `encrypted`. Before this pass those rows were
// read only by the Data Protection lens, so an S3 bucket carried a verdict that
// never reached its asset: no finding, no coverage, and the dashboard read it
// "Not assessed" every night.
//
// # What it raises
//
// A finding only when a resource is DETERMINED and NOT encrypted. Encrypted is
// clean whoever holds the key: provider-managed versus customer-managed stays a
// Data Protection lens distinction, not a risk score (owner decision,
//. The score is the algorithms catalogue's AT-REST-PLAINTEXT row
// (CLAUDE.md "The catalogue drives risk scoring"): edit the row, not this
// file. Without the row there is nothing to score by, so the pass raises
// nothing for an unencrypted record and does not claim its asset — counted as
// Unscorable, never read as clean. The subject is the asset, so several
// unencrypted records on one asset are one finding whose evidence names each.
//
// # What it claims (MarkAssessed)
//
// Coverage on the crypto producer's key, but only for an asset whose at-rest
// records are ALL determined and which has NO live crypto configuration. That
// asset's whole crypto surface is what this pass read, so "assessed by crypto"
// is true of it. An asset that also has configurations is the main crypto
// pass's to claim — judging its storage says nothing about its TLS — and an
// undetermined record (AccessDenied on GetBucketEncryption) means nothing was
// measured, which must read "Not assessed", not clean. Marking generously is
// the failure mode (producer.MarkAssessed).
//
// It writes through its own crypto-producer Writer and sweeps only its own
// kind, so it cannot resolve the crypto or wireless passes' rows.
type AtRestProducer struct {
	db     *sql.DB
	writer *producer.Writer
}

// NewAtRestProducer builds the producer over the RLS-subject handle.
func NewAtRestProducer(appDB *sql.DB) (*AtRestProducer, error) {
	w, err := producer.New(findings.ProducerCrypto)
	if err != nil {
		return nil, err
	}
	return &AtRestProducer{db: appDB, writer: w}, nil
}

// AtRestRun is one pass over one tenant.
type AtRestRun struct {
	Raised   int
	Resolved int
	// Records is how many at-rest records the pass read; Undetermined how many
	// had no measured encryption state; Assessed how many assets it claimed.
	Records      int
	Undetermined int
	Assessed     int
	// Unscorable is how many unencrypted records went unraised because the
	// catalogue has no AT-REST-PLAINTEXT row to score them by.
	Unscorable int
}

// atRestPlaintextAlgorithm is the catalogue row that scores unencrypted data
// at rest (scripts/database/seed.sql).
const atRestPlaintextAlgorithm = "AT-REST-PLAINTEXT"

type atRestRecord struct {
	ResourceType string
	Identifier   string
	Name         string
}

// atRestRecordsSQL reads every live at-rest record on a live asset. The two
// flags are compared as jsonb, never cast: `::boolean` on a value a future
// writer spells differently would abort the whole tenant's pass.
const atRestRecordsSQL = `
	SELECT ca.asset_id, ca.resource_type, ca.resource_identifier, COALESCE(ca.resource_name, ''),
	       COALESCE(ca.configuration_data -> 'encryption_determined' = 'true'::jsonb, false) AS determined,
	       COALESCE(ca.configuration_data -> 'encrypted' = 'true'::jsonb, false) AS encrypted,
	       COALESCE(NULLIF(a.display_name, ''), NULLIF(a.hostname, ''), a.id::text) AS label,
	       EXISTS (SELECT 1 FROM crypto_implementations ci
	                WHERE ci.tenant_id = a.tenant_id AND ci.asset_id = a.id AND ci.deleted_at IS NULL) AS has_configurations
	  FROM crypto_applications ca
	  JOIN assets a ON a.tenant_id = ca.tenant_id AND a.id = ca.asset_id AND a.deleted_at IS NULL
	 WHERE ca.tenant_id = $1 AND ca.deleted_at IS NULL AND ca.encryption_context = 'at_rest'
	 ORDER BY ca.asset_id, ca.resource_identifier`

// Run judges every at-rest record of the tenant in one transaction.
func (p *AtRestProducer) Run(ctx context.Context, tenantID uuid.UUID) (AtRestRun, error) {
	var run AtRestRun
	err := shareddatabase.WithTenantTx(ctx, p.db, tenantID, func(tx *sql.Tx) error {
		var catalogueScore sql.NullInt64
		err := tx.QueryRowContext(ctx, `SELECT risk_score FROM algorithms WHERE code = $1`, atRestPlaintextAlgorithm).
			Scan(&catalogueScore)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		rows, err := tx.QueryContext(ctx, atRestRecordsSQL, tenantID)
		if err != nil {
			return err
		}
		type assetGroup struct {
			label         string
			hasConfigs    bool
			allDetermined bool
			unencrypted   []atRestRecord
		}
		groups := map[uuid.UUID]*assetGroup{}
		for rows.Next() {
			var (
				assetID              uuid.UUID
				rec                  atRestRecord
				determined, enc, cfg bool
				label                string
			)
			if err := rows.Scan(&assetID, &rec.ResourceType, &rec.Identifier, &rec.Name, &determined, &enc, &label, &cfg); err != nil {
				_ = rows.Close()
				return err
			}
			run.Records++
			g := groups[assetID]
			if g == nil {
				g = &assetGroup{label: label, hasConfigs: cfg, allDetermined: true}
				groups[assetID] = g
			}
			if !determined {
				run.Undetermined++
				g.allDetermined = false
				continue
			}
			if !enc {
				g.unencrypted = append(g.unencrypted, rec)
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		_ = rows.Close()

		ids := make([]uuid.UUID, 0, len(groups))
		for id := range groups {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })

		var (
			seen     []producer.Subject
			assessed []uuid.UUID
		)
		for _, assetID := range ids {
			g := groups[assetID]
			scorable := len(g.unencrypted) == 0 || catalogueScore.Valid
			if !scorable {
				run.Unscorable += len(g.unencrypted)
			}
			if g.allDetermined && !g.hasConfigs && scorable {
				assessed = append(assessed, assetID)
			}
			if len(g.unencrypted) == 0 || !scorable {
				continue
			}
			score := int(catalogueScore.Int64)
			subject := producer.Subject{Type: findings.SubjectAsset, ID: assetID}
			evidence := make([]any, 0, len(g.unencrypted))
			names := make([]string, 0, len(g.unencrypted))
			for _, r := range g.unencrypted {
				evidence = append(evidence, map[string]any{
					"resource_type": r.ResourceType, "resource_identifier": r.Identifier, "resource_name": r.Name,
				})
				names = append(names, firstNonBlank(r.Name, r.Identifier))
			}
			detail := "stores data unencrypted at rest"
			if len(names) > 1 || (len(names) == 1 && names[0] != g.label) {
				detail += ": " + strings.Join(names, ", ")
			}
			if _, err := p.writer.Upsert(ctx, tx, tenantID, producer.Finding{
				Kind:         findings.KindUnencryptedAtRest,
				Subject:      subject,
				SubjectLabel: g.label,
				Severity:     string(riskbands.Severity(score)),
				Score:        score,
				Summary:      g.label + " " + detail,
				Evidence:     map[string]any{"at_rest_records": evidence, "algorithm": atRestPlaintextAlgorithm},
			}); err != nil {
				return err
			}
			run.Raised++
			seen = append(seen, subject)
		}
		n, err := p.writer.Sweep(ctx, tx, tenantID, findings.KindUnencryptedAtRest, seen)
		if err != nil {
			return err
		}
		run.Resolved = n
		if len(assessed) > 0 {
			if _, err := p.writer.MarkAssessed(ctx, tx, tenantID, assessed); err != nil {
				return err
			}
		}
		run.Assessed = len(assessed)
		return nil
	})
	if err != nil {
		return AtRestRun{}, fmt.Errorf("at-rest producer: tenant %s: %w", tenantID, err)
	}
	return run, nil
}

func firstNonBlank(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
