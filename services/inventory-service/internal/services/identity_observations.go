package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

type IdentityEnrichmentJob struct {
	ID            uuid.UUID  `json:"id"`
	Action        string     `json:"action"`
	ExecutorScope string     `json:"executor_scope"`
	State         string     `json:"state"`
	Reason        string     `json:"reason"`
	Attempts      int        `json:"attempts"`
	LastAttemptAt *time.Time `json:"last_attempt_at"`
	NextAttemptAt time.Time  `json:"next_attempt_at"`
}

type IdentityObservation struct {
	RetainedEvidence *RetainedEvidencePage   `json:"retained_evidence,omitempty"`
	EnrichmentJobs   []IdentityEnrichmentJob `json:"enrichment_jobs,omitempty"`
	ID               uuid.UUID               `json:"id"`
	SourceKind       string                  `json:"source_kind"`
	SourceRef        string                  `json:"source_ref"`
	CollectorVersion string                  `json:"collector_version"`
	NetworkScope     string                  `json:"network_scope"`
	Evidence         json.RawMessage         `json:"evidence"`
	AdmissionReasons []string                `json:"admission_reasons"`
	State            string                  `json:"state"`
	AssetID          *uuid.UUID              `json:"asset_id"`
	ProposalID       *uuid.UUID              `json:"proposal_id"`
	FirstSeenAt      time.Time               `json:"first_seen_at"`
	LastSeenAt       time.Time               `json:"last_seen_at"`
	OccurrenceCount  int64                   `json:"occurrence_count"`
	EnrichmentState  string                  `json:"enrichment_state"`
	EnrichmentReason string                  `json:"enrichment_reason"`
	LastAttemptAt    *time.Time              `json:"last_attempt_at"`
	NextAttemptAt    *time.Time              `json:"next_attempt_at"`
}

type IdentityObservationPage struct {
	Observations []IdentityObservation `json:"observations"`
	Total        int                   `json:"total"`
	Page         int                   `json:"page"`
	PageSize     int                   `json:"page_size"`
}

type IdentitySummary struct {
	Established       int `json:"established"`
	OperatorConfirmed int `json:"operator_confirmed"`
	Legacy            int `json:"legacy"`
	Unresolved        int `json:"unresolved"`
	Conflicted        int `json:"conflicted"`
}

func (s *AssetService) UsesIdentityAdmission(ctx context.Context, tenant uuid.UUID) (bool, error) {
	if _, err := s.identityEngine(); err != nil {
		return false, err
	}
	var mode string
	err := s.identityRepo.RunInTx(ctx, tenant.String(), func(repo *pgidentity.Repository) error {
		var err error
		mode, err = repo.AdmissionMode(ctx, tenant.String())
		return err
	})
	return mode == "enforce" || mode == "paused", err
}

const identityObservationColumns = `id,source_kind,source_ref,collector_version,network_scope,evidence,
 admission_reasons,state,asset_id,proposal_id,first_seen_at,last_seen_at,occurrence_count,
 enrichment_state,enrichment_reason,last_attempt_at,next_attempt_at`

func scanIdentityObservation(row interface{ Scan(...any) error }) (IdentityObservation, error) {
	var o IdentityObservation
	var reasons pq.StringArray
	err := row.Scan(&o.ID, &o.SourceKind, &o.SourceRef, &o.CollectorVersion, &o.NetworkScope, &o.Evidence,
		&reasons, &o.State, &o.AssetID, &o.ProposalID, &o.FirstSeenAt, &o.LastSeenAt, &o.OccurrenceCount,
		&o.EnrichmentState, &o.EnrichmentReason, &o.LastAttemptAt, &o.NextAttemptAt)
	o.AdmissionReasons = []string(reasons)
	if o.AdmissionReasons == nil {
		o.AdmissionReasons = []string{}
	}
	return o, err
}

func (s *AssetService) GetIdentityObservation(ctx context.Context, tenant, id uuid.UUID) (IdentityObservation, error) {
	var out IdentityObservation
	err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sqlx.Tx) error {
		var err error
		out, err = scanIdentityObservation(tx.QueryRowContext(ctx, `SELECT `+identityObservationColumns+` FROM identity_observations WHERE tenant_id=$1 AND id=$2`, tenant, id))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrObservationNotFound
		}
		if err != nil {
			return err
		}
		out.RetainedEvidence, err = s.retainedEvidence(ctx, tx, tenant, out)
		if err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT id,action,executor_scope,state,reason,attempts,last_attempt_at,next_attempt_at
   FROM identity_enrichment_jobs WHERE tenant_id=$1 AND observation_id=$2 ORDER BY created_at DESC,id LIMIT 100`, tenant, id)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		out.EnrichmentJobs = []IdentityEnrichmentJob{}
		for rows.Next() {
			var j IdentityEnrichmentJob
			if err := rows.Scan(&j.ID, &j.Action, &j.ExecutorScope, &j.State, &j.Reason, &j.Attempts, &j.LastAttemptAt, &j.NextAttemptAt); err != nil {
				return err
			}
			out.EnrichmentJobs = append(out.EnrichmentJobs, j)
		}
		return rows.Err()
	})
	return out, err
}

func (s *AssetService) IdentitySummary(ctx context.Context, tenant uuid.UUID) (IdentitySummary, error) {
	var out IdentitySummary
	err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sqlx.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT
		 count(*) FILTER(WHERE identity_status='established'),
		 count(*) FILTER(WHERE identity_status='operator_confirmed'),
		 count(*) FILTER(WHERE identity_status='legacy')
		 FROM assets WHERE tenant_id=$1 AND deleted_at IS NULL AND asset_status='monitoring'`, tenant).Scan(&out.Established, &out.OperatorConfirmed, &out.Legacy); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM identity_observations WHERE tenant_id=$1
		 AND state='unresolved' AND last_seen_at >= now()-interval '30 days'`, tenant).Scan(&out.Unresolved); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM assets a WHERE a.tenant_id=$1
		 AND a.deleted_at IS NULL AND a.asset_status NOT IN ('archived','denied') AND `+assetIdentityConflictSQL, tenant).Scan(&out.Conflicted)
	})
	return out, err
}

func (s *AssetService) ListIdentityObservations(ctx context.Context, tenant uuid.UUID, state string, page, size int, assetID *uuid.UUID) (IdentityObservationPage, error) {
	out := IdentityObservationPage{Observations: []IdentityObservation{}, Page: page, PageSize: size}
	if page < 1 || size < 1 || size > 100 {
		return out, fmt.Errorf("invalid observation pagination")
	}
	switch state {
	case "unresolved", "linked", "conflict", "dismissed", "expired", "all":
	default:
		return out, fmt.Errorf("invalid observation state")
	}
	where := `tenant_id=$1 AND ($2='all' OR state=$2) AND ($3::uuid IS NULL OR asset_id=$3)
	 AND ($2<>'unresolved' OR last_seen_at >= now()-interval '30 days')`
	err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sqlx.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM identity_observations WHERE `+where, tenant, state, assetID).Scan(&out.Total); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT `+identityObservationColumns+` FROM identity_observations WHERE `+where+
			` ORDER BY last_seen_at DESC,id LIMIT $4 OFFSET $5`, tenant, state, assetID, size, (page-1)*size)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			o, err := scanIdentityObservation(rows)
			if err != nil {
				return err
			}
			out.Observations = append(out.Observations, o)
		}
		return rows.Err()
	})
	return out, err
}
