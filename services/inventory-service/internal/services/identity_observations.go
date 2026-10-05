package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/identityenrichment"
	"github.com/vistasecurity/vistaplatform/shared/identity"
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

// IdentityObservationObserver is the collector the evidence CAME from, and why
// it can or cannot reach the network the evidence is about ( D7).
//
// SensorID is nullable because not every observation has a sensor observer: a
// cloud collector or a device interrogation produced the evidence just the
// same, and reporting uuid.Nil there would read as "sensor 0000…" in the UI.
type IdentityObservationObserver struct {
	SensorID  *uuid.UUID `json:"sensor_id"`
	Name      string     `json:"name"`
	Reachable bool       `json:"reachable"`
	Reason    string     `json:"reason"`
}

// IdentityObservationExecutor is the collector that WOULD run enrichment work
// for this observation — not necessarily the observer ( D4).
type IdentityObservationExecutor struct {
	SensorID uuid.UUID `json:"sensor_id"`
	Name     string    `json:"name"`
}

// IdentityObservationCollector is the whole collector story for one
// observation: who heard it, who can act on it, and what is in the way.
//
// It is null when the observation's network cannot be resolved to a configured
// segment at all. There is no collector answer to give in that case, and
// inventing one ("no collector reaches ...") would name a network the tenant
// never configured.
type IdentityObservationCollector struct {
	Executor *IdentityObservationExecutor `json:"executor"`
	Observer IdentityObservationObserver  `json:"observer"`
	Reason   string                       `json:"reason"`
}

type IdentityObservation struct {
	RetainedEvidence *RetainedEvidencePage         `json:"retained_evidence,omitempty"`
	EnrichmentJobs   []IdentityEnrichmentJob       `json:"enrichment_jobs,omitempty"`
	Collector        *IdentityObservationCollector `json:"collector"`
	ID               uuid.UUID                     `json:"id"`
	SourceKind       string                        `json:"source_kind"`
	SourceRef        string                        `json:"source_ref"`
	CollectorVersion string                        `json:"collector_version"`
	NetworkScope     string                        `json:"network_scope"`
	Evidence         json.RawMessage               `json:"evidence"`
	AdmissionReasons []string                      `json:"admission_reasons"`
	State            string                        `json:"state"`
	AssetID          *uuid.UUID                    `json:"asset_id"`
	ProposalID       *uuid.UUID                    `json:"proposal_id"`
	FirstSeenAt      time.Time                     `json:"first_seen_at"`
	LastSeenAt       time.Time                     `json:"last_seen_at"`
	OccurrenceCount  int64                         `json:"occurrence_count"`
	EnrichmentState  string                        `json:"enrichment_state"`
	EnrichmentReason string                        `json:"enrichment_reason"`
	LastAttemptAt    *time.Time                    `json:"last_attempt_at"`
	NextAttemptAt    *time.Time                    `json:"next_attempt_at"`

	// The review table's fields, resolved server-side so the UI never
	// joins a UUID to a name or re-derives what a row needs.
	//
	// NetworkName is the configured segment's name for NetworkScope, null when
	// the scope is the tenant default or names no segment of this tenant.
	NetworkName *string `json:"network_name"`
	// SourceName is the collector's name for a `sensor:<id>`-shaped SourceRef,
	// else a fixed label for the kind of source. Never the raw ref.
	SourceName      string                         `json:"source_name"`
	Needs           string                         `json:"needs"`
	SuggestedAction string                         `json:"suggested_action"`
	ExplanationCode string                         `json:"explanation_code"`
	SuggestedReason string                         `json:"suggested_reason"`
	Summary         []ObservationIdentifierSummary `json:"summary"`
	// LinkAsset is the one existing asset that owns an identifier of this
	// observation, set exactly when `suggested_action` is `link`.
	LinkAsset *ObservationOwner `json:"link_asset"`
	// EvidenceHeld is true for supporting evidence the engine linked to an
	// established asset but attached nothing from (platform ADR-0003 D2):
	// its endpoints are listed in the evidence and are NOT on the asset.
	// Linking it to that asset (or confirming it) attaches them.
	EvidenceHeld bool `json:"evidence_held"`
}

// ObservationNeedsCounts are the chip badges: the tenant's UNRESOLVED
// observations in the active 30-day window, by needs, whatever the current
// filter is.
type ObservationNeedsCounts struct {
	ReadyToConfirm int `json:"ready_to_confirm"`
	LinkExisting   int `json:"link_existing"`
	NeedsReview    int `json:"needs_review"`
	NeedsNetwork   int `json:"needs_network"`
	NeedsSensor    int `json:"needs_sensor"`
	LikelyNoise    int `json:"likely_noise"`
	All            int `json:"all"`
}

type IdentityObservationPage struct {
	Observations []IdentityObservation `json:"observations"`
	Total        int                   `json:"total"`
	Page         int                   `json:"page"`
	PageSize     int                   `json:"page_size"`
	// Counts is filled by the list endpoint.
	Counts *ObservationNeedsCounts `json:"counts,omitempty"`
}

// ObservationListFilter is the list endpoint's query. The zero Sort is
// last_seen_desc.
type ObservationListFilter struct {
	State        string
	Page         int
	PageSize     int
	AssetID      *uuid.UUID
	Needs        []string
	NetworkScope string
	Source       string
	Query        string
	Sort         string
}

type IdentitySummary struct {
	AdmissionMode     string `json:"admission_mode,omitempty"`
	Established       int    `json:"established"`
	OperatorConfirmed int    `json:"operator_confirmed"`
	Legacy            int    `json:"legacy"`
	Unresolved        int    `json:"unresolved"`
	Conflicted        int    `json:"conflicted"`
	// Provisional counts inventory items the platform inferred from an
	// advertisement and nothing has corroborated yet ( D1).
	//
	// It is NOT part of the three monitored-identity counts above and is
	// deliberately counted differently: those are `asset_status='monitoring'`,
	// because they answer "how well do we know the inventory we watch". A
	// provisional item is `pending_approval` by construction, so counting it
	// the same way would always report zero.
	Provisional int `json:"provisional"`
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

// identityObservationColumns are read through observationReadFrom, which joins
// the segment and the collector so a page resolves its names in the same
// tenant-scoped statement as its rows: no query per row, and a name can only
// come from a row the tenant's own predicate (and RLS) admits. The join keys
// also carry tenant_id, so a scope or source_ref naming ANOTHER tenant's
// segment or sensor finds nothing rather than that tenant's name.
const identityObservationColumns = `o.id,o.source_kind,o.source_ref,o.collector_version,o.network_scope,o.evidence,
 o.admission_reasons,o.state,o.asset_id,o.proposal_id,o.first_seen_at,o.last_seen_at,o.occurrence_count,
 o.enrichment_state,o.enrichment_reason,o.last_attempt_at,o.next_attempt_at,ns.name,s.name,
 (o.state='linked' AND o.resolution_outcome IS NOT DISTINCT FROM 'supporting'),
 ` + observationOwnersJSONSQL

const observationReadFrom = ` FROM identity_observations o
 LEFT JOIN network_segments ns ON ns.tenant_id=o.tenant_id AND ns.id::text=o.network_scope
 LEFT JOIN sensors s ON s.tenant_id=o.tenant_id AND s.id::text=(regexp_match(o.source_ref, ` + sourceSensorRefSQL + `))[1]`

func scanIdentityObservation(row interface{ Scan(...any) error }, now time.Time) (IdentityObservation, error) {
	var o IdentityObservation
	var reasons pq.StringArray
	var networkName, sensorName sql.NullString
	var ownersJSON []byte
	err := row.Scan(&o.ID, &o.SourceKind, &o.SourceRef, &o.CollectorVersion, &o.NetworkScope, &o.Evidence,
		&reasons, &o.State, &o.AssetID, &o.ProposalID, &o.FirstSeenAt, &o.LastSeenAt, &o.OccurrenceCount,
		&o.EnrichmentState, &o.EnrichmentReason, &o.LastAttemptAt, &o.NextAttemptAt, &networkName, &sensorName, &o.EvidenceHeld, &ownersJSON)
	o.AdmissionReasons = []string(reasons)
	if o.AdmissionReasons == nil {
		o.AdmissionReasons = []string{}
	}
	if err != nil {
		return o, err
	}
	if networkName.Valid {
		o.NetworkName = &networkName.String
	}
	var owners []ObservationOwner
	if len(ownersJSON) > 0 {
		if err := json.Unmarshal(ownersJSON, &owners); err != nil {
			return o, err
		}
	}
	annotateObservation(&o, sensorName.String, owners, now)
	return o, nil
}

func (s *AssetService) GetIdentityObservation(ctx context.Context, tenant, id uuid.UUID) (IdentityObservation, error) {
	var out IdentityObservation
	err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sqlx.Tx) error {
		var err error
		out, err = scanIdentityObservation(tx.QueryRowContext(ctx, `SELECT `+identityObservationColumns+observationReadFrom+` WHERE o.tenant_id=$1 AND o.id=$2`, tenant, id), time.Now().UTC())
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
	if err != nil {
		return out, err
	}
	err = s.populateCollectors(ctx, tenant, []*IdentityObservation{&out})
	return out, err
}

func (s *AssetService) IdentitySummary(ctx context.Context, tenant uuid.UUID) (IdentitySummary, error) {
	var out IdentitySummary
	err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sqlx.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT config->'identity_admission'->>'mode' FROM tenant_admin_settings WHERE tenant_id=$1),'disabled')`, tenant).Scan(&out.AdmissionMode); err != nil {
			return err
		}
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
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM assets WHERE tenant_id=$1
		 AND deleted_at IS NULL AND asset_status NOT IN ('archived','denied')
		 AND identity_status='provisional'`, tenant).Scan(&out.Provisional); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM assets a WHERE a.tenant_id=$1
		 AND a.deleted_at IS NULL AND a.asset_status NOT IN ('archived','denied') AND `+assetIdentityConflictSQL, tenant).Scan(&out.Conflicted)
	})
	return out, err
}

func (s *AssetService) ListIdentityObservations(ctx context.Context, tenant uuid.UUID, state string, page, size int, assetID *uuid.UUID) (IdentityObservationPage, error) {
	return s.ListIdentityObservationsFiltered(ctx, tenant, ObservationListFilter{State: state, Page: page, PageSize: size, AssetID: assetID})
}

// observationSorts maps the `sort` parameter to an ORDER BY. Every order ends
// in o.id so a page boundary is stable between two reads.
var observationSorts = map[string]string{
	"":               `o.last_seen_at DESC, o.id`,
	"last_seen_desc": `o.last_seen_at DESC, o.id`,
	"last_seen_asc":  `o.last_seen_at ASC, o.id`,
	"host":           `lower(COALESCE(NULLIF(o.evidence->>'hostname',''), jsonb_path_query_first(o.evidence, '$.identifiers[*] ? (@.kind == "ip_address").value') #>> '{}')) NULLS LAST, o.last_seen_at DESC, o.id`,
	"network":        `lower(ns.name) NULLS LAST, o.last_seen_at DESC, o.id`,
	"needs":          observationNeedsOrderSQL + `, o.last_seen_at DESC, o.id`,
}

// observationSearchSQL is the text `q` searches: names and addresses from the
// evidence, the network's name and the collector's name. Built from the
// identifier and endpoint arrays rather than evidence::text so a search for
// "tcp" or a key name does not match every row.
const observationSearchSQL = `concat_ws(' ', o.evidence->>'hostname', o.evidence->>'display_name', ns.name, s.name,
 (SELECT string_agg(x->>'value', ' ') FROM jsonb_array_elements(CASE WHEN jsonb_typeof(o.evidence->'identifiers')='array' THEN o.evidence->'identifiers' ELSE '[]'::jsonb END) x
   WHERE x->>'kind' IN ('ip_address','hostname','fqdn','mac_address')),
 (SELECT string_agg(e->>'address', ' ') FROM jsonb_array_elements(CASE WHEN jsonb_typeof(o.evidence->'endpoints')='array' THEN o.evidence->'endpoints' ELSE '[]'::jsonb END) e))`

// likeEscaper makes `q` a literal substring under ILIKE.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func (s *AssetService) ListIdentityObservationsFiltered(ctx context.Context, tenant uuid.UUID, f ObservationListFilter) (IdentityObservationPage, error) {
	out := IdentityObservationPage{Observations: []IdentityObservation{}, Page: f.Page, PageSize: f.PageSize}
	if f.Page < 1 || f.PageSize < 1 || f.PageSize > 100 {
		return out, fmt.Errorf("invalid observation pagination")
	}
	switch f.State {
	case "unresolved", "linked", "conflict", "dismissed", "expired", "all":
	default:
		return out, fmt.Errorf("invalid observation state")
	}
	order, ok := observationSorts[f.Sort]
	if !ok {
		return out, fmt.Errorf("invalid observation sort")
	}
	for _, n := range f.Needs {
		if !slices.Contains(ObservationNeedsValues, n) {
			return out, fmt.Errorf("invalid observation needs")
		}
	}
	args := []any{tenant, f.State, f.AssetID}
	where := `o.tenant_id=$1 AND ($2='all' OR o.state=$2) AND ($3::uuid IS NULL OR o.asset_id=$3)
	 AND ($2<>'unresolved' OR o.last_seen_at >= now()-interval '30 days')`
	if len(f.Needs) > 0 {
		args = append(args, pq.Array(f.Needs))
		where += fmt.Sprintf(` AND %s = ANY($%d::text[])`, observationNeedsSQL, len(args))
	}
	if f.NetworkScope != "" {
		args = append(args, f.NetworkScope)
		where += fmt.Sprintf(` AND o.network_scope=$%d`, len(args))
	}
	if f.Source != "" {
		args = append(args, f.Source)
		where += fmt.Sprintf(` AND o.source_ref=$%d`, len(args))
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		args = append(args, "%"+likeEscaper.Replace(q)+"%")
		where += fmt.Sprintf(` AND %s ILIKE $%d`, observationSearchSQL, len(args))
	}
	now := time.Now().UTC()
	err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sqlx.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT count(*)`+observationReadFrom+` WHERE `+where, args...).Scan(&out.Total); err != nil {
			return err
		}
		var counts ObservationNeedsCounts
		if err := tx.QueryRowContext(ctx, `SELECT
		 count(*) FILTER (WHERE needs='ready_to_confirm'), count(*) FILTER (WHERE needs='link_existing'),
		 count(*) FILTER (WHERE needs='needs_review'), count(*) FILTER (WHERE needs='needs_network'),
		 count(*) FILTER (WHERE needs='needs_sensor'), count(*) FILTER (WHERE needs='likely_noise'), count(*)
		 FROM (SELECT `+observationNeedsSQL+` AS needs FROM identity_observations o
		  WHERE o.tenant_id=$1 AND o.state='unresolved' AND o.last_seen_at >= now()-interval '30 days') n`, tenant).
			Scan(&counts.ReadyToConfirm, &counts.LinkExisting, &counts.NeedsReview, &counts.NeedsNetwork, &counts.NeedsSensor, &counts.LikelyNoise, &counts.All); err != nil {
			return err
		}
		out.Counts = &counts
		pageArgs := append(append([]any{}, args...), f.PageSize, (f.Page-1)*f.PageSize)
		rows, err := tx.QueryContext(ctx, `SELECT `+identityObservationColumns+observationReadFrom+` WHERE `+where+
			fmt.Sprintf(` ORDER BY %s LIMIT $%d OFFSET $%d`, order, len(pageArgs)-1, len(pageArgs)), pageArgs...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			o, err := scanIdentityObservation(rows, now)
			if err != nil {
				return err
			}
			out.Observations = append(out.Observations, o)
		}
		return rows.Err()
	})
	if err != nil {
		return out, err
	}
	refs := make([]*IdentityObservation, len(out.Observations))
	for i := range out.Observations {
		refs[i] = &out.Observations[i]
	}
	err = s.populateCollectors(ctx, tenant, refs)
	return out, err
}

// populateCollectors fills each observation's `collector` block ( D7).
//
// It runs AFTER the caller's read transaction rather than inside it. The
// eligibility question is answered by identityenrichment.Store.Scope, which
// opens its own tenant transaction, and nesting that inside the page query
// would hold two pool connections per request for no benefit — a collector
// block is a snapshot of policy, not part of the page's consistent read.
//
// One Scope call per row is deliberate at a page size of 50. The alternative,
// one query joining sensors and agent_addresses against every row's segment,
// would have to re-implement the eligibility rule in SQL — and a second copy of
// that rule is how the UI comes to say a collector is reachable while the
// worker refuses to dispatch to it.
func (s *AssetService) populateCollectors(ctx context.Context, tenant uuid.UUID, observations []*IdentityObservation) error {
	if len(observations) == 0 {
		return nil
	}
	store := &identityenrichment.Store{DB: s.db}
	now := time.Now().UTC()
	names := map[uuid.UUID]string{}
	for _, o := range observations {
		var evidence identity.Observation
		if err := json.Unmarshal(o.Evidence, &evidence); err != nil {
			// Evidence that will not parse is a storage fault, not a collector
			// answer. Report no collector rather than a wrong one.
			continue
		}
		scope, _, err := store.Scope(ctx, tenant, identityenrichment.Observation{ID: o.ID, AssetID: o.AssetID, State: o.State, Evidence: evidence}, now)
		if err != nil {
			return err
		}
		if scope.SegmentID == uuid.Nil {
			continue
		}
		block := &IdentityObservationCollector{Observer: IdentityObservationObserver{
			Reachable: scope.ObserverReachable, Reason: scope.ObserverReason,
		}}
		if scope.ObserverSensorID != uuid.Nil {
			observer := scope.ObserverSensorID
			block.Observer.SensorID = &observer
			names[observer] = ""
		}
		switch {
		case scope.SensorID != uuid.Nil:
			block.Executor = &IdentityObservationExecutor{SensorID: scope.SensorID}
			names[scope.SensorID] = ""
		case scope.BlockReason != "":
			block.Reason = scope.BlockReason
		default:
			block.Reason = identityenrichment.ReasonNoEligibleCollector
		}
		o.Collector = block
	}
	if len(names) == 0 {
		return nil
	}
	ids := make([]uuid.UUID, 0, len(names))
	for id := range names {
		ids = append(ids, id)
	}
	if err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sqlx.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id,name FROM sensors WHERE tenant_id=$1 AND id=ANY($2)`, tenant, pq.Array(ids))
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id uuid.UUID
			var name string
			if err := rows.Scan(&id, &name); err != nil {
				return err
			}
			names[id] = name
		}
		return rows.Err()
	}); err != nil {
		return err
	}
	for _, o := range observations {
		if o.Collector == nil {
			continue
		}
		if o.Collector.Observer.SensorID != nil {
			o.Collector.Observer.Name = names[*o.Collector.Observer.SensorID]
		}
		if o.Collector.Executor != nil {
			o.Collector.Executor.Name = names[o.Collector.Executor.SensorID]
		}
	}
	return nil
}
