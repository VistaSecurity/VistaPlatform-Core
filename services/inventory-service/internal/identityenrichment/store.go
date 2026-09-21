package identityenrichment

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

type Store struct{ DB *database.DB }

func (s *Store) Policy(ctx context.Context, tenant uuid.UUID) (Policy, error) {
	var raw []byte
	err := database.WithTenantTx(ctx, s.DB, tenant, func(tx *sqlx.Tx) error {
		err := tx.QueryRowContext(ctx, `SELECT config FROM tenant_admin_settings WHERE tenant_id=$1`, tenant).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			raw = []byte(`{}`)
			return nil
		}
		return err
	})
	if err != nil {
		return Policy{}, err
	}
	return ParsePolicy(raw)
}

func (s *Store) Candidates(ctx context.Context, tenant uuid.UUID, now time.Time) ([]Observation, error) {
	var out []Observation
	err := database.WithTenantTx(ctx, s.DB, tenant, func(tx *sqlx.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT o.id,o.asset_id,o.state,o.fingerprint,o.evidence,o.last_seen_at
   FROM identity_observations o LEFT JOIN assets a ON a.tenant_id=o.tenant_id AND a.id=o.asset_id
   WHERE o.tenant_id=$1 AND o.state IN ('unresolved','linked') AND o.last_seen_at>$2::timestamptz-interval '30 days'
   AND (o.next_attempt_at IS NULL OR o.next_attempt_at<=$2)
   AND (o.asset_id IS NULL OR (a.deleted_at IS NULL AND a.asset_status NOT IN ('archived','denied')))
   ORDER BY o.next_attempt_at NULLS FIRST,o.updated_at,o.id LIMIT $3`, tenant, now, BatchSize)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var o Observation
			var raw []byte
			if err := rows.Scan(&o.ID, &o.AssetID, &o.State, &o.Fingerprint, &raw, &o.LastSeen); err != nil {
				return err
			}
			if err := json.Unmarshal(raw, &o.Evidence); err != nil {
				return err
			}
			out = append(out, o)
		}
		return rows.Err()
	})
	return out, err
}

// MaterializationCandidates returns retained observations that produced no
// asset and are due another look ( D5).
//
// The whole selection is decided in SQL, including the due-ness test, so the
// LIMIT applies to rows that are ACTUALLY candidates. Filtering in Go after the
// LIMIT would silently starve a tenant: enrichment's own Summary/Finish writes
// touch `updated_at` on every unresolved row every fifteen minutes, so the
// twenty oldest-touched rows are frequently twenty already-materialized ones,
// and everything behind them would never be reached.
//
// `materialized_at NULLS FIRST` puts observations nothing has ever looked at
// ahead of ones due a re-check, which is the order a tenant would want on the
// sweep right after a deploy.
func (s *Store) MaterializationCandidates(ctx context.Context, tenant uuid.UUID, now time.Time) ([]Observation, error) {
	var out []Observation
	err := database.WithTenantTx(ctx, s.DB, tenant, func(tx *sqlx.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id,asset_id,state,fingerprint,evidence,last_seen_at
   FROM identity_observations
   WHERE tenant_id=$1 AND state='unresolved' AND asset_id IS NULL
    AND last_seen_at>$2::timestamptz-interval '30 days'
    AND (materialized_at IS NULL OR materialized_at<$2::timestamptz-$3::interval)
   ORDER BY materialized_at NULLS FIRST,updated_at,id LIMIT $4`, tenant, now, MaterializationInterval.String(), BatchSize)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var o Observation
			var raw []byte
			if err := rows.Scan(&o.ID, &o.AssetID, &o.State, &o.Fingerprint, &raw, &o.LastSeen); err != nil {
				return err
			}
			if err := json.Unmarshal(raw, &o.Evidence); err != nil {
				return err
			}
			out = append(out, o)
		}
		return rows.Err()
	})
	return out, err
}

func (s *Store) Scope(ctx context.Context, tenant uuid.UUID, o Observation, now time.Time) (Scope, []netip.Prefix, error) {
	var out Scope
	var excluded []netip.Prefix
	segment, err := uuid.Parse(o.Evidence.Network.SegmentID)
	if err != nil {
		return out, nil, nil
	}
	out.SegmentID = segment
	// The producer UUID names the OBSERVER, and only that. It is confirmed to
	// be this tenant's sensor below; whether any collector may execute work is
	// a separate question answered by selectExecutor.
	parts := strings.Split(o.Evidence.Source.Ref, ":")
	if len(parts) > 1 && (parts[0] == "sensor" || parts[0] == "scan") && o.Evidence.Source.Kind == "measured" {
		out.ObserverSensorID, _ = uuid.Parse(parts[len(parts)-1])
	}
	err = database.WithTenantTx(ctx, s.DB, tenant, func(tx *sqlx.Tx) error {
		var cidr, metadata string
		err := tx.QueryRowContext(ctx, `SELECT value,COALESCE(metadata,'{}')::text FROM network_segments
   WHERE tenant_id=$1 AND id=$2 AND is_active AND segment_type='cidr'`, tenant, segment).Scan(&cidr, &metadata)
		if errors.Is(err, sql.ErrNoRows) {
			out.SegmentID = uuid.Nil
			return nil
		}
		if err != nil {
			return err
		}
		out.CIDR, err = netip.ParsePrefix(cidr)
		if err != nil {
			return nil
		}
		// The OBSERVER is evaluated exactly as before — this is provenance, and
		// the reasons are the ones already spells out and the UI already
		// renders. It is resolved BEFORE the blocking checks below so that a
		// block for some other reason still leaves the UI able to say who
		// advertised this and whether they can reach it; what changed with
		// is only that a failing observer no longer ends the question.
		observerAddresses, err := evaluateObserver(ctx, tx, tenant, &out, now)
		if err != nil {
			return err
		}
		excluded = append(excluded, observerAddresses...)

		// The current network probe intake resolves scopes by address. Until a
		// trusted job scope is carried through that intake, ambiguous/overlapping
		// spaces must remain blocked, including cloud/private-CIDR overlaps.
		var ambiguous bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM network_segments WHERE tenant_id=$1 AND id<>$2 AND is_active
   AND CASE WHEN segment_type='cidr' THEN value::cidr && $3::cidr ELSE false END)
   OR EXISTS(SELECT 1 FROM network_segments WHERE tenant_id=$1 AND id=$2 AND COALESCE(cloud_network_ref,'')<>'')`, tenant, segment, cidr).Scan(&ambiguous); err != nil {
			return err
		}
		if ambiguous {
			out.BlockReason = "overlapping_network_scope_requires_source_resolution"
			return nil
		}

		var restrictions struct {
			Sensitive            bool `json:"sensitive"`
			ActiveProbesDisabled bool `json:"active_probes_disabled"`
		}
		if err := json.Unmarshal([]byte(metadata), &restrictions); err != nil {
			return err
		}
		out.Sensitive = restrictions.Sensitive || restrictions.ActiveProbesDisabled
		if o.AssetID != nil {
			var class string
			if err := tx.QueryRowContext(ctx, `SELECT class_key FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, *o.AssetID).Scan(&class); err != nil {
				return err
			}
			// Explicit configuration can restrict any class; these device families are
			// conservatively excluded from unattended probes regardless of policy.
			out.Sensitive = out.Sensitive || strings.Contains(class, "industrial") || strings.Contains(class, "medical") || assetclass.IsAncestor(assetclass.KeyOtDevice, class) || strings.HasPrefix(class, "ot_")
		}
		if out.ObserverReason == reasonPlatformCollector {
			// A platform-collector observation is not enrichable through a
			// tenant sensor either: the platform sensor serves every tenant, so
			// acting on what it heard would let one tenant's evidence direct
			// another tenant's collector. No executor is selected at all.
			out.BlockReason = reasonPlatformCollector
			return nil
		}
		executorExcluded, err := selectExecutor(ctx, tx, tenant, &out, now)
		if err != nil {
			return err
		}
		excluded = append(excluded, executorExcluded...)
		if out.SensorID == uuid.Nil {
			out.BlockReason = ReasonNoEligibleCollector
		}
		return nil
	})
	return out, excluded, err
}

const reasonPlatformCollector = "platform_collector_not_authorized_for_identity_enrichment"

// evaluateObserver fills Scope's Observer* fields and returns the observer's own
// interface addresses, which must never become probe targets.
//
// It answers only about the collector the evidence CAME from. It deliberately
// returns no error and no block reason when the observer is not a sensor at all
// (a cloud source, an interrogation) — that is not a failure, it just means
// there is no observer reachability to report.
func evaluateObserver(ctx context.Context, tx *sqlx.Tx, tenant uuid.UUID, out *Scope, now time.Time) ([]netip.Prefix, error) {
	if out.ObserverSensorID == uuid.Nil {
		return nil, nil
	}
	var status, profile, version string
	var heartbeat *time.Time
	var interval int
	var airgap, system bool
	var capabilities pq.StringArray
	err := tx.QueryRowContext(ctx, `SELECT status,version,profile,last_heartbeat,COALESCE(reporting_interval,60),air_gapped,reported_capabilities,COALESCE('system'=ANY(tags),false)
   FROM sensors WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL`, tenant, out.ObserverSensorID).
		Scan(&status, &version, &profile, &heartbeat, &interval, &airgap, &capabilities, &system)
	if errors.Is(err, sql.ErrNoRows) {
		// Not this tenant's sensor (or deleted). Not an observer we can say
		// anything about; the executor search is unaffected.
		out.ObserverSensorID = uuid.Nil
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	switch {
	case system:
		out.ObserverReason = reasonPlatformCollector
		return nil, nil
	case airgap || profile == "system":
		out.ObserverReason = "collector_network_checks_disabled"
		return nil, nil
	case !sensordispatch.IsLive(status, heartbeat, interval, now):
		out.ObserverReason = "observing_collector_offline"
		return nil, nil
	}
	var excluded []netip.Prefix
	rows, err := tx.QueryContext(ctx, `SELECT host(a.address),a.prefix_length FROM agent_addresses a JOIN sensors s ON s.id=a.sensor_id WHERE a.sensor_id=$1 AND s.tenant_id=$2 AND a.last_seen_at>$3::timestamptz-interval '5 minutes' AND a.interface_name=ANY(s.reported_dns_interfaces)`, out.ObserverSensorID, tenant, now)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var address string
		var bits *int
		if err := rows.Scan(&address, &bits); err != nil {
			return nil, err
		}
		a, err := netip.ParseAddr(address)
		if err != nil {
			continue
		}
		excluded = append(excluded, netip.PrefixFrom(a, a.BitLen()))
		// Reported interface prefixes are required, not a guessed /24 or /64.
		if bits != nil && *bits >= 0 && *bits <= a.BitLen() && out.CIDR.Contains(a) {
			out.ObserverReachable = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !out.ObserverReachable {
		out.ObserverReason = "collector_has_no_interface_in_target_network"
	}
	return excluded, nil
}

// selectExecutor picks the collector that will actually run enrichment work for
// this observation: any live, non-platform sensor of the tenant with a freshly
// reported interface address inside the target segment ( D4).
//
// Containment is decided in Go, not as `a.address << $cidr` in SQL, for the same
// reason ProvisionalScope's overlap test is: the comparison needs the reported
// prefix AND the segment's parsed value together, and one malformed row must not
// be able to abort the query for the whole tenant. The SQL narrows by the facts
// SQL is good at (ownership, freshness, the DNS-interface allowlist) and Go
// decides the arithmetic.
//
// Preference is the OBSERVER when it is eligible — it already has the context,
// and keeping work on one collector keeps a tenant's probe traffic where they
// expect it — otherwise the most recent heartbeat, which is the best available
// proxy for "most likely to still be there in a minute".
func selectExecutor(ctx context.Context, tx *sqlx.Tx, tenant uuid.UUID, out *Scope, now time.Time) ([]netip.Prefix, error) {
	if !out.CIDR.IsValid() || out.SegmentID == uuid.Nil {
		return nil, nil
	}
	type candidate struct {
		version    string
		addresses  []netip.Prefix
		dnsCapable bool
		eligible   bool
	}
	order := make([]uuid.UUID, 0, 4)
	candidates := make(map[uuid.UUID]*candidate, 4)
	rows, err := tx.QueryContext(ctx, `SELECT s.id,s.version,s.status,s.last_heartbeat,COALESCE(s.reporting_interval,60),s.reported_capabilities,host(a.address),a.prefix_length
   FROM sensors s JOIN agent_addresses a ON a.sensor_id=s.id
   WHERE s.tenant_id=$1 AND s.deleted_at IS NULL AND NOT COALESCE('system'=ANY(s.tags),false)
    AND NOT s.air_gapped AND s.profile<>'system'
    AND a.last_seen_at>$2::timestamptz-interval '5 minutes' AND a.interface_name=ANY(s.reported_dns_interfaces)
   ORDER BY s.last_heartbeat DESC NULLS LAST,s.id`, tenant, now)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id uuid.UUID
		var version, status, address string
		var heartbeat *time.Time
		var interval int
		var capabilities pq.StringArray
		var bits *int
		if err := rows.Scan(&id, &version, &status, &heartbeat, &interval, &capabilities, &address, &bits); err != nil {
			return nil, err
		}
		if !sensordispatch.IsLive(status, heartbeat, interval, now) {
			continue
		}
		c := candidates[id]
		if c == nil {
			c = &candidate{version: version}
			for _, capability := range capabilities {
				c.dnsCapable = c.dnsCapable || capability == "identity_dns_v1"
			}
			candidates[id] = c
			order = append(order, id)
		}
		a, err := netip.ParseAddr(address)
		if err != nil {
			continue
		}
		c.addresses = append(c.addresses, netip.PrefixFrom(a, a.BitLen()))
		// Reported interface prefixes are required, not a guessed /24 or /64.
		if bits != nil && *bits >= 0 && *bits <= a.BitLen() && out.CIDR.Contains(a) {
			c.eligible = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	chosen := uuid.Nil
	if c, ok := candidates[out.ObserverSensorID]; ok && c.eligible {
		chosen = out.ObserverSensorID
	} else {
		for _, id := range order {
			if candidates[id].eligible {
				chosen = id
				break
			}
		}
	}
	var excluded []netip.Prefix
	for _, id := range order {
		if candidates[id].eligible {
			excluded = append(excluded, candidates[id].addresses...)
		}
	}
	if chosen == uuid.Nil {
		return excluded, nil
	}
	out.SensorID = chosen
	out.SensorVersion = candidates[chosen].version
	out.DNSCapable = candidates[chosen].dnsCapable
	out.Reachable = true
	return excluded, nil
}

const jobColumns = `id,observation_id,request_id,plan,generation,state,reason,attempts,remote_id,result,next_attempt_at,request_evidence`

func scanJob(row interface{ Scan(...any) error }) (Job, error) {
	var j Job
	var plan, evidence []byte
	err := row.Scan(&j.ID, &j.ObservationID, &j.RequestID, &plan, &j.Generation, &j.State, &j.Reason, &j.Attempts, &j.RemoteID, &j.Result, &j.NextAttempt, &evidence)
	if err == nil {
		err = json.Unmarshal(plan, &j.Plan)
		if err == nil {
			err = json.Unmarshal(evidence, &j.RequestEvidence)
		}
	}
	return j, err
}

func (s *Store) Ensure(ctx context.Context, tenant uuid.UUID, o Observation, p Plan, now time.Time) (Job, error) {
	// A cycle is the coordinator's scheduled cohort, not a delivery timestamp.
	// Assign it here for every action so callers cannot silently omit or replace
	// the cohort on DNS/probe jobs while recording it on configured sources.
	p.Cycle = o.Cycle
	var j Job
	raw, err := json.Marshal(p)
	if err != nil {
		return j, err
	}
	evidence, err := json.Marshal(o.Evidence)
	if err != nil {
		return j, err
	}
	generationHash := sha256.Sum256(append([]byte(Generation(o)), raw...))
	generation := hex.EncodeToString(generationHash[:])
	err = database.WithTenantTx(ctx, s.DB, tenant, func(tx *sqlx.Tx) error {
		// The lock and the active-job lookup are keyed by OBSERVATION+ACTION,
		// not by executor ( D4). Executor eligibility changes underneath
		// us — a tenant enrols a sensor on the target VLAN and the very next
		// cycle plans through it — and keying either on the executor would let
		// the new collector start a second in-flight request for work the old
		// one is still running. A job already in flight is returned as-is
		// whoever is now eligible; when its own executor stops being eligible
		// its next dispatch blocks with `authorization_changed_before_dispatch`
		// and the cycle after that plans afresh.
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,72048))`, tenant.String()+":"+o.ID.String()+":"+p.Action); err != nil {
			return err
		}
		// New useful evidence may replace completed work, but never overlaps a
		// still running request for the same observation and action.
		active, err := scanJob(tx.QueryRowContext(ctx, `SELECT `+jobColumns+` FROM identity_enrichment_jobs
   WHERE tenant_id=$1 AND observation_id=$2 AND action=$3
    AND state NOT IN ('completed','blocked') AND (remote_id<>'' OR lease_until>now())
   ORDER BY created_at LIMIT 1`, tenant, o.ID, p.Action))
		if err == nil {
			j = active
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		j, err = scanJob(tx.QueryRowContext(ctx, `INSERT INTO identity_enrichment_jobs(tenant_id,observation_id,generation,action,executor_scope,plan,next_attempt_at,request_evidence)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(tenant_id,observation_id,generation,action,executor_scope)
   DO UPDATE SET generation=EXCLUDED.generation RETURNING `+jobColumns, tenant, o.ID, generation, p.Action, p.Executor, string(raw), now, string(evidence)))
		return err
	})
	j.TenantID = tenant
	return j, err
}

// Claim changes only coordination clocks. A crashed worker's lease expires;
// RequestID survives so an already committed remote dispatch is replayed.
func (s *Store) Claim(ctx context.Context, j Job, now time.Time) (Job, uuid.UUID, bool, error) {
	var claimed Job
	lease := uuid.New()
	ok := false
	err := database.WithTenantTx(ctx, s.DB, j.TenantID, func(tx *sqlx.Tx) error {
		var err error
		claimed, err = scanJob(tx.QueryRowContext(ctx, `UPDATE identity_enrichment_jobs SET lease_id=$3,lease_until=$4+interval '2 minutes',
    last_attempt_at=$4,attempts=CASE WHEN remote_id='' OR state IN ('failed','blocked') THEN attempts+1 ELSE attempts END,updated_at=$4
   WHERE tenant_id=$1 AND id=$2 AND state<>'completed' AND next_attempt_at<=$4
    AND (lease_until IS NULL OR lease_until<$4)
    AND EXISTS(SELECT 1 FROM identity_observations o WHERE o.tenant_id=$1 AND o.id=observation_id AND o.state IN ('unresolved','linked'))
   RETURNING `+jobColumns, j.TenantID, j.ID, lease, now))
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		ok = err == nil
		return err
	})
	claimed.TenantID = j.TenantID
	return claimed, lease, ok, err
}

func (s *Store) Finish(ctx context.Context, j Job, lease uuid.UUID, r Result, now time.Time) error {
	switch r.State {
	case "waiting", "queued", "running", "completed", "blocked", "failed":
	default:
		return fmt.Errorf("invalid enrichment result state")
	}
	if len(r.Data) == 0 {
		r.Data = json.RawMessage(`{}`)
	}
	next := now.Add(time.Minute)
	if r.State == "failed" || r.State == "blocked" {
		next = now.Add(RetryDelay(j.Attempts))
	}
	return database.WithTenantTx(ctx, s.DB, j.TenantID, func(tx *sqlx.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE identity_enrichment_jobs SET state=$4,reason=$5,remote_id=$6,result=$7,
   next_attempt_at=$8,lease_id=NULL,lease_until=NULL,updated_at=$9 WHERE tenant_id=$1 AND id=$2 AND lease_id=$3`, j.TenantID, j.ID, lease, r.State, r.Reason, r.RemoteID, string(r.Data), next, now)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("enrichment lease changed")
		}
		_, err = tx.ExecContext(ctx, `UPDATE identity_observations SET enrichment_state=$3,enrichment_reason=$4,last_attempt_at=$5,next_attempt_at=$6,updated_at=$5
   WHERE tenant_id=$1 AND id=$2`, j.TenantID, j.ObservationID, r.State, r.Reason, now, next)
		return err
	})
}
func (s *Store) Summary(ctx context.Context, tenant, id uuid.UUID, state, reason string, now, next time.Time) error {
	return database.WithTenantTx(ctx, s.DB, tenant, func(tx *sqlx.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE identity_observations SET enrichment_state=$3,enrichment_reason=$4,next_attempt_at=$5,updated_at=$6 WHERE tenant_id=$1 AND id=$2`, tenant, id, state, reason, next, now)
		return err
	})
}

func (s *Store) Observation(ctx context.Context, tenant, id uuid.UUID) (Observation, error) {
	var o Observation
	var raw []byte
	err := database.WithTenantTx(ctx, s.DB, tenant, func(tx *sqlx.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT id,asset_id,state,fingerprint,evidence,last_seen_at FROM identity_observations WHERE tenant_id=$1 AND id=$2`, tenant, id).
			Scan(&o.ID, &o.AssetID, &o.State, &o.Fingerprint, &raw, &o.LastSeen)
	})
	if err == nil {
		err = json.Unmarshal(raw, &o.Evidence)
	}
	return o, err
}
