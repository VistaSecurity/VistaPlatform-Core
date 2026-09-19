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

func (s *Store) Scope(ctx context.Context, tenant uuid.UUID, o Observation, now time.Time) (Scope, []netip.Prefix, error) {
	var out Scope
	var excluded []netip.Prefix
	segment, err := uuid.Parse(o.Evidence.Network.SegmentID)
	if err != nil {
		return out, nil, nil
	}
	out.SegmentID = segment
	// A producer UUID is a candidate executor only after tenant ownership,
	// authenticated heartbeat, interface scope and capability checks below.
	parts := strings.Split(o.Evidence.Source.Ref, ":")
	if len(parts) > 1 && (parts[0] == "sensor" || parts[0] == "scan") && o.Evidence.Source.Kind == "measured" {
		out.SensorID, _ = uuid.Parse(parts[len(parts)-1])
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
		if out.SensorID == uuid.Nil {
			return nil
		}
		var status, profile string
		var heartbeat *time.Time
		var interval int
		var airgap, system bool
		var capabilities pq.StringArray
		err = tx.QueryRowContext(ctx, `SELECT status,version,profile,last_heartbeat,COALESCE(reporting_interval,60),air_gapped,reported_capabilities,COALESCE('system'=ANY(tags),false)
   FROM sensors WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL`, tenant, out.SensorID).
			Scan(&status, &out.SensorVersion, &profile, &heartbeat, &interval, &airgap, &capabilities, &system)
		if errors.Is(err, sql.ErrNoRows) {
			out.SensorID = uuid.Nil
			return nil
		}
		if err != nil {
			return err
		}
		for _, c := range capabilities {
			out.DNSCapable = out.DNSCapable || c == "identity_dns_v1"
		}
		if system {
			out.BlockReason = "platform_collector_not_authorized_for_identity_enrichment"
			return nil
		}
		if airgap || profile == "system" || !sensordispatch.IsLive(status, heartbeat, interval, now) {
			return nil
		}
		rows, err := tx.QueryContext(ctx, `SELECT host(address),prefix_length FROM agent_addresses WHERE sensor_id=$1 AND last_seen_at>now()-interval '5 minutes' AND EXISTS(SELECT 1 FROM sensors WHERE id=$1 AND tenant_id=$2 AND interface_name=ANY(reported_dns_interfaces))`, out.SensorID, tenant)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var address string
			var bits *int
			if err := rows.Scan(&address, &bits); err != nil {
				return err
			}
			a, err := netip.ParseAddr(address)
			if err != nil {
				continue
			}
			excluded = append(excluded, netip.PrefixFrom(a, a.BitLen()))
			// Reported interface prefixes are required, not a guessed /24 or /64.
			if bits != nil && *bits >= 0 && *bits <= a.BitLen() && out.CIDR.Contains(a) {
				out.Reachable = true
			}
		}
		return rows.Err()
	})
	return out, excluded, err
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
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,72048))`, tenant.String()+":"+o.ID.String()+":"+p.Action+":"+p.Executor); err != nil {
			return err
		}
		// New useful evidence may replace completed work, but never overlaps a
		// still running request in the same observation/action/executor scope.
		active, err := scanJob(tx.QueryRowContext(ctx, `SELECT `+jobColumns+` FROM identity_enrichment_jobs
   WHERE tenant_id=$1 AND observation_id=$2 AND action=$3 AND executor_scope=$4
    AND state NOT IN ('completed','blocked') AND (remote_id<>'' OR lease_until>now())
   ORDER BY created_at LIMIT 1`, tenant, o.ID, p.Action, p.Executor))
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
