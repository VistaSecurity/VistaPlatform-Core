// Package store persists sensor and agent desired state.
//
// It is a separate package from agentconfig itself, which must stay pure: the
// standalone sensor imports agentconfig to interpret what it is handed and
// cross-compiles with CGO_ENABLED=0, so a database dependency there would be a
// platform coupling of exactly the kind CLAUDE.md forbids. Nothing on a device
// imports this package.
//
// Every read and write runs inside a transaction that sets `app.tenant_id`, so
// the row-level security policies on the agent_config_* tables apply. The
// tenant is a parameter, never an ambient value.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
)

// Owner names one fleet member. Exactly one of SensorID and AgentID is set,
// mirroring the exactly-one-owner CHECK on the tables.
type Owner struct {
	Runtime  agentconfig.Runtime
	SensorID uuid.UUID
	AgentID  uuid.UUID
}

// SensorOwner and AgentOwner are the two constructors, so a caller cannot build
// an Owner with both ids or neither.
func SensorOwner(id uuid.UUID) Owner {
	return Owner{Runtime: agentconfig.RuntimeSensor, SensorID: id}
}

func AgentOwner(id uuid.UUID) Owner {
	return Owner{Runtime: agentconfig.RuntimeAgent, AgentID: id}
}

// ErrNoOwner is returned for an Owner naming neither a sensor nor an agent.
var ErrNoOwner = errors.New("agentconfig/store: owner names neither a sensor nor an agent")

func (o Owner) columns() (sensor, agent any, err error) {
	switch o.Runtime {
	case agentconfig.RuntimeSensor:
		if o.SensorID == uuid.Nil {
			return nil, nil, ErrNoOwner
		}
		return o.SensorID, nil, nil
	case agentconfig.RuntimeAgent:
		if o.AgentID == uuid.Nil {
			return nil, nil, ErrNoOwner
		}
		return nil, o.AgentID, nil
	}
	return nil, nil, ErrNoOwner
}

// Store reads and writes desired state.
type Store struct{ db *sql.DB }

func New(db *sql.DB) *Store { return &Store{db: db} }

// Desired is everything the console needs about one device: what it should be,
// where each value came from, and how far it has got.
type Desired struct {
	Owner    Owner
	Resolved []agentconfig.Resolved
	Values   agentconfig.Values
	Revision string
	Status   agentconfig.Status
	// Restart is when an operator last asked this device to restart. It is NOT
	// part of the revision: a restart request is not a setting, and folding it
	// into the content hash would make every device that was ever restarted
	// disagree with its own desired state forever.
	Restart agentconfig.RestartRequest
}

// Load computes a device's desired state and reconciles it against what the
// device last reported.
//
// The fleet defaults, the device override and the reported state are read in
// ONE transaction. Read separately, a fleet-default change landing between two
// queries would produce a revision computed from values that were never all in
// force at once — and the device would then be told it has not converged to
// something nobody ever asked for.
func (s *Store) Load(ctx context.Context, tenantID uuid.UUID, owner Owner) (*Desired, error) {
	sensorID, agentID, err := owner.columns()
	if err != nil {
		return nil, err
	}

	out := &Desired{Owner: owner}
	err = s.withTenant(ctx, tenantID, func(tx *sql.Tx) error {
		fleet, err := loadDefaults(ctx, tx, tenantID, owner.Runtime)
		if err != nil {
			return err
		}
		override, err := loadOverride(ctx, tx, sensorID, agentID)
		if err != nil {
			return err
		}
		rep, err := loadReport(ctx, tx, sensorID, agentID)
		if err != nil {
			return err
		}
		restart, err := loadRestart(ctx, tx, sensorID, agentID)
		if err != nil {
			return err
		}
		out.Restart = restart

		out.Resolved = agentconfig.Resolve(owner.Runtime, fleet, override)
		out.Values = make(agentconfig.Values, len(out.Resolved))
		for _, r := range out.Resolved {
			out.Values[r.Key] = r.Value
		}
		out.Revision = agentconfig.Revision(owner.Runtime, out.Values)
		out.Status = agentconfig.Reconcile(owner.Runtime, out.Values, rep)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SaveOverride replaces a device's override and writes an audit row.
//
// The values are validated and normalized by the CALLER (handlers do it, so the
// operator gets the floor notes back); this refuses anything invalid anyway,
// because a store that trusts its caller is one bad handler away from a device
// being handed a setting it cannot parse.
func (s *Store) SaveOverride(ctx context.Context, tenantID uuid.UUID, owner Owner, vals agentconfig.Values, by uuid.UUID) error {
	sensorID, agentID, err := owner.columns()
	if err != nil {
		return err
	}
	if err := agentconfig.Validate(owner.Runtime, vals); err != nil {
		return err
	}
	stripped := stripEmpty(vals)
	payload, err := json.Marshal(stripped)
	if err != nil {
		return fmt.Errorf("agentconfig/store: marshal override: %w", err)
	}

	return s.withTenant(ctx, tenantID, func(tx *sql.Tx) error {
		before, err := loadOverride(ctx, tx, sensorID, agentID)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO public.agent_config_overrides (sensor_id, device_agent_id, values, updated_by)
			VALUES ($1, $2, $3::jsonb, $4)
			ON CONFLICT (`+conflictTarget(owner.Runtime)+`) WHERE `+conflictWhere(owner.Runtime)+`
			DO UPDATE SET values = EXCLUDED.values, updated_by = EXCLUDED.updated_by, updated_at = now()`,
			sensorID, agentID, string(payload), nullUUID(by)); err != nil {
			return fmt.Errorf("agentconfig/store: save override: %w", err)
		}
		return writeAudit(ctx, tx, tenantID, sensorID, agentID, "device", owner.Runtime, before, stripped, by)
	})
}

// SaveDefaults replaces a tenant's fleet defaults for one runtime.
func (s *Store) SaveDefaults(ctx context.Context, tenantID uuid.UUID, rt agentconfig.Runtime, vals agentconfig.Values, by uuid.UUID) error {
	if err := agentconfig.Validate(rt, vals); err != nil {
		return err
	}
	stripped := stripEmpty(vals)
	payload, err := json.Marshal(stripped)
	if err != nil {
		return fmt.Errorf("agentconfig/store: marshal defaults: %w", err)
	}

	return s.withTenant(ctx, tenantID, func(tx *sql.Tx) error {
		before, err := loadDefaults(ctx, tx, tenantID, rt)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO public.agent_config_defaults (tenant_id, runtime, values, updated_by)
			VALUES ($1, $2, $3::jsonb, $4)
			ON CONFLICT (tenant_id, runtime)
			DO UPDATE SET values = EXCLUDED.values, updated_by = EXCLUDED.updated_by, updated_at = now()`,
			tenantID, string(rt), string(payload), nullUUID(by)); err != nil {
			return fmt.Errorf("agentconfig/store: save defaults: %w", err)
		}
		return writeAudit(ctx, tx, tenantID, nil, nil, "fleet", rt, before, stripped, by)
	})
}

// BootstrapFromReport records a device's own starting position, the FIRST time
// it reports one, and returns what it seeded.
//
// Without this, a device that enrolled before the control plane existed is
// answered with the built-in defaults on its first heartbeat and obeys them —
// switching off, on that beat, whatever its file had turned on. The values the
// device reports are therefore adopted as its own override, so the revision it
// receives describes what it is already doing and nothing changes until
// somebody changes it.
//
// Gated on the device never having reported before, not on the override being
// empty. Those differ in the case that matters: an operator who clears an
// override back to "inherit" must not have the device's local value silently
// reinstated on the next beat. One report is the whole window.
//
// Written with no acting user and audited under its own scope, because nobody
// made this change — the device was already like this, and an audit trail that
// attributes it to a person is a trail that lies.
func (s *Store) BootstrapFromReport(ctx context.Context, tenantID uuid.UUID, owner Owner, running agentconfig.Values) (agentconfig.Values, error) {
	sensorID, agentID, err := owner.columns()
	if err != nil {
		return nil, err
	}
	if len(running) == 0 {
		// An older device that does not report what it is running. Adopting
		// "nothing" as its starting position would be inventing one.
		return nil, nil
	}

	var seeded agentconfig.Values
	err = s.withTenant(ctx, tenantID, func(tx *sql.Tx) error {
		reported, err := hasReported(ctx, tx, sensorID, agentID)
		if err != nil {
			return err
		}
		if reported {
			return nil
		}
		fleet, err := loadDefaults(ctx, tx, tenantID, owner.Runtime)
		if err != nil {
			return err
		}
		override, err := loadOverride(ctx, tx, sensorID, agentID)
		if err != nil {
			return err
		}

		seed := agentconfig.BootstrapValues(owner.Runtime, fleet, override, running)
		if len(seed) == 0 {
			// The common case: the device is running the built-in defaults, so
			// there is nothing to record and no row to write.
			return nil
		}

		merged := override.Clone()
		for k, v := range seed {
			merged[k] = v
		}
		merged = stripEmpty(merged)
		payload, err := json.Marshal(merged)
		if err != nil {
			return fmt.Errorf("agentconfig/store: marshal bootstrap: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO public.agent_config_overrides (sensor_id, device_agent_id, values, updated_by)
			VALUES ($1, $2, $3::jsonb, NULL)
			ON CONFLICT (`+conflictTarget(owner.Runtime)+`) WHERE `+conflictWhere(owner.Runtime)+`
			DO UPDATE SET values = EXCLUDED.values, updated_at = now()`,
			sensorID, agentID, string(payload)); err != nil {
			return fmt.Errorf("agentconfig/store: save bootstrap override: %w", err)
		}
		if err := writeAudit(ctx, tx, tenantID, sensorID, agentID, "bootstrap", owner.Runtime, override, merged, uuid.Nil); err != nil {
			return err
		}
		seeded = seed
		return nil
	})
	if err != nil {
		return nil, err
	}
	return seeded, nil
}

// RecordReport stores what a device says it is running.
//
// Called on check-in, from the device's own credentials — never from an
// operator path. It writes no audit row: a device reporting its state is not a
// change somebody made.
func (s *Store) RecordReport(ctx context.Context, tenantID uuid.UUID, owner Owner, rep agentconfig.Report) error {
	sensorID, agentID, err := owner.columns()
	if err != nil {
		return err
	}
	failures, err := json.Marshal(rep.Failures)
	if err != nil {
		return fmt.Errorf("agentconfig/store: marshal failures: %w", err)
	}
	if rep.Failures == nil {
		failures = []byte("{}")
	}
	restart := make([]string, 0, len(rep.PendingRestart))
	for _, k := range rep.PendingRestart {
		restart = append(restart, string(k))
	}
	at := rep.At
	if at.IsZero() {
		at = time.Now()
	}

	return s.withTenant(ctx, tenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO public.agent_config_state (sensor_id, device_agent_id, reported_revision, reported_at, failures, pending_restart)
			VALUES ($1, $2, NULLIF($3, ''), $4, $5::jsonb, $6)
			ON CONFLICT (`+conflictTarget(owner.Runtime)+`) WHERE `+conflictWhere(owner.Runtime)+`
			DO UPDATE SET reported_revision = EXCLUDED.reported_revision,
			              reported_at       = EXCLUDED.reported_at,
			              failures          = EXCLUDED.failures,
			              pending_restart   = EXCLUDED.pending_restart,
			              updated_at        = now()`,
			sensorID, agentID, rep.Revision, at, string(failures), pq.Array(restart))
		if err != nil {
			return fmt.Errorf("agentconfig/store: record report: %w", err)
		}
		return nil
	})
}

func (s *Store) withTenant(ctx context.Context, tenantID uuid.UUID, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("agentconfig/store: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID.String()); err != nil {
		return fmt.Errorf("agentconfig/store: set tenant_id: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func loadDefaults(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, rt agentconfig.Runtime) (agentconfig.Values, error) {
	var raw []byte
	err := tx.QueryRowContext(ctx, `
		SELECT values FROM public.agent_config_defaults
		 WHERE tenant_id = $1 AND runtime = $2`, tenantID, string(rt)).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return agentconfig.Values{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("agentconfig/store: load defaults: %w", err)
	}
	return decodeValues(raw)
}

func loadOverride(ctx context.Context, tx *sql.Tx, sensorID, agentID any) (agentconfig.Values, error) {
	var raw []byte
	err := tx.QueryRowContext(ctx, `
		SELECT values FROM public.agent_config_overrides
		 WHERE (sensor_id IS NOT DISTINCT FROM $1) AND (device_agent_id IS NOT DISTINCT FROM $2)`,
		sensorID, agentID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return agentconfig.Values{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("agentconfig/store: load override: %w", err)
	}
	return decodeValues(raw)
}

// hasReported reports whether this device has ever checked in.
//
// The ROW is the signal, not the revision in it: a device running a build too
// old to name a revision still has a row, and it has still had its one chance
// to establish a starting position.
func hasReported(ctx context.Context, tx *sql.Tx, sensorID, agentID any) (bool, error) {
	var exists bool
	err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM public.agent_config_state
			 WHERE (sensor_id IS NOT DISTINCT FROM $1) AND (device_agent_id IS NOT DISTINCT FROM $2))`,
		sensorID, agentID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("agentconfig/store: check reported state: %w", err)
	}
	return exists, nil
}

func loadReport(ctx context.Context, tx *sql.Tx, sensorID, agentID any) (agentconfig.Report, error) {
	var (
		rev     sql.NullString
		at      sql.NullTime
		rawFail []byte
		restart []string
	)
	err := tx.QueryRowContext(ctx, `
		SELECT reported_revision, reported_at, failures, pending_restart
		  FROM public.agent_config_state
		 WHERE (sensor_id IS NOT DISTINCT FROM $1) AND (device_agent_id IS NOT DISTINCT FROM $2)`,
		sensorID, agentID).Scan(&rev, &at, &rawFail, pq.Array(&restart))
	if errors.Is(err, sql.ErrNoRows) {
		// No row is a device that has never reported — NOT an applied one.
		return agentconfig.Report{}, nil
	}
	if err != nil {
		return agentconfig.Report{}, fmt.Errorf("agentconfig/store: load state: %w", err)
	}

	rep := agentconfig.Report{Revision: rev.String, At: at.Time}
	if len(rawFail) > 0 {
		m := map[string]string{}
		if err := json.Unmarshal(rawFail, &m); err != nil {
			return agentconfig.Report{}, fmt.Errorf("agentconfig/store: decode failures: %w", err)
		}
		if len(m) > 0 {
			rep.Failures = make(map[agentconfig.Key]string, len(m))
			for k, v := range m {
				rep.Failures[agentconfig.Key(k)] = v
			}
		}
	}
	for _, k := range restart {
		rep.PendingRestart = append(rep.PendingRestart, agentconfig.Key(k))
	}
	return rep, nil
}

func writeAudit(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, sensorID, agentID any,
	scope string, rt agentconfig.Runtime, before, after agentconfig.Values, by uuid.UUID) error {
	if len(agentconfig.Diff(before, after)) == 0 {
		// A save that changed nothing is not an event. Recording it would bury
		// the changes that matter under form re-submissions.
		return nil
	}
	b, err := json.Marshal(before)
	if err != nil {
		return fmt.Errorf("agentconfig/store: marshal audit before: %w", err)
	}
	a, err := json.Marshal(after)
	if err != nil {
		return fmt.Errorf("agentconfig/store: marshal audit after: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO public.agent_config_audit
			(tenant_id, sensor_id, device_agent_id, scope, runtime, values_before, values_after, changed_by)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8)`,
		tenantID, sensorID, agentID, scope, string(rt), string(b), string(a), nullUUID(by)); err != nil {
		return fmt.Errorf("agentconfig/store: write audit: %w", err)
	}
	return nil
}

func decodeValues(raw []byte) (agentconfig.Values, error) {
	if len(raw) == 0 {
		return agentconfig.Values{}, nil
	}
	var v agentconfig.Values
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("agentconfig/store: decode values: %w", err)
	}
	if v == nil {
		v = agentconfig.Values{}
	}
	return v, nil
}

// stripEmpty drops keys with no value. An empty Value is how a caller says
// "remove this override"; storing it would make the key look set to nothing,
// which no layer above knows how to read.
func stripEmpty(v agentconfig.Values) agentconfig.Values {
	out := make(agentconfig.Values, len(v))
	for k, val := range v {
		if !val.IsZero() {
			out[k] = val
		}
	}
	return out
}

func conflictTarget(rt agentconfig.Runtime) string {
	if rt == agentconfig.RuntimeSensor {
		return "sensor_id"
	}
	return "device_agent_id"
}

func conflictWhere(rt agentconfig.Runtime) string {
	if rt == agentconfig.RuntimeSensor {
		return "sensor_id IS NOT NULL"
	}
	return "device_agent_id IS NOT NULL"
}

func nullUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

// LoadDefaults returns the tenant's fleet defaults for a runtime, resolved
// against the built-in defaults so every settable key is present.
//
// Resolved rather than raw: the defaults page has to show a value for every
// setting, and an Origin saying whether the tenant set it or is inheriting the
// device's own default. Handing back the raw stored map would make the page
// invent the missing ones, which is where two sources of truth start.
func (s *Store) LoadDefaults(ctx context.Context, tenantID uuid.UUID, rt agentconfig.Runtime) ([]agentconfig.Resolved, error) {
	var out []agentconfig.Resolved
	err := s.withTenant(ctx, tenantID, func(tx *sql.Tx) error {
		fleet, err := loadDefaults(ctx, tx, tenantID, rt)
		if err != nil {
			return err
		}
		out = agentconfig.Resolve(rt, fleet, nil)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RequestRestart records that an operator asked this device to restart.
//
// Upserts the override row, because a device with no settings of its own still
// has to be restartable — and writes an audit row, because a restart is an
// operator action on a customer's host, not a read.
func (s *Store) RequestRestart(ctx context.Context, tenantID uuid.UUID, owner Owner, by uuid.UUID) (time.Time, error) {
	sensorID, agentID, err := owner.columns()
	if err != nil {
		return time.Time{}, err
	}
	at := time.Now()

	err = s.withTenant(ctx, tenantID, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO public.agent_config_overrides (sensor_id, device_agent_id, values, restart_requested_at, restart_requested_by)
			VALUES ($1, $2, '{}'::jsonb, $3, $4)
			ON CONFLICT (`+conflictTarget(owner.Runtime)+`) WHERE `+conflictWhere(owner.Runtime)+`
			DO UPDATE SET restart_requested_at = EXCLUDED.restart_requested_at,
			              restart_requested_by = EXCLUDED.restart_requested_by,
			              updated_at           = now()`,
			sensorID, agentID, at, nullUUID(by)); err != nil {
			return fmt.Errorf("agentconfig/store: request restart: %w", err)
		}
		return writeRestartAudit(ctx, tx, tenantID, sensorID, agentID, owner.Runtime, at, by)
	})
	if err != nil {
		return time.Time{}, err
	}
	return at, nil
}

func loadRestart(ctx context.Context, tx *sql.Tx, sensorID, agentID any) (agentconfig.RestartRequest, error) {
	var at sql.NullTime
	err := tx.QueryRowContext(ctx, `
		SELECT restart_requested_at FROM public.agent_config_overrides
		 WHERE (sensor_id IS NOT DISTINCT FROM $1) AND (device_agent_id IS NOT DISTINCT FROM $2)`,
		sensorID, agentID).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return agentconfig.RestartRequest{}, nil
	}
	if err != nil {
		return agentconfig.RestartRequest{}, fmt.Errorf("agentconfig/store: load restart request: %w", err)
	}
	return agentconfig.RestartRequest{At: at.Time}, nil
}

// writeRestartAudit records the request in the same append-only trail as a
// settings change. A restart is an action taken on somebody's host; "who asked,
// and when" is exactly what an audit trail is for.
func writeRestartAudit(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, sensorID, agentID any,
	rt agentconfig.Runtime, at time.Time, by uuid.UUID) error {
	after, err := json.Marshal(map[string]any{"restart_requested_at": at})
	if err != nil {
		return fmt.Errorf("agentconfig/store: marshal restart audit: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO public.agent_config_audit
			(tenant_id, sensor_id, device_agent_id, scope, runtime, values_before, values_after, changed_by)
		VALUES ($1, $2, $3, 'device', $4, '{}'::jsonb, $5::jsonb, $6)`,
		tenantID, sensorID, agentID, string(rt), string(after), nullUUID(by)); err != nil {
		return fmt.Errorf("agentconfig/store: write restart audit: %w", err)
	}
	return nil
}

// Change is one recorded configuration change, as agent_config_audit holds it.
//
// The table was write-only until this existed: every save wrote a row and
// nothing read one. That is the orphaned layer this project's framework
// forbids, and it mattered more than usual here — the DNS decoder is
// manageable only because the owner's decision paired it with a recorded
// confirmation, and a record nobody can read does not discharge that.
type Change struct {
	At     time.Time          `json:"changed_at"`
	By     uuid.UUID          `json:"changed_by"`
	Scope  string             `json:"scope"`
	Before agentconfig.Values `json:"values_before"`
	After  agentconfig.Values `json:"values_after"`
}

// Changed reports the keys whose value differs between Before and After,
// including keys added or removed. The caller renders the difference; deriving
// it here keeps every reader from re-implementing "what actually moved".
func (c Change) Changed() []agentconfig.Key {
	var keys []agentconfig.Key
	seen := map[agentconfig.Key]bool{}
	for k := range c.After {
		seen[k] = true
		// Value holds POINTERS, so `!=` compares addresses and would report
		// every key as changed on every row — the history would be honest about
		// nothing. Equal compares content, which is what a comparison in this
		// package has always meant.
		if b, ok := c.Before[k]; !ok || !b.Equal(c.After[k]) {
			keys = append(keys, k)
		}
	}
	for k := range c.Before {
		if !seen[k] {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}

// LoadHistory returns the most recent changes affecting one device: its own
// overrides AND the fleet defaults of its runtime, because a device's effective
// configuration moves when either does, and an operator asking "why is this on"
// is not helped by a history that omits half the answers.
//
// Newest first. limit is clamped, so a caller cannot ask for the whole table.
func (s *Store) LoadHistory(ctx context.Context, tenantID uuid.UUID, owner Owner, limit int) ([]Change, error) {
	sensorID, agentID, err := owner.columns()
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []Change
	err = s.withTenant(ctx, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT changed_at, changed_by, scope, values_before, values_after
			  FROM public.agent_config_audit
			 WHERE tenant_id = $1
			   AND runtime = $2
			   AND (
			         (scope = 'device' AND sensor_id IS NOT DISTINCT FROM $3
			                          AND device_agent_id IS NOT DISTINCT FROM $4)
			      OR scope = 'fleet'
			   )
			 ORDER BY changed_at DESC
			 LIMIT $5`, tenantID, string(owner.Runtime), sensorID, agentID, limit)
		if err != nil {
			return fmt.Errorf("agentconfig/store: query history: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var (
				c             Change
				by            uuid.NullUUID
				before, after []byte
			)
			if err := rows.Scan(&c.At, &by, &c.Scope, &before, &after); err != nil {
				return fmt.Errorf("agentconfig/store: scan history: %w", err)
			}
			if by.Valid {
				c.By = by.UUID
			}
			if c.Before, err = decodeValues(before); err != nil {
				return err
			}
			if c.After, err = decodeValues(after); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
