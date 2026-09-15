package postgres

// The two phase-1 asset side tables an intake writes ALONGSIDE identification:
// `asset_facts` (ADR-0005 D2) and `asset_relationships` (ADR-0003).
//
// They live on this Repository rather than in a package of their own for one
// reason: they have to land in the SAME transaction as the [Engine.Resolve]
// that created the asset they hang off. An observed LLDP neighbour becomes a
// pending asset (Resolve) and an edge to it (UpsertRelationship) — commit the
// first without the second and the inventory grows a peer nobody can explain,
// which no later run repairs because the next observation MATCHES that peer and
// never reaches the create path again. [Repository.RunInTx] is the seam that
// makes one unit of work possible, and it hands back a *Repository, so the
// writers have to be methods on it.
//
// They are deliberately NOT part of the [identity.Repository] interface. That
// interface is the identification contract — eight methods, held to
// identitytest.RunRepositoryContract — and facts and edges are not
// identification. A second implementation of identification does not owe
// anybody a fact writer.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/relationships"
)

// ErrSelfEdge is returned for an edge whose two ends are the same asset.
//
// `asset_relationships_no_self_edge_check` forbids it in the database, but a
// caller gets a named error instead of a constraint violation because a
// self-edge is never a data problem at this layer: it means the same host
// resolved twice under two identifiers, which is an identity bug upstream and
// something the caller should log as such rather than retry.
var ErrSelfEdge = errors.New("identity/postgres: an edge cannot join an asset to itself")

// Fact is one row of `asset_facts`: a statement about an asset with the
// provenance that lets ADR-0002 D4 reconcile it against another source's
// answer.
//
// Key must be registered in standards/fact-keys.yaml and Value must match its
// declared type — [Repository.UpsertFacts] enforces both, because the key
// column has no CHECK constraint and the value column is jsonb, so nothing else
// stands between a producer and a fact nobody can read back.
type Fact struct {
	Key   string `json:"key"`
	Value any    `json:"value"`

	SourceKind identity.SourceKind `json:"source_kind"`
	// SourceRef names the producer and is PART OF THE UNIQUE KEY: two sources
	// may hold different values for one key, and the reconciliation precedence
	// chooses the displayed one. Use the ADR-0003 D3 shapes —
	// `interrogation:<job>`, `cloud:<integration>`, `sensor:<id>`, `user:<id>`.
	SourceRef string `json:"source_ref"`

	// Confidence is 0..1 and NULL in the column when zero: zero means NOT
	// ASSESSED, the same convention risk scoring uses, not "certainly wrong".
	Confidence float64 `json:"confidence,omitempty"`
	// ModelID is required (with Confidence) for an inferred fact — ADR-0005 D2:
	// an inferred fact must say what inferred it and how sure it is.
	ModelID string `json:"model_id,omitempty"`

	ObservedAt time.Time `json:"observed_at,omitzero"`
}

// Edge is one row of `asset_relationships`: a typed, directional, canonical
// edge between two assets of one tenant.
type Edge struct {
	FromAssetID string `json:"from_asset_id"`
	ToAssetID   string `json:"to_asset_id"`
	// Type is one of the canonical ten (shared/relationships). Stored once in
	// the canonical direction; the reverse label is derived and never stored.
	Type string `json:"type"`

	SourceKind identity.SourceKind `json:"source_kind"`
	SourceRef  string              `json:"source_ref"`
	Confidence float64             `json:"confidence,omitempty"`

	// Status is one of pending / active / rejected / stale. Callers should get
	// it from [Repository.EdgeStatusFor] rather than choosing one, so ADR-0003
	// D3's table has one implementation.
	Status string `json:"status"`

	// Attributes carries the type-specific detail ADR-0003 D2 names: the local
	// and remote port names of an LLDP neighbour, a VLAN id, a protocol.
	Attributes map[string]any `json:"attributes,omitempty"`

	ObservedAt time.Time `json:"observed_at,omitzero"`
}

// Relationship status values.
const (
	EdgeStatusPending  = "pending"
	EdgeStatusActive   = "active"
	EdgeStatusRejected = "rejected"
	EdgeStatusStale    = "stale"
)

// ---------------------------------------------------------------------------
// asset_facts
// ---------------------------------------------------------------------------

// UpsertFacts writes facts about one asset on behalf of one producer.
//
// producer is a `shared/facts` producer key; every fact is checked against the
// registry for BOTH "is this key registered" and "may this producer write it".
// The second check is not pedantry: a collector writing a key it is not
// registered for means two subsystems disagree about who owns a fact, which is
// how one key ends up with two meanings and neither consumer notices.
//
// The upsert key is (tenant, asset, key, source_ref) — per source, deliberately.
// Collapsing it to (tenant, asset, key) would make the last writer win and
// destroy the disagreement ADR-0002 D4's precedence exists to resolve.
//
// A fact whose ObservedAt is OLDER than the row already stored for that
// (key, source) is discarded rather than applied. A late-arriving old
// measurement is evidence of what was true then, not of what is true now.
func (r *Repository) UpsertFacts(ctx context.Context, asset identity.AssetRef, producer string, fs []Fact) error {
	if len(fs) == 0 {
		return nil
	}
	assetID, err := parseAsset(asset.ID)
	if err != nil {
		return err
	}
	rows := make([]struct {
		f     Fact
		value []byte
	}, 0, len(fs))
	for _, f := range fs {
		key := strings.TrimSpace(f.Key)
		if !facts.MayWrite(producer, key) {
			if _, known := facts.Get(key); !known {
				return fmt.Errorf("identity/postgres: fact key %q is not registered in standards/fact-keys.yaml", key)
			}
			return fmt.Errorf("identity/postgres: fact key %q does not list %s as a producer", key, producer)
		}
		if err := facts.ValidateValue(key, f.Value); err != nil {
			return fmt.Errorf("identity/postgres: %w", err)
		}
		if f.SourceKind == identity.SourceInferred && (f.Confidence <= 0 || strings.TrimSpace(f.ModelID) == "") {
			// asset_facts_inferred_needs_provenance_check says the same thing
			// in SQL. Saying it here too names the fact and the rule instead of
			// surfacing a constraint name to the operator.
			return fmt.Errorf("identity/postgres: fact %s is inferred and must carry a confidence and a model_id (ADR-0005 D2)", key)
		}
		raw, err := json.Marshal(f.Value)
		if err != nil {
			return fmt.Errorf("identity/postgres: fact %s: value is not JSON: %w", key, err)
		}
		f.Key = key
		rows = append(rows, struct {
			f     Fact
			value []byte
		}{f, raw})
	}

	return r.withTx(ctx, asset.TenantID, func(tx *sql.Tx) error {
		if err := assertAssetExists(ctx, tx, asset); err != nil {
			return err
		}
		return r.savepoint(ctx, tx, "identity_upsert_facts", func() error {
			for _, row := range rows {
				_, err := tx.ExecContext(ctx, `
					INSERT INTO public.asset_facts (
						tenant_id, asset_id, key, value, source_kind, source_ref,
						confidence, model_id, observed_at
					) VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, NULLIF($8, ''), $9)
					ON CONFLICT (tenant_id, asset_id, key, source_ref) DO UPDATE
					SET value       = EXCLUDED.value,
					    source_kind = EXCLUDED.source_kind,
					    confidence  = EXCLUDED.confidence,
					    model_id    = EXCLUDED.model_id,
					    observed_at = EXCLUDED.observed_at,
					    updated_at  = now()
					WHERE EXCLUDED.observed_at >= public.asset_facts.observed_at`,
					asset.TenantID, assetID, row.f.Key, string(row.value),
					sourceKindOr(row.f.SourceKind), factSourceRef(row.f.SourceRef),
					nullFloat(row.f.Confidence), row.f.ModelID, timeOrNow(row.f.ObservedAt))
				if err != nil {
					return fmt.Errorf("identity/postgres: upsert fact %s: %w", row.f.Key, err)
				}
			}
			return nil
		})
	})
}

// Facts reads back an asset's facts, optionally restricted to the given keys.
//
// Every source's row is returned, not a winner: choosing one is reconciliation
// (identity.Reconcile), which needs the provenance this returns and is the
// caller's decision per attribute group. A reader that silently picked for you
// would hide exactly the disagreement the per-source key exists to preserve.
func (r *Repository) Facts(ctx context.Context, asset identity.AssetRef, keys ...string) ([]Fact, error) {
	assetID, err := parseAsset(asset.ID)
	if err != nil {
		return nil, err
	}
	var out []Fact
	err = r.withTx(ctx, asset.TenantID, func(tx *sql.Tx) error {
		out = out[:0]
		rows, err := tx.QueryContext(ctx, `
			SELECT key, value, source_kind, source_ref, confidence, coalesce(model_id, ''), observed_at
			FROM public.asset_facts
			WHERE tenant_id = $1 AND asset_id = $2
			  AND ($3::text[] IS NULL OR key = ANY($3::text[]))
			ORDER BY key, observed_at DESC`,
			asset.TenantID, assetID, textArrayOrNil(keys))
		if err != nil {
			return fmt.Errorf("identity/postgres: read facts: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var (
				f          Fact
				raw        []byte
				kind       string
				confidence sql.NullFloat64
			)
			if err := rows.Scan(&f.Key, &raw, &kind, &f.SourceRef, &confidence, &f.ModelID, &f.ObservedAt); err != nil {
				return fmt.Errorf("identity/postgres: scan fact: %w", err)
			}
			f.SourceKind = identity.SourceKind(kind)
			if confidence.Valid {
				f.Confidence = confidence.Float64
			}
			if err := json.Unmarshal(raw, &f.Value); err != nil {
				return fmt.Errorf("identity/postgres: fact %s: stored value is not JSON: %w", f.Key, err)
			}
			out = append(out, f)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// factSourceRef defaults an empty producer reference to the column's own
// default rather than NULL. source_ref is part of the unique key and the column
// is NOT NULL DEFAULT ” precisely so two rows from "no stated source" cannot
// coexist for one key.
func factSourceRef(ref string) string { return strings.TrimSpace(ref) }

// textArrayOrNil renders keys as a Postgres text[] literal, or NULL for "no
// filter". An empty slice means "no filter", not "match nothing" — a caller
// asking for no particular key wants all of them.
func textArrayOrNil(keys []string) any {
	if len(keys) == 0 {
		return nil
	}
	quoted := make([]string, 0, len(keys))
	for _, k := range keys {
		quoted = append(quoted, `"`+strings.ReplaceAll(k, `"`, `""`)+`"`)
	}
	return "{" + strings.Join(quoted, ",") + "}"
}

// ---------------------------------------------------------------------------
// asset_relationships
// ---------------------------------------------------------------------------

// EdgeStatusFor answers ADR-0003 D3's table: what status does an observed edge
// enter with?
//
//	measured, both endpoints approved        -> active
//	measured, either endpoint still pending  -> pending (resolves with the endpoint)
//	declared by a user                       -> active
//	imported, both endpoints resolved        -> active, else pending
//	inferred                                 -> pending, always (ADR-0008 D3)
//
// It is a method rather than a free function because "are both endpoints
// approved" is a database question, and the one place that answers it is the
// one place the rule can be tested.
func (r *Repository) EdgeStatusFor(ctx context.Context, tenantID string, kind identity.SourceKind, fromID, toID string) (string, error) {
	switch kind {
	case identity.SourceDeclared:
		// A user with assets.update asserting an edge is the same as editing an
		// attribute.
		return EdgeStatusActive, nil
	case identity.SourceInferred:
		// A model's proposal is never a fact (ADR-0008 D3).
		return EdgeStatusPending, nil
	}
	summaries, err := r.LoadSummaries(ctx, tenantID, []string{fromID, toID})
	if err != nil {
		return "", err
	}
	approved := 0
	for _, s := range summaries {
		if s.Status == identity.StatusMonitoring {
			approved++
		}
	}
	// Both ends have to be present AND approved. A summary missing because the
	// asset vanished between the resolve and this call counts as not approved,
	// which is the safe direction: the edge waits in Approvals.
	if approved == 2 {
		return EdgeStatusActive, nil
	}
	return EdgeStatusPending, nil
}

// UpsertRelationship writes one observed edge, idempotently.
//
// The upsert key is (tenant, from, to, type) — the same pair may carry several
// types, so the unique index is on the pair PLUS the type, not on the pair.
// Re-observing an edge bumps last-seen and the observation count rather than
// appending a row.
//
// Two things are deliberately NOT overwritten on a re-observation:
//
//   - A `rejected` edge stays rejected. A human said no; a collector that keeps
//     seeing the thing does not overturn that, it just keeps seeing it.
//   - An `active` edge is never demoted to `pending`. Approval is a decision
//     about the edge, and a later observation of the same edge is not grounds
//     to un-approve it. (This matters because EdgeStatusFor answers `pending`
//     whenever an endpoint is not approved, and an endpoint can be archived
//     later.)
func (r *Repository) UpsertRelationship(ctx context.Context, tenantID string, e Edge) error {
	t := relationships.Type(strings.TrimSpace(e.Type))
	if !t.Valid() {
		return fmt.Errorf("identity/postgres: %q is not one of the canonical relationship types %v", e.Type, relationships.Strings())
	}
	fromID, err := parseAsset(e.FromAssetID)
	if err != nil {
		return err
	}
	toID, err := parseAsset(e.ToAssetID)
	if err != nil {
		return err
	}
	if fromID == toID {
		return fmt.Errorf("%w: %s (%s)", ErrSelfEdge, fromID, t)
	}
	attrs := e.Attributes
	if attrs == nil {
		attrs = map[string]any{}
	}
	raw, err := json.Marshal(attrs)
	if err != nil {
		return fmt.Errorf("identity/postgres: edge %s: attributes are not JSON: %w", t, err)
	}
	status := e.Status
	if status == "" {
		status = EdgeStatusPending
	}

	return r.withTx(ctx, tenantID, func(tx *sql.Tx) error {
		return r.savepoint(ctx, tx, "identity_upsert_edge", func() error {
			_, err := tx.ExecContext(ctx, `
				INSERT INTO public.asset_relationships (
					tenant_id, from_asset_id, to_asset_id, type,
					source_kind, source_ref, confidence, status, attributes,
					first_seen_at, last_seen_at, observation_count
				) VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7, $8, $9::jsonb, $10, $10, 1)
				ON CONFLICT (tenant_id, from_asset_id, to_asset_id, type) DO UPDATE
				SET last_seen_at       = GREATEST(public.asset_relationships.last_seen_at, EXCLUDED.last_seen_at),
				    observation_count  = public.asset_relationships.observation_count + 1,
				    attributes         = public.asset_relationships.attributes || EXCLUDED.attributes,
				    confidence         = GREATEST(public.asset_relationships.confidence, EXCLUDED.confidence),
				    source_kind        = EXCLUDED.source_kind,
				    source_ref         = coalesce(EXCLUDED.source_ref, public.asset_relationships.source_ref),
				    status             = CASE
				                           WHEN public.asset_relationships.status IN ('rejected', 'active')
				                             THEN public.asset_relationships.status
				                           ELSE EXCLUDED.status
				                         END,
				    updated_at         = now()`,
				tenantID, fromID, toID, string(t),
				sourceKindOr(e.SourceKind), strings.TrimSpace(e.SourceRef),
				clampConfidence(edgeConfidence(e.Confidence)), status, string(raw),
				timeOrNow(e.ObservedAt))
			if err != nil {
				return fmt.Errorf("identity/postgres: upsert edge %s %s->%s: %w", t, fromID, toID, err)
			}
			return nil
		})
	})
}

// Relationships reads an asset's edges in both directions. Ordered so a test
// and an operator see the same list twice running.
func (r *Repository) Relationships(ctx context.Context, asset identity.AssetRef) ([]Edge, error) {
	assetID, err := parseAsset(asset.ID)
	if err != nil {
		return nil, err
	}
	var out []Edge
	err = r.withTx(ctx, asset.TenantID, func(tx *sql.Tx) error {
		out = out[:0]
		rows, err := tx.QueryContext(ctx, `
			SELECT from_asset_id, to_asset_id, type, source_kind, coalesce(source_ref, ''),
			       confidence, status, attributes, last_seen_at
			FROM public.asset_relationships
			WHERE tenant_id = $1 AND (from_asset_id = $2 OR to_asset_id = $2)
			ORDER BY type, from_asset_id, to_asset_id`,
			asset.TenantID, assetID)
		if err != nil {
			return fmt.Errorf("identity/postgres: read edges: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var (
				e             Edge
				from, to      uuid.UUID
				kind          string
				rawAttributes []byte
			)
			if err := rows.Scan(&from, &to, &e.Type, &kind, &e.SourceRef,
				&e.Confidence, &e.Status, &rawAttributes, &e.ObservedAt); err != nil {
				return fmt.Errorf("identity/postgres: scan edge: %w", err)
			}
			e.FromAssetID, e.ToAssetID = from.String(), to.String()
			e.SourceKind = identity.SourceKind(kind)
			if err := json.Unmarshal(rawAttributes, &e.Attributes); err != nil {
				return fmt.Errorf("identity/postgres: edge %s: stored attributes are not JSON: %w", e.Type, err)
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// edgeConfidence defaults a caller that said nothing to 1.0 rather than to 0.
//
// The column is NOT NULL DEFAULT 1.00 and has no "not assessed" spelling, so
// zero here would mean "certainly wrong" rather than "unstated" — the opposite
// of the convention `assets.risk_score` uses, and the reason this is not simply
// clamped.
func edgeConfidence(v float64) float64 {
	if v <= 0 {
		return 1
	}
	return v
}
