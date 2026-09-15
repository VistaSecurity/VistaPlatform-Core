// Package postgres is the SQL implementation of [identity.Repository]: the
// storage half of the identification engine (ADR-0002 D3), over the phase-1
// `assets` / `asset_endpoints` / `asset_identifiers` / `asset_history` tables.
//
// It holds no opinions. Precedence, scope rules, conflict detection and
// reconciliation all live in shared/identity, where they are testable without a
// database; this package reads and writes rows and reports the two errors the
// interface documents. The behavioural contract it must satisfy is
// shared/identity/identitytest.RunRepositoryContract, which the in-memory
// implementation also runs — two implementations of one storage contract tested
// by two different suites is how they drift.
//
// # Tenancy
//
// Every statement carries an explicit `tenant_id = $1` predicate AND runs
// inside a transaction that has set `app.tenant_id`, which is the two-layer rule
// in shared/database: the predicate is the control, RLS is the backstop. A
// method called with a tenant other than the one a bound transaction was opened
// for is refused rather than silently re-scoped.
//
// # Transactions
//
// [identity.Repository] has no transaction seam, and one call to
// [identity.Engine.Resolve] makes up to five writes (create, attach, upsert,
// touch, history) that must land together or not at all. [Repository.RunInTx]
// supplies it: it opens ONE tenant-scoped transaction and hands the callback a
// Repository bound to it, so an engine built with
// [identity.Engine.WithRepository] on that value does all of its work inside it.
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/assetclasshistory"
	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// Repository implements [identity.Repository] over Postgres.
//
// The zero value is not usable; build one with [New]. A Repository returned by
// [Repository.RunInTx] is BOUND: it runs on one transaction, for one tenant, and
// refuses any other.
type Repository struct {
	db *sql.DB

	// tx and boundTenant are set only on a bound Repository.
	tx          *sql.Tx
	boundTenant string
}

// New returns a Repository over db. Each method opens its own tenant-scoped
// transaction; use [Repository.RunInTx] to make several calls share one.
func New(db *sql.DB) *Repository { return &Repository{db: db} }

var _ identity.Repository = (*Repository)(nil)

// RunInTx runs fn against a Repository bound to a single tenant-scoped
// transaction, committing when fn returns nil and rolling back otherwise.
//
// This is the seam [identity.Repository] does not have. Use it around one
// observation:
//
//	err := repo.RunInTx(ctx, tenantID, func(r *postgres.Repository) error {
//	        res, err = engine.WithRepository(r).Resolve(ctx, obs)
//	        return err
//	})
//
// Without it, a conflict resolved half-way — the pending asset created, the
// merge proposal not — is a permanent inconsistency no later run repairs,
// because the next observation matches the asset that was created and never
// reaches the conflict path again.
func (r *Repository) RunInTx(ctx context.Context, tenantID string, fn func(*Repository) error) error {
	if r.tx != nil {
		// Already bound. Nesting would need a savepoint and, more importantly,
		// would let a caller believe it had an independent transaction.
		if err := r.checkTenant(tenantID); err != nil {
			return err
		}
		return fn(r)
	}
	tid, err := parseTenant(tenantID)
	if err != nil {
		return err
	}
	return database.WithTenantTx(ctx, r.db, tid, func(tx *sql.Tx) error {
		return fn(&Repository{db: r.db, tx: tx, boundTenant: tid.String()})
	})
}

// Tx returns the transaction a bound Repository runs on, or nil.
//
// It exists so a CALLER can put its own writes in the same unit of work as the
// engine's. One observation is one fact about the world: the asset, its
// identifiers, its endpoints, its last-seen, its history AND the context,
// status and history rows the intake path writes about it either all land or
// none do. Without this the caller could only open a second transaction, and a
// failure between the two leaves an asset whose history says it was created and
// whose context says nothing happened.
//
// The tenant session is already set on it (`app.tenant_id`), so a caller must
// use it only for the tenant the Repository is bound to — which is the tenant
// it passed to [Repository.RunInTx].
func (r *Repository) Tx() *sql.Tx { return r.tx }

// withTx runs fn on the bound transaction, or on a fresh tenant-scoped one.
func (r *Repository) withTx(ctx context.Context, tenantID string, fn func(*sql.Tx) error) error {
	if r.tx != nil {
		if err := r.checkTenant(tenantID); err != nil {
			return err
		}
		return fn(r.tx)
	}
	tid, err := parseTenant(tenantID)
	if err != nil {
		return err
	}
	return database.WithTenantTx(ctx, r.db, tid, fn)
}

// checkTenant refuses to run a bound Repository against another tenant. The
// bound transaction's app.tenant_id is already set, so the write would either
// fail the RLS WITH CHECK or — for a superuser/owner connection, where RLS is
// dormant — succeed against the wrong tenant. Neither is acceptable silently.
func (r *Repository) checkTenant(tenantID string) error {
	if tenantID != r.boundTenant {
		return fmt.Errorf("identity/postgres: repository is bound to tenant %s but was called for %s",
			r.boundTenant, tenantID)
	}
	return nil
}

func parseTenant(tenantID string) (uuid.UUID, error) {
	tid, err := uuid.Parse(strings.TrimSpace(tenantID))
	if err != nil {
		return uuid.Nil, fmt.Errorf("identity/postgres: tenant id %q is not a uuid: %w", tenantID, err)
	}
	return tid, nil
}

// parseAsset turns an asset id into a uuid. A value that is not a uuid names no
// row, so it is reported as [identity.ErrAssetNotFound] rather than as a parse
// error: "no such asset" is exactly what it means, and the interface documents
// that a missing asset and an asset in another tenant give the same answer.
func parseAsset(id string) (uuid.UUID, error) {
	aid, err := uuid.Parse(strings.TrimSpace(id))
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: %q", identity.ErrAssetNotFound, id)
	}
	return aid, nil
}

// savepoint runs fn inside a savepoint when this Repository is bound to a
// caller's transaction, so a write that fails (a unique violation the engine
// could not foresee) does not abort the whole unit of work. On an unbound
// Repository each method already owns its transaction and there is nothing to
// protect, so fn runs directly.
func (r *Repository) savepoint(ctx context.Context, tx *sql.Tx, name string, fn func() error) error {
	if r.tx == nil {
		return fn()
	}
	if _, err := tx.ExecContext(ctx, "SAVEPOINT "+name); err != nil {
		return fmt.Errorf("identity/postgres: savepoint: %w", err)
	}
	if err := fn(); err != nil {
		if _, rbErr := tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT "+name); rbErr != nil {
			return errors.Join(err, fmt.Errorf("identity/postgres: rollback to savepoint: %w", rbErr))
		}
		return err
	}
	_, err := tx.ExecContext(ctx, "RELEASE SAVEPOINT "+name)
	if err != nil {
		return fmt.Errorf("identity/postgres: release savepoint: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

// FindByIdentifier returns the assets carrying this identifier value.
//
// The lookup is the unique index of DATA_MODEL §2 —
// (tenant_id, kind, value, coalesce(scope,”)) — so it normally returns at most
// one row. It returns them all, in a stable order, because the engine treats
// more than one as a conflict and a store that had lost the invariant must be
// detectable rather than tidy.
//
// Soft-deleted assets are NOT filtered out. They still own their identifiers as
// far as the unique index is concerned, so hiding one here would mean telling
// the engine an identifier is free and then failing its insert with a conflict
// the engine was told could not happen.
func (r *Repository) FindByIdentifier(ctx context.Context, tenantID string, kind identity.Kind, value, scope string) ([]identity.AssetRef, error) {
	var refs []identity.AssetRef
	err := r.withTx(ctx, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT asset_id
			FROM public.asset_identifiers
			WHERE tenant_id = $1 AND kind = $2 AND value = $3 AND coalesce(scope, '') = $4
			ORDER BY asset_id`,
			tenantID, string(kind), value, scope)
		if err != nil {
			return fmt.Errorf("identity/postgres: find %s: %w", kind, err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return fmt.Errorf("identity/postgres: scan owner: %w", err)
			}
			refs = append(refs, identity.AssetRef{TenantID: tenantID, ID: id.String()})
		}
		return rows.Err()
	})
	return refs, err
}

// LoadSummaries returns the summaries for these ids, in the order asked,
// skipping ids the tenant does not have. A missing id is not an error: the
// caller is loading merge candidates, and one deleted between the lookup and
// the load is a smaller set, not a failure.
func (r *Repository) LoadSummaries(ctx context.Context, tenantID string, ids []string) ([]identity.AssetSummary, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	// An id that is not a uuid cannot name a row. Dropping it here keeps the
	// query from failing wholesale on one bad value, which would turn "one
	// candidate is unknown" into "no candidates".
	wanted := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, err := uuid.Parse(strings.TrimSpace(id)); err == nil {
			wanted = append(wanted, strings.TrimSpace(id))
		}
	}
	if len(wanted) == 0 {
		return nil, nil
	}

	byID := make(map[string]*identity.AssetSummary, len(wanted))
	err := r.withTx(ctx, tenantID, func(tx *sql.Tx) error {
		// The segment, the last sighting and the two comparable class attributes
		// travel with the summary because the matcher seam compares them
		// (ADR-0008 D1): two records agreeing on a hostname while disagreeing
		// about the SEGMENT are probably two things, and two disagreeing about
		// the VENDOR certainly are. Only `vendor` and `model` are lifted out of
		// `attributes` — identity.SummaryAttributeKeys — because a candidate
		// summary is what a seam needs to rank a pairing, not the asset.
		rows, err := tx.QueryContext(ctx, `
			SELECT id, class_key, coalesce(display_name, ''), asset_status,
			       coalesce(network_segment_id::text, ''), last_seen_at,
			       coalesce(attributes ->> 'vendor', ''), coalesce(attributes ->> 'model', '')
			FROM public.assets
			WHERE tenant_id = $1 AND id = ANY($2::uuid[])`,
			tenantID, pgUUIDArray(wanted))
		if err != nil {
			return fmt.Errorf("identity/postgres: load summaries: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var (
				id                            uuid.UUID
				classKey, displayName, status string
				segment                       string
				lastSeen                      time.Time
				vendor, model                 string
			)
			if err := rows.Scan(&id, &classKey, &displayName, &status,
				&segment, &lastSeen, &vendor, &model); err != nil {
				return fmt.Errorf("identity/postgres: scan summary: %w", err)
			}
			byID[id.String()] = &identity.AssetSummary{
				Ref:            identity.AssetRef{TenantID: tenantID, ID: id.String()},
				ClassKey:       classKey,
				DisplayName:    displayName,
				Status:         status,
				NetworkSegment: segment,
				LastSeenAt:     lastSeen,
				Attributes:     comparableAttributes(vendor, model),
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(byID) == 0 {
			return nil
		}

		// The identifiers are what a reviewer reads on a merge proposal: a
		// candidate with no evidence can only be rubber-stamped.
		idRows, err := tx.QueryContext(ctx, `
			SELECT asset_id, kind, value, coalesce(scope, ''), confidence, source_kind,
			       coalesce(source_ref, ''), last_seen_at
			FROM public.asset_identifiers
			WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[])
			ORDER BY asset_id, kind, value`,
			tenantID, pgUUIDArray(wanted))
		if err != nil {
			return fmt.Errorf("identity/postgres: load candidate identifiers: %w", err)
		}
		defer func() { _ = idRows.Close() }()
		for idRows.Next() {
			var (
				assetID               uuid.UUID
				kind, value, scope    string
				confidence            float64
				sourceKind, sourceRef string
				seenAt                time.Time
			)
			if err := idRows.Scan(&assetID, &kind, &value, &scope, &confidence, &sourceKind, &sourceRef, &seenAt); err != nil {
				return fmt.Errorf("identity/postgres: scan candidate identifier: %w", err)
			}
			s, ok := byID[assetID.String()]
			if !ok {
				continue
			}
			s.Identifiers = append(s.Identifiers, identity.Identifier{
				Kind:       identity.Kind(kind),
				Value:      value,
				Scope:      scope,
				Confidence: confidence,
				Source:     identity.Source{Kind: identity.SourceKind(sourceKind), Ref: sourceRef},
				SeenAt:     seenAt,
			})
		}
		return idRows.Err()
	})
	if err != nil {
		return nil, err
	}

	out := make([]identity.AssetSummary, 0, len(byID))
	for _, id := range ids {
		if s, ok := byID[strings.TrimSpace(id)]; ok {
			out = append(out, *s)
		}
	}
	return out, nil
}

// comparableAttributes builds the narrow attribute map a candidate summary
// carries ([identity.SummaryAttributeKeys]).
//
// An attribute the asset does not have is ABSENT rather than present-and-empty:
// the matcher's agreement features read empty as "unknown, so neither agreement
// nor disagreement", and a key present with an empty value reads the same today
// only by accident.
func comparableAttributes(vendor, model string) map[string]any {
	var out map[string]any
	set := func(k, v string) {
		if strings.TrimSpace(v) == "" {
			return
		}
		if out == nil {
			out = make(map[string]any, 2)
		}
		out[k] = v
	}
	set("vendor", vendor)
	set("model", model)
	return out
}

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------

// CreateAsset writes a new asset with its identifiers and endpoints.
//
// All three land in one transaction: an asset whose identifiers failed to write
// is an asset nothing can ever match again, which is worse than no asset at all.
func (r *Repository) CreateAsset(ctx context.Context, tenantID string, a identity.NewAsset) (identity.AssetRef, error) {
	var ref identity.AssetRef
	err := r.withTx(ctx, tenantID, func(tx *sql.Tx) error {
		return r.savepoint(ctx, tx, "identity_create_asset", func() error {
			classKey := strings.TrimSpace(a.ClassKey)
			if classKey == "" {
				classKey = assetclass.KeyUnknownHost
			}
			classPath, err := classPathFor(ctx, tx, tenantID, classKey)
			if err != nil {
				return err
			}
			status := a.Status
			if status == "" {
				status = identity.StatusPendingApproval
			}
			ownership := normalizeOwnership(a.Ownership)

			var id uuid.UUID
			err = tx.QueryRowContext(ctx, `
				INSERT INTO public.assets (
					tenant_id, class_key, class_path, class_source_kind, class_source_ref,
					class_confidence, display_name, hostname, primary_address,
					asset_status, asset_ownership, network_segment_id, discovery_method,
					confidence_score, first_discovered_at, last_seen_at
				) VALUES (
					$1, $2, $3, $4, NULLIF($5, ''),
					$6, NULLIF($7, ''), NULLIF($8, ''), $9::text::inet,
					$10, $11, $12::uuid, NULLIF($13, ''),
					$14, $15, $16
				)
				RETURNING id`,
				tenantID, classKey, classPath, classSourceKindOr(a.ClassSourceKind), classSourceRefOr(a),
				nullFloat(a.ClassConfidence), a.DisplayName, a.Hostname, nullInet(a.PrimaryAddress),
				status, ownership, nullUUID(a.NetworkSegment), a.DiscoveryMethod,
				nullPercent(a.Confidence), timeOrNow(a.FirstSeenAt), timeOrNow(a.LastSeenAt),
			).Scan(&id)
			if err != nil {
				return fmt.Errorf("identity/postgres: insert asset: %w", err)
			}
			ref = identity.AssetRef{TenantID: tenantID, ID: id.String()}

			// The first row of the asset's class history: no previous class,
			// and the mechanism read off the provenance the INSERT above just
			// stamped. Every intake path that states a class — discovery,
			// import, a connector, the class picker — reaches the database
			// through this one INSERT, so recording it here is what makes the
			// history complete rather than a log of edits to assets that
			// happened to be edited.
			//
			// In the same transaction as the asset, for the same reason the
			// identifiers are: a history row whose asset rolled back is a
			// record of something that did not happen.
			tenantUUID, err := uuid.Parse(strings.TrimSpace(tenantID))
			if err != nil {
				return fmt.Errorf("identity/postgres: tenant id %q is not a uuid: %w", tenantID, err)
			}
			if err := assetclasshistory.Record(ctx, tx, tenantUUID, id, assetclasshistory.Entry{
				To:     classKey,
				Source: assetclasshistory.SourceForClassProvenance(classSourceKindOr(a.ClassSourceKind)),
				Evidence: map[string]any{
					"class_source_kind": classSourceKindOr(a.ClassSourceKind),
					"class_source_ref":  classSourceRefOr(a),
				},
			}); err != nil {
				return err
			}

			if err := r.attach(ctx, tx, ref, a.Identifiers); err != nil {
				return err
			}
			return r.upsertEndpoints(ctx, tx, ref, a.Endpoints)
		})
	})
	if err != nil {
		return identity.AssetRef{}, err
	}
	return ref, nil
}

// AttachIdentifiers records identifiers against an existing asset, idempotently.
func (r *Repository) AttachIdentifiers(ctx context.Context, asset identity.AssetRef, ids []identity.Identifier) error {
	if len(ids) == 0 {
		return nil
	}
	return r.withTx(ctx, asset.TenantID, func(tx *sql.Tx) error {
		if err := assertAssetExists(ctx, tx, asset); err != nil {
			return err
		}
		return r.savepoint(ctx, tx, "identity_attach", func() error {
			return r.attach(ctx, tx, asset, ids)
		})
	})
}

// attach is the upsert shared by CreateAsset and AttachIdentifiers.
//
// The ON CONFLICT ... WHERE clause is what turns the unique index into an
// answer instead of an error: a row already owned by ANOTHER asset matches the
// index, fails the WHERE, updates nothing and returns nothing — so a zero
// row count IS the conflict, reported as [identity.ErrIdentifierConflict]
// without ever provoking a constraint violation that would poison the
// transaction.
func (r *Repository) attach(ctx context.Context, tx *sql.Tx, asset identity.AssetRef, ids []identity.Identifier) error {
	assetID, err := parseAsset(asset.ID)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if id.Kind == "" || strings.TrimSpace(id.Value) == "" {
			// The absence of an identifier is not an identifier whose value is
			// "". The engine normalises before it gets here; this is the
			// backstop for a caller that did not.
			continue
		}
		res, err := tx.ExecContext(ctx, `
			INSERT INTO public.asset_identifiers (
				tenant_id, asset_id, kind, value, scope, source_kind, source_ref,
				confidence, first_seen_at, last_seen_at
			) VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, NULLIF($7, ''), $8, $9, $9)
			ON CONFLICT (tenant_id, kind, value, coalesce(scope, '')) DO UPDATE
			SET last_seen_at = GREATEST(public.asset_identifiers.last_seen_at, EXCLUDED.last_seen_at),
			    confidence   = GREATEST(public.asset_identifiers.confidence, EXCLUDED.confidence),
			    source_ref   = coalesce(EXCLUDED.source_ref, public.asset_identifiers.source_ref),
			    updated_at   = now()
			WHERE public.asset_identifiers.asset_id = EXCLUDED.asset_id`,
			asset.TenantID, assetID, string(id.Kind), id.Value, id.Scope,
			sourceKindOr(id.Source.Kind), id.Source.Ref, clampConfidence(id.Confidence),
			timeOrNow(id.SeenAt))
		if err != nil {
			return fmt.Errorf("identity/postgres: attach %s=%q: %w", id.Kind, id.Value, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("identity/postgres: attach %s: rows affected: %w", id.Kind, err)
		}
		if n == 0 {
			return fmt.Errorf("%w: %s=%q", identity.ErrIdentifierConflict, id.Kind, id.Value)
		}
	}
	return nil
}

// UpsertEndpoints writes endpoints under the asset, keyed by the endpoint
// identity of DATA_MODEL §2. Endpoints are dependent identity: they are never
// matched on their own, only upserted under an asset the identifiers resolved.
func (r *Repository) UpsertEndpoints(ctx context.Context, asset identity.AssetRef, eps []identity.EndpointObservation) error {
	if len(eps) == 0 {
		return nil
	}
	return r.withTx(ctx, asset.TenantID, func(tx *sql.Tx) error {
		if err := assertAssetExists(ctx, tx, asset); err != nil {
			return err
		}
		return r.savepoint(ctx, tx, "identity_endpoints", func() error {
			return r.upsertEndpoints(ctx, tx, asset, eps)
		})
	})
}

func (r *Repository) upsertEndpoints(ctx context.Context, tx *sql.Tx, asset identity.AssetRef, eps []identity.EndpointObservation) error {
	if len(eps) == 0 {
		return nil
	}
	assetID, err := parseAsset(asset.ID)
	if err != nil {
		return err
	}
	for _, ep := range eps {
		addr := nullInet(ep.Address)
		fqdn := strings.ToLower(strings.TrimSpace(ep.FQDN))
		if addr == nil && fqdn == "" {
			// asset_endpoints_addressable_check would reject it, and an
			// endpoint that is neither an address nor a name is not an
			// observation of anything.
			continue
		}
		transport := strings.ToLower(strings.TrimSpace(ep.Transport))
		switch transport {
		case "tcp", "udp", "none":
		default:
			// The same default [identity.EndpointKey] applies, so the dedupe
			// key the engine computed and the row written here agree.
			transport = "none"
		}
		// Every enrichment column below is written with `coalesce(EXCLUDED.x,
		// existing)` on conflict: an observation that does not know a service
		// name or a binding must not ERASE one an observation that did know
		// has already recorded. A TLS probe of a port a host agent has already
		// named would otherwise blank the process name on every scan.
		_, err := tx.ExecContext(ctx, `
			INSERT INTO public.asset_endpoints (
				tenant_id, asset_id, address, fqdn, port, transport, protocol,
				service_name, service_confidence, service_identification_method, bound_local,
				source_kind, source_ref, status, first_seen_at, last_seen_at
			) VALUES (
				$1, $2, $3::text::inet, NULLIF($4, ''), $5, $6,
				(SELECT e.enumlabel::text::public.protocol_type
				   FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid
				  WHERE t.typname = 'protocol_type' AND e.enumlabel = $7),
				NULLIF($8, ''), coalesce(NULLIF($9, ''), 'none'), NULLIF($10, ''), $11,
				$12, NULLIF($13, ''), 'active', $14, $14
			)
			ON CONFLICT (tenant_id, asset_id, coalesce(address::text, ''), coalesce(fqdn, ''), coalesce(port, -1), transport)
			DO UPDATE SET
				last_seen_at = GREATEST(public.asset_endpoints.last_seen_at, EXCLUDED.last_seen_at),
				protocol     = coalesce(EXCLUDED.protocol, public.asset_endpoints.protocol),
				service_name = coalesce(EXCLUDED.service_name, public.asset_endpoints.service_name),
				service_confidence = CASE WHEN EXCLUDED.service_name IS NOT NULL
				                          THEN EXCLUDED.service_confidence
				                          ELSE public.asset_endpoints.service_confidence END,
				service_identification_method = CASE WHEN EXCLUDED.service_name IS NOT NULL
				                          THEN EXCLUDED.service_identification_method
				                          ELSE public.asset_endpoints.service_identification_method END,
				bound_local  = coalesce(EXCLUDED.bound_local, public.asset_endpoints.bound_local),
				source_ref   = coalesce(EXCLUDED.source_ref, public.asset_endpoints.source_ref),
				status       = 'active',
				updated_at   = now()`,
			asset.TenantID, assetID, addr, fqdn, nullPort(ep.Port), transport,
			strings.TrimSpace(ep.Protocol),
			strings.TrimSpace(ep.ServiceName), strings.TrimSpace(ep.ServiceConfidence),
			strings.TrimSpace(ep.ServiceIdentificationMethod), ep.BoundLocal,
			sourceKindOr(ep.Source.Kind), ep.Source.Ref,
			timeOrNow(ep.SeenAt))
		if err != nil {
			return fmt.Errorf("identity/postgres: upsert endpoint %s: %w", ep.Key(), err)
		}
	}
	return nil
}

// Touch advances the asset's last-seen, never backwards: a late-arriving old
// observation is evidence the asset existed then, not evidence it has not been
// seen since. GREATEST does that in one statement, so two concurrent touches
// cannot interleave into a regression.
func (r *Repository) Touch(ctx context.Context, asset identity.AssetRef, seenAt time.Time) error {
	assetID, err := parseAsset(asset.ID)
	if err != nil {
		return err
	}
	return r.withTx(ctx, asset.TenantID, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE public.assets
			SET last_seen_at = GREATEST(last_seen_at, $3), updated_at = now()
			WHERE tenant_id = $1 AND id = $2`,
			asset.TenantID, assetID, timeOrNow(seenAt))
		if err != nil {
			return fmt.Errorf("identity/postgres: touch %s: %w", asset.ID, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("identity/postgres: touch: rows affected: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("%w: %s", identity.ErrAssetNotFound, asset.ID)
		}
		return nil
	})
}

// RecordHistory appends one asset_history row.
//
// `seq` orders them. Every entry the engine writes for one observation shares a
// transaction, so `created_at` — which defaults to now(), the TRANSACTION
// timestamp — is identical across all of them and cannot order anything. A
// timeline that reverses `created` and `merge_proposed` tells the story
// backwards.
func (r *Repository) RecordHistory(ctx context.Context, e identity.HistoryEntry) error {
	assetID, err := parseAsset(e.AssetID)
	if err != nil {
		return err
	}
	changes := e.Changes
	if changes == nil {
		changes = map[string]any{}
	}
	// Provenance travels with the entry: "who said so" is the question a
	// history exists to answer.
	if e.Source.Kind != "" {
		changes["source_kind"] = string(e.Source.Kind)
	}
	if e.Source.Mode != "" {
		changes["source_mode"] = string(e.Source.Mode)
	}
	payload, err := json.Marshal(changes)
	if err != nil {
		return fmt.Errorf("identity/postgres: marshal history changes: %w", err)
	}
	source := strings.TrimSpace(e.Source.Ref)
	if source == "" {
		// asset_history.source is NOT NULL, and "" would claim the change had
		// no producer. The kind is the coarsest true answer available.
		source = string(e.Source.Kind)
		if source == "" {
			source = "unknown"
		}
	}
	return r.withTx(ctx, e.TenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO public.asset_history (asset_id, tenant_id, actor_user_id, source, action, changes_json, created_at)
			VALUES ($1, $2, $3::uuid, $4, $5, $6::jsonb, $7)`,
			assetID, e.TenantID, nullUUID(e.ActorUserID), source, string(e.Action), payload, timeOrNow(e.At))
		if err != nil {
			return fmt.Errorf("identity/postgres: record %s history: %w", e.Action, err)
		}
		return nil
	})
}

// OpenMergeProposal records a merge proposal for the Approvals queue.
//
// There is no proposals table in phase 1, and inventing one here would be a
// second home for a decision the Approvals workstream owns. The proposal is an
// `asset_history` row with action `merge_proposed` — the value ADR-0002 D3's
// third outcome exists for — whose changes_json carries the candidates, the
// reason and the evidence. `kind: merge_proposal` marks the row as the proposal
// ITSELF rather than the engine's separate pointer entry, which carries only
// `proposal_id`; the Approvals surface reads on that marker.
//
// The subject asset is also pinned to `pending_approval`. A conflict must never
// promote anything: the proposal is the human's work item and the asset waits
// for it.
func (r *Repository) OpenMergeProposal(ctx context.Context, tenantID string, p identity.MergeProposal) (identity.ProposalRef, error) {
	subject := p.ObservationAssetID
	if subject == "" {
		subject = p.AcceptedAssetID
	}
	if subject == "" && len(p.Candidates) > 0 {
		subject = p.Candidates[0].Ref.ID
	}
	if subject == "" {
		return identity.ProposalRef{}, errors.New("identity/postgres: merge proposal names no asset")
	}
	subjectID, err := parseAsset(subject)
	if err != nil {
		return identity.ProposalRef{}, err
	}

	candidates := make([]map[string]any, 0, len(p.Candidates))
	for _, c := range p.Candidates {
		matched := make([]map[string]any, 0, len(c.MatchedIdentifiers))
		for _, id := range c.MatchedIdentifiers {
			matched = append(matched, map[string]any{
				"kind": string(id.Kind), "value": id.Value, "scope": id.Scope,
			})
		}
		candidate := map[string]any{
			"asset_id":            c.Ref.ID,
			"matched_identifiers": matched,
			"score":               c.Score,
			"reason":              c.Reason,
		}
		// The score's working, when the matcher could show any. Omitted rather
		// than written empty: a candidate the null matcher left unscored has no
		// explanation, and `"explanation": []` would read as "we looked and
		// there was nothing to say".
		if len(c.Explanation) > 0 {
			factors := make([]map[string]any, 0, len(c.Explanation))
			for _, f := range c.Explanation {
				factors = append(factors, map[string]any{
					"feature":      f.Feature,
					"label":        f.Label,
					"value":        f.Value,
					"weight":       f.Weight,
					"contribution": f.Contribution,
				})
			}
			candidate["explanation"] = factors
		}
		candidates = append(candidates, candidate)
	}
	fingerprint := identity.MergeProposalFingerprint(p)
	payload, err := json.Marshal(map[string]any{
		"kind":                 "merge_proposal",
		"status":               "pending",
		"observation_asset_id": p.ObservationAssetID,
		"candidates":           candidates,
		"reason":               p.Reason,
		// Which matcher RANKED this proposal, whether or not it accepted
		// anything. A proposal a human resolves should still be able to say
		// which model put the winner at the top (ADR-0008 D4.1).
		"model_id":            p.ModelID,
		"source_ref":          p.SourceRef,
		"auto_accepted":       p.AutoAccepted,
		"accepted_asset_id":   p.AcceptedAssetID,
		"accepted_score":      p.AcceptedScore,
		"accepted_model_id":   p.AcceptedModelID,
		"accepted_source_ref": p.AcceptedSourceRef,
		"source_kind":         string(p.Source.Kind),
		// The idempotency key. See idx_asset_history_pending_merge_proposal.
		"fingerprint": fingerprint,
	})
	if err != nil {
		return identity.ProposalRef{}, fmt.Errorf("identity/postgres: marshal merge proposal: %w", err)
	}
	source := strings.TrimSpace(p.Source.Ref)
	if source == "" {
		source = "unknown"
	}

	var id uuid.UUID
	err = r.withTx(ctx, tenantID, func(tx *sql.Tx) error {
		if err := assertAssetExists(ctx, tx, identity.AssetRef{TenantID: tenantID, ID: subject}); err != nil {
			return err
		}
		// ON CONFLICT DO NOTHING against idx_asset_history_pending_merge_proposal:
		// a PENDING proposal with this fingerprint already exists, so this
		// observation has already asked the question and a human already has
		// the work item. Re-asking it every poll is how the queue filled with
		// ninety-six identical rows a day.
		//
		// No conflict TARGET is named: the index is partial, and naming a
		// partial index's columns would require repeating its predicate here —
		// a second copy of the rule, free to drift from the first.
		err := tx.QueryRowContext(ctx, `
			INSERT INTO public.asset_history (asset_id, tenant_id, source, action, changes_json, created_at)
			VALUES ($1, $2, $3, 'merge_proposed', $4::jsonb, $5)
			ON CONFLICT DO NOTHING
			RETURNING id`,
			subjectID, tenantID, source, payload, timeOrNow(p.ProposedAt)).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			// The insert was suppressed. Return the EXISTING proposal's id, not
			// an error and not a zero ref: the caller is about to tell somebody
			// "review the merge proposal", and it has to name the one that is
			// actually in the queue.
			if err := tx.QueryRowContext(ctx, `
				SELECT id FROM public.asset_history
				WHERE tenant_id = $1
				  AND action = 'merge_proposed'
				  AND changes_json ->> 'fingerprint' = $2
				  AND COALESCE(changes_json ->> 'status', 'pending') = 'pending'
				ORDER BY seq DESC
				LIMIT 1`, tenantID, fingerprint).Scan(&id); err != nil {
				return fmt.Errorf("identity/postgres: find the existing merge proposal: %w", err)
			}
			// Still refresh the observation's status below: the asset is
			// contested whether or not this is the first time we said so.
		} else if err != nil {
			return fmt.Errorf("identity/postgres: open merge proposal: %w", err)
		}
		// The observation asset stays pending while a human decides. Applied to
		// the observation only: an auto-accepted merge writes into an existing
		// asset, and demoting that one would take a monitored asset out of
		// service on a model's say-so.
		//
		// PreserveObservationStatus is the same argument for a proposal raised
		// ABOUT an existing asset (a person editing its identifiers): the asset
		// was in service before the edit and one unverified keystroke does not
		// take it out.
		if p.ObservationAssetID != "" && !p.PreserveObservationStatus {
			obsID, err := parseAsset(p.ObservationAssetID)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
				UPDATE public.assets SET asset_status = 'pending_approval', updated_at = now()
				WHERE tenant_id = $1 AND id = $2 AND asset_status <> 'denied'`,
				tenantID, obsID); err != nil {
				return fmt.Errorf("identity/postgres: pin merge observation pending: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return identity.ProposalRef{}, err
	}
	return identity.ProposalRef{TenantID: tenantID, ID: id.String()}, nil
}

// ---------------------------------------------------------------------------
// Read-backs the contract test needs (identitytest.LastSeenReader / HistoryReader)
// ---------------------------------------------------------------------------

// LastSeen returns the asset's last-seen timestamp, zero when unknown. Nothing
// in production reads it; the contract test does, to check that Touch is
// monotonic — the only property that subtest exists for.
func (r *Repository) LastSeen(ref identity.AssetRef) time.Time {
	assetID, err := parseAsset(ref.ID)
	if err != nil {
		return time.Time{}
	}
	var at time.Time
	_ = r.withTx(context.Background(), ref.TenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(),
			`SELECT last_seen_at FROM public.assets WHERE tenant_id = $1 AND id = $2`,
			ref.TenantID, assetID).Scan(&at)
	})
	return at.UTC()
}

// HistoryFor returns one asset's history entries, oldest first.
//
// Tenant-scoped and transactional like every other method here: it takes the
// whole [identity.AssetRef] and runs under the tenant session, so there is no
// read path on this type that can see another tenant's rows. It used to take a
// bare asset id — matching an earlier shape of [identitytest.HistoryReader] —
// and read `asset_history` with no tenant predicate and no transaction; that is
// fail-closed under the app role (app.tenant_id unset returns nothing) and
// fail-OPEN under an owner connection, and "no production caller today" is not
// a property an exported method keeps.
//
// Ordering is by `seq`, the append counter — see [Repository.RecordHistory] for
// why created_at cannot order these.
func (r *Repository) HistoryFor(ref identity.AssetRef) []identity.HistoryEntry {
	aid, err := parseAsset(ref.ID)
	if err != nil {
		return nil
	}
	var out []identity.HistoryEntry
	_ = r.withTx(context.Background(), ref.TenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(context.Background(), `
			SELECT tenant_id, asset_id, action, source, changes_json, created_at
			FROM public.asset_history
			WHERE tenant_id = $1 AND asset_id = $2
			ORDER BY seq`, ref.TenantID, aid)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var (
				tenantID, asset uuid.UUID
				action, source  string
				raw             []byte
				at              time.Time
			)
			if err := rows.Scan(&tenantID, &asset, &action, &source, &raw, &at); err != nil {
				return err
			}
			e := identity.HistoryEntry{
				TenantID: tenantID.String(),
				AssetID:  asset.String(),
				Action:   identity.HistoryAction(action),
				Source:   identity.Source{Ref: source},
				At:       at.UTC(),
			}
			var changes map[string]any
			if err := json.Unmarshal(raw, &changes); err == nil {
				e.Changes = changes
				if k, ok := changes["source_kind"].(string); ok {
					e.Source.Kind = identity.SourceKind(k)
				}
				if m, ok := changes["source_mode"].(string); ok {
					e.Source.Mode = identity.MeasurementMode(m)
				}
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func assertAssetExists(ctx context.Context, tx *sql.Tx, ref identity.AssetRef) error {
	assetID, err := parseAsset(ref.ID)
	if err != nil {
		return err
	}
	var exists bool
	err = tx.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM public.assets WHERE tenant_id = $1 AND id = $2)`,
		ref.TenantID, assetID).Scan(&exists)
	if err != nil {
		return fmt.Errorf("identity/postgres: check asset %s: %w", ref.ID, err)
	}
	if !exists {
		return fmt.Errorf("%w: %s", identity.ErrAssetNotFound, ref.ID)
	}
	return nil
}

// classPathFor resolves the materialised ancestry for a class key. The
// generated registry answers for every platform class without a query; the
// table is consulted only for a tenant leaf subclass, which is a runtime row the
// generator cannot know about.
//
// A key in neither is stored with itself as its path rather than rejected:
// class_path is NOT NULL and denormalised for the facet prefix, and refusing to
// create the asset would lose a real observation over a registry gap.
func classPathFor(ctx context.Context, tx *sql.Tx, tenantID, key string) (string, error) {
	if c, ok := assetclass.Get(key); ok {
		return c.Path, nil
	}
	var path string
	err := tx.QueryRowContext(ctx, `
		SELECT path FROM public.asset_classes
		WHERE key = $2 AND (tenant_id = $1 OR tenant_id IS NULL)
		ORDER BY (tenant_id IS NULL)
		LIMIT 1`, tenantID, key).Scan(&path)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return key, nil
	case err != nil:
		return "", fmt.Errorf("identity/postgres: resolve class path for %q: %w", key, err)
	}
	return path, nil
}

// normalizeOwnership maps the engine's ownership vocabulary onto the three
// values assets_asset_ownership_check allows. The engine bridges two spellings
// of "outside" (ADR-0002 D1's `external` and the live classifier's
// `third_party`); the column carries the classifier's.
func normalizeOwnership(v string) string {
	switch strings.TrimSpace(strings.ToLower(v)) {
	case identity.OwnershipInternal:
		return "internal"
	case identity.OwnershipExternal, identity.OwnershipThirdParty:
		return "third_party"
	default:
		return "unknown"
	}
}

func sourceKindOr(k identity.SourceKind) string {
	if k.Valid() {
		return string(k)
	}
	return string(identity.SourceMeasured)
}

// classSourceKindOr is sourceKindOr over the CLASS column's vocabulary, which
// has `rule` as well as the four (workstream 2.10b). A separate function
// because `assets.class_source_kind` is the only column that accepts it, and
// routing the two through one validator is how a `rule` fact would reach a
// CHECK that refuses it.
func classSourceKindOr(k identity.ClassSourceKind) string {
	if k.Valid() {
		return string(k)
	}
	return string(identity.ClassSourceMeasured)
}

// classSourceRefOr is what `class_source_ref` records: the class decider when
// the caller named one, else the observation's own producer.
//
// The fallback is not decoration — it is what every pre-2.10b caller relied on,
// and the column is what the query language's `proposed_by` sugar reads. An
// empty string reaches the INSERT's NULLIF and becomes NULL, which is the
// honest value for "nothing recorded who decided this".
func classSourceRefOr(a identity.NewAsset) string {
	if ref := strings.TrimSpace(a.ClassSourceRef); ref != "" {
		return ref
	}
	return a.Source.Ref
}

func clampConfidence(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 1:
		return 1
	default:
		return v
	}
}

func nullFloat(v float64) any {
	if v == 0 {
		// Zero confidence means NOT ASSESSED, the same convention risk scoring
		// uses, and the column is nullable to say exactly that.
		return nil
	}
	return clampConfidence(v)
}

// nullPercent maps the observation's 0..1 confidence onto assets.confidence_score,
// which is an integer percentage.
func nullPercent(v float64) any {
	if v <= 0 {
		return nil
	}
	return int(clampConfidence(v)*100 + 0.5)
}

func nullPort(p int) any {
	if p <= 0 || p > 65535 {
		// DATA_MODEL §2: NULL for an at-rest or declared endpoint. The old
		// "AT-REST" port sentinel is retired, and 0 is not a port.
		return nil
	}
	return p
}

// nullInet returns the address only when it parses. An unparseable value would
// abort the statement, and one malformed address in a batch must not lose the
// whole observation.
func nullInet(v string) any {
	s := strings.TrimSpace(v)
	if s == "" {
		return nil
	}
	if _, err := netip.ParseAddr(s); err != nil {
		if _, err := netip.ParsePrefix(s); err != nil {
			return nil
		}
	}
	return s
}

func nullUUID(v string) any {
	s := strings.TrimSpace(v)
	if s == "" {
		return nil
	}
	if _, err := uuid.Parse(s); err != nil {
		return nil
	}
	return s
}

func timeOrNow(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC()
	}
	return t.UTC()
}

// pgUUIDArray renders ids as a Postgres array literal. lib/pq's pq.Array is not
// used so this package keeps its dependency surface to database/sql; the values
// are uuid-validated by the caller, so the literal cannot carry anything else.
func pgUUIDArray(ids []string) string {
	return "{" + strings.Join(ids, ",") + "}"
}
