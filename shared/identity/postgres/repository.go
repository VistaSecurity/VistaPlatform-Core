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
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/assetclasshistory"
	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/hostnamequality"
	"github.com/vistasecurity/vistaplatform/shared/relationships"
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

	// freshReceipts records, per observation id, the receipt StoreObservation
	// INSERTED in this transaction — as opposed to one it found already there
	// (a transport retry, or a re-evaluation replaying stored evidence).
	// FinishObservation reads it to tell a new sighting from a re-read of an
	// old one when it settles which row the resolution belongs to
	// (observation_split.go). Only a bound Repository has one transaction to
	// remember it for.
	freshReceipts map[string]string
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

// Bind returns a Repository bound to a transaction the CALLER already opened —
// the other direction of [Repository.RunInTx], for a caller whose unit of work
// is not the engine's. The transaction must already carry the tenant session
// (`app.tenant_id`) for tenantID, which is what database.WithTenantTx sets up;
// the Repository neither commits nor rolls it back.
//
// inventory-service's rule-merge executor uses it to re-read the two records
// through [Repository.LoadSummaries] and [Repository.LastKeptSeparate] inside
// the merge's own transaction, under the merge's locks, so the same-device rule
// is judged on exactly the rows the merge then moves ( Phase 4).
func Bind(db *sql.DB, tx *sql.Tx, tenantID string) (*Repository, error) {
	if tx == nil {
		return nil, errors.New("identity/postgres: Bind needs a transaction")
	}
	tid, err := parseTenant(tenantID)
	if err != nil {
		return nil, err
	}
	return &Repository{db: db, tx: tx, boundTenant: tid.String()}, nil
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
			SELECT id, class_key, coalesce(display_name, ''), coalesce(hostname, ''), asset_status,
			       identity_status,
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
				id                                      uuid.UUID
				classKey, displayName, hostname, status string
				identityStatus, segment                 string
				lastSeen                                time.Time
				vendor, model                           string
			)
			if err := rows.Scan(&id, &classKey, &displayName, &hostname, &status,
				&identityStatus, &segment, &lastSeen, &vendor, &model); err != nil {
				return fmt.Errorf("identity/postgres: scan summary: %w", err)
			}
			byID[id.String()] = &identity.AssetSummary{
				Ref:            identity.AssetRef{TenantID: tenantID, ID: id.String()},
				ClassKey:       classKey,
				DisplayName:    displayName,
				Hostname:       hostname,
				Status:         status,
				IdentityStatus: identityStatus,
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
			       coalesce(source_ref, ''), last_seen_at, coalesce(address_assignment, ''), coalesce(key_algorithm, ''),
			       device_confirmed_at
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
				assignment            string
				keyAlgorithm          string
				deviceConfirmed       sql.NullTime
			)
			if err := idRows.Scan(&assetID, &kind, &value, &scope, &confidence, &sourceKind, &sourceRef, &seenAt, &assignment, &keyAlgorithm, &deviceConfirmed); err != nil {
				return fmt.Errorf("identity/postgres: scan candidate identifier: %w", err)
			}
			s, ok := byID[assetID.String()]
			if !ok {
				continue
			}
			held := identity.Identifier{
				Kind:         identity.Kind(kind),
				Value:        value,
				Scope:        scope,
				Confidence:   confidence,
				Assignment:   identity.AddressAssignment(assignment),
				Source:       identity.Source{Kind: identity.SourceKind(sourceKind), Ref: sourceRef},
				SeenAt:       seenAt,
				KeyAlgorithm: keyAlgorithm,
			}
			if deviceConfirmed.Valid {
				held.DeviceConfirmedAt = deviceConfirmed.Time.UTC()
			}
			s.Identifiers = append(s.Identifiers, held)
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
		if err := lockIdentifiers(ctx, tx, tenantID, a.Identifiers); err != nil {
			return err
		}
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
					confidence_score, first_discovered_at, last_seen_at, metadata,
					identity_status, import_only_sources
				) VALUES (
					$1, $2, $3, $4, NULLIF($5, ''),
					$6, NULLIF($7, ''), NULLIF($8, ''), $9::text::inet,
					$10, $11, $12::uuid, NULLIF($13, ''),
					$14, $15, $16, $17::jsonb,
					COALESCE(NULLIF($18, ''), 'legacy'),
					CASE WHEN $19::text = '' THEN NULL ELSE ARRAY[$19::text] END
				)
				RETURNING id`,
				tenantID, classKey, classPath, classSourceKindOr(a.ClassSourceKind), classSourceRefOr(a),
				nullFloat(a.ClassConfidence), a.DisplayName, a.Hostname, nullInet(a.PrimaryAddress),
				status, ownership, nullUUID(a.NetworkSegment), a.DiscoveryMethod,
				nullPercent(a.Confidence), timeOrNow(a.FirstSeenAt), timeOrNow(a.LastSeenAt),
				nameMetadata(a.Source), strings.TrimSpace(a.IdentityStatus),
				// A connection creating the asset makes it import-only
				// (import_only.go); every other source leaves it NULL.
				importOnlySourceRef(a.Source),
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

			if _, err := r.attach(ctx, tx, ref, a.Identifiers); err != nil {
				return err
			}
			_, err = r.upsertEndpoints(ctx, tx, ref, a.Endpoints)
			return err
		})
	})
	if err != nil {
		return identity.AssetRef{}, err
	}
	return ref, nil
}

// AttachIdentifiers records identifiers against an existing asset, idempotently.
//
// It returns how many identifiers were newly inserted, as opposed to already
// held and merely refreshed (see [identity.Repository.AttachIdentifiers]).
func (r *Repository) AttachIdentifiers(ctx context.Context, asset identity.AssetRef, ids []identity.Identifier) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	var added int
	err := r.withTx(ctx, asset.TenantID, func(tx *sql.Tx) error {
		added = 0
		if err := lockIdentifiers(ctx, tx, asset.TenantID, ids); err != nil {
			return err
		}
		writable, err := lockWritableAsset(ctx, tx, asset)
		if err != nil {
			return err
		}
		if !writable {
			return nil
		}
		return r.savepoint(ctx, tx, "identity_attach", func() error {
			n, err := r.attach(ctx, tx, asset, ids)
			added = n
			return err
		})
	})
	if err != nil {
		return 0, err
	}
	return added, nil
}

// attach is the upsert shared by CreateAsset and AttachIdentifiers.
//
// The ON CONFLICT ... WHERE clause is what turns the unique index into an
// answer instead of an error: a row already owned by ANOTHER asset matches the
// index, fails the WHERE, updates nothing and returns nothing — so a zero
// row count IS the conflict, reported as [identity.ErrIdentifierConflict]
// without ever provoking a constraint violation that would poison the
// transaction.
//
// Provenance on a re-sighting is [identity.UpsertIdentifier]'s rule, which the
// in-memory store runs as Go and the identitytest contract holds both to:
//
//   - source_kind moves only UP declared > measured = imported > inferred
//     ([identity.SourceRank]). A value held as DERIVED and now observed
// natively is upgraded ( Phase 2), and a value a collector measured
// and an operator now declares is upgraded too: before, only
//     `inferred` could move, so the declaration left the row `measured` while
//     the ref below was overwritten with the declaration's — a row that said
//     one thing in each column.
//   - source_ref travels WITH source_kind: replaced on an upgrade, refreshed by
//     a non-empty ref of the same kind, and otherwise kept. A weaker sighting
//     never rewrites who vouched for the value — a `measured` row whose ref
//     said "derived:eui64:…" would tell the asset page it was worked out when
//     it was seen.
//   - address_assignment is replaced only by a non-NULL value from a source at
//     least as strong as the stored one, so a pinned address is never
//     unpinned by a sensor sighting (which says nothing) or by an agent's
//     "dhcp" against an operator's declaration.
//
// Every SET expression reads the row's OLD values, so the CASEs all see the
// same pre-update source_kind.
//
// It returns how many rows were INSERTED. `xmax = 0` on the returned row is
// how Postgres says "this tuple was never updated or locked by another
// transaction", which for an `INSERT ... ON CONFLICT DO UPDATE` is exactly
// "the insert path ran"; a conflict that took the UPDATE branch carries the
// updating transaction's id there.
func (r *Repository) attach(ctx context.Context, tx *sql.Tx, asset identity.AssetRef, ids []identity.Identifier) (int, error) {
	assetID, err := parseAsset(asset.ID)
	if err != nil {
		return 0, err
	}
	inserted := 0
	for _, id := range ids {
		if id.Kind == "" || strings.TrimSpace(id.Value) == "" {
			// The absence of an identifier is not an identifier whose value is
			// "". The engine normalises before it gets here; this is the
			// backstop for a caller that did not.
			continue
		}
		if !id.Assignment.Valid() {
			return 0, fmt.Errorf("identity/postgres: attach %s=%q: address assignment %q is not static, dynamic or empty", id.Kind, id.Value, id.Assignment)
		}
		var wasInserted bool
		err := tx.QueryRowContext(ctx, `
			INSERT INTO public.asset_identifiers (
				tenant_id, asset_id, kind, value, scope, source_kind, source_ref,
				confidence, first_seen_at, last_seen_at, address_assignment, key_algorithm, device_confirmed_at
			) VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, NULLIF($7, ''), $8, $9, $9, NULLIF($10, ''), NULLIF($11, ''), $12)
			ON CONFLICT (tenant_id, kind, value, coalesce(scope, '')) DO UPDATE
			SET last_seen_at = GREATEST(public.asset_identifiers.last_seen_at, EXCLUDED.last_seen_at),
			    -- A device confirmation never moves backwards (leasefresh.go);
			    -- GREATEST skips NULLs, so a sighting that confirmed nothing
			    -- leaves one that did in place.
			    device_confirmed_at = GREATEST(public.asset_identifiers.device_confirmed_at, EXCLUDED.device_confirmed_at),
			    confidence   = GREATEST(public.asset_identifiers.confidence, EXCLUDED.confidence),
			    source_kind  = CASE
			        WHEN `+sourceRankSQL("EXCLUDED.source_kind")+` > `+sourceRankSQL("public.asset_identifiers.source_kind")+`
			        THEN EXCLUDED.source_kind
			        ELSE public.asset_identifiers.source_kind END,
			    source_ref   = CASE
			        WHEN `+sourceRankSQL("EXCLUDED.source_kind")+` > `+sourceRankSQL("public.asset_identifiers.source_kind")+`
			        THEN EXCLUDED.source_ref
			        WHEN EXCLUDED.source_kind = public.asset_identifiers.source_kind
			        THEN coalesce(EXCLUDED.source_ref, public.asset_identifiers.source_ref)
			        ELSE public.asset_identifiers.source_ref END,
			    address_assignment = CASE
			        WHEN EXCLUDED.address_assignment IS NOT NULL
			         AND `+sourceRankSQL("EXCLUDED.source_kind")+` >= `+sourceRankSQL("public.asset_identifiers.source_kind")+`
			        THEN EXCLUDED.address_assignment
			        ELSE public.asset_identifiers.address_assignment END,
			    -- An SSH host key's algorithm ( Decision 4): a sighting
			    -- that says it fills in a row stored before it was recorded;
			    -- one that does not leaves it as it was.
			    key_algorithm = coalesce(EXCLUDED.key_algorithm, public.asset_identifiers.key_algorithm),
			    updated_at   = now()
			WHERE public.asset_identifiers.asset_id = EXCLUDED.asset_id
			RETURNING (xmax = 0)`,
			asset.TenantID, assetID, string(id.Kind), id.Value, id.Scope,
			sourceKindOr(id.Source.Kind), id.Source.Ref, clampConfidence(id.Confidence),
			timeOrNow(id.SeenAt), string(id.StoredAssignment()), id.KeyAlgorithm,
			sql.NullTime{Time: id.DeviceConfirmedAt.UTC(), Valid: !id.DeviceConfirmedAt.IsZero()}).Scan(&wasInserted)
		if errors.Is(err, sql.ErrNoRows) {
			// No row back is the WHERE clause refusing another asset's row.
			return 0, fmt.Errorf("%w: %s=%q", identity.ErrIdentifierConflict, id.Kind, id.Value)
		}
		if err != nil {
			return 0, fmt.Errorf("identity/postgres: attach %s=%q: %w", id.Kind, id.Value, err)
		}
		if wasInserted {
			inserted++
		}
	}
	for _, id := range ids {
		if vouches(sourceKindOr(id.Source.Kind), id.Source.Ref) {
			if err := ClearImportOnlyIfVouched(ctx, tx, asset.TenantID, assetID); err != nil {
				return 0, err
			}
			break
		}
	}
	return inserted, nil
}

// UpsertEndpoints writes endpoints under the asset, keyed by the endpoint
// identity of DATA_MODEL §2. Endpoints are dependent identity: they are never
// matched on their own, only upserted under an asset the identifiers resolved.
//
// It returns how many endpoints were newly inserted or had their protocol or
// service name change; a sighting that only moves last-seen is not counted
// (see [identity.Repository.UpsertEndpoints]).
func (r *Repository) UpsertEndpoints(ctx context.Context, asset identity.AssetRef, eps []identity.EndpointObservation) (int, error) {
	if len(eps) == 0 {
		return 0, nil
	}
	var changed int
	err := r.withTx(ctx, asset.TenantID, func(tx *sql.Tx) error {
		changed = 0
		writable, err := lockWritableAsset(ctx, tx, asset)
		if err != nil {
			return err
		}
		if !writable {
			return nil
		}
		return r.savepoint(ctx, tx, "identity_endpoints", func() error {
			n, err := r.upsertEndpoints(ctx, tx, asset, eps)
			changed = n
			return err
		})
	})
	if err != nil {
		return 0, err
	}
	return changed, nil
}

// ReconcileSourceEndpoints closes the asset's endpoints one source recorded
// that a complete set from it no longer lists (see
// [identity.Repository.ReconcileSourceEndpoints] and
// [identity.CompleteEndpointSet]). It is the only writer of an endpoint's
// `closed` status from observation; it used to live in
// device-interrogation-service as a separate transaction after the engine's
// (closeAbsentEndpoints, WP7 F12), and runs on the engine's now.
//
// The source match is `starts_with(source_ref, prefix)` rather than LIKE, so no
// value can be read as a pattern. Absence is decided by endpoint key in Go,
// the same key the engine dedupes and upserts on, with the address in its
// canonical form on both sides.
func (r *Repository) ReconcileSourceEndpoints(ctx context.Context, asset identity.AssetRef, sourcePrefix string, observed []identity.EndpointObservation, at time.Time) ([]string, error) {
	if strings.TrimSpace(sourcePrefix) == "" {
		return nil, fmt.Errorf("identity/postgres: reconcile endpoints: empty source prefix")
	}
	assetID, err := parseAsset(asset.ID)
	if err != nil {
		return nil, err
	}
	keep := make(map[string]bool, len(observed))
	for _, ep := range observed {
		ep = ep.Sanitized()
		keep[reconcileEndpointKey(ep.Address, ep.FQDN, ep.Port, ep.Transport)] = true
	}
	var closed []string
	err = r.withTx(ctx, asset.TenantID, func(tx *sql.Tx) error {
		closed = nil
		writable, err := lockWritableAsset(ctx, tx, asset)
		if err != nil || !writable {
			return err
		}
		// The same per-asset lock the upsert takes, so a concurrent upsert
		// cannot reopen a row between this read and the close.
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
			endpointUpsertLockKey(asset.TenantID, asset.ID)); err != nil {
			return fmt.Errorf("identity/postgres: lock endpoints for asset %s: %w", asset.ID, err)
		}
		rows, err := tx.QueryContext(ctx, `
			SELECT id, coalesce(host(address), ''), coalesce(fqdn, ''), coalesce(port, 0), transport
			  FROM public.asset_endpoints
			 WHERE tenant_id = $1 AND asset_id = $2
			   AND status <> 'closed'
			   AND source_ref IS NOT NULL
			   AND starts_with(source_ref, $3)
			   AND last_seen_at <= $4`,
			asset.TenantID, assetID, sourcePrefix, at.UTC())
		if err != nil {
			return fmt.Errorf("identity/postgres: read %s's endpoints on %s: %w", sourcePrefix, asset.ID, err)
		}
		var ids []string
		for rows.Next() {
			var id, addr, fqdn, transport string
			var port int
			if err := rows.Scan(&id, &addr, &fqdn, &port, &transport); err != nil {
				_ = rows.Close()
				return err
			}
			key := reconcileEndpointKey(addr, fqdn, port, transport)
			if keep[key] {
				continue
			}
			ids = append(ids, id)
			closed = append(closed, key)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		_, err = tx.ExecContext(ctx, `
			UPDATE public.asset_endpoints SET status = 'closed', updated_at = now()
			 WHERE tenant_id = $1 AND id = ANY($2::uuid[])`,
			asset.TenantID, pgUUIDArray(ids))
		if err != nil {
			return fmt.Errorf("identity/postgres: close absent endpoints on %s: %w", asset.ID, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(closed)
	return closed, nil
}

// reconcileEndpointKey is [identity.EndpointObservation.Key] with the address
// in netip's canonical spelling, so a stored inet and an observed string
// compare equal however each was written.
func reconcileEndpointKey(addr, fqdn string, port int, transport string) string {
	addr = strings.TrimSpace(addr)
	if a, err := netip.ParseAddr(addr); err == nil {
		addr = a.Unmap().WithZone("").String()
	}
	switch t := strings.ToLower(strings.TrimSpace(transport)); t {
	case "tcp", "udp", "none":
		transport = t
	default:
		transport = "none"
	}
	return identity.EndpointObservation{Address: addr, FQDN: fqdn, Port: port, Transport: transport}.Key()
}

func (r *Repository) upsertEndpoints(ctx context.Context, tx *sql.Tx, asset identity.AssetRef, eps []identity.EndpointObservation) (int, error) {
	if len(eps) == 0 {
		return 0, nil
	}
	assetID, err := parseAsset(asset.ID)
	if err != nil {
		return 0, err
	}
	changed := 0

	// Serializes concurrent endpoint upserts for THIS asset. The
	// match-by-address path below is a SELECT then an INSERT-or-UPDATE, which
	// is not atomic the way a single `INSERT ... ON CONFLICT` is: two ingest
	// workers racing to upsert the same (address, port, transport) under
	// different FQDN spellings could otherwise both miss the SELECT and both
	// insert, recreating the exact duplicate-endpoint defect this function
	// exists to close. crypto_dedup.go's lockAssetMaterializationSQL is the
	// identical shape of problem and fix — a stricter unique index was
	// rejected there for the same reason it is rejected here: existing
	// installs already hold duplicate rows, and a stricter index would fail to
	// build against them (see the doc comment on asset_endpoints_identity_uniq
	// in scripts/database/schema.sql and the POST-MIGRATIONS block that merges
	// pre-existing duplicates instead of relying on the index to prevent new
	// ones).
	if _, err := tx.ExecContext(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		endpointUpsertLockKey(asset.TenantID, asset.ID),
	); err != nil {
		return 0, fmt.Errorf("identity/postgres: lock endpoints for asset %s: %w", asset.ID, err)
	}

	for _, ep := range eps {
		// Defense in depth: the engine's stampEndpoints already does this, but
		// this repository has one other direct caller
		// (AssetService.resolveEndpointForFinding) and is itself the last line
		// of defense before a row is written.
		ep = ep.Sanitized()
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
		port := nullPort(ep.Port)

		if addr != nil {
			// An endpoint identified by an address is identified by
			// (address, port, transport) — FQDN is an attribute of that
			// endpoint, not part of what identifies it (see
			// [identity.EndpointObservation.Sanitized] and
			// [identity.EndpointObservation.Key]). Match on that narrower
			// identity FIRST: an existing row with the same address, port and
			// transport but a different (or empty) fqdn is the SAME endpoint
			// wearing a different name, not a second listener.
			matched, didChange, err := r.mergeEndpointByAddress(ctx, tx, asset, assetID, addr, port, transport, fqdn, ep)
			if err != nil {
				return 0, err
			}
			if matched {
				if didChange {
					changed++
				}
				continue
			}
		}

		// Falls through here for a genuinely new (address, port, transport),
		// or for an address-less (fqdn-only) endpoint, whose identity IS the
		// full tuple below. Every enrichment column is written with
		// `coalesce(EXCLUDED.x, existing)` on conflict: an observation that
		// does not know a service name or a binding must not ERASE one an
		// observation that did know has already recorded. A TLS probe of a
		// port a host agent has already named would otherwise blank the
		// process name on every scan.
		//
		// What it reports back is whether this endpoint is worth a timeline
		// row: a new one, or one whose protocol or service name this sighting
		// changed. The `prev` CTE reads the row under the statement's own
		// snapshot, i.e. as it was BEFORE the update, so the comparison needs
		// no second round trip. (attach() uses `xmax = 0` instead, which a
		// partitioned table such as this one will not return.)
		var wasInserted, enrichmentChanged bool
		err := tx.QueryRowContext(ctx, `
			WITH prev AS (
				SELECT protocol::text AS protocol, service_name
				  FROM public.asset_endpoints
				 WHERE tenant_id = $1 AND asset_id = $2
				   AND address IS NOT DISTINCT FROM $3::text::inet
				   AND coalesce(fqdn, '') = $4
				   AND port IS NOT DISTINCT FROM $5::int
				   AND transport = $6
			)
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
				updated_at   = now()
			RETURNING
			    NOT EXISTS (SELECT 1 FROM prev),
			    EXISTS (SELECT 1 FROM prev p
			             WHERE p.protocol IS DISTINCT FROM public.asset_endpoints.protocol::text
			                OR p.service_name IS DISTINCT FROM public.asset_endpoints.service_name)`,
			asset.TenantID, assetID, addr, fqdn, port, transport,
			strings.TrimSpace(ep.Protocol),
			strings.TrimSpace(ep.ServiceName), strings.TrimSpace(ep.ServiceConfidence),
			strings.TrimSpace(ep.ServiceIdentificationMethod), ep.BoundLocal,
			sourceKindOr(ep.Source.Kind), ep.Source.Ref,
			timeOrNow(ep.SeenAt)).Scan(&wasInserted, &enrichmentChanged)
		if err != nil {
			return 0, fmt.Errorf("identity/postgres: upsert endpoint %s: %w", ep.Key(), err)
		}
		if wasInserted || enrichmentChanged {
			changed++
		}
	}
	for _, ep := range eps {
		if vouches(sourceKindOr(ep.Source.Kind), ep.Source.Ref) {
			if err := ClearImportOnlyIfVouched(ctx, tx, asset.TenantID, assetID); err != nil {
				return 0, err
			}
			break
		}
	}
	return changed, nil
}

// mergeEndpointByAddress looks for an existing asset_endpoints row identified
// by (tenant_id, asset_id, address, port, transport) — ignoring fqdn, which is
// an attribute rather than identity once an address is known. When found, it
// UPDATEs that row rather than letting the caller INSERT a second one for the
// same listener under a different name.
//
// fqdn is filled on the row only when the observation has one AND the row's is
// empty — "empty never wins" — so a name a prior observation established is
// never blanked by a later observation that does not know it, and never
// overwritten by a differently-spelled one either. This is deliberately
// asymmetric with the other enrichment columns below, which follow the
// ordinary "new wins when present" rule: two sources naming the SAME address
// differently (a DNS PTR vs. a certificate SAN) should not flap the display
// name on every re-scan.
//
// sni and alpn are not touched: nothing populates them through
// [identity.EndpointObservation] today (see the struct — it carries no such
// fields), so there is nothing to merge yet. A future field added there
// should follow the same "empty never wins" rule as fqdn.
//
// Reports whether an existing row was matched and updated, and whether that
// update changed its protocol or service name (the endpoint changes worth a
// timeline row; a refreshed last-seen is not one). false means the
// caller should fall through to the ordinary `INSERT ... ON CONFLICT`, which
// also covers the address-less (fqdn-only) endpoint case this function never
// sees (it is only called when addr != nil).
func (r *Repository) mergeEndpointByAddress(
	ctx context.Context, tx *sql.Tx, asset identity.AssetRef, assetID uuid.UUID,
	addr, port any, transport, fqdn string, ep identity.EndpointObservation,
) (matched, changed bool, err error) {
	var id uuid.UUID
	var existingFQDN, oldProtocol, oldService sql.NullString
	err = tx.QueryRowContext(ctx, `
		SELECT id, fqdn, protocol::text, service_name
		  FROM public.asset_endpoints
		 WHERE tenant_id = $1 AND asset_id = $2
		   AND address = $3::inet
		   AND port IS NOT DISTINCT FROM $4::int
		   AND transport = $5`,
		asset.TenantID, assetID, addr, port, transport,
	).Scan(&id, &existingFQDN, &oldProtocol, &oldService)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, false, nil
	case err != nil:
		return false, false, fmt.Errorf("identity/postgres: match endpoint %s by address: %w", ep.Key(), err)
	}

	newFQDN := existingFQDN.String
	if newFQDN == "" && fqdn != "" {
		newFQDN = fqdn
	}
	var newProtocol, newService sql.NullString
	err = tx.QueryRowContext(ctx, `
		UPDATE public.asset_endpoints SET
			fqdn         = NULLIF($1, ''),
			last_seen_at = GREATEST(last_seen_at, $2),
			protocol     = coalesce((SELECT e.enumlabel::text::public.protocol_type
			                            FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid
			                           WHERE t.typname = 'protocol_type' AND e.enumlabel = $3), protocol),
			service_name = coalesce(NULLIF($4, ''), service_name),
			service_confidence = CASE WHEN NULLIF($4, '') IS NOT NULL
			                          THEN coalesce(NULLIF($5, ''), 'none')
			                          ELSE service_confidence END,
			service_identification_method = CASE WHEN NULLIF($4, '') IS NOT NULL
			                          THEN NULLIF($6, '')
			                          ELSE service_identification_method END,
			bound_local  = coalesce($7, bound_local),
			source_ref   = coalesce(NULLIF($8, ''), source_ref),
			status       = 'active',
			updated_at   = now()
		 WHERE tenant_id = $9 AND id = $10
		RETURNING protocol::text, service_name`,
		newFQDN, timeOrNow(ep.SeenAt), strings.TrimSpace(ep.Protocol),
		strings.TrimSpace(ep.ServiceName), strings.TrimSpace(ep.ServiceConfidence),
		strings.TrimSpace(ep.ServiceIdentificationMethod), ep.BoundLocal,
		ep.Source.Ref,
		asset.TenantID, id,
	).Scan(&newProtocol, &newService)
	if err != nil {
		return false, false, fmt.Errorf("identity/postgres: update matched endpoint %s: %w", ep.Key(), err)
	}
	return true, oldProtocol != newProtocol || oldService != newService, nil
}

// endpointUpsertLockKey namespaces the advisory lock so it cannot collide with
// an unrelated advisory lock elsewhere in the platform. Mirrors
// assetMaterializationLockKey in services/inventory-service's crypto_dedup.go,
// which serializes the identically-shaped SELECT-then-write race for
// crypto_implementations.
func endpointUpsertLockKey(tenantID, assetID string) string {
	return "vistaplatform:identity_endpoints:" + tenantID + ":" + assetID
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

func nameMetadata(src identity.Source) string {
	raw, err := json.Marshal(map[string]string{"name_source_kind": src.NameKind()})
	if err != nil {
		return `{"name_source_kind":"measured-passive"}`
	}
	return string(raw)
}

// PromoteNames raises hostname and display_name when the incoming names are
// strictly better quality. See [identity.Repository.PromoteNames].
func (r *Repository) PromoteNames(ctx context.Context, asset identity.AssetRef, hostname, displayName, sourceKind string) error {
	assetID, err := parseAsset(asset.ID)
	if err != nil {
		return err
	}
	return r.withTx(ctx, asset.TenantID, func(tx *sql.Tx) error {
		var currentHost, currentDisp, currentSrc string
		err := tx.QueryRowContext(ctx, `
			SELECT coalesce(hostname, ''), coalesce(display_name, ''),
			       CASE WHEN EXISTS (SELECT 1 FROM public.asset_history h WHERE h.tenant_id = assets.tenant_id AND h.asset_id = assets.id AND (h.source = 'manual' OR h.changes_json->>'source_kind' = 'declared') AND (h.action = 'created' OR h.changes_json->>'hostname' IS NOT NULL OR h.changes_json->>'display_name' IS NOT NULL)) THEN 'declared' ELSE coalesce(metadata ->> 'name_source_kind', '') END
			FROM public.assets
			WHERE tenant_id = $1 AND id = $2
			FOR UPDATE`,
			asset.TenantID, assetID).Scan(&currentHost, &currentDisp, &currentSrc)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: %s", identity.ErrAssetNotFound, asset.ID)
		}
		if err != nil {
			return fmt.Errorf("identity/postgres: promote names load %s: %w", asset.ID, err)
		}
		newHost, newDisp := currentHost, currentDisp
		changed := false
		if hostnamequality.ShouldPromote(currentHost, hostname, currentSrc, sourceKind) {
			newHost = strings.TrimSpace(hostname)
			changed = true
		}
		if hostnamequality.ShouldPromote(currentDisp, displayName, currentSrc, sourceKind) {
			newDisp = strings.TrimSpace(displayName)
			changed = true
		}
		if !changed {
			return nil
		}
		kind := hostnamequality.NormalizeSource(sourceKind)
		res, err := tx.ExecContext(ctx, `
			UPDATE public.assets
			SET hostname = NULLIF($3, ''),
			    display_name = NULLIF($4, ''),
			    metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object('name_source_kind', $5::text),
			    updated_at = now()
			WHERE tenant_id = $1 AND id = $2`,
			asset.TenantID, assetID, newHost, newDisp, kind)
		if err != nil {
			return fmt.Errorf("identity/postgres: promote names %s: %w", asset.ID, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("identity/postgres: promote names: rows affected: %w", err)
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

// HistoryHasChange reports whether the asset's timeline already holds a row of
// this action whose changes contain subset (jsonb `@>`). See
// [identity.Repository.HistoryHasChange].
func (r *Repository) HistoryHasChange(ctx context.Context, asset identity.AssetRef, action identity.HistoryAction, subset map[string]any) (bool, error) {
	assetID, err := parseAsset(asset.ID)
	if err != nil {
		return false, err
	}
	payload, err := json.Marshal(subset)
	if err != nil {
		return false, fmt.Errorf("identity/postgres: marshal history subset: %w", err)
	}
	var seen bool
	err = r.withTx(ctx, asset.TenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM public.asset_history
				 WHERE tenant_id = $1 AND asset_id = $2 AND action = $3
				   AND changes_json @> $4::jsonb)`,
			asset.TenantID, assetID, string(action), string(payload)).Scan(&seen)
	})
	if err != nil {
		return false, fmt.Errorf("identity/postgres: look for %s history on %s: %w", action, asset.ID, err)
	}
	return seen, nil
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

	fingerprint := identity.MergeProposalFingerprint(p)
	payload, err := json.Marshal(mergeProposalPayload(p, fingerprint))
	if err != nil {
		return identity.ProposalRef{}, fmt.Errorf("identity/postgres: marshal merge proposal: %w", err)
	}
	source := strings.TrimSpace(p.Source.Ref)
	if source == "" {
		source = "unknown"
	}

	var id uuid.UUID
	var reused bool
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
			//
			// FOR UPDATE: the fold below is a read-modify-write, and two
			// observations re-asking the question in parallel must not each
			// fold into the same old copy and lose the other's evidence.
			var (
				stored    []byte
				createdAt time.Time
			)
			if err := tx.QueryRowContext(ctx, `
				SELECT id, changes_json, created_at FROM public.asset_history
				WHERE tenant_id = $1
				  AND action = 'merge_proposed'
				  AND changes_json ->> 'fingerprint' = $2
				  AND COALESCE(changes_json ->> 'status', 'pending') = 'pending'
				ORDER BY seq DESC
				LIMIT 1
				FOR UPDATE`, tenantID, fingerprint).Scan(&id, &stored, &createdAt); err != nil {
				return fmt.Errorf("identity/postgres: find the existing merge proposal: %w", err)
			}
			// A recurring sighting FOLDS its evidence into the pending question
			// ( A3) — the union of what every sighting matched, the best
			// score — without changing its original proposal time or any
			// decision. identity.FoldMergeProposal is the rule; the in-memory
			// store applies the same function.
			prior, err := decodeStoredMergeProposal(stored, createdAt)
			if err != nil {
				return err
			}
			incoming := p
			incoming.ProposedAt = timeOrNow(p.ProposedAt)
			merged := identity.FoldMergeProposal(prior, incoming)
			refreshed, err := json.Marshal(mergeProposalPayload(merged, fingerprint))
			if err != nil {
				return fmt.Errorf("identity/postgres: marshal folded merge proposal: %w", err)
			}
			// `||` rather than a replace: keys another path stamped on the row
			// (the approvals path's reconcile notes, for one) survive a fold.
			if _, err := tx.ExecContext(ctx, `UPDATE public.asset_history
             SET changes_json=changes_json||$3::jsonb||jsonb_build_object('latest_evidence_at',$4::timestamptz)
             WHERE tenant_id=$1 AND id=$2 AND coalesce(changes_json->>'status','pending')='pending'`,
				tenantID, id, refreshed, merged.LatestEvidenceAt); err != nil {
				return fmt.Errorf("identity/postgres: fold pending merge evidence: %w", err)
			}
			reused = true
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
	return identity.ProposalRef{TenantID: tenantID, ID: id.String(), Reused: reused}, nil
}

// mergeProposalPayload is the `changes_json` a merge proposal row carries — the
// shape the Approvals surface reads. One spelling for the insert and for the
// fold, so a reused proposal cannot drift from a fresh one.
func mergeProposalPayload(p identity.MergeProposal, fingerprint string) map[string]any {
	candidates := make([]map[string]any, 0, len(p.Candidates))
	var snapshots []map[string]any
	for _, c := range p.Candidates {
		matched := make([]map[string]any, 0, len(c.MatchedIdentifiers))
		for _, id := range c.MatchedIdentifiers {
			m := map[string]any{
				"kind": string(id.Kind), "value": id.Value, "scope": id.Scope,
			}
			// A generic name ( B2) is per-observation context, not
			// identity, so it is not in the identifier's key — but it is part
			// of the EVIDENCE: the rule-merge executor re-evaluates the
			// same-device rule from this row, and its condition 8 ("no
			// candidate linked by a generic name alone") has to be able to see
			// it. Written only when true, so every other row is unchanged.
			if id.Generic {
				m["generic"] = true
			}
			// Likewise a DERIVED identifier ( Phase 2) keeps its
			// provenance here: the rule counts a derived MAC and no other
			// derived kind (condition 3), and a reviewer reading the proposal
			// should see which value was worked out rather than seen.
			if id.Inferred() {
				m["source"] = map[string]any{"kind": string(id.Source.Kind), "ref": id.Source.Ref}
			}
			matched = append(matched, m)
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
		// The candidate as the matcher compared it ( Phase 5), for the
		// lossless training export. A TOP-LEVEL list keyed by asset id, not a
		// key inside the candidate: an executed merge rewrites `candidates`
		// (reconcileMergeProposals remaps every merged record onto the survivor
		// and drops the duplicates), and the losing record's snapshot is the
		// half of the training pair that would go with it.
		if c.Snapshot != nil {
			snap := matcherSidePayload(*c.Snapshot, true)
			snap["asset_id"] = c.Ref.ID
			snapshots = append(snapshots, snap)
		}
		candidates = append(candidates, candidate)
	}
	payload := map[string]any{
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
	}
	// The same-device rule's verdict ( Phase 4) — the rule-merge
	// executor's work item. Written only when the rule held: the fold merges
	// with `||`, so an absent key leaves a verdict another sighting stamped
	// (or the executor cleared) exactly as it is.
	if p.RuleVerdict != "" {
		payload["rule_verdict"] = p.RuleVerdict
		evidence := p.RuleEvidence
		if evidence == nil {
			evidence = []string{}
		}
		payload["rule_evidence"] = evidence
	}
	// The two top candidates scored against EACH OTHER ( Phase 5).
	// Advisory: nothing reads it to decide. Omitted when unscored, because a
	// written 0 would read as "scored, and certainly two things".
	if p.PairScore > 0 {
		payload["pair_score"] = p.PairScore
		payload["pair_asset_ids"] = p.PairAssetIDs
		payload["pair_reason"] = p.PairReason
	}
	// The observation side as the matcher saw it, so an export of this row is
	// a complete training sample (scripts/export-merge-decisions.sql).
	if len(p.ObservationIdentifiers) > 0 {
		payload["observation_identifiers"] = identifierPayload(p.ObservationIdentifiers)
	}
	if p.ObservationContext != nil {
		payload["observation_context"] = matcherSidePayload(*p.ObservationContext, false)
	}
	if len(snapshots) > 0 {
		payload["candidate_snapshots"] = snapshots
	}
	return payload
}

// identifierPayload is the compact spelling of identifiers on a proposal row:
// kind, value, scope, and the two per-value marks the matcher reads — derived
// (`source_kind = inferred`) and generic. Provenance refs, confidences and
// times are left out: the row is evidence for a reviewer and a training
// sample, not a second copy of asset_identifiers.
func identifierPayload(ids []identity.Identifier) []map[string]any {
	out := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		m := map[string]any{"kind": string(id.Kind), "value": id.Value, "scope": id.Scope}
		if id.Inferred() {
			m["derived"] = true
		}
		if id.Generic {
			m["generic"] = true
		}
		out = append(out, m)
	}
	return out
}

// matcherSidePayload is one side's matcher snapshot. Identifiers only when
// asked for: on the observation they live under `observation_identifiers`.
func matcherSidePayload(s identity.MatcherSide, withIdentifiers bool) map[string]any {
	m := map[string]any{
		"name":        s.Name,
		"class":       s.Class,
		"segment":     s.Segment,
		"vendor":      s.Vendor,
		"model":       s.Model,
		"source_kind": s.SourceKind,
	}
	if !s.SeenAt.IsZero() {
		m["seen_at"] = s.SeenAt.UTC().Format(time.RFC3339Nano)
	}
	if withIdentifiers {
		m["identifiers"] = identifierPayload(s.Identifiers)
	}
	return m
}

// storedIdentifier is [identifierPayload]'s element, read back.
type storedIdentifier struct {
	Kind    string `json:"kind"`
	Value   string `json:"value"`
	Scope   string `json:"scope"`
	Derived bool   `json:"derived"`
	Generic bool   `json:"generic"`
}

func (s storedIdentifier) identifier() identity.Identifier {
	id := identity.Identifier{Kind: identity.Kind(s.Kind), Value: s.Value, Scope: s.Scope, Generic: s.Generic}
	if s.Derived {
		id.Source.Kind = identity.SourceInferred
	}
	return id
}

func storedIdentifiers(in []storedIdentifier) []identity.Identifier {
	if len(in) == 0 {
		return nil
	}
	out := make([]identity.Identifier, 0, len(in))
	for _, s := range in {
		out = append(out, s.identifier())
	}
	return out
}

// storedMatcherSide is [matcherSidePayload], read back.
type storedMatcherSide struct {
	Name        string             `json:"name"`
	Class       string             `json:"class"`
	Segment     string             `json:"segment"`
	Vendor      string             `json:"vendor"`
	Model       string             `json:"model"`
	SourceKind  string             `json:"source_kind"`
	SeenAt      *time.Time         `json:"seen_at"`
	Identifiers []storedIdentifier `json:"identifiers"`
}

func (s *storedMatcherSide) side() *identity.MatcherSide {
	if s == nil {
		return nil
	}
	out := &identity.MatcherSide{
		Name: s.Name, Class: s.Class, Segment: s.Segment, Vendor: s.Vendor, Model: s.Model,
		SourceKind: s.SourceKind, Identifiers: storedIdentifiers(s.Identifiers),
	}
	if s.SeenAt != nil {
		out.SeenAt = s.SeenAt.UTC()
	}
	return out
}

// storedCandidateSnapshot is one entry of `candidate_snapshots`.
type storedCandidateSnapshot struct {
	AssetID string `json:"asset_id"`
	storedMatcherSide
}

// storedMergeProposal is [mergeProposalPayload]'s shape, read back.
type storedMergeProposal struct {
	ObservationAssetID string `json:"observation_asset_id"`
	Candidates         []struct {
		AssetID            string                `json:"asset_id"`
		MatchedIdentifiers []identity.Identifier `json:"matched_identifiers"`
		Score              float64               `json:"score"`
		Reason             string                `json:"reason"`
		Explanation        []seams.MatchFactor   `json:"explanation"`
	} `json:"candidates"`
	CandidateSnapshots     []storedCandidateSnapshot `json:"candidate_snapshots"`
	PairScore              float64                   `json:"pair_score"`
	PairAssetIDs           []string                  `json:"pair_asset_ids"`
	PairReason             string                    `json:"pair_reason"`
	ObservationIdentifiers []storedIdentifier        `json:"observation_identifiers"`
	ObservationContext     *storedMatcherSide        `json:"observation_context"`
	Reason                 string                    `json:"reason"`
	ModelID                string                    `json:"model_id"`
	SourceRef              string                    `json:"source_ref"`
	AutoAccepted           bool                      `json:"auto_accepted"`
	AcceptedAssetID        string                    `json:"accepted_asset_id"`
	AcceptedScore          float64                   `json:"accepted_score"`
	AcceptedModelID        string                    `json:"accepted_model_id"`
	AcceptedSourceRef      string                    `json:"accepted_source_ref"`
	SourceKind             string                    `json:"source_kind"`
	LatestEvidenceAt       *time.Time                `json:"latest_evidence_at"`
}

// decodeStoredMergeProposal reads a pending proposal row back into the value
// [identity.FoldMergeProposal] folds into. `createdAt` is the row's own time,
// which is when the question was first asked.
func decodeStoredMergeProposal(raw []byte, createdAt time.Time) (identity.MergeProposal, error) {
	var s storedMergeProposal
	if err := json.Unmarshal(raw, &s); err != nil {
		return identity.MergeProposal{}, fmt.Errorf("identity/postgres: decode the pending merge proposal: %w", err)
	}
	p := identity.MergeProposal{
		ObservationAssetID: s.ObservationAssetID,
		Source:             identity.Source{Kind: identity.SourceKind(s.SourceKind)},
		Reason:             s.Reason,
		ProposedAt:         createdAt.UTC(),
		ModelID:            s.ModelID,
		SourceRef:          s.SourceRef,
		AutoAccepted:       s.AutoAccepted,
		AcceptedAssetID:    s.AcceptedAssetID,
		AcceptedScore:      s.AcceptedScore,
		AcceptedModelID:    s.AcceptedModelID,
		AcceptedSourceRef:  s.AcceptedSourceRef,
		// rule_verdict / rule_evidence are deliberately NOT read back: the fold
		// writes with `||`, so a stored verdict the incoming sighting does not
		// restate stays on the row untouched, and one it does restate is
		// replaced. Decoding them would be plumbing nothing depends on.

		PairScore:              s.PairScore,
		PairAssetIDs:           s.PairAssetIDs,
		PairReason:             s.PairReason,
		ObservationIdentifiers: storedIdentifiers(s.ObservationIdentifiers),
		ObservationContext:     s.ObservationContext.side(),
	}
	if s.LatestEvidenceAt != nil {
		p.LatestEvidenceAt = s.LatestEvidenceAt.UTC()
	}
	snapshots := make(map[string]*identity.MatcherSide, len(s.CandidateSnapshots))
	for i := range s.CandidateSnapshots {
		snapshots[s.CandidateSnapshots[i].AssetID] = s.CandidateSnapshots[i].side()
	}
	for _, c := range s.Candidates {
		p.Candidates = append(p.Candidates, identity.MergeCandidate{
			Ref:                identity.AssetRef{ID: c.AssetID},
			MatchedIdentifiers: c.MatchedIdentifiers,
			Score:              c.Score,
			Reason:             c.Reason,
			Explanation:        c.Explanation,
			Snapshot:           snapshots[c.AssetID],
		})
	}
	return p, nil
}

// LastKeptSeparate implements [identity.Repository]: the engine's decision
// memory.
//
// A proposal is an `asset_history` row (see OpenMergeProposal) and its
// resolution is what the approvals path patched onto `changes_json` —
// `status`, `resolved_at`, `resolved_by`. The asset set is the candidates'
// `asset_id`s plus the observation asset; the query asks for rows whose set
// CONTAINS every id given (`<@`), newest first. Candidates are read back in Go
// rather than in SQL because the kinds that matched them are nested one level
// further down, and the engine wants those too.
//
// The predicate is the tenant plus a handful of jsonb operators over rows with
// `action = 'merge_proposed'`, which are rare; it runs once per conflict, not
// per observation, and needs no index of its own.
func (r *Repository) LastKeptSeparate(ctx context.Context, tenantID string, assetIDs []string) (identity.PriorDecision, bool, error) {
	if len(assetIDs) == 0 {
		return identity.PriorDecision{}, false, nil
	}
	ids := make([]string, 0, len(assetIDs))
	for _, id := range assetIDs {
		aid, err := parseAsset(id)
		if err != nil {
			// Not a uuid names no row, so no proposal ever named it.
			return identity.PriorDecision{}, false, nil
		}
		ids = append(ids, aid.String())
	}

	var (
		id  uuid.UUID
		raw []byte
	)
	found := false
	err := r.withTx(ctx, tenantID, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `
			SELECT id, changes_json
			  FROM public.asset_history
			 WHERE tenant_id = $1
			   AND action = 'merge_proposed'
			   AND changes_json ->> 'kind' = 'merge_proposal'
			   AND changes_json ->> 'status' = 'kept_separate'
			   AND $2::text[] <@ (
			         (SELECT coalesce(array_agg(c ->> 'asset_id'), '{}'::text[])
			            FROM jsonb_array_elements(changes_json -> 'candidates') AS c)
			         || ARRAY[coalesce(changes_json ->> 'observation_asset_id', '')]
			       )
			 ORDER BY seq DESC
			 LIMIT 1`, tenantID, pgUUIDArray(ids)).Scan(&id, &raw)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("identity/postgres: read prior kept-separate decisions: %w", err)
		}
		found = true
		return nil
	})
	if err != nil || !found {
		return identity.PriorDecision{}, false, err
	}

	var body struct {
		ObservationAssetID string `json:"observation_asset_id"`
		ResolvedAt         string `json:"resolved_at"`
		ResolvedBy         string `json:"resolved_by"`
		Candidates         []struct {
			AssetID            string `json:"asset_id"`
			MatchedIdentifiers []struct {
				Kind string `json:"kind"`
			} `json:"matched_identifiers"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return identity.PriorDecision{}, false, fmt.Errorf("identity/postgres: decode prior decision %s: %w", id, err)
	}
	d := identity.PriorDecision{
		ProposalID:         id.String(),
		ObservationAssetID: body.ObservationAssetID,
		DecidedBy:          body.ResolvedBy,
	}
	if body.ResolvedAt != "" {
		if at, err := time.Parse(time.RFC3339, body.ResolvedAt); err == nil {
			d.DecidedAt = at.UTC()
		}
	}
	seen := map[identity.Kind]bool{}
	for _, c := range body.Candidates {
		d.Candidates = append(d.Candidates, c.AssetID)
		for _, m := range c.MatchedIdentifiers {
			k := identity.Kind(m.Kind)
			if !seen[k] {
				seen[k] = true
				d.MatchedKinds = append(d.MatchedKinds, k)
			}
		}
	}
	return d, true, nil
}

// IdentifierLastSeen implements [identity.Repository]: the identifier row's
// own `asset_identifiers.last_seen_at`.
//
// That column is per identifier, not per asset. The attach upsert advances it
// with GREATEST(last_seen_at, EXCLUDED.last_seen_at) every time an observation
// resolved to the owner carries the value, so it answers "when was the current
// owner last seen WITH this value" — which for an address is "when did that
// device last hold this lease". `assets.last_seen_at` would be the wrong
// column: a device seen yesterday at a DIFFERENT address still has a fresh
// asset row.
//
// The lookup is the unique index (tenant, kind, value, coalesce(scope, ”)), so
// it returns at most one row; MAX() makes a store that lost the invariant
// answer with the freshest holder rather than an arbitrary one.
func (r *Repository) IdentifierLastSeen(ctx context.Context, tenantID string, id identity.Identifier) (time.Time, bool, error) {
	var seen sql.NullTime
	err := r.withTx(ctx, tenantID, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `
			SELECT max(last_seen_at)
			  FROM public.asset_identifiers
			 WHERE tenant_id = $1 AND kind = $2 AND value = $3 AND coalesce(scope, '') = $4`,
			tenantID, string(id.Kind), id.Value, id.Scope).Scan(&seen)
		if err != nil {
			return fmt.Errorf("identity/postgres: read last-seen of %s=%q: %w", id.Kind, id.Value, err)
		}
		return nil
	})
	if err != nil || !seen.Valid {
		return time.Time{}, false, err
	}
	return seen.Time.UTC(), true, nil
}

// announcementEdgeType is the relationship a floating address is recorded as:
// the address's asset is `hosted_on` the node that announces it (reverse label
// "hosts"). Chosen over a new vocabulary entry because the ten types of
// ADR-0003 D2 are a registry every producer and the query language share, and
// "the VIP's asset currently rests on this node" is what `hosted_on` means.
// The mechanism is in the edge's attributes.
const announcementEdgeType = relationships.HostedOn

// RecordAnnouncement implements [identity.Repository].
//
// The edge is holder → announcer, type `hosted_on`, measured, with the
// evidence — the MACs, the addresses, whether the ARP was gratuitous — in
// attributes under `floating_address`. Its status follows ADR-0003 D3's table
// through EdgeStatusFor, so an announcement between two approved assets is
// active at once and one involving a pending asset waits with it.
func (r *Repository) RecordAnnouncement(ctx context.Context, announcer, holder identity.AssetRef, a identity.Announcement) error {
	if announcer.TenantID != holder.TenantID {
		return fmt.Errorf("identity/postgres: announcer %s and holder %s are in different tenants", announcer.ID, holder.ID)
	}
	if announcer.ID == holder.ID {
		return fmt.Errorf("%w: %s announces its own address", ErrSelfEdge, announcer.ID)
	}
	kind := a.Source.Kind
	if kind == "" {
		kind = identity.SourceMeasured
	}
	status, err := r.EdgeStatusFor(ctx, holder.TenantID, kind, holder.ID, announcer.ID)
	if err != nil {
		return fmt.Errorf("identity/postgres: edge status for the announcement: %w", err)
	}
	return r.UpsertRelationship(ctx, holder.TenantID, Edge{
		FromAssetID: holder.ID,
		ToAssetID:   announcer.ID,
		Type:        string(announcementEdgeType),
		SourceKind:  kind,
		SourceRef:   a.Source.Ref,
		Confidence:  1,
		Status:      status,
		Attributes: map[string]any{
			"floating_address": map[string]any{
				"mechanism":      "l2_announcement",
				"macs":           a.MACs,
				"addresses":      a.Addresses,
				"gratuitous_arp": a.Gratuitous,
			},
		},
		ObservedAt: a.At,
	})
}

// AddressAnnounced implements [identity.Repository]: has the floating-address
// rule ever recorded `address` as announced for `holder`?
//
// Both places [identity.Engine]'s resolveFloating writes are consulted:
//
//   - the holder's outgoing `hosted_on` edges. RecordAnnouncement upserts one
//     per (holder, announcer) and merges attributes with `||`, so an edge's
//     `floating_address.addresses` is only that announcer's LATEST
//     announcement;
//   - the holder's `asset_history` entries carrying `floating_address` — the
//     `updated` entry resolveFloating writes on the holder for every
//     announcement. Append-only, so an address announced once and since
//     superseded on the edge still counts.
//
// jsonb `?` tests array membership of a string, which is exactly how both
// payloads store the addresses (canonical `ip_address` values).
func (r *Repository) AddressAnnounced(ctx context.Context, holder identity.AssetRef, address string) (bool, error) {
	holderID, err := parseAsset(holder.ID)
	if err != nil {
		return false, nil
	}
	var announced bool
	err = r.withTx(ctx, holder.TenantID, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (
			         SELECT 1 FROM public.asset_relationships
			          WHERE tenant_id = $1 AND from_asset_id = $2 AND type = $3
			            AND attributes -> 'floating_address' -> 'addresses' ? $4)
			    OR EXISTS (
			         SELECT 1 FROM public.asset_history
			          WHERE tenant_id = $1 AND asset_id = $2
			            AND changes_json -> 'floating_address' -> 'addresses' ? $4)`,
			holder.TenantID, holderID, string(announcementEdgeType), address).Scan(&announced)
		if err != nil {
			return fmt.Errorf("identity/postgres: reading announcements of %s for %s: %w", address, holder.ID, err)
		}
		return nil
	})
	return announced, err
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

// Endpoints returns the endpoints under an asset, oldest first. Nothing in
// production reads it; the contract test does
// ([identitytest.EndpointReader]), to check that a repeat upsert of the same
// (address, port, transport) merges into one row instead of accumulating a
// second one for a differently-spelled fqdn.
func (r *Repository) Endpoints(ref identity.AssetRef) []identity.EndpointObservation {
	assetID, err := parseAsset(ref.ID)
	if err != nil {
		return nil
	}
	var out []identity.EndpointObservation
	_ = r.withTx(context.Background(), ref.TenantID, func(tx *sql.Tx) error {
		// host(address), not address::text: the latter renders the netmask
		// (`192.0.2.10` comes back as `192.0.2.10/32`), which is the exact
		// mistake documented on resolveEndpointForFinding's read-back query in
		// inventory-service.
		rows, err := tx.QueryContext(context.Background(), `
			SELECT coalesce(host(address), ''), coalesce(fqdn, ''), coalesce(port, 0), transport
			  FROM public.asset_endpoints
			 WHERE tenant_id = $1 AND asset_id = $2
			 ORDER BY first_seen_at, id`, ref.TenantID, assetID)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var addr, fqdn, transport string
			var port int
			if err := rows.Scan(&addr, &fqdn, &port, &transport); err != nil {
				return err
			}
			out = append(out, identity.EndpointObservation{
				Address: addr, FQDN: fqdn, Port: port, Transport: transport,
			})
		}
		return rows.Err()
	})
	return out
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// lockWritableAsset prevents post-resolution writes racing a merge. Ordinary
// archived records still match historical evidence without receiving children;
// merged/deleted references must be resolved again to their current owner.
func lockWritableAsset(ctx context.Context, tx *sql.Tx, ref identity.AssetRef) (bool, error) {
	var archived, unavailable bool
	err := tx.QueryRowContext(ctx, `SELECT asset_status='archived',deleted_at IS NOT NULL OR NULLIF(metadata->>'merged_into','') IS NOT NULL FROM assets WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, ref.TenantID, ref.ID).Scan(&archived, &unavailable)
	if errors.Is(err, sql.ErrNoRows) || unavailable {
		return false, fmt.Errorf("%w: %s", identity.ErrAssetNotFound, ref.ID)
	}
	if err != nil {
		return false, err
	}
	return !archived, nil
}

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

// sourceRankSQL is [identity.SourceRank] as a SQL expression over a
// source_kind column. TestSourceRankSQLMatchesGo pins the two together.
func sourceRankSQL(col string) string {
	return "(CASE " + col + " WHEN 'declared' THEN 3 WHEN 'inferred' THEN 1 ELSE 2 END)"
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
//
// Validating with netip is NOT the same question Postgres asks. Go accepts an
// IPv6 zone — `fe80::1%eth0`, and on Windows `fe80::1%6`, which is what a host
// agent reports for a socket bound to a link-local address — and `inet` does
// not, so the value passed this check and died at the cast with 22P02. One
// zoned socket then failed the whole statement, which failed the whole host
// inventory: exactly the batch-wide loss this function exists to prevent, by a
// value it declared valid. So the zone is STRIPPED rather than the address
// dropped: a listener on a link-local address is a real listener, and the zone
// names an interface index on the reporting host that means nothing here.
func nullInet(v string) any {
	s := strings.TrimSpace(v)
	if s == "" {
		return nil
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.WithZone("").String()
	}
	if prefix, err := netip.ParsePrefix(s); err == nil {
		return netip.PrefixFrom(prefix.Addr().WithZone(""), prefix.Bits()).String()
	}
	return nil
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
