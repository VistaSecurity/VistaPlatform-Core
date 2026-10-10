package services

// The identification engine's seat in inventory-service (workstream 1.2).
//
// Before this, six intake paths used four different dedupe keys — ingest matched
// host-or-IP plus port, spreadsheet import and CMDB pull matched host-or-IP
// WITHOUT port, cloud discovery matched devices on type plus hostname-or-ARN,
// and manual create did not dedupe at all — with no ON CONFLICT anywhere. Every
// one of them now builds an identity.Observation and calls one engine.
//
// Each builder below answers the same three questions for its path: what
// identifiers did we actually observe, what scope do the weak ones (hostname, ip)
// belong to, and what class do we believe this is. A builder that cannot answer
// the first question honestly must not invent an answer — see
// errNoIdentifiers.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/identityaudit"
	"github.com/vistasecurity/vistaplatform/shared/identity/identitysettings"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// errNoIdentifiers is returned by a builder that observed nothing an asset could
// ever be matched on.
//
// An identifier-less observation is not a cheap asset; it is an asset that can
// never be recognised again, so every re-observation of the same thing creates
// another one. The old ingest produced exactly that whenever a finding had
// neither hostname nor IP. The one legitimate identifier-less case is a
// DECLARED service (ADR-0002 D3's dependent identity: a business service is
// identified by (tenant, name)), and phase 1 has no path that declares one.
var errNoIdentifiers = errors.New("observation carries no identifier; it could never be matched again")

// identityEngine returns the engine, building it on first use.
//
// It is built lazily rather than in NewAssetService because the tenant's dynamic
// scopes (DHCP segments, where an IP address must never decide a match) are a
// per-tenant runtime fact, and a nil segment service means we do not know them —
// in which case the safe answer is the empty set, which makes ip_address vote.
// That is today's behaviour; narrowing it is workstream 2.x's job with the
// segment's dynamic flag.
func (s *AssetService) identityEngine() (*identity.Engine, error) {
	s.identityOnce.Do(func() {
		s.identityRepo = pgidentity.New(s.db.DB.DB)
		s.identityEng, s.identityErr = identity.New(identity.Config{AdmissionEnabled: identity.AvailableCapabilities().Admission,
			Repo: s.identityRepo,
			// ProvisionalInventory is D2 (create a provisional asset) and
			// the provisional half of D3 (corroborate it, hearsay yields), and
			// THIS is the one constructor that turns it on. The flag defaults
			// to false so every other engine — device-interrogation-service's,
			// the memory-repo tests', a tool's — never creates a provisional
			// asset; inventory-service owns the asset table, the observation
			// table and the enrichment worker, so it is the only place that can
			// honour the whole rule (create provisional, corroborate in place,
			// materialise retained evidence). A second caller enabling it
			// without those pieces would create provisional assets nothing
			// ever promotes. The flag does NOT change the single-owner
			// shortcut (every identifier one asset's -> OutcomeSupporting):
			// that is ownership, unconditional in every engine.
			ProvisionalInventory: true,
			// AutoAcceptThreshold is left at zero HERE — never auto-merge
			// (ADR-0002 D5) — and supplied per observation by
			// resolveObservationWith, from the tenant's own setting. It has to
			// be per-observation: the engine is built once per process and
			// serves every tenant, so a threshold fixed here would be one
			// tenant's decision applied to all of them, and a tenant turning
			// auto-accept off would keep auto-merging until the next deploy.
			//
			// Matcher is left nil, which means the seam registry's DEFAULT —
			// the learned model of shared/identity/matcher (ADR-0008 D2). It
			// RANKS and EXPLAINS the candidates on a conflict; with the
			// threshold at zero it decides nothing.
		})
	})
	return s.identityEng, s.identityErr
}

// resolveObservationWith runs one observation through the engine inside ONE
// transaction — the asset, its identifiers, its endpoints, its last-seen and its
// history rows — together with the caller's own writes.
//
// Retry: the engine resolves identifier ownership before it writes, but between
// that read and the write another ingest of the same host can claim the same
// identifier. The repository reports that as ErrIdentifierConflict rather than
// letting the unique index raise, and the honest response is to resolve again —
// the second pass sees the row the racing writer committed and MATCHES it, which
// is the outcome that was true all along. Once, not in a loop: a second conflict
// is a different fact (a store that has lost the invariant), and retrying
// forever would hide it.
//
// `after` runs on the engine's transaction once the resolution is known, so the
// context, status and history rows an intake path writes about an observation
// land with the identity rows or not at all. One observation is one fact about
// the world; splitting it across two transactions leaves an asset whose history
// says it was created and whose context says nothing happened, and no later run
// repairs that — the next observation MATCHES the asset that exists and never
// takes the create path again.
//
// `after` is given a tenant-scoped *sqlx.Tx over the same *sql.Tx, because that
// is the handle the rest of this service speaks. It must not commit or roll
// back: returning an error does that, and the whole observation is undone.
//
// A resolution that wrote nothing (the floor's contested path, where every
// identifier belongs to somebody else) hands `after` a ZERO asset ref. The
// callback is still run — a caller may want to log it — and must check
// [identity.AssetRef.Zero] before writing anything.
func (s *AssetService) resolveObservationWith(
	ctx context.Context,
	obs identity.Observation,
	after func(tx *sqlx.Tx, res identity.Resolution) error,
) (identity.Resolution, error) {
	return s.resolveObservationWithRepo(ctx, obs, func(_ *pgidentity.Repository, tx *sqlx.Tx, res identity.Resolution) error {
		if after == nil {
			return nil
		}
		return after(tx, res)
	})
}

// resolveObservationWithRepo is [AssetService.resolveObservationWith] with the
// engine's BOUND repository handed to the callback as well as the sqlx handle.
//
// Some side tables an intake writes are not SQL this service spells — facts
// (`asset_facts`) and edges (`asset_relationships`) go through typed writers on
// shared/identity/postgres, which validate the fact registry and the canonical
// edge direction before touching the database. Those writers must run on the
// engine's transaction: calling them on the service's unbound repository would
// open a SECOND transaction on the pool while this one still holds the asset row
// uncommitted, and their assertAssetExists would not be able to see the asset
// that is being created a few lines above them.
func (s *AssetService) resolveObservationWithRepo(
	ctx context.Context,
	obs identity.Observation,
	after func(repo *pgidentity.Repository, tx *sqlx.Tx, res identity.Resolution) error,
) (identity.Resolution, error) {
	return s.resolveObservationAttributed(ctx, obs, nil, after)
}

// resolveObservationAttributed is [AssetService.resolveObservationWithRepo]
// with an optional `attribute` hook, run on the engine's transaction before
// Resolve, that may supply a verified person's scan request for this
// observation (operator_scan_attribution.go). Read there, not before, so the
// asset's lifecycle and Active Scan record are read under the same
// transaction that links the observation to it.
func (s *AssetService) resolveObservationAttributed(
	ctx context.Context,
	obs identity.Observation,
	attribute func(ctx context.Context, tx *sqlx.Tx) (*identity.OperatorScanRequest, error),
	after func(repo *pgidentity.Repository, tx *sqlx.Tx, res identity.Resolution) error,
) (identity.Resolution, error) {
	res, _, _, err := s.resolveObservationGated(ctx, obs, nil, attribute, after)
	return res, err
}

// existingAsset is what an intake learns, before it resolves, about the asset
// an observation's identifiers already belong to: the first owner, in
// observation order, whose asset row is not soft-deleted.
type existingAsset struct {
	ID     uuid.UUID
	Status string
	Found  bool
}

// observationGate is an intake's decision, taken on the engine's transaction
// before Resolve, about whether this observation is resolved at all. It sees
// the asset the observation's identifiers already belong to and may amend obs
// (its class hint) before the engine reads it. Returning false declines: the
// transaction is rolled back having written nothing, and the caller acts on
// the existing asset it was shown (a denied asset's last-seen, a third-party
// route) outside it.
type observationGate func(ctx context.Context, tx *sqlx.Tx, existing existingAsset, obs *identity.Observation) (proceed bool, err error)

// errObservationDeclined is how a declining gate leaves the transaction: as an
// error, so RunInTx rolls back; it never reaches a caller.
var errObservationDeclined = errors.New("the intake declined the observation before resolution")

// resolveObservationGated is [AssetService.resolveObservationAttributed] with an
// optional gate, run on the engine's transaction before Resolve ( F5).
//
// The gate replaces a pre-lookup an intake used to make on its own
// connections ([AssetService.lookupExistingAsset]) before handing the same
// observation to the engine, which then looked every identifier up a second
// time. Here the owners are read ONCE, under the identifier locks
// ([identity.Engine.SnapshotOwners]); the gate decides on them, and the engine
// resolves on the same snapshot ([identity.Engine.WithOwnerSnapshot]). The
// intake's decision and the engine's therefore rest on one read instead of two
// that a concurrent writer could separate.
//
// It reports the existing asset the gate saw (from the last attempt, when the
// identifier-conflict retry ran twice) and whether the observation was
// resolved; resolved is false only when the gate declined.
func (s *AssetService) resolveObservationGated(
	ctx context.Context,
	obs identity.Observation,
	gate observationGate,
	attribute func(ctx context.Context, tx *sqlx.Tx) (*identity.OperatorScanRequest, error),
	after func(repo *pgidentity.Repository, tx *sqlx.Tx, res identity.Resolution) error,
) (identity.Resolution, existingAsset, bool, error) {
	engine, err := s.identityEngine()
	if err != nil {
		return identity.Resolution{}, existingAsset{}, false, fmt.Errorf("identification engine unavailable: %w", err)
	}
	var res identity.Resolution
	var existing existingAsset
	// The observation as the engine resolved it — the gate may have amended
	// its class hint — for the post-commit audit and drift events.
	resolvedObs := obs
	run := func() error {
		existing = existingAsset{}
		return s.identityRepo.RunInTx(ctx, obs.TenantID, func(r *pgidentity.Repository) error {
			tx := s.sqlxOver(r.Tx())
			resolveObs := obs
			var snapshot *identity.OwnerSnapshot
			if gate != nil {
				snap, sErr := engine.WithRepository(r).SnapshotOwners(ctx, resolveObs)
				if sErr != nil {
					return sErr
				}
				ex, eErr := existingFromSnapshot(ctx, tx, resolveObs.TenantID, snap)
				if eErr != nil {
					return eErr
				}
				existing = ex
				proceed, gErr := gate(ctx, tx, ex, &resolveObs)
				if gErr != nil {
					return gErr
				}
				if !proceed {
					return errObservationDeclined
				}
				snapshot = snap
			}
			// The tenant's auto-accept threshold, read in THIS transaction.
			//
			// Per observation and uncached, deliberately. A cache would make a
			// tenant turning auto-merge off take effect "soon" — and "a config
			// change that silently did not take effect" is a failure this
			// codebase has hit repeatedly (envFrom ConfigMaps, --reuse-values).
			// The read is one primary-key lookup on a row this transaction is
			// about to touch anyway; correctness is worth it on the one setting
			// that decides whether the platform may merge two assets unasked.
			threshold, tErr := s.autoAcceptThreshold(ctx, tx, obs.TenantID)
			if tErr != nil {
				return tErr
			}
			// The tenant's rule-merge switch ( Phase 4), read the same way
			// and for the same reason: it decides whether a same-device verdict
			// is stamped on this observation's proposal for the rule-merge
			// executor to act on. Absent means ON; a read the database refuses
			// fails the observation rather than guessing.
			autoMerge, mErr := identitysettings.ReadAutoMergeExistingFor(ctx, tx, obs.TenantID)
			if mErr != nil {
				return mErr
			}

			eng := engine.WithAutoAcceptThreshold(threshold).WithAutoMergeExisting(autoMerge).WithRepository(r).WithOwnerSnapshot(snapshot)
			if attribute != nil {
				req, aErr := attribute(ctx, tx)
				if aErr != nil {
					return aErr
				}
				if req != nil {
					eng = eng.WithOperatorScanRequest(*req)
				}
			}
			resolvedObs = resolveObs
			var rErr error
			res, rErr = eng.Resolve(ctx, resolveObs)
			if rErr != nil {
				return rErr
			}
			// An asset in a located segment takes that segment's location when
			// it records none, on every intake path that resolves through here
			// (findings, host observations, posted sightings, source imports).
			// The engine writes network_segment_id when it creates an asset,
			// and nothing else on these paths gave the asset the segment's
			// location — so a hearsay-created asset (a UniFi client table's
			// peer) sat in the segment under "No site recorded" on the map
			// while its neighbours sat under the segment's site. Only the
			// asset's OWN segment is used, never the observation's, and a
			// conflict places nothing. Runs before `after`, so a source that
			// states a site still writes it.
			if !res.Asset.Zero() && res.Outcome != identity.OutcomeConflict {
				if pErr := r.InheritSegmentLocation(ctx, res.Asset, obs.Source); pErr != nil {
					return pErr
				}
			}
			if after == nil {
				return nil
			}
			return after(r, tx, res)
		})
	}
	err = run()
	if errors.Is(err, identity.ErrIdentifierConflict) {
		log.Printf("[AssetService] identity: %s raced another writer for an identifier; resolving again", observationLabel(obs))
		err = run()
	}
	if errors.Is(err, errObservationDeclined) {
		return identity.Resolution{}, existing, false, nil
	}
	if err != nil {
		return identity.Resolution{}, existing, false, err
	}
	// AFTER the commit. An audit event announcing a merge that then rolled back
	// would be a record of something that did not happen.
	s.auditAutoAcceptedMerge(ctx, resolvedObs, res)
	// The same reason: a host key rotation announced for a resolution that
	// rolled back never happened ( Decision 4).
	s.publishIdentityDrift(ctx, resolvedObs, res)
	return res, existing, true, nil
}

// existingFromSnapshot finds the first owner in the snapshot, in observation
// order, whose asset is not soft-deleted, and reads its approval status on the
// engine's transaction. It is lookupExistingAsset's answer computed from the
// owners the engine will resolve on, without reading them again.
func existingFromSnapshot(ctx context.Context, tx *sqlx.Tx, tenantID string, snap *identity.OwnerSnapshot) (existingAsset, error) {
	checked := map[string]bool{}
	for _, io := range snap.Owners() {
		for _, ref := range io.Owners {
			if checked[ref.ID] {
				continue
			}
			checked[ref.ID] = true
			assetID, err := uuid.Parse(ref.ID)
			if err != nil {
				continue
			}
			var status string
			err = tx.QueryRowContext(ctx, `
				SELECT asset_status FROM assets
				WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`, tenantID, assetID).Scan(&status)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return existingAsset{}, fmt.Errorf("reading asset status: %w", err)
			}
			return existingAsset{ID: assetID, Status: status, Found: true}, nil
		}
	}
	return existingAsset{}, nil
}

// autoAcceptThreshold reads the tenant's setting on the engine's transaction.
//
// Any failure to read it is reported, not swallowed into the default: a
// threshold the database would not give us is not evidence the tenant set zero,
// and the observation is better refused and retried than resolved under a
// setting nobody chose. (A tenant who has simply never set one DOES get zero —
// that is identitysettings.ReadAutoAcceptThreshold's answer, not an error.)
func (s *AssetService) autoAcceptThreshold(ctx context.Context, tx *sqlx.Tx, tenantID string) (float64, error) {
	return identitysettings.ReadAutoAcceptThresholdFor(ctx, tx, tenantID)
}

// auditAutoAcceptedMerge records that the platform merged two assets without
// being asked.
//
// The event itself is built by shared/identity/identityaudit, because
// device-interrogation-service's two engines write the SAME event since
// workstream 4.6a and a tenant asking "what has the matcher done to my
// inventory?" is asking one question. What stays here is WHEN to call it:
// after the commit, because an audit event announcing a merge that then rolled
// back would be a record of something that did not happen.
//
// A nil logger is a documented state, not a bug — without it the merge still
// happens and is still in `asset_history`; only the audit trail is thinner.
func (s *AssetService) auditAutoAcceptedMerge(ctx context.Context, obs identity.Observation, res identity.Resolution) {
	identityaudit.LogAutoAcceptedMerge(ctx, s.auditLogger, obs, res)
}

// sqlxOver wraps the engine's raw *sql.Tx as the *sqlx.Tx the rest of this
// service speaks, carrying the pool's field mapper so StructScan and Select
// behave exactly as they do on a transaction sqlx opened itself.
//
// sqlx has no exported constructor for this, and `driverName` is unexported, so
// the wrapper cannot do bind-type translation: NAMED queries (`:name`) and
// sqlx.In on this handle would not work. Nothing in the callbacks uses them —
// every statement is positional `$n` — and a named query here would fail loudly
// at the first call rather than silently, so this is a constraint rather than a
// trap.
func (s *AssetService) sqlxOver(tx *sql.Tx) *sqlx.Tx {
	if tx == nil {
		return nil
	}
	wrapped := &sqlx.Tx{Tx: tx}
	if s.db != nil && s.db.DB != nil {
		wrapped.Mapper = s.db.Mapper
	}
	return wrapped
}

// lookupExistingAsset answers "do we already have this thing?" WITHOUT creating
// anything.
//
// Resolve cannot answer it: resolving creates. Two decisions in the ingest path
// have to be made before anything is written — whether a third-party endpoint is
// already an ELEVATED asset (refresh in place) or just noise (route to
// external_connections), and whether a denied fingerprint should suppress a
// CREATION (it must not suppress an update to an asset that still exists).
//
// It looks each identifier up on the same unique key the engine uses, so it
// cannot match more loosely than identification would: an unscoped hostname
// finds only another unscoped hostname, never one in some other segment.
func (s *AssetService) lookupExistingAsset(ctx context.Context, tenantID uuid.UUID, obs identity.Observation) (uuid.UUID, string, bool, error) {
	if _, err := s.identityEngine(); err != nil {
		return uuid.Nil, "", false, err
	}
	for _, id := range obs.Identifiers {
		refs, err := s.identityRepo.FindByIdentifier(ctx, obs.TenantID, id.Kind, id.Value, id.Scope)
		if err != nil {
			return uuid.Nil, "", false, err
		}
		for _, ref := range refs {
			assetID, err := uuid.Parse(ref.ID)
			if err != nil {
				continue
			}
			status, ok, err := s.assetStatusOf(tenantID, assetID)
			if err != nil {
				return uuid.Nil, "", false, err
			}
			if ok {
				return assetID, status, true, nil
			}
		}
	}
	return uuid.Nil, "", false, nil
}

// assetStatusOf reads one asset's approval status. A soft-deleted asset reports
// false: the identifier still belongs to it (the unique index spans deleted rows
// too), but for the purpose of "is this thing in the inventory" it is not.
func (s *AssetService) assetStatusOf(tenantID, assetID uuid.UUID) (string, bool, error) {
	var status string
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`
			SELECT asset_status FROM assets
			WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`, tenantID, assetID).Scan(&status)
	})
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", false, nil
	case err != nil:
		return "", false, fmt.Errorf("reading asset status: %w", err)
	}
	return status, true, nil
}

// matchedAssetStatus answers "what status does this asset actually HAVE?" for
// an ingest that matched an EXISTING asset.
//
// The ingest's own `status` is the decision discovery-processor reached by
// running the tenant's auto-approval rules over one discovery row. That decides
// what a NEW asset lands as and nothing more: an asset that already exists has
// a status a human or a rule already gave it, and a later observation of it is
// not a re-application for approval.
//
// fallback is returned when the status cannot be read — a soft-deleted asset,
// or a failed read. Both are reasons to keep the caller's conservative answer
// rather than to invent a more permissive one.
func (s *AssetService) matchedAssetStatus(tenantID, assetID uuid.UUID, fallback string) string {
	status, ok, err := s.assetStatusOf(tenantID, assetID)
	if err != nil {
		log.Printf("[AssetService] reading the status of matched asset %s failed; treating it as %s: %v", assetID, fallback, err)
		return fallback
	}
	if !ok {
		return fallback
	}
	return status
}

// errEndpointNotAttached is resolveEndpointForFinding's answer for a finding
// that describes a socket the asset does not have: no identity decision
// attached it (platform ADR-0003 D2). The caller skips whatever it was going
// to hang off that socket — a service name, a crypto configuration — with a
// log line; it never creates the endpoint itself.
var errEndpointNotAttached = errors.New("the identity decision attached no endpoint for this socket")

// resolveEndpointForFinding returns the id of the endpoint a finding was
// measured on. It LOOKS IT UP; it never creates it.
//
// Endpoints follow the identity decision (platform ADR-0003 D2): the engine
// writes the observation's endpoints inside its own transaction when it
// matches, creates or provisionally creates an asset, and writes none when the
// evidence only supports an established asset. A post-engine writer that
// upserted here — as this did until — put a supporting scan's ports on
// the asset the engine had just declined to attach anything to. So this finds
// the endpoint the engine (or an operator's Link / Confirm, or the
// interrogated-device path) already wrote, and returns errEndpointNotAttached
// when there is none.
//
// It returns uuid.Nil, nil when the finding describes no socket — an at-rest
// cloud resource. That is the replacement for the "AT-REST" port sentinel: the
// old model needed a fake port because an asset WAS a port, and the new one does
// not because an asset may simply have no endpoint.
//
// The lookup spells the endpoint exactly as the engine's UpsertEndpoints keys
// it (EndpointKey from shared/identity), so the row the engine wrote is the row
// found here.
func (s *AssetService) resolveEndpointForFinding(ctx context.Context, tenantID, assetID uuid.UUID, f IngestFinding) (uuid.UUID, error) {
	ep, ok := findingEndpoint(f, nonPlaceholderIP(f.IPAddress))
	if !ok {
		return uuid.Nil, nil
	}

	// Matched on the INET value, not on its text rendering. `address::text`
	// renders the netmask — `192.0.2.10` comes back as `192.0.2.10/32` — so
	// comparing it against the bare address the caller holds matched NOTHING,
	// ever: every configuration materialised from ingest got a NULL endpoint_id
	// while this logged a warning and carried on. (The unique index below uses
	// the same coalesce(address::text,'') on BOTH sides, so it is self-consistent
	// and correct; only a comparison against a bare parameter is wrong.)
	//
	// IS NOT DISTINCT FROM rather than coalesce(): it is null-safe without
	// inventing a sentinel, and NULL address / NULL port are real values here —
	// an at-rest endpoint has both.
	//
	// The address branch below deliberately does NOT also require fqdn to
	// match. identity/postgres.Repository.UpsertEndpoints, which wrote the row,
	// matches an address-bearing endpoint on (address, port, transport) alone
	// and merges fqdn into the existing row ("empty never wins" — see its
	// mergeEndpointByAddress) rather than requiring an exact match. A read-back
	// that still demanded fqdn equality would miss the very row that call just
	// wrote or updated whenever the existing row already carried a DIFFERENT
	// (non-empty) fqdn than this observation's — which is exactly the case an
	// active scan with no resolved name hits against a passively-discovered,
	// already-named endpoint.
	var id uuid.UUID
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		if ep.Address != "" {
			return tx.QueryRow(`
				SELECT id FROM asset_endpoints
				WHERE tenant_id = $1 AND asset_id = $2
				  AND address = $3::text::inet
				  AND port IS NOT DISTINCT FROM $4::int
				  AND transport = $5`,
				tenantID, assetID,
				ep.Address, nullablePort(ep.Port), endpointTransport(ep)).Scan(&id)
		}
		return tx.QueryRow(`
			SELECT id FROM asset_endpoints
			WHERE tenant_id = $1 AND asset_id = $2
			  AND address IS NULL
			  AND coalesce(fqdn, '') = coalesce($3::text, '')
			  AND port IS NOT DISTINCT FROM $4::int
			  AND transport = $5`,
			tenantID, assetID,
			nullableText(ep.FQDN), nullablePort(ep.Port), endpointTransport(ep)).Scan(&id)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, fmt.Errorf("endpoint %s on asset %s: %w", ep.Key(), assetID, errEndpointNotAttached)
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("look up endpoint %s: %w", ep.Key(), err)
	}
	return id, nil
}

// attachDecidedFindingEndpoint has the engine write a finding's endpoint onto
// an asset a decision outside the precedence walk already chose ( WP7
// F17): an interrogation finding that verifiably belongs to the device that was
// interrogated (interrogation_owned_ingest.go), or a retained payload replayed
// onto the asset its observation is linked to. Endpoints are written only by
// shared/identity (identity.AttachDecidedEndpoints): sanitised, never onto an
// archived or denied asset, and named on the asset's timeline with the
// decision that attached them.
func (s *AssetService) attachDecidedFindingEndpoint(ctx context.Context, tenantID, assetID uuid.UUID, f IngestFinding, decision identity.DecidedEndpoints) error {
	ep, ok := findingEndpoint(f, nonPlaceholderIP(f.IPAddress))
	if !ok {
		return nil
	}
	if _, err := s.identityEngine(); err != nil {
		return err
	}
	src := identity.Source{Kind: identity.SourceMeasured, Ref: "device_interrogation"}
	if f.SourceSensorID != nil && *f.SourceSensorID != "" {
		src.Ref = "sensor:" + *f.SourceSensorID
	}
	obs := identity.Observation{TenantID: tenantID.String(), Source: src, Endpoints: []identity.EndpointObservation{ep}}
	ref := identity.AssetRef{TenantID: tenantID.String(), ID: assetID.String()}
	return s.identityRepo.RunInTx(ctx, tenantID.String(), func(r *pgidentity.Repository) error {
		if _, err := identity.AttachDecidedEndpoints(ctx, r, obs, ref, decision, findingObservedAt(f)); err != nil {
			return fmt.Errorf("attach endpoint %s: %w", ep.Key(), err)
		}
		return nil
	})
}

// attachObservationEndpoints has the engine write an observation's evidence
// endpoints onto the asset a decision linked it to, inside the caller's
// transaction. It is what Link and Confirm do with supporting evidence the
// engine held (platform ADR-0003 D2), and what corroboration does with a held
// observation's sockets: the decision is the attachment the engine declined to
// make. Endpoints are stamped with the observation's own source and time, so
// the asset's Services & Endpoints tab says who measured them, not who clicked.
func attachObservationEndpoints(ctx context.Context, repo *pgidentity.Repository, ref identity.AssetRef, obs identity.Observation, at time.Time, decision identity.DecidedEndpoints) error {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	if _, err := identity.AttachDecidedEndpoints(ctx, repo, obs, ref, decision, at); err != nil {
		return fmt.Errorf("attach the observation's endpoints to %s: %w", ref.ID, err)
	}
	return nil
}

// endpointTransport applies the same default EndpointKey does, so the key the
// engine deduped on and the row this reads back cannot disagree.
func endpointTransport(ep identity.EndpointObservation) string {
	t := strings.ToLower(strings.TrimSpace(ep.Transport))
	switch t {
	case "tcp", "udp", "none":
		return t
	default:
		return "none"
	}
}

func nullableText(v string) interface{} {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return strings.TrimSpace(v)
}

func nullablePort(p int) interface{} {
	if p <= 0 || p > 65535 {
		return nil
	}
	return p
}

// observationLabel renders an observation for a log line without dereferencing
// anything that might be absent.
func observationLabel(obs identity.Observation) string {
	if obs.DisplayName != "" {
		return obs.DisplayName
	}
	if len(obs.Identifiers) > 0 {
		return string(obs.Identifiers[0].Kind) + "=" + obs.Identifiers[0].Value
	}
	return "(no identifiers)"
}

// ---------------------------------------------------------------------------
// Per-path observation builders
// ---------------------------------------------------------------------------

// discoveryObservation builds the observation for the sensor / active-scan /
// PCAP / cloud intake, all of which arrive as an IngestFinding.
//
// The finding becomes an identity.Sighting (discoverySighting) and the intake
// decides the rest: which segment the address and the name are in — what
// makes hostname and ip_address able to decide a match at all (ADR-0002 D3) —
// whether that segment is dynamic, the admission flags from the channel the
// evidence came through, and identifier hygiene. What stays here is the two
// checks only this service can make about who WROTE the row: that a collector
// claiming a sensor id is a sensor of this tenant, and whether a cloud listing
// is the platform's own collector (cloudCollectorAuthoritative), which picks
// the `api` channel.
func (s *AssetService) discoveryObservation(tenantID uuid.UUID, f IngestFinding, effectiveIP *string, ownership string) (identity.Observation, error) {
	return s.discoveryObservationIn(nil, tenantID, f, effectiveIP, ownership)
}

// discoveryObservationIn is discoveryObservation scoped against an import
// request's one segment snapshot ( F4).
func (s *AssetService) discoveryObservationIn(segs *importSegments, tenantID uuid.UUID, f IngestFinding, effectiveIP *string, ownership string) (identity.Observation, error) {
	if f.SourceSensorID != nil && findingCollectorSource(f) {
		sensorID, err := uuid.Parse(strings.TrimSpace(*f.SourceSensorID))
		if err != nil || sensorID == uuid.Nil || s.db == nil {
			return identity.Observation{}, errors.New("invalid discovery collector identity")
		}
		var registered bool
		if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
			return tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM sensors WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL)`, tenantID, sensorID).Scan(&registered)
		}); err != nil {
			return identity.Observation{}, fmt.Errorf("verify discovery collector: %w", err)
		}
		if !registered {
			return identity.Observation{}, errors.New("discovery collector does not belong to tenant")
		}
	}
	cloudAuthoritative, err := s.cloudCollectorAuthoritative(context.Background(), tenantID, f)
	if err != nil {
		return identity.Observation{}, err
	}
	// Leniency is a decision made HERE and visible: one malformed MAC in a batch
	// must not lose the whole finding, and assessSighting logs every reject.
	res, err := s.assessSightingIn(context.Background(), segs, findingLabel(f), discoverySighting(tenantID, f, effectiveIP, ownership, cloudAuthoritative))
	if errors.Is(err, identity.ErrNoUsableIdentifier) {
		return identity.Observation{}, fmt.Errorf("%w: %s", errNoIdentifiers, findingLabel(f))
	}
	if err != nil {
		return identity.Observation{}, err
	}
	return res.Observation, nil
}

// applicationDependentIdentifier builds the `name` identifier that carries an
// application's DEPENDENT identity (ADR-0002 D3), or reports that this
// observation is not an application.
//
// # What was wrong
//
// The `application` branch carried `identifier_precedence: [cmdb_sys_id]` and
// nothing else, so an application from any source but a CMDB could never be
// matched a second time. The first sighting created an asset holding a hostname
// identifier that was not allowed to vote for its class; the second sighting
// found that hostname already owned, had nothing left to attach, hit the
// identity floor and opened a merge proposal — against the asset it WAS. A
// poller on a fifteen-minute schedule produced ninety-six of those a day, each
// naming one candidate, none of them resolvable into anything.
//
// # The key
//
// identity.ResolveDependent owns the spelling, so this and any future writer of
// an application row produce the same string rather than two dedupe keys for
// one concept — the failure the whole package exists to end. The canonical form
// is `application:<parent>:<product>|<instance>`, stored as a `name` identifier
// scoped by the CLASS KEY, which is how the `service` branch already works.
//
// # The parent is the host AS OBSERVED, not the host asset's id
//
// ADR-0002 D3 keys an application under its host ASSET. Using the asset id here
// would mean resolving — and, when it is unknown, CREATING — a host from an
// observation that only ever described an application, minting a second asset
// nobody observed; and it would make the application's own identity move the
// day its host was merged, producing a duplicate application and a proposal for
// it. The host's strongest observed identifier is stable, costs no extra
// resolution, and invents nothing. The consequence is honest and bounded: a
// host known by two names yields two applications and a merge proposal, which
// is the right question for a human rather than a silent guess.
//
// hostname/fqdn are deliberately NOT in the application precedence: they would
// match the HOST asset, and an application is not its host.
func applicationDependentIdentifier(classKey, hostname, ip string, f IngestFinding) (identity.Identifier, bool) {
	if classKey == "" || !assetclass.IsAncestor(assetclass.KeyApplication, classKey) {
		return identity.Identifier{}, false
	}
	parent := strings.ToLower(strings.TrimSpace(hostname))
	if parent == "" {
		parent = strings.TrimSpace(ip)
	}
	if parent == "" {
		// Nothing to be under. An application with no host is not a thing this
		// path can identify, and inventing a parent would be the fabricated
		// identity the floor exists to refuse.
		return identity.Identifier{}, false
	}

	// Product: what the application IS. The identified service name when a
	// collector supplied one, else the class itself — true, just coarse, which
	// is the rule the class taxonomy already follows.
	product := rawDataString(f.RawData, "service_name", "product", "application", "software")
	if product == "" {
		product = classKey
	}
	// Instance: what distinguishes two of them on one host. The port, which is
	// the only thing a discovery finding reliably has.
	instance := rawDataString(f.RawData, "instance_name", "instance")
	if instance == "" && f.Port != nil && *f.Port > 0 {
		instance = strconv.Itoa(*f.Port)
	}

	dep, err := dependentApplicationIdentity(parent, product, instance)
	if err != nil {
		log.Printf("[AssetService] identity: %s: could not key the application under %q: %v",
			findingLabel(f), parent, err)
		return identity.Identifier{}, false
	}
	return identity.Identifier{
		Kind: identity.KindName, Value: dep.Canonical, Scope: classKey, Confidence: 1,
	}, true
}

// dependentApplicationIdentity is the one call into identity.ResolveDependent
// for an application. `tenant` is a placeholder: ResolveDependent requires a
// tenant on the parent ref but does not put it in the canonical key for a
// parented kind — the parent already scopes it, and the identifier row is
// tenant-scoped by its own table.
func dependentApplicationIdentity(parent, product, instance string) (identity.DependentIdentity, error) {
	var engine identity.Engine
	return engine.ResolveDependent(context.Background(),
		identity.DependentApplication,
		identity.AssetRef{TenantID: "tenant", ID: parent},
		identity.ApplicationKey(product, instance))
}

// manualObservation builds the observation for an asset a person or an importer
// declared: manual create, spreadsheet import, CMDB pull.
//
// Source kind is declared or imported, never measured — nobody probed anything.
// ADR-0002 D4 ranks those below a measurement for identity facts and ABOVE it
// for context (owner, business unit, environment), which is the engine's job,
// not this builder's. The declaration becomes a `person` sighting (an `api`
// one for a connection import) and the intake scopes it; an identifier the
// caller wrote its own scope on keeps that scope (withExplicitScopes).
//
// The name is NOT judged generic or synthetic ( B2): a `printer` somebody
// typed or curated is a statement about which device this is, and the intake
// grades only what a collector measured.
func (s *AssetService) manualObservation(tenantID uuid.UUID, in models.AssetInput, source identity.Source) (identity.Observation, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return identity.Observation{}, err
	}
	receipt := sha256.Sum256(body)
	receiptID := in.ObservationReceiptID
	if receiptID == "" {
		receiptID = hex.EncodeToString(receipt[:])
	}
	if in.ObservationTime.IsZero() {
		in.ObservationTime = time.Now().UTC()
	}
	sg, scoped, err := declaredSighting(tenantID, in, source, receiptID)
	if err != nil {
		return identity.Observation{}, err
	}
	res, err := s.assessSighting(context.Background(), "declared asset", sg)
	if err != nil && !errors.Is(err, identity.ErrNoUsableIdentifier) {
		return identity.Observation{}, err
	}
	obs, rejected := withExplicitScopes(res, scoped)
	for _, r := range rejected {
		log.Printf("[AssetService] identity: declared %s identifier rejected: %v", r.Identifier.Kind, r.Err)
	}
	if len(obs.Identifiers) == 0 {
		if assetclass.IsAncestor(assetclass.KeyService, in.ClassKey) {
			return identity.Observation{}, fmt.Errorf("%w: a %s is identified by its name, so display_name is required",
				errNoIdentifiers, in.ClassKey)
		}
		return identity.Observation{}, fmt.Errorf("%w: an asset needs a hostname, an address or an identifier", errNoIdentifiers)
	}
	return obs, nil
}

// ---------------------------------------------------------------------------
// finding → observation field helpers
// ---------------------------------------------------------------------------

// cloudCollectorAuthoritative reports whether a finding is a cloud provider's
// own listing of a resource, written by the platform's cloud collector — the
// evidence that may establish an asset keyed on the provider's resource id.
//
// Why it matters: the at-rest collectors (object storage, managed databases,
// key stores) record nothing themselves; their resources reach inventory ONLY
// as findings. Unmarked, a finding carrying just a bucket name and its ARN has
// no device or address binding, so a tenant in ENFORCE admission mode parked
// every one of them as an unresolved observation and none ever became an
// asset. The load balancers and distributions were unaffected only because the
// collector also records those through upsertDeviceAsset, which has always
// admitted them as authoritative. A cloud API listing a resource is the same
// statement whichever of the two paths carries it.
//
// All three conditions are required, and none of them may be relaxed:
//
//   - The row was written under this tenant's platform-managed
//     device-interrogation sensor — the one sensor the cloud collector writes
//     sensor_discoveries under (writeSensorDiscoveriesTx). This is the trust
//     anchor. `discovery_method = cloud_api` alone is NOT: it sits in the
//     sensor-controlled metadata envelope, so any tenant sensor could claim it.
//     `platform_managed` is set only by the platform's own provisioning, never
//     by a tenant registration (see sensor-manager auto_registration.go).
//   - The finding says it came from a cloud API. The platform sensor also
//     carries device-interrogation rows, which are not a provider's listing.
//   - The finding carries the provider's resource id. That is what the
//     admission is keyed on (`authoritative_identifier`), and what makes the
//     next run of the same discovery match the same asset.
//
// A sensor's passive observation, an active scan, or a cloud-shaped row from
// any other sensor stays exactly as unauthoritative as before.
func (s *AssetService) cloudCollectorAuthoritative(ctx context.Context, tenantID uuid.UUID, f IngestFinding) (bool, error) {
	if s.db == nil || f.SourceSensorID == nil || !isCloudAPIFinding(f) || cloudResourceID(f) == "" {
		return false, nil
	}
	sensorID, err := uuid.Parse(strings.TrimSpace(*f.SourceSensorID))
	if err != nil || sensorID == uuid.Nil {
		return false, nil
	}
	var platform bool
	if err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM sensors
				 WHERE tenant_id = $1 AND id = $2
				   AND profile = 'device_interrogation'
				   AND platform_managed
				   AND deleted_at IS NULL)`, tenantID, sensorID).Scan(&platform)
	}); err != nil {
		return false, fmt.Errorf("verify cloud collector: %w", err)
	}
	return platform, nil
}

func findingCollectorSource(f IngestFinding) bool {
	ref := findingSource(f).Ref
	// "interrogation" is a collector too: the converter now preserves
	// device_interrogation on a sensor_discoveries row, and that row's
	// sensor id must be verified like any other collector's.
	return ref == "sensor" || strings.HasPrefix(ref, "sensor:") || ref == "scan" || strings.HasPrefix(ref, "scan:") || ref == "interrogation"
}

func findingSource(f IngestFinding) identity.Source {
	ref := "sensor"
	mode := identity.ModePassive
	switch strings.ToLower(rawDataString(f.RawData, "source")) {
	case "cloud_discovery":
		ref, mode = "cloud", identity.ModeActive
	case "device_interrogation":
		ref, mode = "interrogation", identity.ModeActive
	case "pcap", "pcap_upload":
		ref, mode = "sensor:pcap", identity.ModePassive
	case "discovery_jobs", "active_scan":
		ref, mode = "scan", identity.ModeActive
	case "sensor_discovery", "sensor_discoveries":
		ref, mode = "sensor", identity.ModePassive
	}
	if provider := rawDataString(f.RawData, "cloud_provider"); provider != "" {
		ref = "cloud:" + strings.ToLower(provider)
		mode = identity.ModeActive
	}
	if (ref == "sensor" || ref == "sensor:pcap" || ref == "scan") && f.SourceSensorID != nil {
		if sensorID, err := uuid.Parse(strings.TrimSpace(*f.SourceSensorID)); err == nil && sensorID != uuid.Nil {
			ref += ":" + sensorID.String()
		}
	}
	return identity.Source{Kind: identity.SourceMeasured, Ref: ref, Mode: mode}
}

// findingConfidence is the intake's confidence in the observation as a whole,
// which is what an approval rule's min_confidence reads. Zero means NOT STATED —
// the finding carried no confidence — and the approval rules treat it as such
// rather than as "certainly wrong".
func findingConfidence(f IngestFinding) float64 {
	if raw, ok := f.RawData["confidence_score"]; ok {
		switch v := raw.(type) {
		case float64:
			return v
		case int:
			return float64(v)
		}
	}
	return 0
}

func findingNetworkType(f IngestFinding) string {
	return rawDataString(f.RawData, "network_type")
}

// findingObservedAt is when the thing was seen, when the producer said so.
//
// Zero is returned when it did not, and the engine then stamps its own clock.
// That is the truthful fallback — "when we processed it" — where inventing a
// measurement time would put a number in the history that nothing measured.
func findingObservedAt(f IngestFinding) time.Time {
	for _, key := range []string{"observed_at", "discovered_at", "timestamp", "seen_at"} {
		if t, ok := f.RawData[key].(time.Time); ok {
			return t.UTC()
		}
		v, ok := f.RawData[key].(string)
		if !ok || strings.TrimSpace(v) == "" {
			continue
		}
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// findingClassHint maps the intake's asset-type opinion onto a class key.
//
// Three readings, in descending order of how directly the producer said it:
// the cloud `resource_type`, the producer's `device_type`, and last the legacy
// four-value asset_type. All three go through the ONE table set in
// shared/assetclass. Empty is a legitimate answer: the engine then falls back
// to `unknown_host` or `external` from the network ownership, which is ADR-0002
// D1's rule and more honest than guessing `server`.
//
// # Why `device_type` is read here
//
// The class hint is not cosmetic — it selects the class's IDENTIFIER
// PRECEDENCE, which is what decides whether an identifier is allowed to vote.
//
// Half the cloud collectors write `resource_type` (buckets, RDS, the
// enumerated VPCs/subnets/instances) and half write only `device_type`
// (CloudFront, API Gateway, the three key stores, the managed load balancers).
// For the second half the hint fell through to the legacy `asset_type`, which
// the converter stamps `service` for all of them — so they were classed
// `application`, whose precedence is `[cmdb_sys_id, name]` and contains no
// `cloud_resource_id`.
//
// The consequence measured on demo: a CloudFront distribution's two discovery
// rows both CARRIED the distribution id, and the identity engine logged
// `carried cloud_resource_id=…, which belongs to another asset; it was not
// attached` for each of them before creating a second and a third asset beside
// the one the collector had just made. had made the identifier present;
// the class made it mute. The certificate then never materialized, because the
// duplicates were `pending_approval` and a pending asset's crypto is deferred.
//
// device-interrogation-service's own side has always read `device_type`
// through this same table (`DeviceTypeClassKey`). Two sides of one question
// reading two different keys is the drift ADR-0002 exists to end, and is
// exactly the shape fixed for the identifier list.
func findingClassHint(f IngestFinding) string {
	if key := cloudClassHint(rawDataString(f.RawData, "resource_type", "cloud_resource_type")); key != "" {
		return key
	}
	if key := assetclass.FromDeviceType(rawDataString(f.RawData, "device_type")); key != "" {
		return string(key)
	}
	if key, ok := assetclass.FromLegacyAssetType(f.AssetType); ok {
		return key
	}
	return ""
}

// cloudClassHint maps a cloud collector's resource type onto a class key,
// through the ONE table in shared/assetclass.
//
// It used to be a private switch here, and it did not know the strings the
// collectors write: they emit `s3_bucket`, `gcs_bucket`, `rds_instance` and
// `cloudsql_instance`, and it knew `s3`, `bucket`, `rds` and `sql_database`.
// So a bucket got no class hint, the engine fell back to the finding's legacy
// `asset_type` — which for these findings is `service` — and every S3 bucket in
// the tenant was inventoried as an APPLICATION while every RDS instance became
// a server. Both were guesses presented as facts, and both fed the
// application-identity failure above.
//
// An UNRECOGNISED resource type is now `cloud_resource`, the top-level class:
// coarse and true beats a guessed leaf, and beats falling through to a class
// the finding never claimed.
func cloudClassHint(resourceType string) string {
	key, ok := assetclass.FromCloudResourceType(resourceType)
	if !ok {
		return ""
	}
	return string(key)
}

// cloudResourceID digs the provider's resource identifier out of the finding.
// ARN, Azure resource id and GCP self-link all land in the same identifier kind
// — they are the same thing under three names.
//
// The key list is identity.CloudResourceIDKeys, shared with the collector side
// (device-interrogation-service's cloudResourceIDFromMetadata). Both must read
// the same keys: when they disagree, the collector identifies a resource by its
// provider id and the finding for the same resource identifies it by hostname,
// and one resource becomes two assets. That is how a CloudFront distribution
// and its alias — one distribution, two hostnames, `distribution_id` and
// nothing else naming it — became two assets once started routing owned
// cloud findings onto assets at all.
func cloudResourceID(f IngestFinding) string {
	return identity.CloudResourceIDFromMetadata(f.RawData)
}

// findingEndpoint turns the finding's address and port into the endpoint
// observation. The second result is false when there is no socket here at all —
// an at-rest cloud resource — which is what retires the AT-REST port sentinel:
// the asset is created with NO endpoint rather than one on a fake port.
func findingEndpoint(f IngestFinding, effectiveIP *string) (identity.EndpointObservation, bool) {
	if findingIsAtRest(f) {
		return identity.EndpointObservation{}, false
	}
	addr := strings.TrimSpace(derefString(effectiveIP))
	host := strings.TrimSpace(derefString(f.Hostname))
	if addr == "" && host == "" {
		return identity.EndpointObservation{}, false
	}
	ep := identity.EndpointObservation{Address: addr, Transport: "tcp"}
	if strings.Contains(strings.TrimSuffix(host, "."), ".") {
		ep.FQDN = strings.ToLower(host)
	}
	// `host` is whatever the intake path called the scan target, and an
	// active-scan path that resolves nothing gives it back the literal
	// address it was told to probe — which still "contains a dot" and so
	// passed the check above as an FQDN. Sanitized() folds that back into
	// Address (a no-op when addr already carries the same value, since
	// Address is already set) rather than leaving a fake name that produces a
	// second asset_endpoints row for a listener already recorded under
	// addr's own address.
	ep = ep.Sanitized()
	if ep.Address == "" && ep.FQDN == "" {
		// A single-label hostname with no address: `asset_endpoints` requires an
		// address or an FQDN, and a bare label is neither. The asset still
		// records the hostname as an IDENTIFIER — this says only that the
		// finding describes no reachable face, which is the same answer as an
		// at-rest resource.
		return identity.EndpointObservation{}, false
	}
	if f.Port != nil && *f.Port > 0 {
		ep.Port = *f.Port
	} else {
		// No port observed. Not a socket, so not a transport either.
		ep.Transport = "none"
	}
	if proto, verdict := resolveProtocol(f.Protocol); verdict == protocolEnum {
		ep.Protocol = proto
	}
	return ep, true
}

// rawDataString reads the first of the given keys that holds a non-empty string.
func rawDataString(raw map[string]interface{}, keys ...string) string {
	if raw == nil {
		return ""
	}
	for _, k := range keys {
		if v, ok := raw[k].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// findingLeafCertFingerprints returns the SHA-256 fingerprints of the LEAF
// certificates in a finding's canonical `certificates` array (CLAUDE.md "Single
// certificate format"): entries at chain_order 0, or with no chain_order, that
// are not CA certificates. An intermediate or root is the CA's identity, not
// the device's. Only the fingerprint is read.
func findingLeafCertFingerprints(raw map[string]interface{}) []string {
	certs, _ := raw["certificates"].([]interface{})
	var out []string
	seen := map[string]bool{}
	for _, c := range certs {
		m, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		if order, has := m["chain_order"]; has {
			if n, ok := order.(float64); !ok || n != 0 {
				if i, ok := order.(int); !ok || i != 0 {
					continue
				}
			}
		}
		if ca, _ := m["is_ca"].(bool); ca {
			continue
		}
		fp, _ := m["fingerprint_sha256"].(string)
		fp = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(fp), ":", ""))
		if fp == "" || seen[fp] {
			continue
		}
		seen[fp] = true
		out = append(out, fp)
	}
	return out
}
