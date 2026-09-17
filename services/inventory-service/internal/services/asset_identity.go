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
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/netip"
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
		s.identityEng, s.identityErr = identity.New(identity.Config{
			Repo: s.identityRepo,
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
	engine, err := s.identityEngine()
	if err != nil {
		return identity.Resolution{}, fmt.Errorf("identification engine unavailable: %w", err)
	}
	var res identity.Resolution
	run := func() error {
		return s.identityRepo.RunInTx(ctx, obs.TenantID, func(r *pgidentity.Repository) error {
			tx := s.sqlxOver(r.Tx())
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

			var rErr error
			res, rErr = engine.WithAutoAcceptThreshold(threshold).WithRepository(r).Resolve(ctx, obs)
			if rErr != nil {
				return rErr
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
	if err != nil {
		return identity.Resolution{}, err
	}
	// AFTER the commit. An audit event announcing a merge that then rolled back
	// would be a record of something that did not happen.
	s.auditAutoAcceptedMerge(ctx, obs, res)
	return res, nil
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

// resolveEndpointForFinding returns the id of the endpoint a finding was
// measured on, creating it if the asset does not have it yet.
//
// It returns uuid.Nil, nil when the finding describes no socket — an at-rest
// cloud resource. That is the replacement for the "AT-REST" port sentinel: the
// old model needed a fake port because an asset WAS a port, and the new one does
// not because an asset may simply have no endpoint.
//
// The dedupe key is EndpointKey from shared/identity, the same spelling the
// engine's UpsertEndpoints uses, so an endpoint created here and one created by
// an observation are one row rather than two.
func (s *AssetService) resolveEndpointForFinding(ctx context.Context, tenantID, assetID uuid.UUID, f IngestFinding) (uuid.UUID, error) {
	effectiveIP := f.IPAddress
	if effectiveIP != nil && (*effectiveIP == "" || isUnspecifiedIP(*effectiveIP)) {
		effectiveIP = nil
	}
	ep, ok := findingEndpoint(f, effectiveIP)
	if !ok {
		return uuid.Nil, nil
	}
	if _, err := s.identityEngine(); err != nil {
		return uuid.Nil, err
	}
	ref := identity.AssetRef{TenantID: tenantID.String(), ID: assetID.String()}
	if err := s.identityRepo.UpsertEndpoints(ctx, ref, []identity.EndpointObservation{ep}); err != nil {
		return uuid.Nil, fmt.Errorf("upsert endpoint %s: %w", ep.Key(), err)
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
	// match. identity/postgres.Repository.UpsertEndpoints, just called above,
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
	if err != nil {
		return uuid.Nil, fmt.Errorf("read back endpoint %s: %w", ep.Key(), err)
	}
	return id, nil
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
// Scope is the network segment the address falls in, resolved by the existing
// segment service. It is what makes hostname and ip_address able to decide a
// match at all: unscoped, ADR-0002 D3 says they do not vote, because "printer-2"
// and 10.0.0.5 are answers to a question only once you say where you were
// standing. FromLegacyAsset in shared/identity documents the same gap.
func (s *AssetService) discoveryObservation(tenantID uuid.UUID, f IngestFinding, effectiveIP *string, ownership string) (identity.Observation, error) {
	obs := identity.Observation{
		TenantID:   tenantID.String(),
		Source:     findingSource(f),
		ObservedAt: findingObservedAt(f),
		Confidence: findingConfidence(f),
		Network: identity.Network{
			Ownership: ownership,
			Type:      findingNetworkType(f),
		},
	}

	segmentID, dynamicScope := s.observationScope(tenantID, effectiveIP, f.Hostname)
	obs.Network.SegmentID = segmentID
	if dynamicScope {
		obs.DynamicScopes = map[string]bool{segmentID: true}
	}

	host := strings.TrimSpace(derefString(f.Hostname))
	if host != "" {
		obs.Hostname = strings.ToLower(host)
		obs.DisplayName = obs.Hostname
		// A dotted name is an FQDN, which is globally unique and needs no
		// scope; a single label is a hostname and identifies only within one.
		kind := identity.KindHostname
		scope := segmentID
		if strings.Contains(strings.TrimSuffix(host, "."), ".") {
			kind = identity.KindFQDN
			scope = ""
		}
		obs.Identifiers = append(obs.Identifiers, identity.Identifier{
			Kind: kind, Value: host, Scope: scope, Confidence: 1,
		})
	}
	if ip := strings.TrimSpace(derefString(effectiveIP)); ip != "" {
		obs.Identifiers = append(obs.Identifiers, identity.Identifier{
			Kind: identity.KindIPAddress, Value: ip, Scope: segmentID, Confidence: 1,
		})
		if obs.DisplayName == "" {
			obs.DisplayName = ip
		}
	}

	// Cloud findings carry the strongest identifier we ever get for them: the
	// provider's own resource id. It outranks everything else in the precedence
	// list for a cloud class, which is why a bucket with no address still
	// deduplicates correctly — the old path collapsed every such resource onto
	// one asset through the shared 0.0.0.0 placeholder.
	if rid := cloudResourceID(f); rid != "" {
		obs.Identifiers = append(obs.Identifiers, identity.Identifier{
			Kind: identity.KindCloudResourceID, Value: rid, Confidence: 1,
		})
	}
	if mac := rawDataString(f.RawData, "mac_address", "mac"); mac != "" {
		obs.Identifiers = append(obs.Identifiers, identity.Identifier{
			Kind: identity.KindMACAddress, Value: mac, Confidence: 1,
		})
	}
	if serial := rawDataString(f.RawData, "serial_number", "serial"); serial != "" {
		obs.Identifiers = append(obs.Identifiers, identity.Identifier{
			Kind: identity.KindSerialNumber, Value: serial, Confidence: 1,
		})
	}
	if fp := rawDataString(f.RawData, "ssh_host_key_fingerprint", "host_key_fingerprint"); fp != "" {
		obs.Identifiers = append(obs.Identifiers, identity.Identifier{
			Kind: identity.KindSSHHostKeyFingerprint, Value: fp, Confidence: 1,
		})
	}

	obs.ClassHint = findingClassHint(f)
	if ep, ok := findingEndpoint(f, effectiveIP); ok {
		obs.Endpoints = append(obs.Endpoints, ep)
	}

	// An APPLICATION has no identity of its own (ADR-0002 D3): it is identified
	// by its position under a host, plus what it is and which instance. Give it
	// that key, or it can never be recognised a second time — see
	// applicationDependentIdentifier for what went wrong without one.
	if id, ok := applicationDependentIdentifier(obs.ClassHint, host, derefString(effectiveIP), f); ok {
		obs.Identifiers = append(obs.Identifiers, id)
	}

	// Leniency is a decision made HERE and visible: one malformed MAC in a batch
	// must not lose the whole finding, but the reject is logged rather than
	// dropped.
	clean, rejected := obs.Sanitize()
	for _, r := range rejected {
		log.Printf("[AssetService] identity: %s dropped a %s identifier: %v", findingLabel(f), r.Identifier.Kind, r.Err)
	}
	if len(clean.Identifiers) == 0 {
		return identity.Observation{}, fmt.Errorf("%w: %s", errNoIdentifiers, findingLabel(f))
	}
	return clean, nil
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
// not this builder's.
func (s *AssetService) manualObservation(tenantID uuid.UUID, in models.AssetInput, source identity.Source) (identity.Observation, error) {
	obs := identity.Observation{
		TenantID:   tenantID.String(),
		Source:     source,
		Confidence: 1, // a person or a system of record asserted it
		// The class attributes, so the matcher seam has a vendor and a model to
		// COMPARE when this turns out to be contested (workstream 4.6). The
		// engine does not write them — reconciling an attribute against what an
		// asset already holds is ADR-0002 D4's job and stays with the caller —
		// and it reads only identity.SummaryAttributeKeys out of the map.
		//
		// This path is where they come from in practice: a CMDB pull and a
		// spreadsheet import both carry make and model for hardware, and a
		// disagreement about either is real evidence that two records are two
		// things rather than one.
		Attributes: in.Attributes,
	}
	segmentID, dynamicScope := s.observationScope(tenantID, in.IPAddress, in.Hostname)
	obs.Network.SegmentID = segmentID
	if dynamicScope {
		obs.DynamicScopes = map[string]bool{segmentID: true}
	}
	if in.AssetOwnership != nil {
		obs.Network.Ownership = *in.AssetOwnership
	}

	for _, id := range in.Identifiers {
		kind := identity.Kind(strings.TrimSpace(strings.ToLower(id.Kind)))
		if !kind.Valid() {
			log.Printf("[AssetService] identity: ignoring identifier of unknown kind %q", id.Kind)
			continue
		}
		scope := strings.TrimSpace(derefString(id.Scope))
		if kind.RequiresScope() && scope == "" {
			// An unscoped hostname or IP is still RECORDED — it is true — but
			// it cannot decide a match. Defaulting it to the segment the
			// address resolves to is the honest scope when we have one.
			//
			// A `name` is NOT scoped by segment: it identifies within a CLASS
			// (ADR-0002 D3's erratum), and the builder ten lines below already
			// scopes the display-name form that way. A user-supplied `name`
			// arriving through the identifiers array got the segment instead,
			// so the same service declared twice — once by display name, once
			// as an explicit identifier — produced two rows for one thing and
			// neither matched the other.
			scope = defaultScopeForKind(kind, in.ClassKey, segmentID)
		}
		obs.Identifiers = append(obs.Identifiers, identity.Identifier{
			Kind: kind, Value: strings.TrimSpace(id.Value), Scope: scope, Confidence: 1,
		})
	}

	host := strings.TrimSpace(derefString(in.Hostname))
	if host != "" {
		obs.Hostname = strings.ToLower(host)
		obs.DisplayName = obs.Hostname
		kind := identity.KindHostname
		scope := segmentID
		if strings.Contains(strings.TrimSuffix(host, "."), ".") {
			kind = identity.KindFQDN
			scope = ""
		}
		obs.Identifiers = append(obs.Identifiers, identity.Identifier{
			Kind: kind, Value: host, Scope: scope, Confidence: 1,
		})
	}
	if ip := strings.TrimSpace(derefString(in.IPAddress)); ip != "" {
		obs.Identifiers = append(obs.Identifiers, identity.Identifier{
			Kind: identity.KindIPAddress, Value: ip, Scope: segmentID, Confidence: 1,
		})
		if obs.DisplayName == "" {
			obs.DisplayName = ip
		}
	}

	obs.ClassHint = in.ClassKey

	// A DECLARED service is identified by its name and nothing else
	// (ADR-0002 D3 erratum: "services identify by (tenant, class, name),
	// realised as the `name` identifier kind"). The scope is the class key:
	// a business service and a technical service may share a name, and the
	// class is what says they are different things.
	//
	// Before this the three service classes had an EMPTY precedence, so a
	// tenant picking "Business service" in the class picker got "an asset needs
	// a hostname, an address or an identifier" and had no way to satisfy it.
	if name := strings.TrimSpace(derefString(in.DisplayName)); name != "" {
		obs.DisplayName = name
		if assetclass.IsAncestor(assetclass.KeyService, in.ClassKey) {
			obs.Identifiers = append(obs.Identifiers, identity.Identifier{
				Kind: identity.KindName, Value: name, Scope: in.ClassKey, Confidence: 1,
			})
		}
	}

	for _, ep := range in.Endpoints {
		transport := strings.TrimSpace(ep.Transport)
		if transport == "" {
			transport = "tcp"
		}
		port := 0
		if ep.Port != nil {
			port = *ep.Port
		}
		obs.Endpoints = append(obs.Endpoints, identity.EndpointObservation{
			Address:   derefString(ep.Address),
			FQDN:      derefString(ep.FQDN),
			Port:      port,
			Transport: transport,
			Protocol:  derefString(ep.Protocol),
		})
	}

	clean, rejected := obs.Sanitize()
	for _, r := range rejected {
		log.Printf("[AssetService] identity: declared %s identifier rejected: %v", r.Identifier.Kind, r.Err)
	}
	if len(clean.Identifiers) == 0 {
		if assetclass.IsAncestor(assetclass.KeyService, in.ClassKey) {
			return identity.Observation{}, fmt.Errorf("%w: a %s is identified by its name, so display_name is required",
				errNoIdentifiers, in.ClassKey)
		}
		return identity.Observation{}, fmt.Errorf("%w: an asset needs a hostname, an address or an identifier", errNoIdentifiers)
	}
	return clean, nil
}

// observationScope resolves the scope hostname and ip_address identify within,
// and whether that scope hands addresses out dynamically.
//
// It NEVER returns an empty scope. "This tenant has no segments" — which is
// every fresh tenant — is a fact about their topology, not the absence of one,
// and the tenant-wide default scope (ADR-0002 D3 erratum) is what it means.
// Returning "" here is what made one host, ingested three times, into three
// assets: neither its hostname nor its IP could vote, so nothing matched, and
// every asset after the first carried no identifier at all.
//
// The ADDRESS half is shared/identity/postgres's ScopeForAddress, so this
// service and device-interrogation-service cannot disagree about which segment
// an address is in — one more spelling of this lookup is one more dedupe key.
// The NAME half is still local: a `domain` segment is matched by hostname, which
// an address-keyed lookup cannot answer, and dropping it would silently
// un-scope every host in a domain segment.
func (s *AssetService) observationScope(tenantID uuid.UUID, ip, hostname *string) (string, bool) {
	// s.db nil is the pure-unit-test shape: the builders are testable without a
	// database, and with no database there are no segments to resolve against —
	// the tenant default is the right answer, not a panic.
	if addr, ok := parseObservedAddr(ip); ok && s.db != nil && s.db.DB != nil {
		if _, err := s.identityEngine(); err == nil {
			// The empty cloud-network ref is an ANSWER, not a placeholder, and
			// it is the right one for every intake that reaches here: a
			// cryptographic finding off the wire and a passive host observation
			// are both seen on a network the sensor watches, and neither
			// carries a VPC. The segment rows they must match are exactly the
			// ones with a NULL `cloud_network_ref`, which the unique index
			// folds to '' — so "" selects them and nothing else.
			//
			// Only the path that ENUMERATED a cloud network knows its ref, and
			// that is device-interrogation's (managed_asset.go passes one
			// through). Passing a ref we did not observe would scope a LAN host
			// into a VPC's segment; passing "" from the cloud path would do the
			// reverse, which is the collision fixed.
			scope, dynamic, err := s.identityRepo.ScopeForAddress(context.Background(), tenantID.String(), addr, "")
			if err == nil && scope != "" {
				return scope, dynamic
			}
			if err != nil {
				// A failed lookup is not a reason to lose the observation, but
				// it must not be silent: it degrades every identifier in this
				// batch to the tenant default.
				log.Printf("[AssetService] identity: resolving the segment for %s failed; scoping to the tenant default: %v", addr, err)
			}
		}
	}
	// No address, or none that resolved: a domain segment may still place it by
	// name.
	if s.networkSegmentService != nil {
		if seg, err := s.networkSegmentService.GetSegmentForIP(tenantID, ip, hostname); err == nil && seg != nil {
			return seg.ID.String(), false
		}
	}
	return identity.ScopeTenantDefault, false
}

// parseObservedAddr turns the address an intake observed into a netip.Addr.
// The second result is false for absent, empty or unparseable values — and for
// the unspecified address, which cloud collectors use as a placeholder and
// which is inside nothing.
func parseObservedAddr(ip *string) (netip.Addr, bool) {
	v := strings.TrimSpace(derefString(ip))
	if v == "" {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(v)
	if err != nil || !addr.IsValid() || addr.IsUnspecified() {
		return netip.Addr{}, false
	}
	return addr.Unmap().WithZone(""), true
}

// ---------------------------------------------------------------------------
// finding → observation field helpers
// ---------------------------------------------------------------------------

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
// Cloud resource types are mapped directly where the collector named one;
// otherwise the legacy four-value asset_type is translated by the one table in
// shared/assetclass. Empty is a legitimate answer: the engine then falls back to
// `unknown_host` or `external` from the network ownership, which is ADR-0002
// D1's rule and more honest than guessing `server`.
func findingClassHint(f IngestFinding) string {
	if key := cloudClassHint(rawDataString(f.RawData, "resource_type", "cloud_resource_type")); key != "" {
		return key
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
func cloudResourceID(f IngestFinding) string {
	return rawDataString(f.RawData, "arn", "resource_id", "cloud_resource_id", "self_link", "resource_uri")
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
