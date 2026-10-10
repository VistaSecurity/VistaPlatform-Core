package services

// Where an interrogation's ops observations land.
//
// A vendor interrogation has always retrieved far more than cryptography and
// thrown most of it away at projection: UniFi's device objects carry uplinks,
// port tables and LLDP neighbours; PAN-OS system info was fetched and
// discarded whole. made the collectors EMIT that as registered facts and
// canonical relationships (ADR-0004 D1, ADR-0003 D2). This file is where those
// stop being a payload and become rows.
//
// Three things happen here, in order, and the order matters:
//
//  1. **Sanitize, again.** The registry already sanitized the result at the
//     collector boundary — but on the agent path that happened in the
//     CUSTOMER'S BINARY, a release of our code we do not control the version
//     of, and the result arrived over HTTP. Redacting on receipt costs one pass
//     and makes the platform's own guarantee independent of which agent build
//     sent it. "Collect posture, never key material" is not a promise we can
//     delegate to a process we cannot see.
//
//  2. **Resolve every subject and peer through the identification engine** —
//     inventory-service's, the one engine host (platform ADR-0003 D3). A
//     collector cannot resolve an asset: it describes a peer by identifiers,
//     this file sends that as an identity.Sighting, and the engine decides
//     which asset it is, creating a pending one when it is nobody we know.
//     That is what turns "this firewall sees a neighbour with MAC aa:bb:…"
//     into a node on the map.
//
//  3. **Write facts per subject and edges per pair**, with the edge's status
//     decided by ADR-0003 D3 rather than by whoever wrote the collector.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
	"github.com/vistasecurity/vistaplatform/shared/classify"
	"github.com/vistasecurity/vistaplatform/shared/classify/classifystore"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/classproposal"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	sharednetwork "github.com/vistasecurity/vistaplatform/shared/network"
)

// InterrogationObservations is what an interrogation observed beyond its crypto
// assets: the hardware identity of the device itself, the registered ops facts,
// and the edges. It is the subset of the shared core's InterrogateResult that
// this sink persists, named separately because the agent path reconstructs it
// from a JSON payload rather than holding the core's type.
type InterrogationObservations struct {
	ObservedAt     time.Time
	DeviceIdentity *di.DeviceIdentity
	Facts          []di.FactObservation
	Relationships  []di.RelationshipObservation
	// Producer is the shared/facts producer key these facts are written under.
	// Empty means device-interrogation, which is what every vendor collector
	// is. The host-inventory path passes `device-agent`, because that is what
	// the registry lists for os.kernel, hw.uuid, svc.listening_sockets and the
	// rest of the agent's keys — routing them through device-interrogation
	// would fail validation, and widening those keys' producer lists to make it
	// pass would be the "one key, two meanings" bug the validation exists to
	// prevent.
	Producer string
}

// producer is the shared/facts producer key to write under.
func (o InterrogationObservations) producer() string {
	if o.Producer != "" {
		return o.Producer
	}
	return facts.ProducerDeviceInterrogation
}

// Empty reports whether there is nothing to persist.
func (o InterrogationObservations) Empty() bool {
	return o.DeviceIdentity == nil && len(o.Facts) == 0 && len(o.Relationships) == 0
}

// ObservationSink writes an interrogation's facts, identity and relationships
// onto the asset model.
//
// It resolves nothing itself: every subject and peer is posted to
// inventory-service as a sighting (sighting_poster.go), and the facts and
// edges are written against the asset ids that come back. Both the agent
// result path (ResultProcessor) and the in-cluster path
// (DeviceInterrogationService) persist through one of these.
type ObservationSink struct {
	db *sql.DB

	// The fact and edge writer (asset_facts, asset_relationships). Never used
	// to resolve identity.
	storeOnce sync.Once
	repo      *pgidentity.Repository

	// The rule-based classifier over the CURATED classification_rules table
	// (ADR-0004 D6, workstream 2.10b), reloaded on an interval so an admin's
	// rule becomes live without a restart.
	//
	// The COLLECTORS already consult the rules, through
	// shared/deviceinterrogation/classhint.go — but they consult
	// classify.Default(), the compiled-in table, because the same code runs
	// inside the device agent, which has no database. This is the other half:
	// the service that DOES have the table applies it to a peer the collector
	// could form no opinion about.
	classifyOnce sync.Once
	classifyRef  *classify.Refresher

	// classifierSet is the seam set a peer is classified through. Nil means
	// [seams.Default], which is what production uses and what every
	// constructor leaves it at.
	//
	// It exists for ONE reason: the shipped classifier weights decline to
	// answer on a MAC address alone — correctly, since a single OUI bucket is
	// thin evidence — and a peer reference carries nothing else. So the MODEL
	// branch of applyPeerClassRules is unreachable from a test that uses the
	// real weights, and an unreachable branch is an untested one. The branch
	// decides whether a machine's guess reaches an asset or the approval queue,
	// which is not a thing to ship untested.
	//
	// A field rather than a package variable so one test cannot leak its stub
	// into another.
	classifierSet func() seams.Set
}

// seamSet returns the seam set to classify through.
func (s *ObservationSink) seamSet() seams.Set {
	if s.classifierSet != nil {
		return s.classifierSet()
	}
	return seams.Default()
}

// NewObservationSink returns a sink over the RLS-scoped connection.
func NewObservationSink(db *sql.DB) *ObservationSink { return &ObservationSink{db: db} }

// classifier returns the rule engine over the curated table, building it once.
func (s *ObservationSink) classifier() *classify.Refresher {
	s.classifyOnce.Do(func() {
		interval, _ := classify.RefreshIntervalFromEnv()
		var repo classify.Repository
		if s.db != nil {
			repo = classifystore.New(s.db)
		}
		ctx := context.Background()
		s.classifyRef = classify.NewRefresher(ctx, repo, interval, log.Printf)
		go s.classifyRef.Run(ctx)
	})
	return s.classifyRef
}

// store is the fact and edge writer over the sink's connection.
func (s *ObservationSink) store() *pgidentity.Repository {
	s.storeOnce.Do(func() { s.repo = pgidentity.New(s.db) })
	return s.repo
}

// Persist writes everything an interrogation observed about assetID and its
// peers.
//
// Failures are returned, not swallowed — the caller decides whether losing the
// ops observations should fail the job — but one bad fact does not lose the
// rest: each is attempted and the errors are joined. A collector emitting one
// unregistered key must not cost a switch its entire port table.
func (s *ObservationSink) Persist(
	ctx context.Context,
	tenantID, assetID uuid.UUID,
	source identity.Source,
	obs InterrogationObservations,
) error {
	if obs.Empty() {
		return nil
	}
	return shareddatabase.WithSessionAdvisoryLocks(ctx, s.db, []shareddatabase.SessionAdvisoryLock{{Key: pgidentity.HostSnapshotLockKey(tenantID)}}, func() error {
		return s.persist(ctx, tenantID, assetID, source, obs)
	})
}

// persist runs under the tenant snapshot lock, including calls from host
// materialization, which already owns that lock.
func (s *ObservationSink) persist(ctx context.Context, tenantID, assetID uuid.UUID, source identity.Source, obs InterrogationObservations) error {
	if obs.Empty() {
		return nil
	}
	repo := s.store()

	// Defence in depth: re-run the collector-boundary redactor over anything
	// that arrived from outside this process. Sanitize works on the core's
	// result type, so the observations are wrapped to reuse it verbatim rather
	// than growing a second redactor that can drift from the first.
	wrapped := &di.InterrogateResult{
		DeviceIdentity: obs.DeviceIdentity,
		Facts:          obs.Facts,
		Relationships:  obs.Relationships,
	}
	di.Sanitize(wrapped)

	at := obs.ObservedAt
	if at.IsZero() {
		at = time.Now().UTC()
	}
	self := identity.AssetRef{TenantID: tenantID.String(), ID: assetID.String()}
	var errs []error

	// A replay of a context that recorded its progress does only what is
	// still pending ( item 25): the peers still held and the facts and
	// edges that name one of them. The device's own writes (segments, gateway
	// claims, identity, its own facts) landed on the first pass and are
	// redone only if they failed there. Everything else is nil: do it all.
	only := replayFilter(ctx)
	selfDue := only.due(selfPeerKey)
	pass := newPassPeers(ctx, s, tenantID, source, at)

	// The device's networks must exist as cidr segments BEFORE peers are
	// resolved, so a peer's address resolves into its segment, and the DHCP
	// posture the device measured is the segment's stored posture by the time
	// inventory-service's Intake reads it. That stored posture is the ONLY way
	// a run's DHCP answer reaches identity: there is no per-run overlay
	// ( item 7), so an operator's static marking is never overridden.
	for _, f := range wrapped.Facts {
		if !selfDue || f.Key != facts.KeyNetVlans {
			continue
		}
		if err := s.ensureVLANSegments(ctx, tenantID, assetID, f.Value); err != nil {
			return fmt.Errorf("vlan segments: %w", err)
		}
	}

	// Then the device's own address on each of those networks, claimed for
	// it, and its home segment (gateway_claims.go). Before the peers,
	// so a neighbour reported at one of the device's addresses meets the
	// device rather than a record that address would otherwise have made.
	// A failure here is reported with the rest and loses nothing else.
	if selfDue && obs.producer() == facts.ProducerDeviceInterrogation {
		if err := s.persistGatewayClaims(ctx, tenantID, assetID, source, at, wrapped.Facts); err != nil {
			errs = append(errs, fmt.Errorf("gateway addresses: %w", err))
			pass.fail(selfPeerKey)
		}
	}

	// The device owns every interface MAC it reports, so a sensor hearing it
	// from another interface matches it instead of "replacing" it.
	if selfDue && obs.producer() == facts.ProducerDeviceInterrogation {
		if err := s.persistInterfaceMACs(ctx, tenantID, assetID, source, at, wrapped.Facts); err != nil {
			errs = append(errs, err)
			pass.fail(selfPeerKey)
		}
	}

	obs.DeviceIdentity, obs.Facts, obs.Relationships = wrapped.DeviceIdentity, wrapped.Facts, wrapped.Relationships
	ctx, retained, err := s.preparePeerContext(ctx, tenantID, assetID, source, at, obs)
	if err != nil {
		return err
	}

	if selfDue && wrapped.DeviceIdentity != nil {
		if err := s.persistIdentity(ctx, repo, tenantID, self, source, at, wrapped.DeviceIdentity); err != nil {
			errs = append(errs, err)
			pass.fail(selfPeerKey)
		}
	}

	// Facts, grouped by the asset they are ABOUT. An interrogation is not
	// always about one asset: a UniFi controller reports the interfaces, uptime
	// and serial of every device it manages, and attributing a switch's port
	// table to the controller would be a worse answer than not collecting it.
	//
	// Each subject is resolved once for the pass (passPeers), however many
	// facts it carries.
	bySubject := map[identity.AssetRef][]pgidentity.Fact{}
	keysBySubject := map[identity.AssetRef]map[string]bool{}
	for _, f := range wrapped.Facts {
		subject, key := self, selfPeerKey
		if !f.Subject.IsZero() {
			key = retainedPeerKey(f.Subject)
		}
		if !only.due(key) {
			continue
		}
		if !f.Subject.IsZero() {
			resolved, resolveErr := pass.resolve(ctx, f.Subject)
			if resolveErr != nil {
				var retained *identity.RetainedObservation
				if errors.As(resolveErr, &retained) {
					continue
				}
				if errors.Is(resolveErr, errPeerSyntheticNamesOnly) || errors.Is(resolveErr, errSightingRefused) {
					log.Printf("[ObservationSink] fact %s skipped: subject %v", f.Key, resolveErr)
					continue
				}
				errs = append(errs, fmt.Errorf("fact %s: resolving subject: %w", f.Key, resolveErr))
				continue
			}
			subject = resolved
		}
		bySubject[subject] = append(bySubject[subject], pgidentity.Fact{
			Key:        f.Key,
			Value:      f.Value,
			SourceKind: source.Kind,
			SourceRef:  source.Ref,
			Confidence: f.Confidence,
			ObservedAt: at,
		})
		if keysBySubject[subject] == nil {
			keysBySubject[subject] = map[string]bool{}
		}
		keysBySubject[subject][key] = true
	}
	for subject, fs := range bySubject {
		if err := repo.UpsertFacts(ctx, subject, obs.producer(), fs); err != nil {
			errs = append(errs, fmt.Errorf("writing %d facts for asset %s: %w", len(fs), subject.ID, err))
			for key := range keysBySubject[subject] {
				pass.fail(key)
			}
		}
	}

	for _, rel := range wrapped.Relationships {
		if !only.edgeDue(rel) {
			continue
		}
		if err := s.persistRelationship(ctx, repo, pass, tenantID, self, source, at, rel); err != nil {
			errs = append(errs, err)
			pass.failEdge(rel)
		}
	}
	return s.finishPeerContext(ctx, tenantID, retained, pass, errs)
}

// persistIdentity records the hardware identity an interrogation measured.
//
// Vendor, model and firmware are FACTS with provenance — the same registered
// keys the collectors emit and the same keys the Devices form writes as
// declared, so the two land on one key with two sources and ADR-0002 D4 decides
// which shows. The serial is an IDENTIFIER, not a fact: it is how the asset is
// recognised, and `devices.serial_number` being a plain column is a large part
// of why an interrogated device and the same host seen elsewhere were two rows.
//
// The serial goes to the engine as a sighting, bound to the device through
// the identifiers it already holds (selfIdentitySighting). It used to be
// attached directly, with no engine, no scope check and no proposal when it
// belonged to another asset ( item 4); now a serial another asset owns is
// a merge proposal, and one nobody owns attaches to the device the session
// was opened to.
func (s *ObservationSink) persistIdentity(
	ctx context.Context,
	repo *pgidentity.Repository,
	tenantID uuid.UUID,
	self identity.AssetRef,
	source identity.Source,
	at time.Time,
	di *di.DeviceIdentity,
) error {
	var errs []error

	fs := deviceFacts(di.Vendor, di.Model, di.FirmwareVersion, source, at)
	if v := strings.TrimSpace(di.OSVersion); v != "" {
		fs = append(fs, pgidentity.Fact{
			Key:        facts.KeyOSVersion,
			Value:      v,
			SourceKind: source.Kind,
			SourceRef:  source.Ref,
			Confidence: 1,
			ObservedAt: at,
		})
	}
	if len(fs) > 0 {
		if err := repo.UpsertFacts(ctx, self, facts.ProducerDeviceInterrogation, fs); err != nil {
			errs = append(errs, fmt.Errorf("writing device identity facts: %w", err))
		}
	}

	if serial := strings.TrimSpace(di.SerialNumber); serial != "" {
		assetID, err := uuid.Parse(self.ID)
		if err != nil {
			return errors.Join(append(errs, fmt.Errorf("device identity: asset id %q: %w", self.ID, err))...)
		}
		known, err := knownAssetIdentifiers(ctx, s.db, tenantID, assetID)
		if err != nil {
			return errors.Join(append(errs, fmt.Errorf("reading the device's identifiers: %w", err))...)
		}
		if len(known) == 0 {
			// Nothing ties a sighting to the device the session was opened
			// to, so a serial sent alone would be a new device to the engine
			// — a duplicate of this one. Not sent; the next interrogation of a
			// device that has an identifier sends it.
			log.Printf("[ObservationSink] serial %q read from asset %s not sent: the asset holds no identifier to bind it to", serial, self.ID)
			return errors.Join(errs...)
		}
		if assetOwns(known, identity.KindSerialNumber, serial) {
			// Already the device's: a sighting would add only a retained
			// observation row per run (its source is the job).
			return errors.Join(errs...)
		}
		_, res, err := postSighting(ctx, s.db, selfIdentitySighting(tenantID, source, at, serial, known))
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("resolving the device's serial: %w", err))
		case res.Asset.ID != self.ID:
			// A conflict (the serial is another asset's: a merge proposal is
			// waiting) or evidence held for review. Either way not this
			// device's to claim; the engine said so, and Approvals has it.
			log.Printf("[ObservationSink] serial %q read from asset %s resolved %s (asset %q, proposal %q); not attached",
				serial, self.ID, res.Outcome, res.Asset.ID, res.Proposal.ID)
		}
	}
	return errors.Join(errs...)
}

// persistRelationship resolves an observed edge's two ends, through the
// pass's memo, and writes it.
func (s *ObservationSink) persistRelationship(
	ctx context.Context,
	repo *pgidentity.Repository,
	pass *passPeers,
	tenantID uuid.UUID,
	self identity.AssetRef,
	source identity.Source,
	at time.Time,
	rel di.RelationshipObservation,
) error {
	subject := self
	if !rel.Subject.IsZero() {
		resolved, err := pass.resolve(ctx, rel.Subject)
		if err != nil {
			var retained *identity.RetainedObservation
			if errors.As(err, &retained) {
				return nil
			}
			if errors.Is(err, errPeerContested) || errors.Is(err, errPeerSyntheticNamesOnly) || errors.Is(err, errSightingRefused) {
				log.Printf("[ObservationSink] %s edge skipped: subject %v", rel.Type, err)
				return nil
			}
			return fmt.Errorf("edge %s: resolving subject: %w", rel.Type, err)
		}
		subject = resolved
	}
	peer, err := pass.resolve(ctx, rel.Peer)
	if err != nil {
		var retained *identity.RetainedObservation
		if errors.As(err, &retained) {
			return nil
		}
		if errors.Is(err, errPeerContested) || errors.Is(err, errPeerSyntheticNamesOnly) || errors.Is(err, errSightingRefused) {
			// Not a failure of the interrogation: one edge could not be
			// attached because a human has to settle who its far end is, or
			// because its far end carries nothing that identifies it.
			// Logged and skipped, so the rest of the job's edges still land.
			log.Printf("[ObservationSink] %s edge skipped: %v", rel.Type, err)
			return nil
		}
		return fmt.Errorf("edge %s: resolving peer: %w", rel.Type, err)
	}

	// Belt and braces: neither end may be a zero ref by the time an edge is
	// written. An empty asset id reaches the database as a malformed uuid and
	// surfaces as a parse error naming nothing — the opaque failure this whole
	// path used to produce.
	if subject.Zero() || peer.Zero() {
		log.Printf("[ObservationSink] %s edge skipped: an end did not resolve to an asset", rel.Type)
		return nil
	}

	// Direction is the collector's, because only the collector knows which end
	// it was standing on. The reverse of a type is a LABEL, never a second type
	// (ADR-0003 D2), so an edge whose canonical direction runs towards the
	// subject is emitted as PeerToSubject rather than as a flipped type.
	from, to := subject, peer
	if rel.Direction == di.PeerToSubject {
		from, to = peer, subject
	}

	status, err := repo.EdgeStatusFor(ctx, tenantID.String(), source.Kind, from.ID, to.ID)
	if err != nil {
		return fmt.Errorf("edge %s: deciding status: %w", rel.Type, err)
	}

	err = repo.UpsertRelationship(ctx, tenantID.String(), pgidentity.Edge{
		FromAssetID: from.ID,
		ToAssetID:   to.ID,
		Type:        rel.Type,
		SourceKind:  source.Kind,
		SourceRef:   source.Ref,
		Status:      status,
		Attributes:  rel.Attributes,
		ObservedAt:  at,
	})
	if errors.Is(err, pgidentity.ErrSelfEdge) {
		// Both ends resolved to the same asset. The edge is not wrong so much
		// as meaningless — it means one host matched twice under two
		// identifiers — so it is logged as the identity signal it is and
		// dropped rather than failing the interrogation.
		log.Printf("[ObservationSink] %s edge from %s resolved to itself; dropped (the two ends are one asset)", rel.Type, from.ID)
		return nil
	}
	return err
}

// resolvePeer turns a collector's PeerRef into an asset, creating a pending one
// when it is nobody we know.
//
// This is what makes the map possible from an interrogation: a switch's LLDP
// neighbour is described only by a MAC and a system name, and the engine's job
// is to say whether that is a host already in the inventory or a new one. The
// peer goes to inventory-service as a sighting (peerSighting); what comes back
// is the asset the edge or fact lands on.
func (s *ObservationSink) resolvePeer(
	ctx context.Context,
	tenantID uuid.UUID,
	peer di.PeerRef,
	source identity.Source,
	at time.Time,
) (identity.AssetRef, error) {
	sighting, prop, err := s.peerSighting(ctx, tenantID, peer, source, at)
	if err != nil {
		return identity.AssetRef{}, err
	}
	state, _ := ctx.Value(peerContextKey{}).(*retainedPeerContext)
	if state != nil {
		if original, found := state.retainedPeer(peer); found {
			// The sighting exactly as first received, so a replay is the same
			// delivery (receipt, observed-at) rather than a new one.
			sighting = original
		}
	}
	// No FirstHand: a peer is described by somebody else. See [classIntent].
	res, _, err := s.resolveSightingWith(ctx, sighting, classIntent{Proposal: prop}, func(tx *sql.Tx, res identity.Resolution) error {
		return retainPeerContext(ctx, tx, tenantID, res)
	})
	if err != nil {
		return identity.AssetRef{}, err
	}
	if res.Asset.Zero() {
		if res.ObservationID != "" {
			return identity.AssetRef{}, retainedPeerOutcome(ctx, res)
		}
		// The identity floor: every identifier the collector gave for this peer
		// already belongs to some other asset and none of them may decide, so
		// the engine opened a merge proposal and created nothing.
		//
		// Returned as a NAMED error rather than an empty ref. The empty ref
		// flowed on into EdgeStatusFor and UpsertRelationship as an empty asset
		// id, and the operator was told "asset not found" — which is both wrong
		// and unactionable: the asset is not missing, it is contested, and there
		// is a proposal waiting that the message never mentioned.
		return identity.AssetRef{}, fmt.Errorf("%w: peer %s (merge proposal %s is waiting in Approvals)",
			errPeerContested, sightingLabel(sighting), res.Proposal.ID)
	}
	if state != nil && state.Replay {
		ready := false
		if err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM assets WHERE tenant_id=$1 AND id=$2 AND asset_status='monitoring' AND deleted_at IS NULL)`, tenantID, res.Asset.ID).Scan(&ready)
		}); err != nil {
			return identity.AssetRef{}, err
		}
		if !ready {
			return identity.AssetRef{}, retainedPeerOutcome(ctx, res)
		}
	}
	return res.Asset, nil
}

// sightingLabel names a sighting in a log line or an error.
func sightingLabel(s identity.Sighting) string {
	if s.DisplayName != "" {
		return s.DisplayName
	}
	if len(s.Identifiers) > 0 {
		return string(s.Identifiers[0].Kind) + "=" + s.Identifiers[0].Value
	}
	return "(no identifiers)"
}

// classOutcome is what the CLASS half of a resolution did, beside what the
// identity half did.
//
// It exists so a caller can report the truth rather than a constant. The
// host-inventory job row has carried a `class_applied` field since 2.11b and it
// was hard-coded false, because nothing could apply a class; now that something
// can, a field that still said false would be worse than the one that was
// honestly always false.
type classOutcome struct {
	// Promoted is true when the rules moved the asset off the unassigned
	// `unknown_host` / `external` floor. See [classproposal.Promote] for the
	// five guards that decide it.
	Promoted bool
}

// classIntent is the classifier's answer about an observation, plus what this
// intake is entitled to DO with it.
//
// # Why the entitlement is a field and not a constant
//
// The two intakes that classify through this sink hold evidence of different
// KINDS, and ADR-0002 D4's precedence is about exactly that difference:
//
//   - A host inventory is the subject's own account of itself, taken by an agent
//     running ON it or over an authenticated session TO it. There is no more
//     direct measurement in the product — hostSighting gives it confidence 1
//     for that reason — so a rule reading `os.name = Microsoft Windows 11 Pro`
//     off it may fill an asset's EMPTY class without asking anybody.
//   - A peer is DESCRIBED by a third party: a switch's LLDP neighbour table, a
//     controller's device list. It is hearsay, however well-formed, and the
//     device being described never spoke. A class from it is a proposal, on a
//     `unknown_host` asset as much as on any other.
//
// Collapsing the two would make the neighbour table's opinion as good as the
// machine's own, which is the mistake the mDNS reflector taught: a reflected
// advertisement reaching the inventory as a first-hand claim.
type classIntent struct {
	// Proposal is what the classifier argued. A zero value means "nothing
	// classified this", and both [classproposal.Record] and
	// [classproposal.Promote] write nothing for it.
	Proposal classify.ClassProposal

	// FirstHand says the evidence came from the SUBJECT ITSELF. Only a
	// first-hand intake may promote an asset off the unclassified floor.
	FirstHand bool
}

// resolveSightingWith posts one sighting to inventory-service, then — once the
// engine's decision is committed there — does the class work the resolution
// owes and the caller's own writes, in ONE transaction of this service's.
//
// Shared by the peer path and host inventory, which BUILD their sightings
// differently and must: a peer is described by identifiers and nothing else,
// while a host inventory carries the host's own sockets as endpoints and
// states its identity at first hand. What they share is the running of it.
//
// This is two transactions where it used to be one (the engine's, with the
// class proposal and the retained context inside it). The engine's half —
// asset, identifiers, endpoints, history, the tenant's auto-accept threshold,
// the retry on a racing identifier claim, the audit event for an auto-accepted
// merge — is inventory-service's and lands or does not. This half is
// idempotent and is retried by whatever retries the caller (the next
// interrogation, the agent's next report, the retained-context worker): a
// class proposal is recorded once per asset and class, a retained context
// once per id.
//
// A zero [classIntent] means "nothing classified this", and
// [classproposal.Record] writes nothing for it.
func (s *ObservationSink) resolveSightingWith(
	ctx context.Context,
	sighting identity.Sighting,
	intent classIntent,
	after ...func(*sql.Tx, identity.Resolution) error,
) (identity.Resolution, classOutcome, error) {
	_, res, err := postSighting(ctx, s.db, sighting)
	if err != nil {
		return identity.Resolution{}, classOutcome{}, err
	}
	tenantID, err := uuid.Parse(strings.TrimSpace(sighting.TenantID))
	if err != nil {
		return identity.Resolution{}, classOutcome{}, fmt.Errorf("sighting tenant %q is not a uuid: %w", sighting.TenantID, err)
	}
	var class classOutcome
	err = shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		var cErr error
		class, cErr = s.recordClassOutcome(ctx, tx, tenantID, res, intent)
		if cErr != nil {
			return cErr
		}
		for _, callback := range after {
			if err := callback(tx, res); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return res, classOutcome{}, err
	}
	return res, class, nil
}

// recordClassOutcome raises the class proposal an interrogated peer owes, on
// the engine's own transaction.
//
// # Why this exists (workstream 4.6a, closing a 2.10b/4.2 limit)
//
// applyPeerClassRules has always run the classifier over what a peer reference
// carries. What it could do with the answer was asymmetric: a RULE's class went
// onto a peer the engine was about to CREATE, and everything else was dropped —
// a class for an EXISTING peer, and any class the learned model proposed, were
// computed and thrown away, because this service had no proposal writer. The
// comment that said so called it follow-up work; this is the follow-up.
//
// The four "write nothing" cases are [classproposal.Record]'s and are shared
// with inventory-service's intake, so a peer classified here and the same host
// classified there produce the same row rather than two dialects of one.
//
// A resolution that wrote no asset — the identity floor's contested path —
// writes nothing: a proposal against an asset that does not exist is a queue
// item pointing at nothing.
//
// # Promote first, then propose
//
// [classproposal.Promote] runs before [classproposal.Record] and the order is
// the point. An EXISTING asset still on the unassigned floor gets the rules'
// class applied directly — nothing was ever decided about it, so there is
// nothing to review — and Record then sees a class equal to the proposal and
// correctly writes nothing. An asset holding a real class is left alone by
// Promote and gets a proposal from Record, which is what stops two measured
// classes flapping against each other on every observation.
//
// Running Record FIRST would raise a proposal and then immediately satisfy it,
// leaving a pending question in Approvals whose answer is already on the asset.
func (s *ObservationSink) recordClassOutcome(
	ctx context.Context,
	tx *sql.Tx,
	tenantID uuid.UUID,
	res identity.Resolution,
	intent classIntent,
) (classOutcome, error) {
	prop := intent.Proposal
	var out classOutcome
	if res.Asset.Zero() {
		return out, nil
	}
	if prop.Class == "" && !prop.Conflict {
		return out, nil
	}
	assetID, err := uuid.Parse(strings.TrimSpace(res.Asset.ID))
	if err != nil {
		return out, fmt.Errorf("class proposal: asset id %q is not a uuid: %w", res.Asset.ID, err)
	}

	// FIRST-HAND evidence only, and never on the CREATE path. On a create the
	// class is already on the asset — classproposal.Apply put it on the
	// observation — and the asset is in Approvals, so approving it approves the
	// class; promoting as well would write a second history row for one
	// decision, and one of them would claim a move from a class the asset never
	// held. For a peer, see [classIntent]: hearsay proposes, it does not decide.
	if intent.FirstHand && res.Outcome != identity.OutcomeCreated {
		promoted, pErr := classproposal.Promote(ctx, tx, tenantID, assetID, prop)
		if pErr != nil {
			return out, pErr
		}
		out.Promoted = promoted
	}

	return out, classproposal.Record(ctx, tx, tenantID, assetID, res.Outcome, prop)
}

// errPeerContested means a relationship's far end could not be resolved because
// every identifier it carries belongs to another asset. The edge is not
// attached; a human has a merge proposal to settle first.
var errPeerContested = errors.New("the peer's identity is contested, so the edge was not attached")

// errPeerSyntheticNamesOnly means a peer's only identifiers were names that are
// not identity (hostnamequality.IsIdentityName) or addresses that are not
// ( D2: temporary-shaped IPv6, unscopable link-local). Callers skip that
// peer's edge or fact and carry on, the way they treat a contested peer.
var errPeerSyntheticNamesOnly = errors.New("the peer carries only synthetic names or rotating addresses, which are not identifiers")

// applyPeerClassRules asks the classifier what a peer is, and returns its full
// answer so the caller can raise the proposal it owes.
//
// The evidence is what a peer reference carries. That used to be its MAC
// ADDRESSES and nothing else, which made the rules' honest answer `unknown_host`
// for almost every neighbour: an OUI names a manufacturer, and every
// manufacturer that matters makes switches, access points and phones alike. A
// device that had literally announced "I am a bridge and a router, I am a Cisco
// WS-C3750X" over LLDP came back unclassified, because the interrogators parsed
// that and then dropped it on the floor.
//
// It now carries the platform, the advertised software version and the LLDP/CDP
// capability bits as well (`di.PeerRef`), which are the fields the `pid`,
// `lldp_capabilities` and `cdp_capabilities` rules are written against. Still
// narrow, and deliberately: a peer is DESCRIBED, not measured, and the honest
// outcome for a peer that advertised nothing is still no class at all.
//
// Two halves, and they are different acts:
//
//  1. A RULE's class goes onto the observation, with `class_source_kind: rule`
//     and a `class_source_ref` naming the row, exactly as intake does on the
//     sensor path — so a reviewer reading two assets classified by the same rule
//     sees one provenance rather than two spellings of it. It only ever fills a
//     hint the COLLECTOR did not set: a ClassHint the collector set is a
//     conclusion it EARNED from the API it spoke, and a rule does not overrule a
//     measurement.
//  2. Everything else — a class for an existing peer, and any class the LEARNED
//     classifier proposed — is returned, not applied, and becomes a proposal in
//     Approvals (see [ObservationSink.recordClassOutcome]). A model PROPOSES; it
//     never sets a class. Applying one with `class_source_kind: rule` would be
//     false provenance on the field a reviewer audits, and applying it as
//     `inferred` would be a machine deciding — the thing ADR-0008 D3 exists to
//     stop.
//
// Until workstream 4.6a the second half was simply dropped: this service had no
// proposal writer, so a model's answer and a rule's answer about an EXISTING
// peer were both computed and discarded.
func (s *ObservationSink) applyPeerClassRules(ctx context.Context, peer di.PeerRef) classify.ClassProposal {
	var macs []string
	for _, id := range peer.Identifiers {
		if id.Kind == string(di.IdentifierMACAddress) {
			if v := strings.TrimSpace(id.Value); v != "" {
				macs = append(macs, v)
			}
		}
	}
	input := classify.ClassifyInput{
		MACs:  macs,
		Model: strings.TrimSpace(peer.Platform),
		// Not peer.ClassHint: a class hint is somebody's ANSWER, and feeding an
		// answer back in as evidence is how a guess becomes its own
		// corroboration.
		LLDPCapabilities: peer.LLDPCapabilities,
		CDPCapabilities:  peer.CDPCapabilities,
	}
	if input.Model == "" && len(macs) == 0 &&
		len(input.LLDPCapabilities) == 0 && len(input.CDPCapabilities) == 0 {
		// Nothing was advertised. Asking the engine about an empty input can
		// only produce an answer with no evidence behind it.
		return classify.ClassProposal{}
	}
	// Through the SEAM, like inventory-service's intake: the Classifier is
	// selectable and `Config{Classifier: "none"}` means "propose no class at
	// all", which a call site that names RuleClassifier itself cannot honour.
	// The seam's default chains the learned classifier beneath the rules, and
	// `CLASSIFIER_MODEL_ENABLED=false` turns that half off — leaving the rules
	// running, which is why the model is not a second control here.
	c := seams.ClassifierFor(s.seamSet(), s.classifier().Engine())
	out := seams.Explain(ctx, c, seams.ClassFacts(input))

	// Unknown stays unknown, and so does a conflict — but a CONFLICT is still
	// returned, because naming the classes that disagreed is how the catalogue
	// gets fixed rather than the asset guessed at. The caller applies a rule's
	// class to the sighting (applyClassToSighting).
	return out
}

// dhcpPosture is what an interrogated device said about DHCP on one of its
// networks. It is three-valued because the fact contract is: `dhcp_enabled` is
// optional on a net.vlans item, and only UniFi reports it today. A FortiGate
// subinterface or an F5 self-IP describes a network without saying whether
// anything hands out leases on it, and "unknown stays unknown" — absent is not
// false.
type dhcpPosture string

const (
	dhcpEnabled  dhcpPosture = "enabled"
	dhcpDisabled dhcpPosture = "disabled"
	dhcpUnknown  dhcpPosture = "unknown"
)

// segmentSourceInterrogation is the provenance a learned segment carries in
// `metadata.source`. The producing device is named beside it
// (`source_device_type`, `source_asset_id`) rather than in it, so the value a
// reader matches on does not change with the vendor.
const segmentSourceInterrogation = "interrogation"

// segmentSourceLegacyUniFi is what learned segments were labelled before any
// vendor but UniFi could produce one. Rows carrying it are still ours to
// refresh; no backfill rewrites them, the next interrogation of the same
// network relabels them.
const segmentSourceLegacyUniFi = "unifi"

type vlanSegmentSpec struct {
	CIDR        string
	Name        string
	DHCP        dhcpPosture
	NetworkType string
}

// vlanSegmentSpecs extracts cidr segments from a net.vlans fact.
//
// Any entry with a usable prefix is a segment, whichever vendor emitted it: a
// UniFi network, a FortiGate VLAN subinterface and an F5 self-IP all describe
// the same thing, a network the device has an address on. An entry without a
// prefix (a Cisco VLAN database row: id and name) is not a scope, and neither
// is a prefix that describes no network of hosts — see [segmentablePrefix].
func vlanSegmentSpecs(value any) []vlanSegmentSpec {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var entries []map[string]any
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil
	}
	var out []vlanSegmentSpec
	for _, e := range entries {
		subnet, _ := e["subnet"].(string)
		prefix, err := netip.ParsePrefix(strings.TrimSpace(subnet))
		if err != nil {
			continue
		}
		// Stored in the form ScopeForAddress compares against: it unmaps every
		// address, so a segment kept as ::ffff:10.0.0.0/120 would contain none.
		prefix, ok := sharednetwork.UnmapPrefix(prefix)
		if !ok || !segmentablePrefix(prefix) {
			continue
		}
		posture := dhcpUnknown
		if dhcp, ok := e["dhcp_enabled"].(bool); ok {
			posture = dhcpDisabled
			if dhcp {
				posture = dhcpEnabled
			}
		}
		name, _ := e["name"].(string)
		if strings.TrimSpace(name) == "" {
			name = prefix.String()
		}
		out = append(out, vlanSegmentSpec{
			CIDR:        prefix.String(),
			Name:        name,
			DHCP:        posture,
			NetworkType: sharednetwork.PrefixNetworkType(prefix),
		})
	}
	return out
}

// segmentablePrefix reports whether a masked, unmapped prefix describes a network of
// hosts. A host route (/32, /128) is one address, a default route is every
// address, and loopback, link-local and multicast space are not networks a
// tenant's devices are placed in — a segment over any of them would scope
// identities by something that is not where the host was standing.
func segmentablePrefix(p netip.Prefix) bool {
	a := p.Addr()
	if p.Bits() == 0 || p.Bits() >= a.BitLen() {
		return false
	}
	return !a.IsUnspecified() && !a.IsLoopback() && !a.IsLinkLocalUnicast() &&
		!a.IsMulticast() && !a.IsLinkLocalMulticast() && !a.IsInterfaceLocalMulticast()
}

// vlanSegmentMetadata is what a learned segment records about itself.
//
// It deliberately does NOT carry `dynamic`. The effective DHCP flag has three
// possible authors — an operator, a device that measured it, traffic that
// implied it — with a precedence between them, and that rule lives in exactly
// one place (pgidentity.RecordSegmentPosture). Writing the key here as well
// would be a second author outside the rule, able to overwrite an operator's
// answer with a measurement on any owned row. [ensureVLANSegments] states the
// posture through the shared helper after the row exists, and only when the
// device ANSWERED: an unknown posture is recorded as `dhcp: unknown` and
// nothing else. How identity treats an unknown is the reader's decision, and
// it is the conservative one in both places that read it:
// [vlanSegmentSpec.leaseScope] for this run, and ScopeForAddress
// (shared/identity/postgres) for every run after it.
func vlanSegmentMetadata(spec vlanSegmentSpec, deviceType, assetID string) map[string]any {
	meta := map[string]any{
		"source":          segmentSourceInterrogation,
		"source_asset_id": assetID,
		"dhcp":            string(spec.DHCP),
	}
	if deviceType != "" {
		meta["source_device_type"] = deviceType
	}
	return meta
}

// ensureVLANSegments creates, or refreshes, the cidr segments a device's
// net.vlans fact declares.
//
// Its ROWS are its own only when it created them. The INSERT does nothing on a
// CIDR that already exists, so an operator-declared segment keeps its name,
// type and metadata; the UPDATE refreshes only rows a previous interrogation
// created — under the current label or the legacy `unifi` one.
//
// The DHCP POSTURE is different, and it is written to the matching segment
// whatever created it ( C2). A controller that answered "this network
// hands out addresses" has measured a fact about the network, and an operator
// who drew the same CIDR by hand did not measure it — leaving their segment
// silent about DHCP is how every home network ended up with addresses still
// voting on identity. It goes through pgidentity.RecordSegmentPosture, which
// owns the precedence: the measurement never overwrites an operator's answer,
// it is recorded beside it and takes over if the operator withdraws theirs.
//
// An unknown posture never overwrites a known one: a UniFi controller that
// measured DHCP on a network and a firewall that routes the same network
// without knowing are not in disagreement, and the row keeps the answer.
// An unknown posture is not stated at all.
func (s *ObservationSink) ensureVLANSegments(ctx context.Context, tenantID, assetID uuid.UUID, value any) error {
	if s.db == nil {
		return nil
	}
	specs := vlanSegmentSpecs(value)
	if len(specs) == 0 {
		return nil
	}
	return shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		// The device the networks were learned from. Both interrogation paths
		// (in-cluster and agent) hand the sink the interrogated asset, so this
		// is read here once rather than threaded through each of them.
		var deviceType string
		if err := tx.QueryRowContext(ctx, `
			SELECT coalesce(metadata->>'device_type', '')
			FROM public.assets WHERE tenant_id = $1 AND id = $2`,
			tenantID, assetID).Scan(&deviceType); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("read source device type: %w", err)
		}
		for _, spec := range specs {
			metadata, err := json.Marshal(vlanSegmentMetadata(spec, deviceType, assetID.String()))
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO public.network_segments
					(tenant_id, name, segment_type, value, network_type, environment, is_active, metadata)
				VALUES ($1, $2, 'cidr', $3, $4, 'production'::public.environment_type, true, $5::jsonb)
				ON CONFLICT (tenant_id, value, coalesce(cloud_network_ref, ''::text)) DO NOTHING`,
				tenantID, spec.Name, spec.CIDR, spec.NetworkType, string(metadata)); err != nil {
				return fmt.Errorf("insert vlan segment %s: %w", spec.CIDR, err)
			}
			if _, err := tx.ExecContext(ctx, `
				UPDATE public.network_segments
				SET metadata = COALESCE(metadata, '{}'::jsonb) || $3::jsonb,
				    updated_at = now()
				WHERE tenant_id = $1 AND value = $2 AND segment_type = 'cidr'
				  AND metadata->>'source' IN ($4, $5)
				  AND coalesce(cloud_network_ref, '') = ''
				  AND NOT ($6::boolean AND metadata ? 'dynamic')`,
				tenantID, spec.CIDR, string(metadata),
				segmentSourceInterrogation, segmentSourceLegacyUniFi,
				spec.DHCP == dhcpUnknown); err != nil {
				return fmt.Errorf("update vlan segment %s: %w", spec.CIDR, err)
			}
			if spec.DHCP == dhcpUnknown {
				continue
			}
			var segmentID string
			if err := tx.QueryRowContext(ctx, `
				SELECT id::text FROM public.network_segments
				WHERE tenant_id = $1 AND value = $2 AND segment_type = 'cidr'
				  AND coalesce(cloud_network_ref, '') = ''`,
				tenantID, spec.CIDR).Scan(&segmentID); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					// The value is taken by a segment of another type (the
					// unique index ignores type). Identity never consults
					// such a segment by address, so there is no posture to state.
					continue
				}
				return fmt.Errorf("find vlan segment %s: %w", spec.CIDR, err)
			}
			if _, err := pgidentity.RecordSegmentPosture(ctx, tx, tenantID.String(), segmentID,
				pgidentity.PostureMeasured, spec.DHCP == dhcpEnabled,
				pgidentity.PostureEvidence{SourceAssetID: assetID.String(), ObservedAt: time.Now()}); err != nil {
				return fmt.Errorf("record dhcp posture for vlan segment %s: %w", spec.CIDR, err)
			}
		}
		return nil
	})
}
