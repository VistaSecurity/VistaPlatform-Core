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
//  2. **Resolve every subject and peer through the identification engine.**
//     A collector cannot resolve an asset — it describes a peer by identifiers
//     and the engine decides which asset that is, creating a pending one when
//     it is nobody we know. That is what turns "this firewall sees a neighbour
//     with MAC aa:bb:…" into a node on the map.
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
	"github.com/vistasecurity/vistaplatform/shared/identity/hostnamequality"
	"github.com/vistasecurity/vistaplatform/shared/identity/identityaudit"
	"github.com/vistasecurity/vistaplatform/shared/identity/identitysettings"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// InterrogationObservations is what an interrogation observed beyond its crypto
// assets: the hardware identity of the device itself, the registered ops facts,
// and the edges. It is the subset of the shared core's InterrogateResult that
// this sink persists, named separately because the agent path reconstructs it
// from a JSON payload rather than holding the core's type.
type InterrogationObservations struct {
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
// It owns its own identification engine rather than borrowing DeviceService's
// because both the agent result path (ResultProcessor) and the in-cluster path
// (DeviceInterrogationService) persist the same observations and neither owns
// the other.
type ObservationSink struct {
	db *sql.DB

	once sync.Once
	repo *pgidentity.Repository
	eng  *identity.Engine
	err  error

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

func (s *ObservationSink) engine() (*identity.Engine, *pgidentity.Repository, error) {
	s.once.Do(func() {
		s.repo = pgidentity.New(s.db)
		// AutoAcceptThreshold stays at zero HERE and is supplied PER
		// OBSERVATION by resolveObservationWith, from the tenant's own setting
		// (workstream 4.6a). The engine is built once per process and serves
		// every tenant, so a threshold fixed here would be one tenant's
		// decision applied to all of them.
		//
		// Before 4.6a it was zero for everybody, which meant a peer could never
		// be auto-merged whatever the tenant set. The four fences that govern
		// an auto-accept are [identity.Engine]'s and were never the gap; the
		// number was.
		s.eng, s.err = identity.New(identity.Config{Repo: s.repo})
	})
	return s.eng, s.repo, s.err
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
	engine, repo, err := s.engine()
	if err != nil {
		return fmt.Errorf("identification engine unavailable: %w", err)
	}

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

	at := time.Now().UTC()
	self := identity.AssetRef{TenantID: tenantID.String(), ID: assetID.String()}
	var errs []error

	// DHCP-backed VLANs must exist as cidr segments BEFORE peers are resolved,
	// so ScopeForAddress can mark lease IPs dynamic and they cannot vote.
	for _, f := range wrapped.Facts {
		if f.Key != facts.KeyNetVlans {
			continue
		}
		ctx = context.WithValue(ctx, observedDHCPKey{}, append(observedDHCP(ctx), vlanSegmentSpecs(f.Value)...))
		if err := s.ensureVLANSegments(ctx, tenantID, f.Value); err != nil {
			return fmt.Errorf("vlan segments: %w", err)
		}
	}

	if wrapped.DeviceIdentity != nil {
		if err := s.persistIdentity(ctx, repo, self, source, at, wrapped.DeviceIdentity); err != nil {
			errs = append(errs, err)
		}
	}

	// Facts, grouped by the asset they are ABOUT. An interrogation is not
	// always about one asset: a UniFi controller reports the interfaces, uptime
	// and serial of every device it manages, and attributing a switch's port
	// table to the controller would be a worse answer than not collecting it.
	bySubject := map[identity.AssetRef][]pgidentity.Fact{}
	for _, f := range wrapped.Facts {
		subject := self
		if !f.Subject.IsZero() {
			resolved, resolveErr := s.resolvePeer(ctx, engine, tenantID, f.Subject, source, at)
			if resolveErr != nil {
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
	}
	for subject, fs := range bySubject {
		if err := repo.UpsertFacts(ctx, subject, obs.producer(), fs); err != nil {
			errs = append(errs, fmt.Errorf("writing %d facts for asset %s: %w", len(fs), subject.ID, err))
		}
	}

	for _, rel := range wrapped.Relationships {
		if err := s.persistRelationship(ctx, engine, repo, tenantID, self, source, at, rel); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// persistIdentity records the hardware identity an interrogation measured.
//
// Vendor, model and firmware are FACTS with provenance — the same registered
// keys the collectors emit and the same keys the Devices form writes as
// declared, so the two land on one key with two sources and ADR-0002 D4 decides
// which shows. The serial is an IDENTIFIER, not a fact: it is how the asset is
// recognised, and `devices.serial_number` being a plain column is a large part
// of why an interrogated device and the same host seen elsewhere were two rows.
func (s *ObservationSink) persistIdentity(
	ctx context.Context,
	repo *pgidentity.Repository,
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
		err := repo.AttachIdentifiers(ctx, self, []identity.Identifier{{
			Kind:       identity.KindSerialNumber,
			Value:      serial,
			Confidence: 1,
			Source:     source,
			SeenAt:     at,
		}})
		switch {
		case errors.Is(err, identity.ErrIdentifierConflict):
			// The serial already belongs to another asset. That is a merge
			// question for a human — two assets claiming one serial is exactly
			// the conflict the Approvals queue exists for — and forcing it here
			// would be the auto-merge ADR-0002 D5 forbids.
			log.Printf("[ObservationSink] serial %q already belongs to another asset in tenant %s; not attached to %s",
				serial, self.TenantID, self.ID)
		case err != nil:
			errs = append(errs, fmt.Errorf("attaching serial: %w", err))
		}
	}
	return errors.Join(errs...)
}

// persistRelationship resolves an observed edge's two ends and writes it.
func (s *ObservationSink) persistRelationship(
	ctx context.Context,
	engine *identity.Engine,
	repo *pgidentity.Repository,
	tenantID uuid.UUID,
	self identity.AssetRef,
	source identity.Source,
	at time.Time,
	rel di.RelationshipObservation,
) error {
	subject := self
	if !rel.Subject.IsZero() {
		resolved, err := s.resolvePeer(ctx, engine, tenantID, rel.Subject, source, at)
		if err != nil {
			if errors.Is(err, errPeerContested) {
				log.Printf("[ObservationSink] %s edge skipped: subject %v", rel.Type, err)
				return nil
			}
			return fmt.Errorf("edge %s: resolving subject: %w", rel.Type, err)
		}
		subject = resolved
	}
	peer, err := s.resolvePeer(ctx, engine, tenantID, rel.Peer, source, at)
	if err != nil {
		if errors.Is(err, errPeerContested) {
			// Not a failure of the interrogation: one edge could not be
			// attached because a human has to settle who its far end is.
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
// is to say whether that is a host already in the inventory or a new one.
func (s *ObservationSink) resolvePeer(
	ctx context.Context,
	engine *identity.Engine,
	tenantID uuid.UUID,
	peer di.PeerRef,
	source identity.Source,
	at time.Time,
) (identity.AssetRef, error) {
	obs, prop, err := s.peerObservation(ctx, tenantID, peer, source, at)
	if err != nil {
		return identity.AssetRef{}, err
	}
	// No FirstHand: a peer is described by somebody else. See [classIntent].
	res, _, err := s.resolveObservationWith(ctx, engine, obs, classIntent{Proposal: prop})
	if err != nil {
		return identity.AssetRef{}, err
	}
	if res.Asset.Zero() {
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
			errPeerContested, observationLabel(obs), res.Proposal.ID)
	}
	return res.Asset, nil
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
//     direct measurement in the product — observationFor gives it confidence 1
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

// resolveObservationWith runs one fully-built observation through the engine, on
// the engine's own transaction, carrying the classifier's answer about the thing
// being resolved — and what this intake may do with it — so the class work it
// owes lands in the same transaction as the asset.
//
// Separated from resolvePeer because the two callers BUILD the observation
// differently and must: a peer a device reported is described by identifiers and
// nothing else, while a host inventory carries the host's own sockets as
// endpoints and states its identity at first hand. What they share is the
// running of it, including the one retry, and that is what lives here.
//
// A zero [classIntent] means "nothing classified this", and
// [classproposal.Record] writes nothing for it.
//
// The host-inventory path used to pass exactly that — it asked the rules and
// then recorded the answer on the job row instead of doing anything with it,
// because until 4.6a this service had no proposal writer. It has one now and
// that path passes a real proposal, which is what stopped a fully inventoried
// laptop from sitting at `unknown_host` for ever.
func (s *ObservationSink) resolveObservationWith(
	ctx context.Context,
	engine *identity.Engine,
	obs identity.Observation,
	intent classIntent,
) (identity.Resolution, classOutcome, error) {
	var res identity.Resolution
	var class classOutcome
	run := func() error {
		return s.repo.RunInTx(ctx, obs.TenantID, func(r *pgidentity.Repository) error {
			// The tenant's auto-accept threshold, read in THIS transaction and
			// on every observation (workstream 4.6a). See
			// identitysettings.ReadAutoAcceptThreshold for why it is neither
			// cached nor captured at construction, and why a failed READ is an
			// error rather than a silent fall back to "never".
			threshold, tErr := identitysettings.ReadAutoAcceptThresholdFor(ctx, r.Tx(), obs.TenantID)
			if tErr != nil {
				return tErr
			}

			var rErr error
			res, rErr = engine.WithAutoAcceptThreshold(threshold).WithRepository(r).Resolve(ctx, obs)
			if rErr != nil {
				return rErr
			}
			if intent.FirstHand && !res.Asset.Zero() && res.Outcome != identity.OutcomeConflict {
				if err := r.ProjectSegmentLocation(ctx, res.Asset, obs.Network.SegmentID, obs.Source); err != nil {
					return err
				}
			}
			// Reset per attempt. The retry below runs this whole closure a
			// second time against a different asset, and a `Promoted` left over
			// from the attempt that rolled back would be a promotion nothing
			// performed.
			class = classOutcome{}
			var cErr error
			class, cErr = s.recordClassOutcome(ctx, r, obs, res, intent)
			return cErr
		})
	}
	err := run()
	if errors.Is(err, identity.ErrIdentifierConflict) {
		// Another intake claimed one of the observation's identifiers between
		// our ownership read and our write. Resolving again matches the row it
		// committed, which is the answer that was true all along. Once, not in
		// a loop: a second conflict is a different fact.
		err = run()
	}
	if err != nil {
		return identity.Resolution{}, classOutcome{}, err
	}
	// AFTER the commit. An audit event announcing a merge that then rolled back
	// would be a record of something that did not happen. Writes nothing unless
	// the matcher actually accepted a merge on the tenant's behalf.
	identityaudit.LogAutoAcceptedMerge(ctx, autoAcceptAuditLogger(), obs, res)
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
	r *pgidentity.Repository,
	obs identity.Observation,
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
	tenantID, err := uuid.Parse(strings.TrimSpace(obs.TenantID))
	if err != nil {
		return out, fmt.Errorf("class proposal: tenant id %q is not a uuid: %w", obs.TenantID, err)
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
		promoted, pErr := classproposal.Promote(ctx, r.Tx(), tenantID, assetID, prop)
		if pErr != nil {
			return out, pErr
		}
		out.Promoted = promoted
	}

	return out, classproposal.Record(ctx, r.Tx(), tenantID, assetID, res.Outcome, prop)
}

// errPeerContested means a relationship's far end could not be resolved because
// every identifier it carries belongs to another asset. The edge is not
// attached; a human has a merge proposal to settle first.
var errPeerContested = errors.New("the peer's identity is contested, so the edge was not attached")

// peerObservation builds the observation for a peer a collector described.
//
// Note what is NOT set: no endpoints. A neighbour seen over LLDP or adopted by
// a controller has not been observed listening on anything — inventing an
// endpoint for it would be the phantom-TLS-endpoint mistake in a new place.
//
// The scope for its weak identifiers (hostname, ip_address) comes from the same
// resolver every other intake uses, so a neighbour a switch reports and the
// same host the sensor sees land in one scope and therefore on one asset. It is
// a method rather than a free function precisely so that resolution has a
// context and a database to do it with.
func (s *ObservationSink) peerObservation(ctx context.Context, tenantID uuid.UUID, peer di.PeerRef, source identity.Source, at time.Time) (identity.Observation, classify.ClassProposal, error) {
	scope, dynamicScope := s.scopeFor(ctx, tenantID, peer)
	if addr, err := netip.ParseAddr(peer.Identifier(di.IdentifierIPAddress)); err == nil {
		for _, segment := range observedDHCP(ctx) {
			prefix, err := netip.ParsePrefix(segment.CIDR)
			if err == nil && segment.Dynamic && prefix.Contains(addr.Unmap()) {
				dynamicScope = true
			}
		}
	}
	obs := identity.Observation{
		TenantID:    tenantID.String(),
		ClassHint:   peer.ClassHint,
		Source:      source,
		ObservedAt:  at,
		DisplayName: strings.TrimSpace(peer.DisplayName),
		// A peer of the tenant's own device, on the tenant's own network.
		Network: identity.Network{Ownership: identity.OwnershipInternal},
		// The collector observed the peer indirectly — the device told us about
		// it. That is a real measurement, but not one we took ourselves, so it
		// does not claim the full confidence of the device's own reading.
		Confidence: 0.8,
	}
	obs.Network.SegmentID = scope
	if dynamicScope {
		obs.DynamicScopes = map[string]bool{scope: true}
	}
	for _, id := range peer.Identifiers {
		kind := identity.Kind(id.Kind)
		if !kind.Valid() {
			// The collector vocabulary is pinned to identity's by
			// TestPeerIdentifierKindsMatchIdentityRegistry, so this is
			// unreachable today and is the loud failure if that ever drifts.
			return identity.Observation{}, classify.ClassProposal{}, fmt.Errorf("peer identifier kind %q is not one of the nine", id.Kind)
		}
		if kind == identity.KindHostname && strings.Contains(strings.TrimSuffix(id.Value, "."), ".") {
			// A dotted name is usually an FQDN — except `.local`, which is
			// link-scoped (RFC 6762 §3). Filing those as unscoped FQDNs is the
			// mDNS reflector merge: a gateway that reflected a laptop's
			// announcement absorbed the laptop by name. Keep `.local` as a
			// scoped hostname, the same rule host-observation ingest uses.
			if !hostnamequality.IsMDNSLocalName(id.Value) {
				kind = identity.KindFQDN
			}
		}
		// hostname and ip_address identify only WITHIN a scope; the other kinds
		// a collector can report about a peer are globally unique, and a scope
		// on one is rejected outright because it would split the uniqueness key.
		identifierScope := ""
		if kind == identity.KindHostname || kind == identity.KindIPAddress {
			identifierScope = scope
		}
		obs.Identifiers = append(obs.Identifiers, identity.Identifier{
			Kind: kind, Value: id.Value, Scope: identifierScope, Confidence: 1,
		})
	}
	var names []string
	if obs.DisplayName != "" {
		names = append(names, obs.DisplayName)
	}
	for _, id := range obs.Identifiers {
		if id.Kind == identity.KindHostname || id.Kind == identity.KindFQDN {
			names = append(names, id.Value)
		}
	}
	if d := hostnamequality.Best(names...); d != "" {
		obs.DisplayName = d
	}
	if h := hostnamequality.BestHostname(peerIdentifierNames(obs.Identifiers)...); h != "" {
		obs.Hostname = strings.ToLower(h)
	}

	// A peer the COLLECTOR could not class — an LLDP neighbour that advertised
	// nothing but a chassis MAC — still has evidence: the OUI. The collectors
	// cannot use the curated table (they run in the agent, which has no
	// database), so this is where an admin's rule reaches a neighbour.
	//
	// It never overrules the collector. A ClassHint the collector set is a
	// conclusion it EARNED from the API it spoke, and applyPeerClassRules fills
	// only an absent one.
	prop := s.applyPeerClassRules(ctx, &obs, peer)

	clean, rejected := obs.Sanitize()
	for _, r := range rejected {
		log.Printf("[ObservationSink] peer %q dropped a %s identifier: %v", obs.DisplayName, r.Identifier.Kind, r.Err)
	}
	if len(clean.Identifiers) == 0 {
		// AddRelationship already refuses a peer with no identifier, so this is
		// the case where every identifier it had failed normalisation here. An
		// identifier-less asset can never be recognised again, so creating one
		// would mint a duplicate on every run.
		return identity.Observation{}, classify.ClassProposal{}, fmt.Errorf("peer %q carries no usable identifier", obs.DisplayName)
	}
	return clean, prop, nil
}

// scopeFor resolves the network segment a peer's address falls in, which is the
// scope its hostname and IP identify within (ADR-0002 D3).
//
// It is the one place in this file that asks the question, so that when the
// resolver moves — the shared `ScopeForAddress` the identity layer is growing —
// there is a single call site to move rather than one per identifier.
func (s *ObservationSink) scopeFor(ctx context.Context, tenantID uuid.UUID, peer di.PeerRef) (string, bool) {
	ip := peer.Identifier(di.IdentifierIPAddress)
	hostname := peer.Identifier(di.IdentifierHostname)
	if hostname == "" {
		hostname = peer.Identifier(di.IdentifierFQDN)
	}
	_, repo, err := s.engine()
	if err != nil {
		repo = nil
	}
	return newDeviceScopeResolver(s.db, repo).segmentScope(ctx, tenantID, ip, hostname, "")
}

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
func (s *ObservationSink) applyPeerClassRules(ctx context.Context, obs *identity.Observation, peer di.PeerRef) classify.ClassProposal {
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
	// gets fixed rather than the asset guessed at.
	classproposal.Apply(obs, out)
	return out
}

type observedDHCPKey struct{}

func observedDHCP(ctx context.Context) []vlanSegmentSpec {
	specs, _ := ctx.Value(observedDHCPKey{}).([]vlanSegmentSpec)
	return specs
}

type vlanSegmentSpec struct {
	CIDR    string
	Name    string
	Dynamic bool
}

// vlanSegmentSpecs extracts cidr segments from a net.vlans fact. Only entries
// that declare dhcp_enabled are UniFi-style networks with DHCP posture; a
// Cisco VLAN id with no prefix is not a scope.
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
		dhcp, hasDHCP := e["dhcp_enabled"].(bool)
		if !hasDHCP {
			continue
		}
		subnet, _ := e["subnet"].(string)
		prefix, err := netip.ParsePrefix(strings.TrimSpace(subnet))
		if err != nil {
			continue
		}
		name, _ := e["name"].(string)
		if strings.TrimSpace(name) == "" {
			name = prefix.Masked().String()
		}
		out = append(out, vlanSegmentSpec{
			CIDR:    prefix.Masked().String(),
			Name:    name,
			Dynamic: dhcp,
		})
	}
	return out
}

func (s *ObservationSink) ensureVLANSegments(ctx context.Context, tenantID uuid.UUID, value any) error {
	if s.db == nil {
		return nil
	}
	specs := vlanSegmentSpecs(value)
	if len(specs) == 0 {
		return nil
	}
	return shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		for _, spec := range specs {
			metadata, err := json.Marshal(map[string]any{
				"dynamic": spec.Dynamic,
				"source":  "unifi",
			})
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO public.network_segments
					(tenant_id, name, segment_type, value, network_type, environment, is_active, metadata)
				VALUES ($1, $2, 'cidr', $3, 'private', 'production'::public.environment_type, true, $4::jsonb)
				ON CONFLICT (tenant_id, value, coalesce(cloud_network_ref, ''::text)) DO NOTHING`,
				tenantID, spec.Name, spec.CIDR, string(metadata)); err != nil {
				return fmt.Errorf("insert vlan segment %s: %w", spec.CIDR, err)
			}
			if _, err := tx.ExecContext(ctx, `
				UPDATE public.network_segments
				SET metadata = COALESCE(metadata, '{}'::jsonb) || $3::jsonb,
				    updated_at = now()
				WHERE tenant_id = $1 AND value = $2 AND segment_type = 'cidr'
				  AND metadata->>'source' = 'unifi' AND coalesce(cloud_network_ref, '') = ''`,
				tenantID, spec.CIDR, string(metadata)); err != nil {
				return fmt.Errorf("update vlan segment %s: %w", spec.CIDR, err)
			}
		}
		return nil
	})
}

func peerIdentifierNames(ids []identity.Identifier) []string {
	var names []string
	for _, id := range ids {
		if id.Kind == identity.KindHostname || id.Kind == identity.KindFQDN {
			names = append(names, id.Value)
		}
	}
	return names
}
