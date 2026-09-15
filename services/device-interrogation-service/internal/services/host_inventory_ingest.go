package services

// The host-inventory consumer (asset-inventory workstream 2.11b).
//
// 2.11a built the collector, both transports, the agent's job type and the
// platform's intake, and then HELD the result: a completed `device_jobs` row
// with the whole payload on it and nothing materialised. This file lifts that
// hold.
//
// # Why it is a separate builder rather than a branch in the crypto path
//
// The hold existed because a host-inventory result handed to the ordinary
// discovery pipeline produces junk, and it produces it confidently: a discovery
// finding per listening socket, a `127.0.0.1` endpoint routed to
// `external_connections` because the classifier reads addresses, and a fresh
// nameless asset on every collection because nothing in that path can match on
// an agent id. None of those is a bug in the pipeline — it is a pipeline for
// crypto findings, and a host inventory is not one.
//
// What a host inventory IS, in the phase-1 model, is four things:
//
//	identity    → asset_identifiers, through the identification engine
//	facts       → asset_facts, under the `device-agent` producer
//	sockets     → asset_endpoints, one per listening socket
//	packages    → software_products + software_installs, source_kind `measured`
//
// Each of those already has a writer. This file is the mapping, and almost all
// of its length is the reasons for the choices in it.
//
// # Three things it must not do
//
//  1. **Never guess a class.** An OS name and a hardware model are evidence,
//     and turning evidence into a class is a RULE's job (ADR-0004 D6's curated
//     table). The seam is asked — see classProposal — and the answer is
//     RECORDED rather than applied, because writing a rule's answer as the
//     asset's class with `class_source_kind: measured` would state a
//     measurement nobody took. Workstream 2.10b is where a proposal becomes a
//     proposal properly; until then the class is `unknown_host`, which is
//     coarse and true.
//  2. **Never retire what a failed step did not see.** Both sweeps here —
//     installs absent from the package list, endpoints absent from the socket
//     list — mark everything the current run did not touch. Run either after a
//     FAILED step and a host whose `dpkg` or `ss` was unreadable reports its
//     entire software inventory as uninstalled, or every service on it as
//     stopped. Each is guarded twice: the section must have SUCCEEDED, and the
//     resulting list must have ARRIVED — the counts travel as facts while the
//     lists travel in other fields, and they are lost independently. See
//     softwareListArrived and listenerListArrived.
//  3. **Never attribute a fact to the wrong asset.** Every fact in a host
//     inventory is about the host; a fact arriving with some OTHER subject
//     means the payload was assembled by something this code does not
//     understand, and it is refused rather than folded onto the host.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/hostinventory"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/software"
	swpostgres "github.com/vistasecurity/vistaplatform/shared/software/postgres"
)

// HostInventoryCounts is what one collection actually wrote.
//
// Every number is reported separately rather than rolled into a single
// "materialised N". "1 asset, 14 facts, 18 endpoints, 412 installs created,
// 6 removed" is a sentence an operator can reconcile against the host in front
// of them; "451 materialised" is not. It is the same reason the SBOM upload
// reports its counts the way it does, and the reason the held run reported
// `materialized: 0` rather than nothing at all.
type HostInventoryCounts struct {
	// AssetID is the asset the report landed on, empty when none did.
	AssetID string `json:"asset_id,omitempty"`
	// AssetCreated distinguishes a host we have never seen from one we have.
	AssetCreated bool `json:"asset_created"`
	// Contested means the engine could not settle which asset this is and
	// opened a MERGE PROPOSAL instead — a singleton identifier disagreed with
	// the asset it matched, or two kinds matched two assets. It is not a
	// failure of the collection: a human has a question to settle, and the
	// reason says which question.
	//
	// AssetID may still be set: when the report carries an identifier nobody
	// owns, the engine creates the observation as its own pending asset beside
	// the proposal, and this run's facts belong on that one until the proposal
	// is settled. When every identifier is already claimed, nothing is created
	// and AssetID is empty.
	Contested       bool   `json:"contested,omitempty"`
	ContestedReason string `json:"contested_reason,omitempty"`

	Identifiers int `json:"identifiers"`
	Facts       int `json:"facts"`
	Endpoints   int `json:"endpoints"`
	// EndpointsClosed is how many of this agent's previously-recorded sockets
	// were absent from this collection and are therefore no longer listening.
	// `closed`, never deleted — the row keeps its first_seen_at and last_seen_at
	// so "this host was serving 8080 in March and stopped" stays answerable, and
	// crypto configurations, external connections and ssh keys all point at
	// endpoint rows.
	EndpointsClosed int `json:"endpoints_closed"`

	// PackagesEnumerated is what the collector counted, and it is present only
	// when the package step SUCCEEDED. Nil means the step failed or did not
	// run, which is why no install was written and no absent-install sweep ran.
	PackagesEnumerated *int `json:"packages_enumerated,omitempty"`
	ProductsCreated    int  `json:"products_created"`
	ProductsMatched    int  `json:"products_matched"`
	InstallsCreated    int  `json:"installs_created"`
	InstallsUpdated    int  `json:"installs_updated"`
	InstallsRemoved    int  `json:"installs_removed"`
	// InstallsActive is what `sw.package_count` was written from: the number of
	// rows an inventory query would return, which is not always the number the
	// collector enumerated (an entry with no usable name is dropped).
	InstallsActive int `json:"installs_active"`

	// ClassProposal is what the Classifier seam made of the host's vendor and
	// model, and ClassApplied says whether it was USED. It is false today, on
	// purpose: see the file header.
	ClassProposal string `json:"class_proposal,omitempty"`
	ClassApplied  bool   `json:"class_applied"`

	// Errors are the things that went wrong without losing the collection. One
	// unregistered fact must not cost a host its package list.
	Errors []string `json:"errors,omitempty"`
}

// Materialized is the headline the job row shows: how many ASSETS this run put
// into the inventory. One, or none.
//
// Deliberately not a sum of the parts. "451" would read as 451 assets to
// anybody scanning the Job Logs, and the thing a host inventory materialises is
// one host.
func (c HostInventoryCounts) Materialized() int {
	if c.AssetID == "" {
		return 0
	}
	return 1
}

// FullyMaterialized is the "nothing to see here" claim, and it is hard to make:
// an asset landed, nothing errored, and the identity was not contested.
func (c HostInventoryCounts) FullyMaterialized() bool {
	return c.AssetID != "" && !c.Contested && len(c.Errors) == 0
}

// HostInventoryIngest materialises a host-inventory result.
//
// It holds an ObservationSink rather than duplicating its pieces because the
// sink already owns the identification engine, the fact writer and the segment
// resolver, and because BOTH paths into this file — the local intake handler
// and the result processor — need the same one.
type HostInventoryIngest struct {
	db *sql.DB
	// bypassDB writes the processing summary back onto the job row. That write
	// is keyed by job id and carries no tenant in context, which is the same
	// reason the rest of the finalize path runs on the bypass handle.
	bypassDB *sql.DB
	sink     *ObservationSink
}

// NewHostInventoryIngest builds the consumer. db is the RLS-scoped connection
// everything this file writes goes through; bypassDB is only for the job row's
// own processing summary.
func NewHostInventoryIngest(db, bypassDB *sql.DB) *HostInventoryIngest {
	return &HostInventoryIngest{db: db, bypassDB: bypassDB, sink: NewObservationSink(db)}
}

// MaterialiseAndRecord materialises a collection and writes what it did onto
// the job row.
//
// Both doors into this consumer use it — the local intake handler, which
// created the job row itself, and the result processor, which is finalising a
// remote job — so a run's counts are recorded the same way whichever mode it
// came from, and the Job Logs line reads the same.
//
// The error is returned as well as recorded. A caller that owns the job's
// status (the result processor) must fail the job; a caller that has already
// answered the agent (the intake) has only the row to say it on.
func (h *HostInventoryIngest) MaterialiseAndRecord(
	ctx context.Context,
	tenantID, agentID, jobID uuid.UUID,
	obs *di.InterrogateResult,
) (HostInventoryCounts, error) {
	counts, err := h.Materialise(ctx, tenantID, agentID, jobID, obs)

	steps := &ProcessingLog{HostInventory: &counts}
	if obs != nil {
		steps.AssetsReceived = len(obs.Assets)
	}
	if err != nil {
		// Fatal rather than a failed step: nothing per-asset was attempted, so
		// no step failed, and without it the summary would be all-zero and
		// indistinguishable from "there was nothing to do".
		steps.Fatal = err.Error()
	}
	if persistErr := steps.persist(ctx, h.bypassDB, jobID); persistErr != nil {
		log.Printf("[HostInventory] job %s: failed to record the processing summary: %v", jobID, persistErr)
	}
	return counts, err
}

// There are TWO source refs, and the difference between them is load-bearing.
//
// `asset_facts` is unique on (tenant, asset, key, source_ref), so a fact keyed
// on the RUN would leave one stale row per collection, each claiming a value
// that was true once — the same mistake the SBOM path avoids by keying its
// package-count fact on the constant "sbom" rather than the upload id. Facts
// therefore key on the AGENT: one row per (asset, key, agent), this agent's
// current answer, replaced each time it speaks.
//
// `software_installs` needs the opposite. Its absent-install sweep works by
// marking every row whose source_ref is not THIS run's, which is what makes a
// package that has been uninstalled go `removed` without a second bookkeeping
// table — and a stable ref makes that test vacuously false, so nothing is ever
// swept and a host's software list only ever grows. (That is exactly what the
// first cut of this file did, and the second-collection test caught it.) The
// install ref therefore names the run, which is what shared/software's
// `Install.SourceRef` documents it as: "the SBOM document's serial number, the
// agent job id".
//
// Both keep the `agent:` producer prefix, because `identity.Source.Producer()`
// reads everything before the first colon and an approval rule filters on it.
//
// The job fallback in the fact ref should be unreachable — `valid_job_
// assignment` requires an agent for a host_inventory job — and is spelled out
// rather than left to produce an empty ref, because a source with no producer
// cannot be audited, reconciled or filtered, and all three are the point.
func hostInventorySourceRef(agentID, jobID uuid.UUID) string {
	if agentID != uuid.Nil {
		return "agent:" + agentID.String()
	}
	return "agent:job:" + jobID.String()
}

// hostInventoryRunRef names this collection, for the install sweep. See above.
func hostInventoryRunRef(agentID, jobID uuid.UUID) string {
	return hostInventorySourceRef(agentID, jobID) + ":" + jobID.String()
}

// hostInventorySource is the provenance of everything this run writes.
//
// MEASURED and ACTIVE: the platform went and took this reading, either as the
// agent installed on the host or over an authenticated SSH session to it. That
// outranks a passive observation in ADR-0002 D4's precedence, which is correct
// — a host's own account of its packages beats anything inferred from traffic.
func hostInventorySource(agentID, jobID uuid.UUID) identity.Source {
	return identity.Source{
		Kind: identity.SourceMeasured,
		Ref:  hostInventorySourceRef(agentID, jobID),
		Mode: identity.ModeActive,
	}
}

// Materialise turns one host-inventory collection into inventory.
//
// `obs` is the SANITISED observations half of the submission — the half that
// went through di.Sanitize at the collector and again at the intake, and the
// half that carries the package list since the report's duplicate copy was
// dropped from the wire. The report itself is not needed here: everything this
// consumer reads is either a registered fact, an endpoint, or a value in the
// observations' own metadata block.
//
// The error return is for a failure that lost the whole collection. Anything
// smaller is counted in Errors and the rest of the run still lands: losing the
// package list because one fact key was unregistered would be a worse answer
// than a partial one honestly reported.
func (h *HostInventoryIngest) Materialise(
	ctx context.Context,
	tenantID, agentID, jobID uuid.UUID,
	obs *di.InterrogateResult,
) (HostInventoryCounts, error) {
	counts := HostInventoryCounts{}
	if obs == nil {
		return counts, fmt.Errorf("host inventory: no observations to materialise")
	}

	// Defence in depth. The agent sanitised this, and the intake sanitised it
	// again; doing it once more here costs one pass and removes the assumption
	// that the row in device_jobs was written by the version of the intake we
	// think it was. "Collect posture, never key material" is not a promise we
	// delegate to a process we cannot see.
	di.Sanitize(obs)

	meta := hostInventoryMeta(obs)
	source := hostInventorySource(agentID, jobID)

	subject, ok := hostInventorySubject(obs)
	if !ok {
		return counts, fmt.Errorf("host inventory: the observations carry no subject, so there is nothing to bind them to")
	}

	observation, err := h.observationFor(ctx, tenantID, subject, meta, obs, source, hostInventoryRunRef(agentID, jobID))
	if err != nil {
		return counts, err
	}
	counts.Identifiers = len(observation.Identifiers)
	counts.Endpoints = len(observation.Endpoints)

	engine, _, err := h.sink.engine()
	if err != nil {
		return counts, fmt.Errorf("host inventory: identification engine unavailable: %w", err)
	}

	res, err := h.sink.resolveObservation(ctx, engine, observation)
	if err != nil {
		return counts, fmt.Errorf("host inventory: resolving %s: %w", meta.label(), err)
	}
	// A CONFLICT is not a failure and it is not a success. It is the engine
	// saying two things that share an identifier are two things, which is the
	// answer ADR-0002 D5 requires rather than an auto-merge.
	//
	// It is the outcome a report whose agent id matches one asset while its
	// SERIAL disagrees produces: agent_id and serial_number are both SINGLETON
	// kinds, and two different serials are two different chassis whatever else
	// they share. The engine opens a merge proposal and — when the observation
	// still carries an identifier nobody owns — creates the observation as its
	// own pending asset, which is where this run's facts belong until a human
	// settles which machine it is.
	if res.Outcome == identity.OutcomeConflict {
		counts.Contested = true
		counts.ContestedReason = fmt.Sprintf(
			"an identifier %s carries disagrees with the asset it matched, or is already claimed by another; merge proposal %s is waiting in Approvals",
			meta.label(), res.Proposal.ID)
		log.Printf("[HostInventory] %s: %s", meta.label(), counts.ContestedReason)
	}

	if res.Asset.Zero() {
		// The identity floor: EVERY identifier the report carries is owned by
		// somebody else and none of them may decide, so the engine opened a
		// proposal and created nothing. There is no asset to hang facts,
		// endpoints or installs on, and inventing one would be the
		// identifier-less asset the floor exists to prevent.
		//
		// Both counts go to zero, and Identifiers matters as much as Endpoints:
		// they are what this run WROTE, not what the report offered, and a job
		// row reading "5 identifiers" for a run that created nothing invites
		// somebody to go looking for rows that are not there. What the report
		// carried is still recoverable — the whole payload is on the row.
		counts.Identifiers = 0
		counts.Endpoints = 0
		return counts, nil
	}

	counts.AssetID = res.Asset.ID
	counts.AssetCreated = res.Outcome == identity.OutcomeCreated

	assetID, err := uuid.Parse(res.Asset.ID)
	if err != nil {
		return counts, fmt.Errorf("host inventory: identification engine returned an unusable asset id %q: %w", res.Asset.ID, err)
	}

	// --- facts --------------------------------------------------------------
	//
	// sw.package_count is held back and rewritten below from the rows that
	// actually landed; see refreshPackageCount.
	factObs, enumerated, rejected := hostInventoryFacts(obs, subject)
	counts.PackagesEnumerated = enumerated
	counts.Errors = append(counts.Errors, rejected...)
	if len(factObs) > 0 {
		// No DeviceIdentity. Its four values (vendor, model, firmware, os
		// version) are ALREADY registered facts in this payload, emitted by the
		// collector under the keys the registry lists for them, and its serial
		// is already an identifier on the subject the engine just resolved.
		// Passing it as well would write the same values a second time under a
		// second confidence, which is two opinions about one measurement.
		err := h.sink.Persist(ctx, tenantID, assetID, source, InterrogationObservations{
			Facts:    factObs,
			Producer: facts.ProducerDeviceAgent,
		})
		if err != nil {
			counts.Errors = append(counts.Errors, fmt.Sprintf("writing facts: %v", err))
		} else {
			counts.Facts = len(factObs)
		}
	}

	// --- software -----------------------------------------------------------
	//
	// Two gates, not one, and they guard different failures. `enumerated != nil`
	// says the package STEP succeeded; softwareListArrived says the resulting
	// LIST is actually in this payload. See its doc for why the first alone is
	// not enough.
	products := hostInventoryProducts(obs)
	if enumerated != nil {
		if reason, ok := softwareListArrived(*enumerated, len(products)); !ok {
			counts.Errors = append(counts.Errors, reason)
		} else if err := h.writeSoftware(ctx, tenantID, assetID, hostInventoryRunRef(agentID, jobID), source.Ref, products, &counts); err != nil {
			counts.Errors = append(counts.Errors, fmt.Sprintf("writing software installs: %v", err))
		}
	}

	// --- endpoint retirement ------------------------------------------------
	//
	// Same two-gate discipline as the software sweep, for the same reason: a
	// report is a complete statement about this host's sockets only when the
	// listeners step SUCCEEDED and its list actually arrived.
	if reason, ok := listenerListArrived(
		meta.Sections[hostinventory.SectionListeners],
		hasFact(obs, facts.KeySvcListeningSockets),
		len(observation.Endpoints),
	); !ok {
		if reason != "" {
			counts.Errors = append(counts.Errors, reason)
		}
	} else if closed, err := h.closeAbsentEndpoints(ctx, tenantID, assetID,
		hostInventorySourceRef(agentID, jobID)+":", hostInventoryRunRef(agentID, jobID)); err != nil {
		counts.Errors = append(counts.Errors, fmt.Sprintf("closing absent endpoints: %v", err))
	} else {
		counts.EndpointsClosed = closed
	}

	// --- class proposal -----------------------------------------------------
	counts.ClassProposal = classProposal(ctx, obs)

	log.Printf("[HostInventory] %s → asset %s (created=%t): %d identifiers, %d facts, %d endpoints (-%d closed), installs +%d ~%d -%d",
		meta.label(), counts.AssetID, counts.AssetCreated,
		counts.Identifiers, counts.Facts, counts.Endpoints, counts.EndpointsClosed,
		counts.InstallsCreated, counts.InstallsUpdated, counts.InstallsRemoved)
	return counts, nil
}

// ---------------------------------------------------------------------------
// endpoint retirement
// ---------------------------------------------------------------------------

// listenerListArrived decides whether this collection may retire endpoints, and
// says why not when it may not.
//
// A host inventory is the only source that can answer "what is this machine
// listening on" completely — it reads the host's own socket table rather than
// whatever answered a scan — so a socket ABSENT from a good report has stopped
// listening. That is what licenses closing it, and it is also why the licence
// has to be checked rather than assumed.
//
// Two gates, mirroring the software sweep exactly:
//
//  1. **The step succeeded.** A host whose `ss` could not be run reports
//     `listeners: failed` and an empty list. Closing on that would report every
//     service on the machine as stopped because one command was unavailable.
//     The section outcome is read from the collector's own metadata block and
//     not inferred from the list being empty, which is the same claim.
//  2. **The list arrived.** `svc.listening_sockets` is emitted only when the
//     step succeeded AND found at least one socket, so the fact being present
//     while no endpoint reached us means the sockets were lost in transit — the
//     endpoints and the facts travel in different halves of the submission, as
//     the package list does. Closing then would retire a host's whole surface
//     on a transport gap.
//
// A successful step that found NOTHING is a real answer and does license the
// sweep: the fact is absent, no endpoint arrives, and every previously-known
// socket is closed, which is exactly what "this host stopped serving" looks
// like. That is the case the first gate has to be read carefully to permit — it
// is indistinguishable from gate 2's failure on the list alone, and only the
// section outcome separates them.
//
// An empty reason with ok=false means "no licence, and nothing went wrong":
// a failed or absent listeners section is a normal outcome and must not be
// reported as an error on the job row.
func listenerListArrived(section string, sawSocketsFact bool, arrived int) (reason string, ok bool) {
	if section != hostinventory.SectionOK {
		return "", false
	}
	if sawSocketsFact && arrived == 0 {
		return "the collector reported listening sockets but none reached the endpoint builder; " +
			"the list did not arrive, so no endpoint was retired " +
			"(closing them would report every service on this host as stopped)", false
	}
	return "", true
}

// hasFact reports whether a registered key is present in the payload.
func hasFact(obs *di.InterrogateResult, key string) bool {
	for _, f := range obs.Facts {
		if f.Key == key {
			return true
		}
	}
	return false
}

// closeAbsentEndpoints marks this agent's previously-recorded sockets that the
// current collection did not report as `closed`, and returns how many.
//
// Three things it is careful about:
//
//   - **Only THIS agent's rows.** The scope is `source_ref` starting with
//     `agent:<agent id>:`, so an endpoint a network scan or a cloud connector
//     recorded is untouched. A host inventory is authoritative about the
//     sockets the host is listening on; it is not authoritative about an
//     endpoint some other source observed, and closing those would let one
//     source silently overrule every other. `starts_with` rather than LIKE so
//     no value can be read as a pattern.
//   - **`closed`, never DELETE.** `crypto_implementations.endpoint_id`,
//     `external_connections.source_endpoint_id` and `ssh_keys.endpoint_id` all
//     point at these rows, and the history is the point besides: the row keeps
//     its first_seen_at and its last_seen_at, so "this host was serving 8080 in
//     March and stopped" stays answerable. A socket that comes back is upserted
//     straight back to `active`.
//   - **last_seen_at is left alone.** It records when the endpoint was last
//     SEEN, and this run did not see it. Bumping it would say the opposite of
//     what just happened.
//
// Its own transaction rather than the engine's: the engine's has already
// committed the endpoints this run observed by the time we know which rows are
// absent. The window between them can only show an old socket still `active`,
// which is the state it was in a moment earlier anyway.
func (h *HostInventoryIngest) closeAbsentEndpoints(
	ctx context.Context, tenantID, assetID uuid.UUID, agentPrefix, runRef string,
) (int, error) {
	var closed int
	err := shareddatabase.WithTenantTx(ctx, h.db, tenantID, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE asset_endpoints
			   SET status = 'closed', updated_at = now()
			 WHERE tenant_id = $1
			   AND asset_id = $2
			   AND status <> 'closed'
			   AND source_ref IS NOT NULL
			   AND starts_with(source_ref, $3)
			   AND source_ref <> $4`,
			tenantID, assetID, agentPrefix, runRef)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		closed = int(n)
		return nil
	})
	return closed, err
}

// ---------------------------------------------------------------------------
// the observation
// ---------------------------------------------------------------------------

// observationFor builds the identification-engine observation for a host.
//
// Endpoints are on the OBSERVATION rather than written afterwards so they share
// the engine's transaction: one collection is one statement about the world,
// and splitting it would leave an asset whose history says it was created and
// whose endpoints say nothing was listening, with no later run to repair it —
// the next collection MATCHES and never takes the create path again.
func (h *HostInventoryIngest) observationFor(
	ctx context.Context,
	tenantID uuid.UUID,
	subject di.PeerRef,
	meta hostInventoryMetadata,
	obs *di.InterrogateResult,
	source identity.Source,
	runRef string,
) (identity.Observation, error) {
	primary := meta.primaryAddress(obs)
	scope, dynamic := h.sink.scopeForAddress(ctx, tenantID, primary, meta.Hostname)

	out := identity.Observation{
		TenantID: tenantID.String(),
		// Coarse and true. See the file header: a class is a rule's decision.
		ClassHint:  assetclass.KeyUnknownHost,
		Source:     source,
		ObservedAt: meta.collectedAt(),
		// The host said this about itself, either as the agent installed on it
		// or through an authenticated session to it. There is no more direct
		// measurement available anywhere in the product.
		Confidence: 1,
		Network: identity.Network{
			// The tenant's own machine: we are either running on it or logged
			// in to it. `third_party` would be nonsense and `unknown` would
			// understate what an authenticated session establishes.
			Ownership: identity.OwnershipInternal,
			SegmentID: scope,
		},
		DisplayName: strings.TrimSpace(subject.DisplayName),
		Hostname:    strings.ToLower(strings.TrimSpace(meta.Hostname)),
	}
	if dynamic {
		out.DynamicScopes = map[string]bool{scope: true}
	}

	for _, id := range subject.Identifiers {
		kind := identity.Kind(id.Kind)
		if !kind.Valid() {
			// The collector vocabulary is pinned to identity's by
			// TestPeerIdentifierKindsMatchIdentityRegistry, so this is
			// unreachable today and is the loud failure if that ever drifts.
			return identity.Observation{}, fmt.Errorf("host inventory: identifier kind %q is not one of the ten", id.Kind)
		}
		// hostname and ip_address identify only WITHIN a scope; the other kinds
		// a host reports about itself are globally unique, and a scope on one
		// would split the uniqueness key.
		identifierScope := ""
		if kind.RequiresScope() {
			identifierScope = scope
		}
		out.Identifiers = append(out.Identifiers, identity.Identifier{
			Kind: kind, Value: id.Value, Scope: identifierScope, Confidence: 1,
		})
	}
	if out.DisplayName == "" && primary != "" {
		out.DisplayName = primary
	}

	// Endpoints carry the RUN's ref, not the agent's, for the same reason
	// software installs do: the retirement sweep works by closing every row of
	// this agent's whose ref is not THIS run's, and a stable ref makes that test
	// vacuously false so nothing is ever closed.
	out.Endpoints = hostInventoryEndpoints(obs, meta, primary, identity.Source{
		Kind: identity.SourceMeasured, Ref: runRef, Mode: identity.ModeActive,
	})

	clean, rejected := out.Sanitize()
	for _, r := range rejected {
		// One malformed identifier must not lose the collection, but a drop is
		// never silent: an identifier that cannot be stored is an asset that
		// may not be recognisable again.
		log.Printf("[HostInventory] %s: dropped a %s identifier: %v", meta.label(), r.Identifier.Kind, r.Err)
	}
	if len(clean.Identifiers) == 0 {
		return identity.Observation{}, fmt.Errorf(
			"host inventory: %s carries no usable identifier; an asset created from it could never be recognised again, so a new one would appear on every collection",
			meta.label())
	}
	return clean, nil
}

// hostInventoryEndpoints turns the collection's listening sockets into
// endpoints.
//
// These are the point of a host inventory as far as the graph is concerned: a
// socket the host itself reports is the only evidence tying a service to a
// MACHINE rather than to an address that machine happens to answer on today,
// and it sees the loopback-only and firewalled services no network scan can
// reach.
//
// Three decisions:
//
//   - **A wildcard bind is not an address.** `0.0.0.0` and `::` mean "every
//     interface", and writing them into `asset_endpoints.address` would put a
//     literal 0.0.0.0 in the inventory — which is exactly the placeholder row
//     the passive host-observation path had to be stopped from creating. The
//     endpoint takes the host's primary address instead, and its FQDN when
//     there is no address at all. One with neither is skipped: an endpoint that
//     is neither an address nor a name is not an observation of anything, and
//     the database's own addressable_check would refuse it.
//   - **No protocol.** Transport is tcp or udp because the host said so;
//     the APPLICATION protocol is unknown, and `protocol` is left NULL rather
//     than guessed from the port number. A host inventory observes that
//     something is listening, never what it speaks.
//   - **The process name is `reported`, not `inferred`.** The host named the
//     process holding the socket. That is the strongest form of this claim
//     available anywhere in the product — stronger than a banner, which is
//     whatever a service chose to say about itself.
func hostInventoryEndpoints(obs *di.InterrogateResult, meta hostInventoryMetadata, primary string, source identity.Source) []identity.EndpointObservation {
	out := make([]identity.EndpointObservation, 0, len(obs.Assets))
	for i := range obs.Assets {
		a := &obs.Assets[i]
		ep := identity.EndpointObservation{
			Port:      a.Port,
			Transport: strings.ToLower(strings.TrimSpace(a.Protocol)),
			Source:    source,
			SeenAt:    meta.collectedAt(),
		}
		switch addr := strings.TrimSpace(a.IPAddress); {
		case addr != "" && !isWildcardAddress(addr):
			ep.Address = addr
		case primary != "":
			ep.Address = primary
		default:
			ep.FQDN = strings.TrimSpace(meta.FQDN)
			if ep.FQDN == "" {
				ep.FQDN = strings.TrimSpace(meta.Hostname)
			}
		}
		if ep.Address == "" && ep.FQDN == "" {
			continue
		}
		if a.ServiceHints != nil && strings.TrimSpace(a.ServiceHints.ServiceName) != "" {
			ep.ServiceName = strings.TrimSpace(a.ServiceHints.ServiceName)
			ep.ServiceConfidence = a.ServiceHints.Confidence
			ep.ServiceIdentificationMethod = a.ServiceHints.IdentificationMethod
		}
		if v, ok := a.Metadata["bound_local"].(bool); ok {
			// Copied into a fresh variable so this stays correct if `v` is ever
			// hoisted out of the loop — at which point &v would alias and every
			// endpoint would share the last socket's answer, which is invisible
			// whenever the sockets agree and inverts the flag when they do not.
			//
			// As written the copy is redundant: the type assertion declares `v`
			// per iteration, so &v is already safe today. Saying so because the
			// test beside it cannot tell the two apart, and a comment claiming
			// a guard that is not load-bearing is how a vacuous check survives.
			bound := v
			ep.BoundLocal = &bound
		}
		out = append(out, ep)
	}
	return out
}

// isWildcardAddress reports whether a bound address means "every interface".
//
// Parsed rather than string-matched, for the reason isLoopback is parsed in the
// collector: `0.0.0.0`, `::`, `0:0:0:0:0:0:0:0` and `::ffff:0.0.0.0` are the
// same answer, and a prefix test knows only the spellings somebody thought of.
func isWildcardAddress(v string) bool {
	a, err := netip.ParseAddr(strings.TrimSpace(v))
	if err != nil {
		return false
	}
	return a.Unmap().IsUnspecified()
}

// ---------------------------------------------------------------------------
// facts
// ---------------------------------------------------------------------------

// hostInventoryFacts selects the facts to write, and reports what the collector
// enumerated.
//
// Two things happen here rather than at the write:
//
//  1. **A fact about somebody else is REFUSED.** Every fact in a host inventory
//     is about the host; the subject rides on each one because a local
//     collection has no device row to attach to. A fact whose subject is
//     something else means the payload was assembled by something this code
//     does not understand, and attributing it to the host would be the "one
//     controller's port table filed under the wrong switch" mistake the
//     ObservationSink's per-subject grouping exists to prevent. It is counted
//     as an error, not dropped silently.
//  2. **sw.package_count is held back.** It is rewritten after the installs
//     land, from the rows that actually landed — see refreshPackageCount. Its
//     PRESENCE here is what says the package step succeeded, which is the only
//     thing that licenses the absent-install sweep, so the value is returned
//     even though the fact is not written from this batch.
//
// The subject is stripped from every fact that survives. The engine has already
// resolved it, and leaving it on would send the ObservationSink back through
// the peer-resolution path for a subject we have just decided — a second,
// differently-built observation of one host.
func hostInventoryFacts(obs *di.InterrogateResult, subject di.PeerRef) (out []di.FactObservation, enumerated *int, errs []string) {
	want := identifierKey(subject)
	for _, f := range obs.Facts {
		if !f.Subject.IsZero() && identifierKey(f.Subject) != want {
			errs = append(errs, fmt.Sprintf(
				"fact %s describes a different subject (%s) than the host this report is about; refused rather than attributed to the host",
				f.Key, f.Subject.DisplayName))
			continue
		}
		if f.Key == facts.KeySWPackageCount {
			if n, ok := intValue(f.Value); ok {
				enumerated = &n
			}
			continue
		}
		f.Subject = di.PeerRef{}
		out = append(out, f)
	}
	return out, enumerated, errs
}

// identifierKey renders a peer's identifiers as one comparable string, so two
// references to the same host compare equal regardless of field order in the
// JSON they arrived as.
func identifierKey(peer di.PeerRef) string {
	parts := make([]string, 0, len(peer.Identifiers))
	for _, id := range peer.Identifiers {
		parts = append(parts, id.Kind+"="+id.Value)
	}
	return strings.Join(parts, "\x00")
}

// intValue reads a fact value that should be a whole number. JSON decoding
// turns every number into a float64, and a value that came straight from Go is
// an int, so both are accepted and nothing else is.
func intValue(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil
	}
	return 0, false
}

// ---------------------------------------------------------------------------
// software
// ---------------------------------------------------------------------------

// softwareListArrived reports whether the package list the collector says it
// enumerated is actually present in this payload, and why not when it is not.
//
// It is the second half of the sweep guard, and it closes a door the first half
// leaves open. `sw.package_count` licenses the write because its presence means
// the package STEP succeeded — but the count travels as a FACT while the list
// travels in `device_info.packages`, which is a different field of a different
// half of the submission. A payload that carries the count and not the list
// therefore reaches writeSoftware with an empty product set, and
// MarkAbsentRemoved marks the host's ENTIRE measured software inventory
// `removed` — a silent data loss caused by a transport gap, not by anything
// anybody measured.
//
// That gap is not hypothetical. On the remote path the two halves are
// `JobResult.Facts` and `JobResult.Metadata`, which can be lost independently;
// on the local path the report's copy of the list was just taught to drop off
// the wire (withoutPackageList), so the next person trimming the payload is
// trimming next to the only surviving copy.
//
// The test is `enumerated > 0 && arrived == 0`, and both ends of it matter:
//
//   - A genuinely package-less host enumerates ZERO and sends no list at all
//     (ToObservations omits the key when the slice is empty). enumerated == 0
//     is no contradiction, the sweep runs, and "everything I recorded before is
//     gone" is the correct reading of an empty enumeration that SUCCEEDED.
//   - `arrived` is the count of identifiable products AFTER dedup, so it is
//     legitimately smaller than what the collector counted — two entries
//     sharing a purl, an entry with no usable name. Only NONE of them arriving
//     is a contradiction; a shortfall is not.
//
// Refusing writes nothing rather than writing half: the previous run's picture
// of this host's software is the last one anybody actually measured, and
// keeping it is more honest than replacing it with a list that did not arrive.
func softwareListArrived(enumerated, arrived int) (reason string, ok bool) {
	if enumerated > 0 && arrived == 0 {
		return fmt.Sprintf(
			"the collector enumerated %d package(s) but the payload carries none; "+
				"the list did not arrive, so no install was written and the absent-install sweep did NOT run "+
				"(running it would mark this host's whole measured software inventory removed)",
			enumerated), false
	}
	return "", true
}

// writeSoftware turns the collection's package list into catalogue rows and
// installs, then rewrites `sw.package_count` from what landed.
//
// One transaction for the whole list, for the reason the SBOM upload uses one:
// a half-written software inventory shows a list that looks complete with no
// way to tell which half is missing.
//
// Only reached when the package step SUCCEEDED and its list actually arrived —
// the caller checks both — so an empty `products` here means a host with no
// packages, which is a real answer and is written as one.
// `runRef` names this collection and is what the sweep compares against;
// `factRef` names the agent and is what the package-count fact is keyed on. See
// hostInventorySourceRef for why they differ.
func (h *HostInventoryIngest) writeSoftware(
	ctx context.Context,
	tenantID, assetID uuid.UUID,
	runRef, factRef string,
	products []software.Product,
	counts *HostInventoryCounts,
) error {
	return shareddatabase.WithTenantTx(ctx, h.db, tenantID, func(tx *sql.Tx) error {
		for _, p := range products {
			productID, created, err := swpostgres.UpsertProduct(ctx, tx, tenantID, p, software.SourceMeasured)
			if err != nil {
				return fmt.Errorf("upserting product %q: %w", p.Name, err)
			}
			if created {
				counts.ProductsCreated++
			} else {
				counts.ProductsMatched++
			}

			// No install path. A package database entry names a package, not a
			// directory; the collector does not ask for file lists (that is a
			// command per package and a lot of a customer's filesystem), so
			// there is nothing honest to put here. The unique index coalesces
			// NULL to '' precisely so repeated observations of a pathless
			// install converge on one row.
			installCreated, err := swpostgres.UpsertInstall(ctx, tx, tenantID, assetID, productID,
				"", software.SourceMeasured, runRef)
			if err != nil {
				return fmt.Errorf("upserting install of %q: %w", p.Name, err)
			}
			if installCreated {
				counts.InstallsCreated++
			} else {
				counts.InstallsUpdated++
			}
		}

		removed, err := swpostgres.MarkAbsentRemoved(ctx, tx, tenantID, assetID, software.SourceMeasured, runRef)
		if err != nil {
			return fmt.Errorf("marking absent installs removed: %w", err)
		}
		counts.InstallsRemoved = removed

		active, err := swpostgres.ActiveInstallCount(ctx, tx, tenantID, assetID, software.SourceMeasured)
		if err != nil {
			return fmt.Errorf("counting active installs: %w", err)
		}
		counts.InstallsActive = active
		return refreshPackageCount(ctx, tx, tenantID, assetID, factRef, active)
	})
}

// hostInventoryProducts decodes the package list out of the observations'
// metadata and deduplicates it by catalogue identity.
//
// The list is read from `device_info.packages`, which is the ALLOWLISTED
// projection the collector built (name, version, vendor, arch, manager, purl)
// and the only copy that has been through di.Sanitize. The report's own copy no
// longer travels — see device-agent's withoutPackageList.
//
// Deduplication is by [software.Product.Identity] after the writer's fold, so
// one host listing the same purl from two package managers is one catalogue row
// and one install rather than two round trips and a doubled count. An entry
// with no usable name is dropped: `software_products.name` is NOT NULL, and
// inventing a name for a nameless entry would put a row in the catalogue that
// matches nothing and means nothing.
func hostInventoryProducts(obs *di.InterrogateResult) []software.Product {
	raw, ok := obs.DeviceInfo["packages"]
	if !ok || raw == nil {
		return nil
	}
	blob, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var entries []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Vendor  string `json:"vendor"`
		PURL    string `json:"purl"`
	}
	if err := json.Unmarshal(blob, &entries); err != nil {
		return nil
	}

	seen := make(map[string]bool, len(entries))
	out := make([]software.Product, 0, len(entries))
	for _, e := range entries {
		p := swpostgres.FoldForWrite(software.Product{
			Name:    e.Name,
			Version: e.Version,
			Vendor:  e.Vendor,
			PURL:    e.PURL,
			// No CPE. Nothing on a host reports its own CPE, and one assembled
			// by string-formatting a vendor name is a guess that reads like an
			// identifier; the enricher resolves it later from the vendor and
			// product already stored (standards/fact-keys.yaml, sw.cpe).
		})
		if !p.Identifiable() {
			continue
		}
		id := p.Identity()
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, p)
	}
	return out
}

// refreshPackageCount rewrites `sw.package_count` for this asset from the host
// agent's source.
//
// The value is the count of ACTIVE MEASURED installs, not the number the
// collector enumerated. The two differ when an entry had no usable name or two
// entries shared one purl, and the fact's job (per standards/fact-keys.yaml) is
// to distinguish "no software found" from "software was never enumerated" — the
// number that answers that is the number of rows an inventory query returns.
// Both numbers reach the job row, so the gap is visible rather than hidden.
//
// Scoped to `measured` and written under the agent's source ref, so an SBOM
// upload's count and an agent's count are two rows and neither claims the
// other's coverage.
func refreshPackageCount(ctx context.Context, tx *sql.Tx, tenantID, assetID uuid.UUID, sourceRef string, count int) error {
	// The key column has no CHECK constraint and the value column is jsonb, so
	// this validator is the only thing between a producer and a fact nobody can
	// read back. Checked even though the value is an int we just counted: the
	// call is what fails loudly if the key is ever renamed or retyped.
	if err := facts.ValidateValue(facts.KeySWPackageCount, count); err != nil {
		return err
	}
	value, err := json.Marshal(count)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO asset_facts (tenant_id, asset_id, key, value, source_kind, source_ref, observed_at)
		VALUES ($1, $2, $3, $4::jsonb, $5, $6, now())
		ON CONFLICT (tenant_id, asset_id, key, source_ref)
		DO UPDATE SET value = excluded.value,
		              source_kind = excluded.source_kind,
		              observed_at = excluded.observed_at,
		              updated_at = now()`,
		tenantID, assetID, facts.KeySWPackageCount, string(value),
		software.SourceMeasured, sourceRef)
	return err
}

// ---------------------------------------------------------------------------
// class
// ---------------------------------------------------------------------------

// classProposal asks the Classifier seam what the rules make of this host, and
// returns the answer for the RECORD.
//
// It is not applied. Writing a rule's answer into `assets.class_key` needs it
// to arrive with `class_source_kind: inferred` and a proposal a human can
// accept or reject — which is workstream 2.10b's intake-builder work, not this
// file's. Writing it as `measured` (the column's default, and what this path
// would get for free) would state that the platform MEASURED the host to be a
// server, which nothing did: a rule matched a model string.
//
// So the proposal is recorded on the job row, where an operator can see what
// the rules would have said, and the asset stays `unknown_host`. When 2.10b
// lands, this is the call whose result it consumes.
//
// # What it is given
//
// Vendor and model, because those are what the rule table matches on, and the
// NON-LOOPBACK listening ports, because `port_profile` rules read them.
// Loopback ports are excluded deliberately: a port profile describes what a
// device EXPOSES, and a service bound to 127.0.0.1 exposes nothing — including
// it would let a developer laptop running a local database match a
// database-server profile.
//
// The OS name is not passed: `classify.ClassifyInput` has no OS field (2.10a's
// rule vocabulary is MACs, sysObjectID, ENIP vendor id, cloud resource type,
// banners, ports, vendor, model and platform), and inventing one here would be
// a rule input no rule can read.
func classProposal(ctx context.Context, obs *di.InterrogateResult) string {
	input := seams.AssetFacts{Facts: map[string]any{}}
	for _, f := range obs.Facts {
		switch f.Key {
		case facts.KeyHWVendor:
			input.Facts[seams.FactVendor] = f.Value
		case facts.KeyHWModel:
			input.Facts[seams.FactModel] = f.Value
		}
	}
	if ports := exposedPorts(obs); len(ports) > 0 {
		input.Facts[seams.FactOpenPorts] = ports
	}
	if len(input.Facts) == 0 {
		return ""
	}
	proposal, err := (seams.RuleClassifier{}).Classify(ctx, input)
	if err != nil || proposal.Unknown {
		// "The rules did not decide" is a normal outcome with a complete
		// answer, not a failure, and must not be logged as one.
		return ""
	}
	return proposal.Class
}

// exposedPorts is the set of ports the host listens on that something else
// could reach. See classProposal for why loopback sockets are excluded.
func exposedPorts(obs *di.InterrogateResult) []int {
	seen := map[int]bool{}
	out := make([]int, 0, len(obs.Assets))
	for i := range obs.Assets {
		a := &obs.Assets[i]
		if bound, ok := a.Metadata["bound_local"].(bool); ok && bound {
			continue
		}
		if a.Port <= 0 || seen[a.Port] {
			continue
		}
		seen[a.Port] = true
		out = append(out, a.Port)
	}
	return out
}

// ---------------------------------------------------------------------------
// the metadata block
// ---------------------------------------------------------------------------

// hostInventoryMetadata is the collector's own account of the run, as it
// travels in `device_info.host_inventory`.
//
// Read through a typed struct rather than asserted field by field, because the
// struct IS the contract: a field the collector renames stops arriving loudly
// instead of being read as an empty interface value.
type hostInventoryMetadata struct {
	Collected string            `json:"collected"`
	Mode      string            `json:"mode"`
	Platform  string            `json:"platform"`
	Hostname  string            `json:"hostname"`
	FQDN      string            `json:"fqdn"`
	Sections  map[string]string `json:"sections"`
}

// hostInventoryMeta decodes the metadata block, returning a zero value when the
// payload carries none. A missing block is survivable — the facts and
// identifiers are the substance — so it does not fail the run.
func hostInventoryMeta(obs *di.InterrogateResult) hostInventoryMetadata {
	var meta hostInventoryMetadata
	raw, ok := obs.DeviceInfo["host_inventory"]
	if !ok || raw == nil {
		return meta
	}
	blob, err := json.Marshal(raw)
	if err != nil {
		return meta
	}
	_ = json.Unmarshal(blob, &meta)
	return meta
}

// label names the host for a log line, most specific identity first.
func (m hostInventoryMetadata) label() string {
	switch {
	case strings.TrimSpace(m.FQDN) != "":
		return m.FQDN
	case strings.TrimSpace(m.Hostname) != "":
		return m.Hostname
	case strings.TrimSpace(m.Platform) != "":
		return "an unnamed " + m.Platform + " host"
	default:
		return "an unnamed host"
	}
}

// collectedAt is when the collection finished. A zero time is left zero so the
// engine stamps its own clock rather than this inventing one.
func (m hostInventoryMetadata) collectedAt() time.Time {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(m.Collected))
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// primaryAddress is the host's own first non-loopback address, read from the
// net.interfaces fact.
//
// It is the address a weak identifier is SCOPED by and the address a
// wildcard-bound endpoint is recorded at. Read from the interface list rather
// than from the sockets because a socket's bound address is a property of the
// socket: a host whose every service listens on 0.0.0.0 still has addresses,
// and a host with one loopback-only service is not a loopback-only host.
//
// A local collection reports no segment of its own — the agent knows its
// addresses, not the tenant's topology — so the address is handed to the shared
// segment resolver, which falls back to the tenant-wide default scope when it
// is inside no configured segment. See ADR-0002 D3's erratum for why that
// fallback exists at all: an unscoped weak identifier can decide nothing, and a
// host observed three times became three assets.
func (m hostInventoryMetadata) primaryAddress(obs *di.InterrogateResult) string {
	for _, f := range obs.Facts {
		if f.Key != facts.KeyNetInterfaces {
			continue
		}
		blob, err := json.Marshal(f.Value)
		if err != nil {
			return ""
		}
		var ifaces []struct {
			Addresses []string `json:"addresses"`
			Virtual   bool     `json:"virtual"`
		}
		if err := json.Unmarshal(blob, &ifaces); err != nil {
			return ""
		}
		for _, ifc := range ifaces {
			if ifc.Virtual {
				// A veth, a bridge or a tunnel address is not where this host
				// lives, and scoping its identity by one would file it in a
				// segment that exists only inside the machine.
				continue
			}
			for _, addr := range ifc.Addresses {
				// The collector records CIDR form where the source gave a
				// prefix length; the scope resolver wants the address.
				if a, ok := parseHostAddress(addr); ok {
					return a
				}
			}
		}
	}
	return ""
}

// parseHostAddress strips a prefix length and rejects the addresses that are
// not a host's own: loopback, unspecified, and anything unparseable.
func parseHostAddress(v string) (string, bool) {
	s := strings.TrimSpace(v)
	if s == "" {
		return "", false
	}
	if prefix, err := netip.ParsePrefix(s); err == nil {
		s = prefix.Addr().String()
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", false
	}
	a = a.Unmap()
	if a.IsLoopback() || a.IsUnspecified() || a.IsLinkLocalUnicast() {
		return "", false
	}
	return a.String(), true
}

// hostInventorySubject recovers the host the report is about.
//
// The subject rides on every fact, because a local collection has no device row
// to attach to and the identifiers are the only way the identification engine
// can bind the report to an asset. `agent.mode` is emitted unconditionally by
// the collector, so a payload with any facts at all has one; a payload with
// none cannot be materialised, and says so.
func hostInventorySubject(obs *di.InterrogateResult) (di.PeerRef, bool) {
	for _, f := range obs.Facts {
		if !f.Subject.IsZero() {
			return f.Subject, true
		}
	}
	return di.PeerRef{}, false
}

// scopeForAddress resolves the segment an address falls in, and whether that
// segment hands addresses out dynamically.
//
// A thin wrapper on the sink's resolver so this file has ONE call site for the
// question, and so the answer is byte-for-byte the one every other intake gets
// — one more spelling of this lookup would be one more dedupe key.
func (s *ObservationSink) scopeForAddress(ctx context.Context, tenantID uuid.UUID, ip, hostname string) (string, bool) {
	_, repo, err := s.engine()
	if err != nil {
		repo = nil
	}
	// The empty cloud-network ref is the point: a host inventory describes a
	// machine, not a cloud resource, so there is no VPC to disambiguate two
	// subnets that share a CIDR by. The resolver falls back to the tenant-wide
	// default scope when the address is inside no configured segment.
	return newDeviceScopeResolver(s.db, repo).segmentScope(ctx, tenantID, ip, hostname, "")
}
