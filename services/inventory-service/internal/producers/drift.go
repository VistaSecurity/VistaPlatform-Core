package producers

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/driftsettings"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer"
)

// DriftProducer is the `drift` finding producer (ADR-0005 D3, workstream 4.7).
//
// It answers one question, four ways: "is this different from what this tenant
// has been looking like?" — where "has been looking like" is everything
// observed BEFORE a window that reaches `drift.baseline_days` back from now.
//
//	a class new to a network segment   → drift/new_class_in_segment  on the ASSET
//	a protocol new to an asset         → drift/unexpected_protocol    on the ASSET
//	a listening-port set that moved    → drift/port_profile_changed   on the ASSET
//	a certificate issuer new to an asset → drift/new_issuer           on the ASSET
//
// # Rule-based, and that is the whole of it
//
// ADR-0008 lists a drift-detector seam. This is NOT its implementation and does
// not register against it: the seam proposes [seams.Anomaly] values onto the
// alert rail, carrying a model id and a confidence, and this producer writes
// deterministic findings from SQL. The seams package says which is which —
// "the rule-based work the ADR lists in the null/rule-based default column
// lives in the services that own that data and keeps running whether or not a
// seam is configured". This is that path. A model-backed detector, when there
// is one, proposes BESIDE these findings; it does not replace them, and
// nothing here consults a model (ADR-0008 D5).
//
// # The baseline, and why nothing is drift without one
//
// The window is [now - baseline_days, now]. Anything whose FIRST observation
// falls inside it is a candidate; anything older is the baseline it is compared
// against. Two gates decide whether a comparison is possible at all, and both
// exist because "we have not been watching long enough to tell" must never be
// reported as "this is new":
//
//  1. TENANT WARM-UP. Until the tenant's oldest asset is at least
//     `baseline_days` old, the producer does nothing — it does not raise, and it
//     does not SWEEP. A brand-new tenant would otherwise get one finding per
//     asset, protocol, port set and issuer on the day they onboarded, which is
//     every asset they have. Not sweeping is the same honesty pointed the other
//     way: a pass that could not evaluate has made no statement, and resolving
//     on it would render "not evaluated" as "the condition went away".
//  2. PER-SUBJECT BASELINE. A comparison needs something to compare against, so
//     each kind requires its own subject to have history older than the window:
//     the SEGMENT must contain an asset first seen before the cutoff, the ASSET
//     must have spoken some protocol / had some listening port / presented some
//     certificate before it. Without that there is no baseline for this
//     subject, and "not in the baseline" is not an answer — it is the absence of
//     one. Counted as `NoBaseline` rather than silently skipped.
//
// # What resolves a drift finding
//
// Two things, and both fall out of recomputing the whole picture every pass:
//
//   - the observation AGES INTO the baseline. A protocol first seen 10 days ago
//     is drift under a 30-day window; on day 31 its first observation is older
//     than the cutoff, the producer stops asserting it, and the sweep closes the
//     finding. Nothing special happens — "new" is a property of the window, not
//     a flag on a row.
//   - the condition GOES AWAY. The port closed again, the certificate was
//     replaced, the asset left the segment.
//
// # A human's decision survives the next pass
//
// Every drift finding carries an `observation_key` in its evidence: a stable
// string naming WHAT is being reported (which class, which protocols, which
// port delta, which issuers). The identity index allows one open row per
// (producer, kind, subject), so a later, DIFFERENT observation about the same
// asset lands on the same row — and [producer.Writer.Upsert] leaves an ACTIVE
// row's workflow_status alone, which is exactly right for a re-observation and
// exactly wrong for a new one. Somebody who resolved "started speaking SSH"
// would silently never be told about "started speaking RDP".
//
// So: when the row is ACTIVE, somebody has already moved it off NEW, and the
// observation key has CHANGED, the pass resolves the row first and re-raises it
// — which is the writer's own resurfacing path, and puts the new observation
// back in the triage queue with its history intact. A row whose key is
// unchanged is left alone, so an accepted change stays accepted for as long as
// it is the change that was accepted.
type DriftProducer struct {
	// db is the RLS-subject handle. Every statement in the pass is
	// tenant-scoped; there is no platform catalogue here to read on a bypass
	// role, because drift is judged against the tenant's OWN history.
	db     *sql.DB
	writer *producer.Writer
	now    func() time.Time

	// readPhase is [DriftProducer.read], held as a field so ONE test can make
	// the read fail while the database stays healthy.
	//
	// That distinction is the whole point. A read that fails because the
	// connection is gone fails the write phase too, so a test built on a dead
	// handle proves nothing about the guard: it passes just as well with the
	// guard deleted. What has to be provable is that a read failing for a
	// DATA reason — a scan error on one row of thousands — returns before a
	// write phase that would otherwise have swept every finding the tenant has.
	//
	// The eol producer gets this seam for free by swapping its catalogue store
	// (failed_pass_integration_test.go). This producer reads nothing but the
	// tenant's own tables, so the seam is the phase itself. Production always
	// holds the real method.
	readPhase func(ctx context.Context, tenantID uuid.UUID) (*driftInput, error)
}

// NewDriftProducer builds the producer.
func NewDriftProducer(appDB *sql.DB) (*DriftProducer, error) {
	w, err := producer.New(findings.ProducerDrift)
	if err != nil {
		return nil, err
	}
	p := &DriftProducer{db: appDB, writer: w, now: time.Now}
	p.readPhase = p.read
	return p, nil
}

// DriftRun is one full pass over one tenant.
type DriftRun struct {
	// BaselineDays is the window this pass used, as the tenant has it set.
	BaselineDays int
	// WarmingUp is true when the tenant has not been observed for a full
	// window yet. Nothing was raised AND nothing was swept — see the type
	// comment.
	WarmingUp bool
	// Raised is how many findings were upserted (created or re-observed).
	Raised int
	// Resolved is how many the sweep moved to INACTIVE.
	Resolved int
	// Reopened is how many ACTIVE findings somebody had already dealt with were
	// re-raised because the observation underneath them changed.
	Reopened int
	// Assets is how many assets the pass judged.
	Assets int
	// NoBaseline counts (kind, subject) pairs skipped because the subject has
	// no history older than the window. Reported rather than swallowed: "we
	// could not compare" and "nothing changed" are different answers.
	NoBaseline int
	// Assessed is how many assets this pass claimed COVERAGE of — the ones it
	// could actually compare against a baseline of their own (workstream 3.2).
	// Reported beside NoBaseline because together they are the whole answer:
	// what was judged, and what could not be.
	Assessed int
}

// Run executes the pass for one tenant.
//
// Read, judge, write. An error from the read phase returns WITHOUT sweeping: a
// run that failed part way has not made a full statement about what it sees,
// and sweeping on a partial answer inactivates live findings and re-raises them
// on the next pass with their workflow status reset.
func (p *DriftProducer) Run(ctx context.Context, tenantID uuid.UUID) (DriftRun, error) {
	var run DriftRun

	in, err := p.readPhase(ctx, tenantID)
	if err != nil {
		return DriftRun{}, fmt.Errorf("drift producer: reading tenant %s: %w", tenantID, err)
	}
	run.BaselineDays = in.baselineDays
	run.Assets = len(in.assets)

	if in.warmingUp {
		// No write phase at all, deliberately. See the type comment.
		run.WarmingUp = true
		return run, nil
	}

	planned := p.judge(in, &run)
	assessed := coveredAssets(in)
	run.Assessed = len(assessed)

	if err := p.write(ctx, tenantID, planned, assessed, &run); err != nil {
		return DriftRun{}, fmt.Errorf("drift producer: writing tenant %s: %w", tenantID, err)
	}
	return run, nil
}

// ---------------------------------------------------------------------------
// read
// ---------------------------------------------------------------------------

// driftAsset is one asset in the population the pass judges.
type driftAsset struct {
	id          uuid.UUID
	label       string
	classKey    string
	segmentID   uuid.NullUUID
	segmentName string
	firstSeen   time.Time
}

// protoObservation is one sighting of one protocol on one asset.
type protoObservation struct {
	assetID   uuid.UUID
	protocol  string
	firstSeen time.Time
	live      bool
	source    string
	refID     uuid.UUID
}

// portObservation is one endpoint's contribution to an asset's port profile.
//
// It carries the ENDPOINT ROW's id and address, not only the port number. A
// port-profile finding without them names "8080 opened" on a host with four
// addresses and leaves the reader to work out which face it appeared on — the
// finding is about an `asset_endpoints` row and could not say which one.
type portObservation struct {
	assetID    uuid.UUID
	endpointID uuid.UUID
	address    string
	fqdn       string
	port       int
	transport  string
	firstSeen  time.Time
	lastSeen   time.Time
	active     bool
}

// endpointLabel is how an endpoint is named in evidence: the address or the
// name it answers on, with the port. Never an id alone — an id is for the
// drill-through, a label is for the person reading the drawer.
func (o portObservation) endpointLabel() string {
	host := o.address
	if host == "" {
		host = o.fqdn
	}
	if host == "" {
		return portKey{port: o.port, transport: o.transport}.String()
	}
	return host + ":" + portKey{port: o.port, transport: o.transport}.String()
}

// issuerObservation is one certificate an asset presented, reduced to its
// issuer. The certificate BODY never travels — an issuer DN and a fingerprint
// are identities, not key material.
type issuerObservation struct {
	assetID     uuid.UUID
	certID      uuid.UUID
	issuerDN    string
	fingerprint string
	firstSeen   time.Time
	live        bool
}

// driftInput is everything one pass reads, in one transaction.
type driftInput struct {
	baselineDays int
	now          time.Time
	cutoff       time.Time
	warmingUp    bool

	assets  []driftAsset
	protos  []protoObservation
	ports   []portObservation
	issuers []issuerObservation

	// assessed is filled by the JUDGE phase rather than the read: the assets
	// this pass could genuinely compare against a baseline of their own.
	//
	// It lives here because the judge already owns this struct and a second
	// return value would say nothing the name does not. What it MEANS is the
	// load-bearing part. Workstream 3.2 turns a `producer_assessments` row into
	// `assets.risk_assessed_by`, and a non-empty array is read as "the risk
	// number on this asset is a real answer" — so an asset with no history of
	// its own, and EVERY asset of a tenant still warming up, is deliberately
	// absent. Over-claiming here renders "we could not compare" as "we compared
	// and found nothing", which is the three-valued collapse the whole producer
	// is built to avoid; under-claiming only reads as "not assessed", which is
	// true and visible.
	assessed map[uuid.UUID]bool
}

// read loads the tenant's window setting and the whole population the pass
// judges, in ONE tenant-scoped transaction.
//
// One transaction because the four reads have to describe the same instant: a
// certificate that appears between the endpoint read and the certificate read
// would be compared against a baseline that does not know about the asset it
// belongs to.
//
// Archived, denied and soft-deleted assets are excluded. Archived and denied
// are both a tenant DECISION to stop tracking something, and drift findings
// about a thing somebody has already dismissed put work back in the queue they
// took it out of. `pending_approval` is kept: a class that has never been on
// this segment before is exactly the thing worth knowing BEFORE approving it.
func (p *DriftProducer) read(ctx context.Context, tenantID uuid.UUID) (*driftInput, error) {
	now := p.now().UTC()
	in := &driftInput{now: now}

	err := shareddatabase.WithTenantTx(ctx, p.db, tenantID, func(tx *sql.Tx) error {
		days, err := driftsettings.ReadBaselineDaysTx(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		in.baselineDays = days
		in.cutoff = now.AddDate(0, 0, -days)

		// Warm-up, over EVERY non-deleted asset including the archived and
		// denied ones the population below drops. The question is "how long
		// have we been watching this tenant", and an asset somebody archived
		// last year is still evidence that we were watching last year.
		var earliest sql.NullTime
		if err := tx.QueryRowContext(ctx, `
			SELECT min(first_discovered_at) FROM assets
			WHERE tenant_id = $1 AND deleted_at IS NULL`, tenantID).Scan(&earliest); err != nil {
			return fmt.Errorf("read the tenant's observation history: %w", err)
		}
		if !earliest.Valid || !warmedUp(earliest.Time, in.cutoff) {
			in.warmingUp = true
			return nil
		}

		if err := p.readAssets(ctx, tx, tenantID, in); err != nil {
			return err
		}
		if err := p.readProtocols(ctx, tx, tenantID, in); err != nil {
			return err
		}
		if err := p.readPorts(ctx, tx, tenantID, in); err != nil {
			return err
		}
		return p.readIssuers(ctx, tx, tenantID, in)
	})
	if err != nil {
		return nil, err
	}
	return in, nil
}

func (p *DriftProducer) readAssets(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, in *driftInput) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT a.id,
		       coalesce(nullif(a.display_name, ''), nullif(a.hostname, ''), a.id::text),
		       a.class_key,
		       a.network_segment_id,
		       coalesce(ns.name, ''),
		       a.first_discovered_at
		FROM assets a
		LEFT JOIN network_segments ns
		       ON ns.tenant_id = a.tenant_id AND ns.id = a.network_segment_id
		WHERE a.tenant_id = $1
		  AND a.deleted_at IS NULL
		  AND a.asset_status NOT IN ('archived', 'denied')`, tenantID)
	if err != nil {
		return fmt.Errorf("query assets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var a driftAsset
		if err := rows.Scan(&a.id, &a.label, &a.classKey, &a.segmentID, &a.segmentName, &a.firstSeen); err != nil {
			return fmt.Errorf("scan asset: %w", err)
		}
		a.firstSeen = a.firstSeen.UTC()
		in.assets = append(in.assets, a)
	}
	return rows.Err()
}

// readProtocols unions the two places a protocol is recorded.
//
// Both, not one: `crypto_implementations.protocol` is what a TLS or SSH probe
// negotiated, `asset_endpoints.protocol` is what a scan or a host inventory
// labelled the socket. An asset that started answering SSH shows up in whichever
// of the two saw it first, and reading only one would make "began using a
// protocol" mean "began using a protocol our favourite collector noticed".
//
// `live` is `status <> 'closed'`, NOT `status = 'active'`. `closed` is a host's
// authoritative "this socket is gone" and is the only observation that means a
// port left the profile. `stale` means only that nothing has looked for thirty
// days (the hygiene pass writes it), and reading that as "closed" would have
// the producer raise `port_profile_changed` saying ports closed on a host
// nobody scanned — drift invented by a collector going quiet. Any tenant whose
// baseline window is longer than the stale threshold would have seen it.
//
// Rows that are no longer live are read too, because they are still evidence
// about the BASELINE: a crypto configuration soft-deleted last week still shows
// that the asset was speaking TLS a year ago, and dropping it would make a
// protocol the asset has always used look new the moment its row was replaced.
func (p *DriftProducer) readProtocols(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, in *driftInput) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT ci.asset_id, ci.protocol::text,
		       coalesce(ci.first_discovered_at, ci.created_at, now()),
		       (ci.deleted_at IS NULL), 'crypto_configuration', ci.id
		FROM crypto_implementations ci
		WHERE ci.tenant_id = $1
		UNION ALL
		SELECT e.asset_id, e.protocol::text,
		       e.first_seen_at, (e.status <> 'closed'), 'endpoint', e.id
		FROM asset_endpoints e
		WHERE e.tenant_id = $1 AND e.protocol IS NOT NULL`, tenantID)
	if err != nil {
		return fmt.Errorf("query protocols: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var o protoObservation
		if err := rows.Scan(&o.assetID, &o.protocol, &o.firstSeen, &o.live, &o.source, &o.refID); err != nil {
			return fmt.Errorf("scan protocol: %w", err)
		}
		o.firstSeen = o.firstSeen.UTC()
		in.protos = append(in.protos, o)
	}
	return rows.Err()
}

// readPorts loads the listening sockets that make up an asset's port profile.
//
// `bound_local IS DISTINCT FROM true` is the exposure rule, and it is
// three-valued on purpose:
//
//   - TRUE  — the socket is bound to loopback and is reachable only from the
//     host itself. EXCLUDED: the profile is about what the asset exposes, and
//     a local helper process coming and going is not a change to that.
//   - FALSE — a host's own view saying "this IS exposed to the network". IN.
//   - NULL  — nobody established it, which is every endpoint a network scan
//     found. IN, because a scan can only ever see what answers on the wire, so
//     a scanned endpoint is network-reachable by construction. Dropping the
//     NULLs would silently remove every scan-discovered port from the profile
//     — "not evaluated" rendered as "not exposed".
func (p *DriftProducer) readPorts(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, in *driftInput) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT e.asset_id, e.id, coalesce(host(e.address), ''), coalesce(e.fqdn, ''),
		       e.port, e.transport, e.first_seen_at, e.last_seen_at, (e.status <> 'closed')
		FROM asset_endpoints e
		WHERE e.tenant_id = $1
		  AND e.port IS NOT NULL
		  AND e.bound_local IS DISTINCT FROM true`, tenantID)
	if err != nil {
		return fmt.Errorf("query ports: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var o portObservation
		if err := rows.Scan(&o.assetID, &o.endpointID, &o.address, &o.fqdn,
			&o.port, &o.transport, &o.firstSeen, &o.lastSeen, &o.active); err != nil {
			return fmt.Errorf("scan port: %w", err)
		}
		o.firstSeen = o.firstSeen.UTC()
		o.lastSeen = o.lastSeen.UTC()
		in.ports = append(in.ports, o)
	}
	return rows.Err()
}

// readIssuers loads the certificates each asset PRESENTS, reduced to issuers.
//
// Two paths because the product writes both: `crypto_implementations
// .certificate_id` is the direct leaf pointer, and
// `crypto_implementation_certificates` carries the chain with a role per entry.
// Only `leaf` and `primary` are taken from the junction — an intermediate or a
// root appearing in a chain is the CA's own certificate, not one this asset
// presented as its identity, and counting them would raise a finding every time
// a CA published a new cross-signed intermediate.
//
// Since every LIVE writer sets both, so the union looks redundant and is
// not. This producer's whole input is OLD data, and a row written before
// and not re-observed since carries the column alone — which is exactly the
// shape of a baseline. Drop the first leg and every asset whose only
// certificate link predates that fix reads as having no certificate history at
// all; worse, the first time one IS re-observed its long-standing CA appears
// for the first time and is reported as a new issuer. Both legs have their own
// test.
//
// Nothing but the issuer DN, the certificate id and the SHA-256 fingerprint
// leaves this query. A fingerprint is a public identity; `certificate_pem` is a
// document and has no business in a finding's evidence.
func (p *DriftProducer) readIssuers(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, in *driftInput) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT ci.asset_id, c.id, c.issuer_dn, c.fingerprint_sha256,
		       coalesce(ci.first_discovered_at, ci.created_at, now()), (ci.deleted_at IS NULL)
		FROM crypto_implementations ci
		JOIN certificates c ON c.tenant_id = ci.tenant_id AND c.id = ci.certificate_id
		WHERE ci.tenant_id = $1
		UNION ALL
		SELECT ci.asset_id, c.id, c.issuer_dn, c.fingerprint_sha256,
		       coalesce(ci.first_discovered_at, ci.created_at, now()), (ci.deleted_at IS NULL)
		FROM crypto_implementations ci
		JOIN crypto_implementation_certificates cic ON cic.crypto_implementation_id = ci.id
		JOIN certificates c ON c.tenant_id = ci.tenant_id AND c.id = cic.certificate_id
		WHERE ci.tenant_id = $1 AND cic.certificate_role IN ('leaf', 'primary')`, tenantID)
	if err != nil {
		return fmt.Errorf("query certificate issuers: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var o issuerObservation
		if err := rows.Scan(&o.assetID, &o.certID, &o.issuerDN, &o.fingerprint, &o.firstSeen, &o.live); err != nil {
			return fmt.Errorf("scan certificate issuer: %w", err)
		}
		o.firstSeen = o.firstSeen.UTC()
		o.issuerDN = strings.TrimSpace(o.issuerDN)
		in.issuers = append(in.issuers, o)
	}
	return rows.Err()
}

// warmedUp reports whether a tenant whose oldest observation is at `earliest`
// has been watched long enough for a baseline ending at `cutoff` to exist.
//
// STRICTLY before, matching the per-subject rule exactly: the baseline is
// everything observed before the cutoff, and the window [cutoff, now] is what
// is compared against it. A tenant whose oldest observation sits exactly ON the
// cutoff has an empty baseline and a window containing everything they own —
// the case this gate exists to catch.
//
// A function rather than an inline comparison so both polarities are pinned by
// a unit test. The direction of this one comparison is the difference between
// "a brand-new tenant gets no drift findings" and "a brand-new tenant gets one
// for every asset it owns", and it reads identically either way round.
func warmedUp(earliest, cutoff time.Time) bool { return earliest.Before(cutoff) }

// ---------------------------------------------------------------------------
// judge
// ---------------------------------------------------------------------------

// plannedDrift is one finding the judge phase decided on.
type plannedDrift struct {
	finding producer.Finding
	// observationKey is the finding's own copy of evidence["observation_key"],
	// so the write phase can compare it against the stored row's without
	// re-parsing the evidence document it is about to send.
	observationKey string
}

// judge turns the read population into findings. No database access: every
// decision here is arithmetic over what read() returned, which is what makes
// the whole of it unit-testable without Postgres.
func (p *DriftProducer) judge(in *driftInput, run *DriftRun) []plannedDrift {
	// Sorted ONCE, here, rather than per kind: the three per-asset kinds all
	// walk the same population and each used to take its own sorted copy. On a
	// large tenant that is three copies of the asset slice and three sorts —
	// and, while the comparison went through uuid.UUID.String(), an allocation
	// per comparison as well. Sorting in place costs one pass and leaves every
	// kind reading the same order, which is what makes the plan deterministic.
	sortAssets(in.assets)
	in.assessed = map[uuid.UUID]bool{}
	var planned []plannedDrift
	planned = append(planned, p.judgeNewClassInSegment(in, run)...)
	planned = append(planned, p.judgeUnexpectedProtocol(in, run)...)
	planned = append(planned, p.judgePortProfile(in, run)...)
	planned = append(planned, p.judgeNewIssuer(in, run)...)

	// Any asset this pass RAISED on has certainly been assessed by it, and has
	// to be recorded even where the per-kind gates above did not — chiefly
	// `new_class_in_segment`, whose subject is by definition an asset too young
	// to have a baseline of its own. Without this the rollup can put a drift
	// SCORE on an asset whose `risk_assessed_by` does not mention drift, which
	// the inventory reads as "not assessed" beside a number this producer
	// supplied.
	for _, pl := range planned {
		if pl.finding.Subject.Type == findings.SubjectAsset {
			in.assessed[pl.finding.Subject.ID] = true
		}
	}
	return planned
}

// A drift finding must never be about a placeholder class, and the one
// definition of that lives in hygiene.go ([isPlaceholderClass]) — the taxonomy
// decides it, not each producer.
//
// `unknown_host` is a real asset with a real gap rather than a placeholder for
// a thing, but "the first unknown_host on this segment" is a statement about
// our own classification coverage, not about the tenant's network, and a
// segment full of unclassified addresses would raise it on the first one and
// say nothing useful. The hygiene producer says so about the same asset, which
// is where that belongs.

// segmentClass is one (segment, class) pair.
type segmentClass struct {
	segment uuid.UUID
	class   string
}

// judgeNewClassInSegment raises on the FIRST asset of a class the segment has
// never held.
//
// One finding, not one per arriving asset. The registry's own title says "the
// first {detail} seen in its network segment", and fifty printers landing on a
// server VLAN in one afternoon is ONE thing to go and look at — the other
// forty-nine are counted in the evidence rather than given a row each.
func (p *DriftProducer) judgeNewClassInSegment(in *driftInput, run *DriftRun) []plannedDrift {
	type group struct {
		baseline int
		window   []driftAsset
	}
	groups := map[segmentClass]*group{}
	// segmentBaseline is how many assets the segment held before the window. A
	// segment with none has no baseline of its own, and every class on it would
	// read as new.
	segmentBaseline := map[uuid.UUID]int{}
	// classesInBaseline is what the segment DID hold, for the evidence.
	classesInBaseline := map[uuid.UUID]map[string]bool{}

	for _, a := range in.assets {
		if !a.segmentID.Valid {
			continue
		}
		seg := a.segmentID.UUID
		if a.firstSeen.Before(in.cutoff) {
			segmentBaseline[seg]++
		}
		if isPlaceholderClass(a.classKey) {
			continue
		}
		key := segmentClass{segment: seg, class: a.classKey}
		g := groups[key]
		if g == nil {
			g = &group{}
			groups[key] = g
		}
		if a.firstSeen.Before(in.cutoff) {
			g.baseline++
			if classesInBaseline[seg] == nil {
				classesInBaseline[seg] = map[string]bool{}
			}
			classesInBaseline[seg][a.classKey] = true
			continue
		}
		g.window = append(g.window, a)
	}

	// Deterministic order, so two passes over the same data plan the same
	// findings in the same order — which is what makes a diff of two runs
	// readable and a test's expectations stable.
	keys := make([]segmentClass, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].segment != keys[j].segment {
			return uuidLess(keys[i].segment, keys[j].segment)
		}
		return keys[i].class < keys[j].class
	})

	var planned []plannedDrift
	for _, k := range keys {
		g := groups[k]
		if g.baseline > 0 || len(g.window) == 0 {
			continue
		}
		if segmentBaseline[k.segment] == 0 {
			// The segment itself is newer than the window. Nothing on it can be
			// "new to it" yet.
			run.NoBaseline++
			continue
		}

		first := g.window[0]
		for _, a := range g.window[1:] {
			if a.firstSeen.Before(first.firstSeen) ||
				(a.firstSeen.Equal(first.firstSeen) && uuidLess(a.id, first.id)) {
				first = a
			}
		}

		label := k.class
		if c, ok := assetclass.Get(k.class); ok && c.Label != "" {
			label = c.Label
		}

		evidence := p.windowEvidence(in)
		evidence["asset_id"] = first.id.String()
		evidence["segment_id"] = k.segment.String()
		if first.segmentName != "" {
			evidence["segment_name"] = first.segmentName
		}
		evidence["baseline"] = map[string]any{
			"classes_in_segment":           sortedKeys(classesInBaseline[k.segment]),
			"segment_assets_before_window": segmentBaseline[k.segment],
		}
		evidence["observed"] = map[string]any{
			"class":             k.class,
			"class_label":       label,
			"assets_in_window":  len(g.window),
			"first_observed_at": first.firstSeen.Format(time.RFC3339),
		}
		obsKey := k.class + "@" + k.segment.String()
		evidence["observation_key"] = obsKey

		planned = append(planned, p.plan(findings.KindNewClassInSegment,
			producer.Subject{Type: findings.SubjectAsset, ID: first.id}, first.label,
			label, evidence, obsKey))
	}
	return planned
}

// protoAgg is one protocol's history on one asset.
type protoAgg struct {
	firstSeen time.Time
	live      bool
	source    string
	refID     uuid.UUID
}

// judgeUnexpectedProtocol raises on an asset that began speaking something it
// had not spoken before the window.
//
// The subject is the ASSET rather than the endpoint, even though the registry
// allows both. Two reasons, and the second is the one that decides it: the unit
// of investigation is "what is this host doing that it was not", not "what is
// this socket doing"; and a protocol observed on a crypto configuration with no
// endpoint_id — which is most of what the passive sensor writes — has no
// endpoint to be the subject OF, so an endpoint-subject kind would silently drop
// them. Several new protocols on one host are one row listing all of them, which
// loses nothing: unlike the end-of-life producer's per-package findings, there
// is one investigation here, not one per protocol.
func (p *DriftProducer) judgeUnexpectedProtocol(in *driftInput, run *DriftRun) []plannedDrift {
	byAsset := map[uuid.UUID]map[string]*protoAgg{}
	for _, o := range in.protos {
		proto := strings.TrimSpace(o.protocol)
		if proto == "" {
			continue
		}
		m := byAsset[o.assetID]
		if m == nil {
			m = map[string]*protoAgg{}
			byAsset[o.assetID] = m
		}
		agg := m[proto]
		if agg == nil {
			m[proto] = &protoAgg{firstSeen: o.firstSeen, live: o.live, source: o.source, refID: o.refID}
			continue
		}
		if o.firstSeen.Before(agg.firstSeen) {
			agg.firstSeen = o.firstSeen
		}
		if o.live && !agg.live {
			agg.live = true
			agg.source = o.source
			agg.refID = o.refID
		}
	}

	var planned []plannedDrift
	for _, a := range in.assets {
		m := byAsset[a.id]
		if len(m) == 0 {
			continue
		}
		var baseline, fresh []string
		for proto, agg := range m {
			if agg.firstSeen.Before(in.cutoff) {
				baseline = append(baseline, proto)
				continue
			}
			if agg.live {
				fresh = append(fresh, proto)
			}
		}
		if len(baseline) == 0 {
			// Nothing to compare against: this asset has never been observed
			// speaking anything until the window opened.
			run.NoBaseline++
			continue
		}
		// Compared, whatever the answer: an asset whose protocols are all in its
		// baseline WAS assessed, and recording it only when something drifted
		// would make coverage mean "had a finding".
		in.assessed[a.id] = true
		if len(fresh) == 0 {
			continue
		}
		sort.Strings(baseline)
		sort.Strings(fresh)

		observed := make([]map[string]any, 0, len(fresh))
		var earliest time.Time
		for _, proto := range fresh {
			agg := m[proto]
			observed = append(observed, map[string]any{
				"protocol":          proto,
				"first_observed_at": agg.firstSeen.Format(time.RFC3339),
				"source":            agg.source,
				"source_id":         agg.refID.String(),
			})
			if earliest.IsZero() || agg.firstSeen.Before(earliest) {
				earliest = agg.firstSeen
			}
		}

		evidence := p.windowEvidence(in)
		evidence["asset_id"] = a.id.String()
		evidence["baseline"] = map[string]any{"protocols": baseline}
		evidence["observed"] = map[string]any{
			"protocols":         fresh,
			"detail":            observed,
			"first_observed_at": earliest.Format(time.RFC3339),
		}
		obsKey := strings.Join(fresh, ",")
		evidence["observation_key"] = obsKey

		planned = append(planned, p.plan(findings.KindUnexpectedProtocol,
			producer.Subject{Type: findings.SubjectAsset, ID: a.id}, a.label,
			strings.Join(fresh, ", "), evidence, obsKey))
	}
	return planned
}

// portKey is one listening socket, identified the way a port profile means it.
type portKey struct {
	port      int
	transport string
}

func (k portKey) String() string {
	if k.transport == "" || k.transport == "tcp" {
		return strconv.Itoa(k.port)
	}
	return strconv.Itoa(k.port) + "/" + k.transport
}

// portAgg folds every endpoint row for one (port, transport) on one asset.
//
// Folded rather than taken row by row because the endpoint identity index is
// (address, fqdn, port, transport): the same port on two addresses is two rows,
// and a port profile that counted them separately would report 443 as both open
// and closed on a host that moved IP.
type portAgg struct {
	firstSeen time.Time
	lastSeen  time.Time
	anyActive bool
	// endpoints are the rows folded into this (port, transport), in read order.
	// Kept so the finding can name WHICH endpoint opened or closed.
	endpoints []portObservation
}

// judgePortProfile raises when the set of listening ports moved either way.
//
// Opening and closing both fire, and both carry the registry's one score: a port
// opening is the case to chase first, and a port CLOSING unexpectedly is how a
// service that has fallen over looks from the outside.
func (p *DriftProducer) judgePortProfile(in *driftInput, run *DriftRun) []plannedDrift {
	byAsset := map[uuid.UUID]map[portKey]*portAgg{}
	for _, o := range in.ports {
		k := portKey{port: o.port, transport: strings.ToLower(strings.TrimSpace(o.transport))}
		m := byAsset[o.assetID]
		if m == nil {
			m = map[portKey]*portAgg{}
			byAsset[o.assetID] = m
		}
		agg := m[k]
		if agg == nil {
			m[k] = &portAgg{
				firstSeen: o.firstSeen, lastSeen: o.lastSeen, anyActive: o.active,
				endpoints: []portObservation{o},
			}
			continue
		}
		if o.firstSeen.Before(agg.firstSeen) {
			agg.firstSeen = o.firstSeen
		}
		if o.lastSeen.After(agg.lastSeen) {
			agg.lastSeen = o.lastSeen
		}
		agg.anyActive = agg.anyActive || o.active
		agg.endpoints = append(agg.endpoints, o)
	}

	var planned []plannedDrift
	for _, a := range in.assets {
		m := byAsset[a.id]
		if len(m) == 0 {
			continue
		}
		var baseline, opened, closed []portKey
		for k, agg := range m {
			inBaseline := agg.firstSeen.Before(in.cutoff)
			switch {
			case inBaseline:
				baseline = append(baseline, k)
				// Closed INSIDE the window: it was there before the window, it
				// is not active now, and it was still being seen inside the
				// window. A socket last seen before the cutoff closed in the
				// baseline, which is history rather than drift.
				if !agg.anyActive && !agg.lastSeen.Before(in.cutoff) {
					closed = append(closed, k)
				}
			case agg.anyActive:
				opened = append(opened, k)
			}
		}
		if len(baseline) == 0 {
			// No port profile before the window: there is nothing for the
			// current one to have changed FROM.
			run.NoBaseline++
			continue
		}
		in.assessed[a.id] = true
		if len(opened) == 0 && len(closed) == 0 {
			continue
		}
		sortPorts(baseline)
		sortPorts(opened)
		sortPorts(closed)

		evidence := p.windowEvidence(in)
		evidence["asset_id"] = a.id.String()
		evidence["baseline"] = map[string]any{"ports": portStrings(baseline)}
		observed := map[string]any{
			"opened": portStrings(opened),
			"closed": portStrings(closed),
		}
		// The endpoint rows behind the delta. Two shapes on purpose:
		//
		//   *_endpoints  scalar labels ("10.0.0.5:8080"), which the drawer's
		//                drift panel renders by joining — so a person sees WHICH
		//                face changed without opening the raw evidence.
		//   endpoints    the objects, each carrying `endpoint_id`, which is the
		//                drill-through. An array of objects, which the drawer
		//                skips by design rather than turning into a JSON dump.
		//
		// Both are bounded by the writer's evidence cap, which truncates with an
		// explicit marker rather than silently.
		openedEPs, openedRows := endpointEvidence(m, opened, "opened")
		closedEPs, closedRows := endpointEvidence(m, closed, "closed")
		if len(openedEPs) > 0 {
			observed["opened_endpoints"] = openedEPs
		}
		if len(closedEPs) > 0 {
			observed["closed_endpoints"] = closedEPs
		}
		if rows := append(openedRows, closedRows...); len(rows) > 0 {
			observed["endpoints"] = rows
		}
		evidence["observed"] = observed
		obsKey := portDelta(opened, closed, 0)
		evidence["observation_key"] = obsKey

		planned = append(planned, p.plan(findings.KindPortProfileChanged,
			producer.Subject{Type: findings.SubjectAsset, ID: a.id}, a.label,
			portDelta(opened, closed, maxPortsInTitle), evidence, obsKey))
	}
	return planned
}

// endpointEvidence renders the endpoint rows behind one side of a port delta:
// the scalar labels a person reads, and the objects a drill-through needs.
//
// Ports are walked in the caller's already-sorted order and each port's
// endpoints in read order, so the evidence a converged re-run writes is
// byte-identical to the last one — the upsert merges evidence per key, and a
// list whose order churned would rewrite the row every night.
func endpointEvidence(m map[portKey]*portAgg, ports []portKey, change string) ([]any, []any) {
	labels := make([]any, 0, len(ports))
	rows := make([]any, 0, len(ports))
	for _, k := range ports {
		agg := m[k]
		if agg == nil {
			continue
		}
		for _, o := range agg.endpoints {
			labels = append(labels, o.endpointLabel())
			row := map[string]any{
				"endpoint_id": o.endpointID.String(),
				"port":        o.port,
				"transport":   o.transport,
				"change":      change,
			}
			// Address and fqdn only when there is one. An empty string here
			// would render as a blank line in the drawer and read as "this
			// endpoint has no address", which is not what NULL means.
			if o.address != "" {
				row["address"] = o.address
			}
			if o.fqdn != "" {
				row["fqdn"] = o.fqdn
			}
			rows = append(rows, row)
		}
	}
	return labels, rows
}

// maxPortsInTitle caps how many ports the one-line summary names. The full
// delta is in the evidence and in the observation key; a title with ninety
// ports in it is a title nobody reads.
const maxPortsInTitle = 6

// issuerAgg is one issuer's history on one asset.
type issuerAgg struct {
	firstSeen time.Time
	live      bool
	certs     []issuerObservation
}

// judgeNewIssuer raises when an asset presents a certificate from a CA it has
// not presented one from before.
//
// The subject is the ASSET, not the certificate, though the registry allows
// both. The registry's own title is "{subject} presented a certificate from a
// new issuer" — the presenter is the asset — and a CA migration that replaces
// forty certificates on one host is ONE decision to confirm, not forty. The
// certificate-subject alternative also rolls up to the asset only through
// `crypto_implementations.endpoint_id`, which is NULL on much of what the
// passive sensor writes, so half of those findings would be unreachable from
// the asset they are about.
func (p *DriftProducer) judgeNewIssuer(in *driftInput, run *DriftRun) []plannedDrift {
	byAsset := map[uuid.UUID]map[string]*issuerAgg{}
	for _, o := range in.issuers {
		if o.issuerDN == "" {
			continue
		}
		m := byAsset[o.assetID]
		if m == nil {
			m = map[string]*issuerAgg{}
			byAsset[o.assetID] = m
		}
		agg := m[o.issuerDN]
		if agg == nil {
			m[o.issuerDN] = &issuerAgg{firstSeen: o.firstSeen, live: o.live, certs: []issuerObservation{o}}
			continue
		}
		if o.firstSeen.Before(agg.firstSeen) {
			agg.firstSeen = o.firstSeen
		}
		agg.live = agg.live || o.live
		if !containsCert(agg.certs, o.certID) {
			agg.certs = append(agg.certs, o)
		}
	}

	var planned []plannedDrift
	for _, a := range in.assets {
		m := byAsset[a.id]
		if len(m) == 0 {
			continue
		}
		var baseline, fresh []string
		for dn, agg := range m {
			if agg.firstSeen.Before(in.cutoff) {
				baseline = append(baseline, dn)
				continue
			}
			if agg.live {
				fresh = append(fresh, dn)
			}
		}
		if len(baseline) == 0 {
			// This asset has never presented a certificate before the window.
			// Its first issuer is not a CHANGE of issuer.
			run.NoBaseline++
			continue
		}
		in.assessed[a.id] = true
		if len(fresh) == 0 {
			continue
		}
		sort.Strings(baseline)
		sort.Strings(fresh)

		observed := make([]map[string]any, 0, len(fresh))
		var earliest time.Time
		for _, dn := range fresh {
			agg := m[dn]
			certs := make([]map[string]any, 0, len(agg.certs))
			for _, c := range agg.certs {
				certs = append(certs, map[string]any{
					"certificate_id":     c.certID.String(),
					"fingerprint_sha256": c.fingerprint,
				})
			}
			observed = append(observed, map[string]any{
				"issuer_dn":         dn,
				"issuer":            issuerLabel(dn),
				"first_observed_at": agg.firstSeen.Format(time.RFC3339),
				"certificates":      certs,
			})
			if earliest.IsZero() || agg.firstSeen.Before(earliest) {
				earliest = agg.firstSeen
			}
		}

		baselineLabels := make([]string, 0, len(baseline))
		for _, dn := range baseline {
			baselineLabels = append(baselineLabels, issuerLabel(dn))
		}

		evidence := p.windowEvidence(in)
		evidence["asset_id"] = a.id.String()
		evidence["baseline"] = map[string]any{
			"issuer_dns": baseline,
			"issuers":    baselineLabels,
		}
		evidence["observed"] = map[string]any{
			"issuer_dns":        fresh,
			"detail":            observed,
			"first_observed_at": earliest.Format(time.RFC3339),
		}
		obsKey := strings.Join(fresh, "|")
		evidence["observation_key"] = obsKey

		detail := issuerLabel(fresh[0])
		if len(fresh) > 1 {
			detail = fmt.Sprintf("%s and %d more", detail, len(fresh)-1)
		}
		planned = append(planned, p.plan(findings.KindNewIssuer,
			producer.Subject{Type: findings.SubjectAsset, ID: a.id}, a.label,
			detail, evidence, obsKey))
	}
	return planned
}

// ---------------------------------------------------------------------------
// write
// ---------------------------------------------------------------------------

// openRow is one of this producer's existing rows, as the write phase needs it.
type openRow struct {
	state          string
	workflow       string
	observationKey string
}

type openKey struct {
	kind        string
	subjectType string
	subjectID   uuid.UUID
}

// write commits the pass: the reopen decisions, every finding, then the sweep —
// ONE transaction, because a sweep that lands without the upserts that justify
// it inactivates live findings.
func (p *DriftProducer) write(ctx context.Context, tenantID uuid.UUID, planned []plannedDrift,
	assessed []uuid.UUID, run *DriftRun) error {
	return shareddatabase.WithTenantTx(ctx, p.db, tenantID, func(tx *sql.Tx) error {
		open, err := p.readOpenRows(ctx, tx, tenantID)
		if err != nil {
			return err
		}

		seen := map[string][]producer.Subject{}
		for _, kind := range driftKinds {
			seen[kind] = nil
		}

		for _, pl := range planned {
			k := openKey{
				kind:        pl.finding.Kind,
				subjectType: pl.finding.Subject.Type,
				subjectID:   pl.finding.Subject.ID,
			}
			if prior, ok := open[k]; ok && needsReopen(prior, pl.observationKey) {
				// Resolve, then Upsert: the writer's own resurfacing path. The
				// row goes INACTIVE and comes straight back ACTIVE with
				// workflow_status reset to NEW (SUPPRESSED excepted, which is a
				// standing decision about the condition rather than about one
				// episode of it), resurfaced_at stamped and its history intact.
				// Without it a person who resolved "started speaking SSH" is
				// never told about "started speaking RDP" on the same host.
				if _, err := p.writer.Resolve(ctx, tx, tenantID, pl.finding.Kind, pl.finding.Subject); err != nil {
					return err
				}
				run.Reopened++
			}
			if _, err := p.writer.Upsert(ctx, tx, tenantID, pl.finding); err != nil {
				return err
			}
			run.Raised++
			seen[pl.finding.Kind] = append(seen[pl.finding.Kind], pl.finding.Subject)
		}

		// The coverage claim, in the SAME transaction as the upserts and the
		// sweep: a pass that dies half way rolls it back with them, and the
		// asset keeps whatever the last COMPLETED pass gave it. The warm-up
		// branch never reaches here at all, which is the point — a pass that
		// could not evaluate has not covered anything.
		if _, err := p.writer.MarkAssessed(ctx, tx, tenantID, assessed); err != nil {
			return err
		}

		for _, kind := range driftKinds {
			n, err := p.writer.Sweep(ctx, tx, tenantID, kind, seen[kind])
			if err != nil {
				return err
			}
			run.Resolved += n
		}
		return nil
	})
}

// needsReopen decides whether an existing row is about a DIFFERENT observation
// that a person has already signed off on the old version of.
//
// Four conditions, and each of them is load-bearing:
//
//   - ACTIVE. An INACTIVE row resurfaces on its own through Upsert, which
//     already resets the workflow status.
//   - the workflow status has MOVED off NEW. A row nobody has touched is
//     already in the triage queue; resolving and re-raising it would add two
//     history rows and an occurrence for no change a reader could see.
//   - not SUPPRESSED. Suppression is a standing decision about the condition,
//     and Upsert preserves it across a resurfacing anyway.
//   - the stored key is non-empty AND different. Empty means the row predates
//     this producer writing an observation key, and treating "I do not know
//     what this row was about" as "it was about something else" would re-open
//     every human-resolved drift finding once, on upgrade, for nothing.
func needsReopen(prior openRow, observationKey string) bool {
	return prior.state == producer.StateActive &&
		prior.workflow != workflowNew &&
		prior.workflow != workflowSuppressed &&
		prior.observationKey != "" &&
		prior.observationKey != observationKey
}

// The two workflow statuses this producer reasons about, spelled as
// findings_workflow_status_check spells them.
const (
	workflowNew        = "NEW"
	workflowSuppressed = "SUPPRESSED"
)

// readOpenRows loads this producer's non-archived rows for the tenant.
//
// In the WRITE transaction rather than the read one: the thing it decides is
// whether a person's workflow decision still applies, and a person can make
// that decision between the two phases.
func (p *DriftProducer) readOpenRows(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID) (map[openKey]openRow, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT kind, subject_type, subject_id, detection_state, workflow_status,
		       coalesce(evidence ->> 'observation_key', '')
		FROM findings
		WHERE tenant_id = $1 AND producer = $2
		  AND control_id IS NULL
		  AND detection_state <> 'ARCHIVED'`, tenantID, findings.ProducerDrift)
	if err != nil {
		return nil, fmt.Errorf("read open drift findings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := map[openKey]openRow{}
	for rows.Next() {
		var k openKey
		var r openRow
		if err := rows.Scan(&k.kind, &k.subjectType, &k.subjectID, &r.state, &r.workflow, &r.observationKey); err != nil {
			return nil, fmt.Errorf("scan open drift finding: %w", err)
		}
		out[k] = r
	}
	return out, rows.Err()
}

// driftKinds is every kind THIS PASS asserts, which is also every kind it may
// sweep. Derived from the registry rather than listed, so a kind added to the
// `drift` producer without a sweep here is impossible — except for the kinds
// listed in driftKindsNotFromBaseline, which this pass does not evaluate.
//
// A Sweep is a full statement: "everything of this kind I do not re-assert has
// gone away." Sweeping a kind this pass cannot evaluate therefore inactivates
// every open row of it on the next run, silently. The exclusion list is the
// only thing standing between a correctly-raised finding and its quiet
// disappearance, which is why TestDriftSweepCoversEveryKindItCanAssert pins it.
var driftKinds = func() []string {
	var out []string
	for _, k := range findings.All {
		if k.Producer == findings.ProducerDrift && !driftKindsNotFromBaseline[k.Key] {
			out = append(out, k.Key)
		}
	}
	return out
}()

// driftKindsNotFromBaseline are `drift` kinds raised somewhere OTHER than this
// baseline pass, and therefore outside what it may sweep.
//
//   - host_key_changed: raised by device-interrogation-service when a managed
//     device presents an SSH host key that differs from the one pinned to it.
//     It is genuine drift — the device's identity changed — but this pass has
//     no baseline of host keys to compare and would resolve every open row on
//     its first run. It is resolved by the interrogation that next succeeds
//     against the device.
var driftKindsNotFromBaseline = map[string]bool{
	findings.KindHostKeyChanged: true,
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// plan builds one finding from the registry's severity, score and title.
//
// Severity and score come from the registry row rather than from a number typed
// here, so "the drift scores are provisional and get revisited" (REGISTRIES.md)
// stays a statement about the YAML and not about four literals in Go.
func (p *DriftProducer) plan(kind string, subject producer.Subject, label, detail string,
	evidence map[string]any, observationKey string) plannedDrift {
	k, ok := findings.Get(findings.ProducerDrift, kind)
	severity := producer.SeverityMedium
	score := 0
	if ok {
		severity = k.DefaultSeverity
		score = k.Score
	}
	return plannedDrift{
		finding: producer.Finding{
			Kind:         kind,
			Subject:      subject,
			SubjectLabel: label,
			Severity:     severity,
			Score:        score,
			Summary:      driftSummary(kind, label, detail),
			Evidence:     evidence,
			// measured: every input is something this platform observed in the
			// tenant's own estate. There is no catalogue behind a drift
			// judgement and no model in it.
			SourceKind: producer.SourceMeasured,
		},
		observationKey: observationKey,
	}
}

// windowEvidence is the part of every drift finding's evidence that says what
// it was compared against and when.
//
// On every finding, not just the first: a person reading a drift finding three
// weeks later needs to know the window it was judged under, and the tenant may
// have changed it since.
func (p *DriftProducer) windowEvidence(in *driftInput) map[string]any {
	return map[string]any{
		"window_days":  in.baselineDays,
		"window_start": in.cutoff.Format(time.RFC3339),
		"window_end":   in.now.Format(time.RFC3339),
		"evaluated_at": in.now.Format(time.RFC3339),
	}
}

// coveredAssets is the judge's coverage set as a sorted slice, so two passes
// over the same population hand the writer the same list.
//
// Named for what it returns rather than `assessedAssets`, which is the hygiene
// producer's test helper for READING producer_assessments back — one package,
// two different things.
func coveredAssets(in *driftInput) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(in.assessed))
	for id := range in.assessed {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return uuidLess(out[i], out[j]) })
	return out
}

// sortAssets orders the population by id, in place, so the plan a pass builds
// is deterministic: two passes over the same data plan the same findings in the
// same order, which is what makes a diff of two runs readable and a test's
// expectations stable.
func sortAssets(assets []driftAsset) {
	sort.Slice(assets, func(i, j int) bool { return uuidLess(assets[i].id, assets[j].id) })
}

// uuidLess orders two UUIDs by their bytes.
//
// Identical to the ordering of their canonical strings — uuid.String() is
// lowercase hex with dashes at fixed positions, and lowercase hex sorts the
// same way as the bytes behind it — but without allocating a 36-byte string on
// every comparison, which a sort does O(n log n) times.
func uuidLess(a, b uuid.UUID) bool { return bytes.Compare(a[:], b[:]) < 0 }

// driftSummary renders the registry's title_template.
func driftSummary(kind, subject, detail string) string {
	k, ok := findings.Get(findings.ProducerDrift, kind)
	if !ok {
		return subject + " changed (" + detail + ")"
	}
	s := strings.ReplaceAll(k.TitleTemplate, "{subject}", subject)
	return strings.ReplaceAll(s, "{detail}", detail)
}

// issuerLabel reduces an issuer DN to the name a person recognises: the CN,
// falling back to the O, falling back to the whole DN.
//
// Deliberately tolerant. An issuer DN arrives from whatever presented the
// certificate and is not ours to trust the shape of; a parser that returned ""
// on anything unexpected would put a blank in a finding title.
func issuerLabel(dn string) string {
	if cn := dnAttribute(dn, "CN"); cn != "" {
		return cn
	}
	if o := dnAttribute(dn, "O"); o != "" {
		return o
	}
	return dn
}

// dnAttribute pulls one RDN value out of a DN string.
//
// Splits on commas, which is wrong for a value containing an escaped comma
// (`O=Example\, Inc`) — it would return `Example\`. Accepted: the result is a
// display label, the un-split DN is in the evidence beside it, and a full RFC
// 4514 parser for a label is more code than the failure costs.
func dnAttribute(dn, attr string) string {
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if len(part) > len(attr)+1 &&
			strings.EqualFold(part[:len(attr)], attr) && part[len(attr)] == '=' {
			return strings.TrimSpace(part[len(attr)+1:])
		}
	}
	return ""
}

// portDelta renders the opened/closed sets as the one-line detail.
//
// `limit` 0 means "all of it", which is what the observation key uses: a key
// that dropped entries would make two genuinely different port changes compare
// equal, and a person's decision about one would silently cover the other.
func portDelta(opened, closed []portKey, limit int) string {
	parts := make([]string, 0, len(opened)+len(closed))
	for _, k := range opened {
		parts = append(parts, "+"+k.String())
	}
	for _, k := range closed {
		parts = append(parts, "-"+k.String())
	}
	if limit > 0 && len(parts) > limit {
		more := len(parts) - limit
		parts = append(parts[:limit:limit], fmt.Sprintf("and %d more", more))
	}
	return strings.Join(parts, ", ")
}

func portStrings(ks []portKey) []string {
	out := make([]string, 0, len(ks))
	for _, k := range ks {
		out = append(out, k.String())
	}
	return out
}

func sortPorts(ks []portKey) {
	sort.Slice(ks, func(i, j int) bool {
		if ks[i].port != ks[j].port {
			return ks[i].port < ks[j].port
		}
		return ks[i].transport < ks[j].transport
	})
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func containsCert(certs []issuerObservation, id uuid.UUID) bool {
	for _, c := range certs {
		if c.certID == id {
			return true
		}
	}
	return false
}
