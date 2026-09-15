// Package estate seeds ONE realistic phase-3 inventory, and states what a full
// producer pass over it produces.
//
// It exists because the Gate 3 proof spans two Go modules that cannot import
// each other. The six finding producers live in
// `inventory-service/internal/producers` (an internal package of that module);
// the framework evaluator, the reconcile and the score rollup live in
// `compliance-engine/internal/services`. Neither can call the other, so the
// end-to-end claim — "a real producer pass makes the Inventory Hygiene and
// Lifecycle frameworks score" — has to be made in two halves:
//
//	half A  inventory-service/internal/jobs/gate3_producer_pass_integration_test.go
//	        seeds this estate, runs the REAL FindingProducerJob over it, and
//	        asserts the database now holds exactly [Estate.ExpectedFindings],
//	        [Estate.ExpectedCoverage] and [Estate.ExpectedFacts].
//
//	half B  compliance-engine/internal/services/gate3_frameworks_integration_test.go
//	        seeds the same estate, calls [Estate.ApplyProducerOutput] to write
//	        that same expected output, and runs the real reconcile over it.
//
// The link between them is half A: the expectations below are not a guess about
// what the producers do, they are a claim half A fails on if it stops being
// true. Change a producer and half A goes red, which is what forces this file —
// and therefore half B's inputs — to be brought back into line. Seeding half B
// by hand instead would let the compliance side keep scoring an inventory the
// producers had stopped producing, which is exactly the drift the gate is for.
//
// Everything here is deliberately concrete. The estate is small enough to hold
// in your head and wide enough that every producer has something to say:
//
//	web-01      owned, sited, monitoring. End-of-life OS; an openssl install
//	            that is both past EOL and carries a critical CVE; a TLS 1.0
//	            configuration on 443. The busiest asset in the estate.
//	db-01       owned, sited, monitoring. A SUPPORTED OS (the control case for
//	            LC-001: a real date that has not passed, which must read PASS
//	            and not NOT ASSESSED) and hardware past end of support. Its
//	            other install is in no catalogue at all — the unidentifiable
//	            case, which must raise nothing rather than "clean".
//	printer-7   no owner, no class, no location: the three record-quality
//	            hygiene kinds, on an asset a collector saw this morning.
//	sw-01       managed over Telnet (mgmt.plaintext), with the socket to match.
//	ghost-01    archived. Judged by nothing, and the far end of the orphan edge.
//	web-01-dup  pending_approval, named with web-01 in an open merge proposal.
//
// Platform-scoped rows (the EOL and vulnerability catalogues, the algorithm
// catalogue) carry no tenant_id, so the tenant CASCADE does not reach them:
// every one is registered for explicit cleanup, or a row left behind answers a
// later test's lookup.
package estate

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Days the estate is built around. Named rather than inline because half A
// asserts rungs that depend on them and half B asserts control statuses that
// depend on the same numbers.
const (
	// SettledDays is how long ago every asset was first discovered. Past the
	// drift producer's default 30-day baseline window, so its pass is a real
	// pass and not a warm-up no-op.
	SettledDays = 200

	// OSEOLDaysAgo puts web-01's operating system past end of life but inside
	// the eol ladder's `longPastDays` (365), so it lands on the middle rung.
	OSEOLDaysAgo = 200
	// SoftwareEOLDaysAgo does the same for the openssl install.
	SoftwareEOLDaysAgo = 40
	// HardwareEOSDaysAgo puts db-01's chassis years past vendor support.
	HardwareEOSDaysAgo = 800
	// SupportedOSDaysAhead is db-01's operating system: a resolved date that
	// has NOT passed. It is what separates "supported" from "not assessed".
	SupportedOSDaysAhead = 900

	// StaleDays is how long ago db-01's second software install was last seen:
	// past the hygiene stale ladder's first rung.
	//
	// The stale subject is an INSTALL rather than an asset on purpose, and the
	// purpose is two-fold. It is the harder case — a child subject the Findings
	// drawer has to resolve back to its host — and it leaves IH-004 ("no stale
	// asset records") with a genuine PASS, which is what makes the Inventory
	// Hygiene score a number that can move rather than a flat zero. A framework
	// where every control fails scores 0 whatever you do to it, and a score that
	// cannot move cannot prove anything about the pass that produced it.
	StaleDays = 95

	// CVSSScore is the openssl advisory's base score. ×10 is the finding's
	// score, and the highest number anywhere in the estate — so it is what
	// web-01's risk rollup must land on.
	CVSSScore = 9.8
	// WeakAlgorithmRisk is the catalogue risk of the algorithm linked to
	// web-01's TLS 1.0 configuration.
	WeakAlgorithmRisk = 85
)

// Estate is the seeded inventory. Every id is a handle the two halves assert
// against by name.
type Estate struct {
	Tenant uuid.UUID

	// --- assets
	Web     uuid.UUID
	DB      uuid.UUID
	Printer uuid.UUID
	Switch  uuid.UUID
	Ghost   uuid.UUID
	WebDup  uuid.UUID
	// --- endpoints
	WebTLS     uuid.UUID
	TelnetPort uuid.UUID
	// --- software installs
	OpenSSLInstall uuid.UUID
	UncataloguedSW uuid.UUID
	// --- relationships
	OrphanEdge uuid.UUID
	LiveEdge   uuid.UUID
	// --- crypto
	WeakConfig uuid.UUID
	// --- the open merge proposal naming Web and WebDup
	Proposal uuid.UUID

	// CVEID is the advisory the openssl install matches.
	CVEID string

	// eol catalogue row ids, so the facts can name the row they came from
	// exactly as the producer does (`catalog:eol:<id>`).
	osRow, swRow, hwRow, supportedOSRow uuid.UUID
}

// Seed writes the estate for one tenant. `owner` must be the superuser handle
// (RLS-exempt), which is what every producer fixture in the repository uses to
// set up.
func Seed(t *testing.T, owner *sql.DB, tenant uuid.UUID) *Estate {
	t.Helper()
	e := &Estate{Tenant: tenant, CVEID: "CVE-2026-98765"}

	settled := daysFromNow(-SettledDays)

	e.Web = e.asset(t, owner, assetSpec{
		hostname: "web-01", class: "server", path: "hardware.computer.server",
		owner: "ops@example.test", site: "DC1", status: "monitoring",
		firstSeen: settled, lastSeen: daysFromNow(0),
	})
	e.DB = e.asset(t, owner, assetSpec{
		hostname: "db-01", class: "server", path: "hardware.computer.server",
		owner: "ops@example.test", site: "DC1", status: "monitoring",
		firstSeen: settled, lastSeen: daysFromNow(0),
	})
	e.Printer = e.asset(t, owner, assetSpec{
		hostname: "printer-7", class: "unknown_host", path: "unknown_host",
		status: "monitoring", firstSeen: settled, lastSeen: daysFromNow(0),
	})
	e.Switch = e.asset(t, owner, assetSpec{
		hostname: "sw-01", class: "switch", path: "hardware.network_device.switch",
		owner: "neteng@example.test", site: "DC1", status: "monitoring",
		firstSeen: settled, lastSeen: daysFromNow(0),
	})
	e.Ghost = e.asset(t, owner, assetSpec{
		hostname: "ghost-01", class: "server", path: "hardware.computer.server",
		status: "archived", firstSeen: settled, lastSeen: daysFromNow(-400),
	})
	e.WebDup = e.asset(t, owner, assetSpec{
		hostname: "web-01-dup", class: "server", path: "hardware.computer.server",
		status: "pending_approval", firstSeen: daysFromNow(-2), lastSeen: daysFromNow(0),
	})

	// --- facts a collector would have written.
	fact(t, owner, tenant, e.Web, facts.KeyOSName, `"Ubuntu"`)
	fact(t, owner, tenant, e.Web, facts.KeyOSVersion, `"18.04.6 LTS"`)
	fact(t, owner, tenant, e.DB, facts.KeyOSName, `"Ubuntu"`)
	fact(t, owner, tenant, e.DB, facts.KeyOSVersion, `"24.04.1 LTS"`)
	fact(t, owner, tenant, e.DB, facts.KeyHWVendor, `"Dell"`)
	fact(t, owner, tenant, e.DB, facts.KeyHWModel, `"PowerEdge VP640"`)
	// The interrogation facts the configuration producer reads. `true` is the
	// finding; sw-01 is the only asset managed in the clear.
	fact(t, owner, tenant, e.Switch, facts.KeyMgmtPlaintext, `true`)
	fact(t, owner, tenant, e.Switch, facts.KeyMgmtProtocol, `"telnet"`)

	// --- endpoints. `first_seen_at` is settled too: the drift producer's port
	// profile baseline is everything observed BEFORE its window, and a socket
	// that first appeared today has nothing to have changed from.
	e.WebTLS = endpoint(t, owner, tenant, e.Web, "198.51.100.11", 443, "tcp", "", "", settled)
	e.TelnetPort = endpoint(t, owner, tenant, e.Switch, "198.51.100.12", 23, "tcp", "telnetd", "banner", settled)

	// --- software. openssl is in both catalogues; the second install is in
	// neither, and must therefore produce NOTHING rather than a clean bill.
	opensslProduct := uuid.New()
	execute(t, owner, `INSERT INTO software_products (id, tenant_id, name, vendor, version, cpe)
	                   VALUES ($1, $2, 'openssl', 'OpenSSL', '3.0.6', $3)`,
		opensslProduct, tenant, opensslCPE)
	e.OpenSSLInstall = uuid.New()
	execute(t, owner, `INSERT INTO software_installs (id, tenant_id, asset_id, product_id, status)
	                   VALUES ($1, $2, $3, $4, 'active')`, e.OpenSSLInstall, tenant, e.Web, opensslProduct)

	uncatalogued := uuid.New()
	execute(t, owner, `INSERT INTO software_products (id, tenant_id, name, vendor, version)
	                   VALUES ($1, $2, 'acme-internal-tool', 'Acme Internal', '1.0.0')`, uncatalogued, tenant)
	e.UncataloguedSW = uuid.New()
	execute(t, owner, `INSERT INTO software_installs (id, tenant_id, asset_id, product_id, status, last_seen_at)
	                   VALUES ($1, $2, $3, $4, 'active', $5)`,
		e.UncataloguedSW, tenant, e.DB, uncatalogued, daysFromNow(-StaleDays))

	// --- relationships. One dangles into the archived asset; one does not.
	e.OrphanEdge = uuid.New()
	execute(t, owner, `INSERT INTO asset_relationships (id, tenant_id, from_asset_id, to_asset_id, type, status)
	                   VALUES ($1, $2, $3, $4, 'connects_to', 'active')`, e.OrphanEdge, tenant, e.Web, e.Ghost)
	e.LiveEdge = uuid.New()
	execute(t, owner, `INSERT INTO asset_relationships (id, tenant_id, from_asset_id, to_asset_id, type, status)
	                   VALUES ($1, $2, $3, $4, 'connects_to', 'active')`, e.LiveEdge, tenant, e.Web, e.DB)

	// --- crypto: a TLS 1.0 configuration with one weak catalogue component.
	//
	// Into the PARTITIONED table rather than the view, for the reason the drift
	// producer's own fixture gives: inserting through the view would be testing
	// Postgres's auto-updatable-view rules rather than the producers. Settled
	// dates, so the drift producer has a protocol baseline for this asset.
	e.WeakConfig = uuid.New()
	execute(t, owner, `INSERT INTO crypto_implementations_partitioned
	                     (id, tenant_id, asset_id, endpoint_id, protocol, protocol_version,
	                      discovery_method, risk_score, first_discovered_at, created_at)
	                   VALUES ($1, $2, $3, $4, 'TLS'::public.protocol_type, 'TLS1.0', 'active', 0, $5, $5)`,
		e.WeakConfig, tenant, e.Web, e.WebTLS, settled)
	algID := uuid.New()
	execute(t, owner, `INSERT INTO algorithms (id, name, code, category, strength, deprecation_status, risk_score, is_pqc, primitive)
	                   VALUES ($1, 'VP-GATE3-RC4', 'VP-GATE3-RC4', 'symmetric', 'weak', 'deprecated', $2, false, 'ae')`,
		algID, WeakAlgorithmRisk)
	t.Cleanup(func() { _, _ = owner.Exec(`DELETE FROM algorithms WHERE id = $1`, algID) })
	execute(t, owner, `INSERT INTO crypto_implementation_algorithms (crypto_implementation_id, algorithm_id, algorithm_type, is_inferred)
	                   VALUES ($1, $2, 'symmetric', false)`, e.WeakConfig, algID)

	// --- the open merge proposal. web-01-dup is the newly-seen half, web-01 the
	// settled candidate; both records carry duplicate_suspected.
	e.Proposal = mergeProposal(t, owner, tenant, e.WebDup, e.Web)

	// --- the platform catalogues.
	e.osRow = eolRow(t, owner, "os", "Canonical", "Ubuntu", "18.04", daysFromNow(-OSEOLDaysAgo))
	e.supportedOSRow = eolRow(t, owner, "os", "Canonical", "Ubuntu", "24.04", daysFromNow(SupportedOSDaysAhead))
	e.swRow = eolRow(t, owner, "software", "OpenSSL", "openssl", "3.0", daysFromNow(-SoftwareEOLDaysAgo))
	e.hwRow = eolRow(t, owner, "hardware", "Dell", "PowerEdge VP640", "vp640", daysFromNow(-HardwareEOSDaysAgo))
	advisory(t, owner, e.CVEID, CVSSScore,
		`{"cpe":"cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*","version_end_excluding":"3.0.7"}`)

	return e
}

// opensslCPE is stored lowercase, exactly as the SBOM writer folds it.
const opensslCPE = "cpe:2.3:a:openssl:openssl:3.0.6:*:*:*:*:*:*:*"

// ---------------------------------------------------------------------------
// What a full producer pass produces
// ---------------------------------------------------------------------------

// Finding is one row the producers are expected to have written.
//
// Severity and score are NOT spelled out here. For a laddered kind the estate
// names the RUNG and [Estate.Verdict] reads the pair out of the registry, so
// this file can never become a second opinion about what a rung is worth; for
// the two kinds whose number comes from outside the registry — a CVSS base
// score, an algorithm's catalogue risk — it names the source instead.
type Finding struct {
	Producer    string
	Kind        string
	SubjectType string
	Subject     uuid.UUID

	// Rung is the registry ladder rung this subject must land on (rungs are
	// ordered worst-last). -1 for a kind with no ladder.
	Rung int
	// Severity and Score override the registry, for the kinds whose number is
	// computed from a catalogue rather than declared: `known_vulnerability`
	// (CVSS ×10) and `weak_configuration` (the worst component's risk).
	Severity string
	Score    int
}

// Name is the estate's own name for an id, so a failure message reads
// "printer-7" rather than a uuid nobody can place.
func (e *Estate) Name(id uuid.UUID) string {
	for name, known := range map[string]uuid.UUID{
		"web-01": e.Web, "db-01": e.DB, "printer-7": e.Printer, "sw-01": e.Switch,
		"ghost-01": e.Ghost, "web-01-dup": e.WebDup,
		"web-01:443": e.WebTLS, "sw-01:23": e.TelnetPort,
		"openssl install": e.OpenSSLInstall, "uncatalogued install": e.UncataloguedSW,
		"orphan edge": e.OrphanEdge, "live edge": e.LiveEdge,
		"web-01 TLS 1.0 configuration": e.WeakConfig,
	} {
		if known == id {
			return name
		}
	}
	return id.String()
}

// Label maps [Estate.Name] over a list of id strings.
func (e *Estate) Label(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, s := range ids {
		if id, err := uuid.Parse(s); err == nil {
			out = append(out, e.Name(id))
			continue
		}
		out = append(out, s)
	}
	return out
}

// Key is the identity half A compares on.
func (f Finding) Key() string {
	return fmt.Sprintf("%s/%s %s:%s", f.Producer, f.Kind, f.SubjectType, f.Subject)
}

// Verdict is the (severity, score) pair a finding must carry, resolved the same
// way for the half that ASSERTS it and the half that writes it.
func (e *Estate) Verdict(t *testing.T, f Finding) (string, int) {
	t.Helper()
	if f.Severity != "" {
		return f.Severity, f.Score
	}
	kind, ok := findings.Get(f.Producer, f.Kind)
	if !ok {
		t.Fatalf("the estate names a finding kind the registry does not have: %s/%s", f.Producer, f.Kind)
	}
	if f.Rung >= 0 {
		if f.Rung >= len(kind.Rungs) {
			t.Fatalf("%s/%s has %d rungs; the estate expects rung %d", f.Producer, f.Kind, len(kind.Rungs), f.Rung)
		}
		return kind.Rungs[f.Rung].Severity, kind.Rungs[f.Rung].Score
	}
	return kind.DefaultSeverity, kind.Score
}

// ExpectedFindings is every ACTIVE finding a full pass over this estate leaves
// behind, and nothing else.
//
// Ordered by producer so a diff reads in the order runTenant runs them.
func (e *Estate) ExpectedFindings() []Finding {
	const noLadder = -1
	return []Finding{
		// eol: web-01's operating system (200 days past, inside the ladder's
		// 365-day "long past" boundary, so the middle rung), its openssl
		// install (40 days past, same rung), db-01's chassis (800 days past —
		// the worst rung).
		//
		// db-01's OWN operating system resolves to a date in the future — a
		// match with nothing to report — and its second install resolves to
		// nothing at all. Neither raises, for different reasons, and the
		// difference is the whole point of the Lifecycle framework.
		{Producer: findings.ProducerEOL, Kind: findings.KindOSEndOfLife, SubjectType: findings.SubjectAsset, Subject: e.Web, Rung: 1},
		{Producer: findings.ProducerEOL, Kind: findings.KindSoftwareEndOfLife, SubjectType: findings.SubjectSoftwareInstall, Subject: e.OpenSSLInstall, Rung: 1},
		{Producer: findings.ProducerEOL, Kind: findings.KindHardwareEndOfSupport, SubjectType: findings.SubjectAsset, Subject: e.DB, Rung: 2},

		// vulnerability: one advisory, matched by CPE, on the INSTALL. Score is
		// the CVSS base score ×10 and the severity is its published band.
		{Producer: findings.ProducerVulnerability, Kind: findings.KindKnownVulnerability, SubjectType: findings.SubjectSoftwareInstall, Subject: e.OpenSSLInstall,
			Rung: noLadder, Severity: "critical", Score: int(CVSSScore * 10)},

		// crypto: the TLS 1.0 configuration with a weak catalogue component.
		// Worst-component-wins, so the score IS the algorithm's catalogue risk.
		{Producer: findings.ProducerCrypto, Kind: findings.KindWeakConfiguration, SubjectType: findings.SubjectCryptoConfiguration, Subject: e.WeakConfig,
			Rung: noLadder, Severity: "high", Score: WeakAlgorithmRisk},

		// configuration: sw-01 is managed in the clear, on the asset (from the
		// interrogation fact) and on the socket that carries it (from the rule
		// table). Two subjects, one kind — which is why the sweep has to be
		// per-kind rather than per-subject-type.
		{Producer: findings.ProducerConfiguration, Kind: findings.KindPlaintextManagement, SubjectType: findings.SubjectAsset, Subject: e.Switch, Rung: noLadder},
		{Producer: findings.ProducerConfiguration, Kind: findings.KindPlaintextManagement, SubjectType: findings.SubjectEndpoint, Subject: e.TelnetPort, Rung: noLadder},

		// hygiene: printer-7's three record-quality problems, the stale install
		// on db-01, the orphan edge, and the duplicate on BOTH halves of the
		// contested pair.
		{Producer: findings.ProducerHygiene, Kind: findings.KindNoOwner, SubjectType: findings.SubjectAsset, Subject: e.Printer, Rung: noLadder},
		{Producer: findings.ProducerHygiene, Kind: findings.KindNoClass, SubjectType: findings.SubjectAsset, Subject: e.Printer, Rung: noLadder},
		{Producer: findings.ProducerHygiene, Kind: findings.KindNoLocation, SubjectType: findings.SubjectAsset, Subject: e.Printer, Rung: noLadder},
		{Producer: findings.ProducerHygiene, Kind: findings.KindStale, SubjectType: findings.SubjectSoftwareInstall, Subject: e.UncataloguedSW, Rung: 1},
		{Producer: findings.ProducerHygiene, Kind: findings.KindOrphanRelationship, SubjectType: findings.SubjectRelationship, Subject: e.OrphanEdge, Rung: noLadder},
		{Producer: findings.ProducerHygiene, Kind: findings.KindDuplicateSuspected, SubjectType: findings.SubjectAsset, Subject: e.Web, Rung: noLadder},
		{Producer: findings.ProducerHygiene, Kind: findings.KindDuplicateSuspected, SubjectType: findings.SubjectAsset, Subject: e.WebDup, Rung: noLadder},

		// drift raises nothing: the estate has been settled for 200 days and
		// nothing in it changed inside the baseline window. That it RAN is
		// visible in the coverage below, which is the honest signal — a drift
		// producer with nothing to say still has to have looked.
	}
}

// ExpectedCoverage is the `producer_assessments` record a full pass leaves:
// producer → the assets it claims to have evaluated.
//
// Coverage is a RECORD, not an inference (ADR-0005 D4, workstream 3.2), and the
// exclusions below are each a decision:
//
//   - the ARCHIVED asset is claimed by nobody. Every producer drops it.
//   - `eol` claims web-01 and db-01: the two with an operating system, hardware
//     or software to look up. printer-7 and sw-01 have none, and claiming them
//     would turn "there was nothing to ask" into "the catalogue had nothing
//     against it".
//   - `vulnerability` claims web-01 only. db-01's install carries neither a CPE
//     nor a PURL, so it is unidentifiable — dropped and counted, never matched
//     — and an asset whose only package cannot be identified has not been
//     checked for vulnerabilities.
//   - `crypto` claims web-01 — the only asset where a component actually
//     resolved against the algorithm catalogue. Score 0 with nothing resolved
//     is NOT ASSESSED, and claiming it would render that as assessed-clean.
//   - `configuration` claims web-01 and sw-01: an explicit mgmt.plaintext fact
//     of either value, or at least one endpoint the rule table ran over.
//   - `hygiene` claims every LIVE asset it read, the pending_approval half of
//     the merge pair included: unlike a catalogue producer it has no "nothing
//     to look up" case, because every question it asks is answerable from the
//     row itself. Only the archived asset is out, because it is not read.
//   - `drift` claims the two assets with a baseline of their own — a port
//     profile or a protocol observed before the window opened. An asset with no
//     endpoint has nothing for this pass to have compared.
func (e *Estate) ExpectedCoverage() map[string][]uuid.UUID {
	return map[string]([]uuid.UUID){
		findings.ProducerEOL:           {e.Web, e.DB},
		findings.ProducerVulnerability: {e.Web},
		findings.ProducerCrypto:        {e.Web},
		findings.ProducerConfiguration: {e.Web, e.Switch},
		findings.ProducerHygiene:       {e.Web, e.DB, e.Printer, e.Switch, e.WebDup},
		findings.ProducerDrift:         {e.Web, e.Switch},
	}
}

// Fact is one `eol.*` fact the eol producer writes beside its findings.
//
// The fact is the DATE; the finding is the problem. An asset whose support ends
// in two years has the first and not the second, which is why db-01 appears
// here with no matching entry in [Estate.ExpectedFindings] — and why LC-001 can
// report PASS for it rather than NOT ASSESSED.
type Fact struct {
	Asset uuid.UUID
	Key   string
	// Date is the catalogue's eol_date, as the producer stores it.
	Date time.Time
	// SourceRef is `catalog:eol:<row id>` — a disputed date leads back to the
	// exact row that said it.
	SourceRef string
}

// ExpectedFacts is every eol.* fact a full pass writes.
func (e *Estate) ExpectedFacts() []Fact {
	return []Fact{
		{Asset: e.Web, Key: facts.KeyEOLOSDate, Date: dateOnly(daysFromNow(-OSEOLDaysAgo)), SourceRef: "catalog:eol:" + e.osRow.String()},
		{Asset: e.Web, Key: facts.KeyEOLSWDate, Date: dateOnly(daysFromNow(-SoftwareEOLDaysAgo)), SourceRef: "catalog:eol:" + e.swRow.String()},
		{Asset: e.DB, Key: facts.KeyEOLOSDate, Date: dateOnly(daysFromNow(SupportedOSDaysAhead)), SourceRef: "catalog:eol:" + e.supportedOSRow.String()},
		{Asset: e.DB, Key: facts.KeyEOLHWDate, Date: dateOnly(daysFromNow(-HardwareEOSDaysAgo)), SourceRef: "catalog:eol:" + e.hwRow.String()},
	}
}

// ApplyProducerOutput writes the expected producer output into the database:
// the findings, the coverage record and the eol.* facts.
//
// This is how half B gets a database in the state a producer pass leaves it,
// without being able to run the producers. `skip` names producers to leave OUT
// — which is the mutation arm: skipping `hygiene` must make IH-005 and IH-006
// read NOT ASSESSED rather than pass, and skipping `eol` must do the same to
// every Lifecycle control.
func (e *Estate) ApplyProducerOutput(t *testing.T, owner *sql.DB, skip ...string) {
	t.Helper()
	skipped := map[string]bool{}
	for _, s := range skip {
		skipped[s] = true
	}

	for _, f := range e.ExpectedFindings() {
		if skipped[f.Producer] {
			continue
		}
		severity, score := e.Verdict(t, f)
		execute(t, owner, `INSERT INTO findings
		    (tenant_id, producer, kind, subject_type, subject_id, severity, score, summary,
		     source_kind, detection_state, workflow_status)
		    VALUES ($1, $2, $3, $4, $5, $6, $7, $3, 'measured', 'ACTIVE', 'NEW')`,
			e.Tenant, f.Producer, f.Kind, f.SubjectType, f.Subject, severity, score)
	}

	for producerKey, assets := range e.ExpectedCoverage() {
		if skipped[producerKey] {
			continue
		}
		for _, id := range assets {
			execute(t, owner, `INSERT INTO producer_assessments (tenant_id, asset_id, producer)
			                   VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, e.Tenant, id, producerKey)
		}
	}

	if skipped[findings.ProducerEOL] {
		return
	}
	for _, f := range e.ExpectedFacts() {
		execute(t, owner, `INSERT INTO asset_facts (tenant_id, asset_id, key, value, source_kind, source_ref, observed_at)
		                   VALUES ($1, $2, $3, to_jsonb($4::text), 'imported', $5, now())`,
			e.Tenant, f.Asset, f.Key, f.Date.Format("2006-01-02"), f.SourceRef)
	}
}

// ---------------------------------------------------------------------------
// seeding helpers
// ---------------------------------------------------------------------------

type assetSpec struct {
	hostname  string
	class     string
	path      string
	owner     string
	site      string
	status    string
	firstSeen time.Time
	lastSeen  time.Time
}

func (e *Estate) asset(t *testing.T, db *sql.DB, spec assetSpec) uuid.UUID {
	t.Helper()
	id := uuid.New()
	var ownerEmail, site any
	if spec.owner != "" {
		ownerEmail = spec.owner
	}
	if spec.site != "" {
		site = spec.site
	}
	execute(t, db, `INSERT INTO assets
	    (id, tenant_id, hostname, display_name, class_key, class_path, asset_status,
	     owner_email, site, first_discovered_at, last_seen_at)
	    VALUES ($1, $2, $3, $3, $4, $5, $6, $7, $8, $9, $10)`,
		id, e.Tenant, spec.hostname, spec.class, spec.path, spec.status,
		ownerEmail, site, spec.firstSeen, spec.lastSeen)
	return id
}

func endpoint(t *testing.T, db *sql.DB, tenant, asset uuid.UUID, addr string, port int, transport, serviceName, method string, firstSeen time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	execute(t, db, `INSERT INTO asset_endpoints
	    (id, tenant_id, asset_id, address, port, transport, service_name,
	     service_identification_method, service_confidence, status, first_seen_at)
	    VALUES ($1, $2, $3, $4::inet, $5, $6, NULLIF($7, ''), NULLIF($8, ''),
	            CASE WHEN $7 = '' THEN 'none' ELSE 'reported' END, 'active', $9)`,
		id, tenant, asset, addr, port, transport, serviceName, method, firstSeen)
	return id
}

func fact(t *testing.T, db *sql.DB, tenant, asset uuid.UUID, key, jsonValue string) {
	t.Helper()
	execute(t, db, `INSERT INTO asset_facts (tenant_id, asset_id, key, value, source_kind, source_ref)
	                VALUES ($1, $2, $3, $4::jsonb, 'measured', 'gate3-estate')`,
		tenant, asset, key, jsonValue)
}

// mergeProposal writes the asset_history row the identification engine writes
// for a contested observation. Hand-built for the same reason the hygiene
// producer's own tests hand-build one: the engine needs a whole observation to
// produce one, and what is under test here is the reading of a PENDING proposal.
func mergeProposal(t *testing.T, db *sql.DB, tenant, observation, candidate uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	payload := fmt.Sprintf(
		`{"kind":"merge_proposal","status":"pending","reason":"contested identifiers",`+
			`"observation_asset_id":%q,"fingerprint":%q,"candidates":[{"asset_id":%q}]}`,
		observation.String(), id.String(), candidate.String())
	execute(t, db, `INSERT INTO asset_history (id, tenant_id, asset_id, source, action, changes_json)
	                VALUES ($1, $2, $3, 'gate3-estate', 'merge_proposed', $4::jsonb)`,
		id, tenant, observation, payload)
	return id
}

// eolRow inserts a platform eol_catalogue row and registers its cleanup.
func eolRow(t *testing.T, db *sql.DB, kind, vendor, product, cycle string, eol time.Time) uuid.UUID {
	t.Helper()
	id := uuid.New()
	execute(t, db, `INSERT INTO eol_catalogue (id, product_kind, vendor, product, cycle, eol_date, source_url)
	                VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id, kind, vendor, product, cycle, eol, "https://endoflife.date/"+strings.ToLower(product))
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM eol_catalogue WHERE id = $1`, id) })
	return id
}

// advisory inserts a vulnerability catalogue row plus its CPE match rule.
func advisory(t *testing.T, db *sql.DB, cveID string, cvss float64, cpeRule string) {
	t.Helper()
	execute(t, db, `INSERT INTO vulnerability_catalogue (cve_id, cvss_score, cvss_vector, cvss_version)
	                VALUES ($1, $2, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', '3.1')
	                ON CONFLICT (cve_id) DO UPDATE SET cvss_score = EXCLUDED.cvss_score`, cveID, cvss)
	execute(t, db, `INSERT INTO vulnerability_matches (cve_id, cpe_match_string)
	                VALUES ($1, $2)
	                ON CONFLICT (cve_id, coalesce(cpe_match_string, ''), coalesce(purl_range, '')) DO NOTHING`,
		cveID, cpeRule)
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM vulnerability_catalogue WHERE cve_id = $1`, cveID) })
}

func execute(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	testdb.RetryTransient(t, func() error {
		_, err := db.Exec(q, args...)
		return err
	})
}

func daysFromNow(days int) time.Time { return time.Now().UTC().AddDate(0, 0, days) }

// dateOnly truncates to the day, because `eol_catalogue.eol_date` is a DATE and
// the fact the producer writes carries whatever Postgres hands back.
func dateOnly(ts time.Time) time.Time {
	return time.Date(ts.Year(), ts.Month(), ts.Day(), 0, 0, 0, 0, time.UTC)
}
