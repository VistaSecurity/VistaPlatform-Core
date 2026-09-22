package producers

// The `drift` producer end to end, against a real Postgres under RLS.
//
// The unit tests cover the decision — what counts as drift against a baseline.
// What only a database can show is the LIFECYCLE, and drift has one the other
// producers do not: a finding that closes because the observation AGED INTO the
// baseline rather than because the condition went away, a warm-up gate that
// must produce nothing AND sweep nothing, and a human's "resolved" that has to
// survive the next pass of the same observation while still being re-opened by
// a different one.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/driftsettings"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/riskrollup"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer/producertest"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// driftFixture is one tenant that has been observed for far longer than the
// default window — a segment with a settled population, and one asset with a
// settled protocol, port profile and certificate issuer. Every case then
// introduces ONE change and asks what the producer says about it.
type driftFixture struct {
	owner  *sql.DB
	app    *sql.DB
	tenant uuid.UUID

	segment       uuid.UUID
	baselineAsset uuid.UUID
	assetID       uuid.UUID
	endpointID    uuid.UUID
	cryptoID      uuid.UUID
	oldCertID     uuid.UUID

	producer *DriftProducer
	now      time.Time
}

const (
	// Comfortably outside any window the tests use.
	settledDays = 400
	oldFP       = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	newFP       = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
)

func newDriftFixture(t *testing.T) *driftFixture {
	t.Helper()
	owner := testdb.Connect(t)
	// No testdb.ApplySchema: the runner applies scripts/database/schema.sql once
	// to the database, and re-applying it per fixture takes ACCESS EXCLUSIVE
	// locks across the whole schema while other package binaries of the same
	// `go test./...` run are querying it.
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)

	f := &driftFixture{owner: owner, app: app, tenant: tenant, now: time.Now().UTC()}

	f.segment = uuid.New()
	exec(t, owner, `INSERT INTO network_segments (id, tenant_id, name, segment_type, value, environment)
	                VALUES ($1, $2, 'Server VLAN', 'cidr', '10.20.0.0/24', 'production')`, f.segment, tenant)

	settled := f.daysAgo(settledDays)
	f.baselineAsset = f.addAsset(t, assetclass.KeyServer, settled, "settled-peer")
	f.assetID = f.addAsset(t, assetclass.KeyServer, settled, "settled-host")

	// The asset's baseline: one endpoint on 443/tcp speaking TLS, and one crypto
	// configuration presenting a certificate from a CA it has always used.
	f.endpointID = f.addEndpoint(t, f.assetID, 443, "tcp", "TLS", settled, f.now, "active", nil)
	f.oldCertID = f.addCertificate(t, "CN=Settled CA, O=Example Ltd", oldFP)
	f.cryptoID = f.addCrypto(t, f.assetID, f.endpointID, "TLS", f.oldCertID, settled, false)

	p, err := NewDriftProducer(app)
	if err != nil {
		t.Fatalf("NewDriftProducer: %v", err)
	}
	p.now = func() time.Time { return f.now }
	f.producer = p
	return f
}

func (f *driftFixture) daysAgo(d int) time.Time { return f.now.AddDate(0, 0, -d) }

// run is one pass, retried past the cross-binary races the shared test database
// produces.
//
// `go test ./...` runs each package's binary concurrently against ONE Postgres,
// and a neighbouring package applying the schema takes ACCESS EXCLUSIVE locks
// across it. This producer's read phase touches five tables in one transaction,
// which is exactly the shape that deadlocks against that — `pq: deadlock
// detected` on a statement with nothing wrong with it. testdb.RetryTransient
// retries only that class; a real failure is deterministic and still fails.
//
// Used wherever a pass is EXPECTED to succeed. The cases that expect an error
// call Run directly, because a retry there would hide the thing under test.
//
// Retry AND the shared schema lock, because the retry alone is not enough: a
// schema apply holds the key exclusively for seconds, and four attempts spaced
// over about a second can all land inside one. That is not hypothetical — it is
// how `make test-integration-db` failed this package while the same test passed
// under `-p 1`. The shared lock makes the overlap impossible instead of
// retrying past it, and being SHARED it does not serialize these tests against
// each other.
func (f *driftFixture) run(t *testing.T, ctx context.Context) DriftRun {
	t.Helper()
	var out DriftRun
	testdb.WithSchemaShareLock(t, f.owner, func() {
		testdb.RetryTransient(t, func() error {
			var err error
			out, err = f.producer.Run(ctx, f.tenant)
			return err
		})
	})
	return out
}

func (f *driftFixture) addAsset(t *testing.T, class string, firstSeen time.Time, name string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	path := class
	if c, ok := assetclass.Get(class); ok && c.Path != "" {
		path = c.Path
	}
	exec(t, f.owner, `INSERT INTO assets (id, tenant_id, class_key, class_path, display_name, hostname,
	                                      network_segment_id, asset_status, first_discovered_at, last_seen_at)
	                  VALUES ($1, $2, $3, $4, $5, $5, $6, 'monitoring', $7, now())`,
		id, f.tenant, class, path, name, f.segment, firstSeen)
	return id
}

func (f *driftFixture) addEndpoint(t *testing.T, assetID uuid.UUID, port int, transport, protocol string,
	firstSeen, lastSeen time.Time, status string, boundLocal *bool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	exec(t, f.owner, `INSERT INTO asset_endpoints (id, tenant_id, asset_id, address, port, transport, protocol,
	                                               bound_local, status, first_seen_at, last_seen_at)
	                  VALUES ($1, $2, $3, ('10.20.0.' || ($4 % 250))::inet, $4, $5, $6::public.protocol_type,
	                          $7, $8, $9, $10)`,
		id, f.tenant, assetID, port, transport, protocol, boundLocal, status, firstSeen, lastSeen)
	return id
}

func (f *driftFixture) addCertificate(t *testing.T, issuerDN, fingerprint string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	exec(t, f.owner, `INSERT INTO certificates (id, tenant_id, subject_dn, issuer_dn, fingerprint_sha256, certificate_pem)
	                  VALUES ($1, $2, 'CN=settled-host', $3, $4, '-----BEGIN CERTIFICATE-----fake-----END CERTIFICATE-----')`,
		id, f.tenant, issuerDN, fingerprint)
	return id
}

func (f *driftFixture) addCrypto(t *testing.T, assetID, endpointID uuid.UUID, protocol string,
	certID uuid.UUID, firstSeen time.Time, deleted bool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	var deletedAt any
	if deleted {
		deletedAt = f.now
	}
	var cert any
	if certID != uuid.Nil {
		cert = certID
	}
	// Into the PARTITIONED table, not the view: the view exists for readers and
	// inserting through it would be testing Postgres's auto-updatable-view rules
	// rather than the producer.
	exec(t, f.owner, `INSERT INTO crypto_implementations_partitioned
	                    (id, tenant_id, asset_id, endpoint_id, protocol, certificate_id,
	                     discovery_method, first_discovered_at, created_at, deleted_at)
	                  VALUES ($1, $2, $3, $4, $5::public.protocol_type, $6, 'passive', $7, $7, $8)`,
		id, f.tenant, assetID, endpointID, protocol, cert, firstSeen, deletedAt)
	return id
}

// setBaselineDays writes the tenant's window, the way the settings page does.
func (f *driftFixture) setBaselineDays(t *testing.T, days int) {
	t.Helper()
	exec(t, f.owner, `INSERT INTO tenant_admin_settings (tenant_id, config) VALUES ($1, '{}'::jsonb)
	                  ON CONFLICT (tenant_id) DO NOTHING`, f.tenant)
	exec(t, f.owner, `UPDATE tenant_admin_settings
	                  SET config = jsonb_set(config || jsonb_build_object($2::text, coalesce(config -> $2::text, '{}'::jsonb)),
	                                         ARRAY[$2::text, $3::text], to_jsonb($4::int), true),
	                      version = version + 1
	                  WHERE tenant_id = $1`,
		f.tenant, driftsettings.SettingsKey, driftsettings.BaselineDaysKey, days)
}

// finding reads one of this producer's rows.
func (f *driftFixture) finding(t *testing.T, kind string, subjectID uuid.UUID) *storedFinding {
	t.Helper()
	var out storedFinding
	var raw []byte
	var resurfaced sql.NullTime
	var err error
	testdb.RetryTransient(t, func() error {
		err = f.owner.QueryRow(`
			SELECT id, detection_state, severity, score, occurrence_count, resurfaced_at, evidence
			FROM findings
			WHERE tenant_id = $1 AND producer = 'drift' AND kind = $2
			  AND subject_type = 'asset' AND subject_id = $3`,
			f.tenant, kind, subjectID).
			Scan(&out.id, &out.state, &out.severity, &out.score, &out.occurrence, &resurfaced, &raw)
		if err == sql.ErrNoRows {
			return nil
		}
		return err
	})
	if err == sql.ErrNoRows {
		return nil
	}
	out.resurfaced = resurfaced.Valid
	out.evidence = map[string]any{}
	if err := json.Unmarshal(raw, &out.evidence); err != nil {
		t.Fatalf("finding evidence is not an object: %v", err)
	}
	return &out
}

func (f *driftFixture) workflow(t *testing.T, id uuid.UUID) string {
	t.Helper()
	var s string
	testdb.RetryTransient(t, func() error {
		return f.owner.QueryRow(`SELECT workflow_status FROM findings WHERE id = $1`, id).Scan(&s)
	})
	return s
}

func (f *driftFixture) setWorkflow(t *testing.T, id uuid.UUID, status string) {
	t.Helper()
	exec(t, f.owner, `UPDATE findings SET workflow_status = $2 WHERE id = $1`, id, status)
}

func (f *driftFixture) activeDriftFindings(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	testdb.RetryTransient(t, func() error {
		clear(out)
		rows, err := f.owner.Query(`
			SELECT id::text, kind FROM findings
			WHERE tenant_id = $1 AND producer = 'drift' AND detection_state = 'ACTIVE'`, f.tenant)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id, kind string
			if err := rows.Scan(&id, &kind); err != nil {
				return err
			}
			out[id] = kind
		}
		return rows.Err()
	})
	return out
}

// --- the writer contract ----------------------------------------------------

func TestIntegration_DriftProducer_WriterContract(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)

	// The contract suite, run with THIS producer's key and kinds — so what it
	// proves is that drift findings obey the lifecycle, not that some example
	// producer's do.
	producertest.Run(t, producertest.Config{
		DB:          app,
		Owner:       owner,
		Producer:    findings.ProducerDrift,
		Kind:        findings.KindUnexpectedProtocol,
		OtherKind:   findings.KindPortProfileChanged,
		SubjectType: findings.SubjectAsset,
	})
}

// --- warm-up ----------------------------------------------------------------

// A tenant onboarded three days ago must get NOTHING — not one finding per
// asset, protocol, port and issuer it owns, which is what a producer without
// this gate would say on day one.
func TestIntegration_DriftProducer_WarmUpRaisesNothingAndSweepsNothing(t *testing.T) {
	f := newDriftFixture(t)
	ctx := context.Background()

	// First, a settled pass that raises something, so there is a live finding a
	// bad warm-up branch could destroy.
	f.addEndpoint(t, f.assetID, 22, "tcp", "SSH", f.daysAgo(3), f.now, "active", nil)
	run := f.run(t, ctx)
	if run.WarmingUp {
		t.Fatal("a tenant with 400 days of history is not warming up")
	}
	before := f.activeDriftFindings(t)
	if len(before) == 0 {
		t.Fatal("the settled pass raised nothing; there is no finding for the warm-up branch to damage")
	}

	// Now move the whole tenant inside the window: every asset first seen
	// yesterday. That is what a tenant onboarded yesterday looks like.
	exec(t, f.owner, `UPDATE assets SET first_discovered_at = $2 WHERE tenant_id = $1`, f.tenant, f.daysAgo(1))

	warm := f.run(t, ctx)
	if !warm.WarmingUp {
		t.Fatal("a tenant whose oldest observation is a day old reported a full baseline")
	}
	if warm.Raised != 0 {
		t.Errorf("the warm-up pass raised %d findings; a tenant we have not watched for a window has no drift", warm.Raised)
	}
	// The other half, and the one that is easy to get wrong: a pass that could
	// not evaluate must not RESOLVE either. "We cannot tell yet" rendered as
	// "the condition went away" is the same three-valued collapse pointed the
	// other way.
	if warm.Resolved != 0 {
		t.Errorf("the warm-up pass resolved %d findings; a pass that made no statement must sweep nothing", warm.Resolved)
	}
	after := f.activeDriftFindings(t)
	if len(after) != len(before) {
		t.Fatalf("the warm-up pass changed the ACTIVE drift count from %d to %d", len(before), len(after))
	}
}

// --- the four kinds ---------------------------------------------------------

func TestIntegration_DriftProducer_NewClassInSegment(t *testing.T) {
	f := newDriftFixture(t)
	ctx := context.Background()

	printer := f.addAsset(t, assetclass.KeyPrinter, f.daysAgo(5), "lobby-printer")

	f.run(t, ctx)
	got := f.finding(t, findings.KindNewClassInSegment, printer)
	if got == nil {
		t.Fatal("no new_class_in_segment finding for the first printer on a server VLAN")
	}
	if got.state != producer.StateActive {
		t.Errorf("detection_state = %q, want ACTIVE", got.state)
	}
	if got.evidence["segment_id"] != f.segment.String() {
		t.Errorf("evidence.segment_id = %v, want %s", got.evidence["segment_id"], f.segment)
	}
	baseline, _ := got.evidence["baseline"].(map[string]any)
	classes, _ := baseline["classes_in_segment"].([]any)
	if len(classes) != 1 || classes[0] != assetclass.KeyServer {
		t.Errorf("evidence.baseline.classes_in_segment = %v, want [server] — what it was compared against", classes)
	}

	// It ages into the baseline: 5 days old under a 30-day window is drift, and
	// under a 3-day window it is history. Same rows, same pass, different
	// window — which is what "ages in" means.
	f.setBaselineDays(t, driftsettings.MinBaselineDays) // 7 days
	exec(t, f.owner, `UPDATE assets SET first_discovered_at = $2 WHERE id = $1`, printer, f.daysAgo(20))

	run := f.run(t, ctx)
	if run.BaselineDays != driftsettings.MinBaselineDays {
		t.Errorf("the pass used a %d-day window; the tenant set %d", run.BaselineDays, driftsettings.MinBaselineDays)
	}
	aged := f.finding(t, findings.KindNewClassInSegment, printer)
	if aged.state != producer.StateInactive {
		t.Errorf("detection_state = %q after the printer aged into the baseline, want INACTIVE", aged.state)
	}
	if aged.id != got.id {
		t.Error("the aged-out finding is a different row; a condition that went away keeps its row")
	}
}

// Archived and denied are both a tenant DECISION to stop tracking something.
// Raising drift about a thing somebody already dismissed puts work back in the
// queue they took it out of.
func TestIntegration_DriftProducer_DismissedAssetsAreNotJudged(t *testing.T) {
	f := newDriftFixture(t)
	ctx := context.Background()

	denied := f.addAsset(t, assetclass.KeyPrinter, f.daysAgo(5), "rejected-printer")
	exec(t, f.owner, `UPDATE assets SET asset_status = 'denied' WHERE id = $1`, denied)
	archived := f.addAsset(t, assetclass.KeyOtDevice, f.daysAgo(5), "retired-plc")
	exec(t, f.owner, `UPDATE assets SET asset_status = 'archived' WHERE id = $1`, archived)

	f.run(t, ctx)
	for _, id := range []uuid.UUID{denied, archived} {
		if got := f.finding(t, findings.KindNewClassInSegment, id); got != nil {
			t.Errorf("a new_class_in_segment finding was raised on an asset the tenant has dismissed (%s)", id)
		}
	}
	// And nothing landed on any other asset for those classes either — the
	// dismissed rows are out of the population, not merely out of the subject
	// position.
	var n int
	testdb.RetryTransient(t, func() error {
		return f.owner.QueryRow(`SELECT count(*) FROM findings
		                         WHERE tenant_id = $1 AND producer = 'drift' AND kind = $2`,
			f.tenant, findings.KindNewClassInSegment).Scan(&n)
	})
	if n != 0 {
		t.Errorf("%d new_class_in_segment findings from a population of dismissed assets, want 0", n)
	}
}

func TestIntegration_DriftProducer_UnexpectedProtocol(t *testing.T) {
	f := newDriftFixture(t)
	ctx := context.Background()

	// The host started answering SSH four days ago.
	f.addEndpoint(t, f.assetID, 22, "tcp", "SSH", f.daysAgo(4), f.now, "active", nil)

	f.run(t, ctx)
	got := f.finding(t, findings.KindUnexpectedProtocol, f.assetID)
	if got == nil {
		t.Fatal("no unexpected_protocol finding for a host that started answering SSH")
	}
	if !strings.Contains(got.evidence["observation_key"].(string), "SSH") {
		t.Errorf("observation_key = %v, want it to name SSH", got.evidence["observation_key"])
	}
	baseline, _ := got.evidence["baseline"].(map[string]any)
	protos, _ := baseline["protocols"].([]any)
	if len(protos) != 1 || protos[0] != "TLS" {
		t.Errorf("evidence.baseline.protocols = %v, want [TLS]", protos)
	}

	// The condition disappears: the socket closed.
	exec(t, f.owner, `UPDATE asset_endpoints SET status = 'closed' WHERE tenant_id = $1 AND port = 22`, f.tenant)
	run := f.run(t, ctx)
	if run.Resolved == 0 {
		t.Error("the pass resolved nothing after the SSH socket closed")
	}
	if after := f.finding(t, findings.KindUnexpectedProtocol, f.assetID); after.state != producer.StateInactive {
		t.Errorf("detection_state = %q after the protocol went away, want INACTIVE", after.state)
	}
}

func TestIntegration_DriftProducer_PortProfileChanged(t *testing.T) {
	f := newDriftFixture(t)
	ctx := context.Background()

	// One port opened inside the window, one baseline port closed inside it,
	// and one loopback socket that must not count either way.
	openedPort := f.addEndpoint(t, f.assetID, 3389, "tcp", "TLS", f.daysAgo(2), f.now, "active", nil)
	closedPort := f.addEndpoint(t, f.assetID, 8080, "tcp", "TLS", f.daysAgo(settledDays), f.daysAgo(2), "closed", nil)
	loopback := true
	f.addEndpoint(t, f.assetID, 5432, "tcp", "TLS", f.daysAgo(2), f.now, "active", &loopback)

	f.run(t, ctx)
	got := f.finding(t, findings.KindPortProfileChanged, f.assetID)
	if got == nil {
		t.Fatal("no port_profile_changed finding after a port opened and another closed")
	}
	observed, _ := got.evidence["observed"].(map[string]any)
	opened, _ := observed["opened"].([]any)
	closed, _ := observed["closed"].([]any)
	if len(opened) != 1 || opened[0] != "3389" {
		t.Errorf("opened = %v, want [3389] — 5432 is bound to loopback and is not exposure", opened)
	}
	if len(closed) != 1 || closed[0] != "8080" {
		t.Errorf("closed = %v, want [8080]", closed)
	}
	// Both directions in the one-line summary, because either can mean an
	// unplanned change.
	if !strings.Contains(got.evidence["observation_key"].(string), "+3389") ||
		!strings.Contains(got.evidence["observation_key"].(string), "-8080") {
		t.Errorf("observation_key = %v, want both directions", got.evidence["observation_key"])
	}

	// The endpoint rows behind the delta, read out of `asset_endpoints` by the
	// producer's own SQL. This is the half a unit test over `judge` cannot
	// reach: the columns have to be SELECTed and scanned for any of it to be
	// there, and a finding that names a port but not the face it appeared on
	// cannot drill through to the row it is about.
	rows, _ := observed["endpoints"].([]any)
	byID := map[string]map[string]any{}
	for _, r := range rows {
		m, _ := r.(map[string]any)
		id, _ := m["endpoint_id"].(string)
		byID[id] = m
	}
	if m := byID[openedPort.String()]; m == nil || m["change"] != "opened" {
		t.Errorf("evidence.observed.endpoints does not name the opened endpoint: %v", rows)
	}
	if m := byID[closedPort.String()]; m == nil || m["change"] != "closed" {
		t.Errorf("evidence.observed.endpoints does not name the closed endpoint: %v", rows)
	}
	// And the readable half carries the address the fixture gave the row.
	openedLabels, _ := observed["opened_endpoints"].([]any)
	if len(openedLabels) != 1 || openedLabels[0] != "10.20.0.139:3389" {
		t.Errorf("opened_endpoints = %v, want [10.20.0.139:3389]", openedLabels)
	}
}

func TestIntegration_DriftProducer_NewIssuer(t *testing.T) {
	f := newDriftFixture(t)
	ctx := context.Background()

	// A certificate from a CA this host has never used, observed two days ago.
	newCert := f.addCertificate(t, "CN=Surprise CA, O=Nobody In Particular", newFP)
	f.addCrypto(t, f.assetID, f.endpointID, "TLS", newCert, f.daysAgo(2), false)

	f.run(t, ctx)
	got := f.finding(t, findings.KindNewIssuer, f.assetID)
	if got == nil {
		t.Fatal("no new_issuer finding after a certificate arrived from an unseen CA")
	}
	if !strings.Contains(got.evidence["observation_key"].(string), "Surprise CA") {
		t.Errorf("observation_key = %v, want it to name the new issuer", got.evidence["observation_key"])
	}
	baseline, _ := got.evidence["baseline"].(map[string]any)
	issuers, _ := baseline["issuers"].([]any)
	if len(issuers) != 1 || issuers[0] != "Settled CA" {
		t.Errorf("evidence.baseline.issuers = %v, want [Settled CA]", issuers)
	}
	// "Collect posture, never key material": the certificate BODY is in the
	// fixture row and must not be anywhere in the finding.
	raw, err := json.Marshal(got.evidence)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	if strings.Contains(string(raw), "BEGIN CERTIFICATE") {
		t.Fatal("the certificate PEM reached the finding's evidence")
	}
}

// A certificate linked ONLY through the chain junction, with no
// `crypto_implementations.certificate_id`, still counts.
//
// Both links are written today by the same code path, but not by every writer —
// the dedup path sets `certificate_id` alone — and a producer that read one of
// them would answer differently depending on which collector saw the host. This
// is the half that has no other test: without it the junction leg of the union
// can be deleted and everything stays green.
func TestIntegration_DriftProducer_NewIssuerThroughTheChainJunction(t *testing.T) {
	f := newDriftFixture(t)
	ctx := context.Background()

	newCert := f.addCertificate(t, "CN=Junction CA, O=Nobody", newFP)
	// certificate_id deliberately NULL: the only link is the junction row.
	impl := f.addCrypto(t, f.assetID, f.endpointID, "TLS", uuid.Nil, f.daysAgo(2), false)
	exec(t, f.owner, `INSERT INTO crypto_implementation_certificates
	                    (crypto_implementation_id, certificate_id, certificate_role, certificate_order)
	                  VALUES ($1, $2, 'leaf', 0)`, impl, newCert)

	f.run(t, ctx)
	got := f.finding(t, findings.KindNewIssuer, f.assetID)
	if got == nil {
		t.Fatal("no new_issuer finding for a certificate linked only through crypto_implementation_certificates")
	}
	if !strings.Contains(got.evidence["observation_key"].(string), "Junction CA") {
		t.Errorf("observation_key = %v, want it to name the junction-linked issuer", got.evidence["observation_key"])
	}

	// A chain INTERMEDIATE is the CA's own certificate, not one this asset
	// presented as its identity. Counting them would raise a finding every time
	// a CA published a new cross-signed intermediate.
	interCert := f.addCertificate(t, "CN=Some Intermediate, O=Settled CA", strings.Repeat("c", 64))
	exec(t, f.owner, `INSERT INTO crypto_implementation_certificates
	                    (crypto_implementation_id, certificate_id, certificate_role, certificate_order)
	                  VALUES ($1, $2, 'intermediate', 1)`, impl, interCert)
	f.run(t, ctx)
	again := f.finding(t, findings.KindNewIssuer, f.assetID)
	if strings.Contains(again.evidence["observation_key"].(string), "Some Intermediate") {
		t.Errorf("observation_key = %v names a chain intermediate", again.evidence["observation_key"])
	}
}

// A soft-deleted crypto configuration is still evidence about the BASELINE.
//
// Without it, replacing the row that recorded a protocol — which is what the
// dedup path does — makes a protocol the asset has always spoken look brand
// new, and the tenant gets a drift finding for a row rewrite.
func TestIntegration_DriftProducer_RetiredRowsStillCountAsBaseline(t *testing.T) {
	f := newDriftFixture(t)
	ctx := context.Background()

	// The asset has spoken SSH for over a year, recorded on a row that has since
	// been superseded and soft-deleted...
	f.addCrypto(t, f.assetID, f.endpointID, "SSH", uuid.Nil, f.daysAgo(settledDays), true)
	// ...and the row that replaced it was written two days ago.
	f.addCrypto(t, f.assetID, f.endpointID, "SSH", uuid.Nil, f.daysAgo(2), false)

	f.run(t, ctx)
	if got := f.finding(t, findings.KindUnexpectedProtocol, f.assetID); got != nil {
		t.Fatalf("unexpected_protocol raised (%q) for a protocol this asset has spoken for a year; "+
			"the retired row that recorded it is still evidence about the baseline", got.evidence["observation_key"])
	}
}

// --- a human's decision -----------------------------------------------------

// The pair that matters, in one test because each half is satisfied by a
// producer that gets the other one wrong.
func TestIntegration_DriftProducer_HumanResolveSurvivesButANewObservationReopens(t *testing.T) {
	f := newDriftFixture(t)
	ctx := context.Background()

	f.addEndpoint(t, f.assetID, 22, "tcp", "SSH", f.daysAgo(4), f.now, "active", nil)
	f.run(t, ctx)
	raised := f.finding(t, findings.KindUnexpectedProtocol, f.assetID)
	if raised == nil {
		t.Fatal("no unexpected_protocol finding to resolve")
	}

	// A person looks at it, decides the SSH was planned, and resolves it.
	f.setWorkflow(t, raised.id, "RESOLVED")

	// The same observation, next pass. It must stay resolved — otherwise every
	// nightly run puts an accepted change back in the queue.
	run2 := f.run(t, ctx)
	if run2.Reopened != 0 {
		t.Errorf("run 2 reopened %d findings; the observation has not changed", run2.Reopened)
	}
	if got := f.workflow(t, raised.id); got != "RESOLVED" {
		t.Fatalf("workflow_status = %q after a pass over the SAME observation, want RESOLVED — an accepted change must stay accepted", got)
	}

	// Now a DIFFERENT observation on the same asset and the same kind. The
	// identity index gives it the same row, and a producer that only looked at
	// detection_state would leave it RESOLVED and never tell anybody.
	f.addEndpoint(t, f.assetID, 445, "tcp", "SMB", f.daysAgo(1), f.now, "active", nil)
	run3 := f.run(t, ctx)
	if run3.Reopened != 1 {
		t.Errorf("run 3 reopened %d findings, want 1", run3.Reopened)
	}
	if got := f.workflow(t, raised.id); got != "NEW" {
		t.Fatalf("workflow_status = %q after a NEW protocol appeared, want NEW — the earlier decision was about SSH, not SMB", got)
	}
	back := f.finding(t, findings.KindUnexpectedProtocol, f.assetID)
	if back.id != raised.id {
		t.Errorf("the re-raised finding is a different row (%s, was %s); the history belongs to the subject", back.id, raised.id)
	}
	if back.state != producer.StateActive {
		t.Errorf("detection_state = %q, want ACTIVE", back.state)
	}
	if !strings.Contains(back.evidence["observation_key"].(string), "SMB") {
		t.Errorf("observation_key = %v does not name the new protocol", back.evidence["observation_key"])
	}
}

// Suppression is a standing decision about the condition, not about one episode
// of it, so a changed observation must NOT drag a suppressed finding back into
// the queue.
func TestIntegration_DriftProducer_SuppressedStaysSuppressed(t *testing.T) {
	f := newDriftFixture(t)
	ctx := context.Background()

	f.addEndpoint(t, f.assetID, 22, "tcp", "SSH", f.daysAgo(4), f.now, "active", nil)
	f.run(t, ctx)
	raised := f.finding(t, findings.KindUnexpectedProtocol, f.assetID)
	f.setWorkflow(t, raised.id, "SUPPRESSED")

	f.addEndpoint(t, f.assetID, 445, "tcp", "SMB", f.daysAgo(1), f.now, "active", nil)
	run := f.run(t, ctx)
	if run.Reopened != 0 {
		t.Errorf("run 2 reopened %d suppressed findings, want 0", run.Reopened)
	}
	if got := f.workflow(t, raised.id); got != "SUPPRESSED" {
		t.Errorf("workflow_status = %q, want SUPPRESSED", got)
	}
}

// --- the failed pass --------------------------------------------------------

// errReadDiedPartWay is what a read phase that died half way through looks
// like: some subjects loaded, the rest never will, and the producer has NOT
// made a full statement about what it sees.
var errReadDiedPartWay = errors.New("reading the tenant's population failed part way through the pass")

// A pass whose READ fails must return an error and sweep NOTHING.
//
// The read is made to fail while the DATABASE STAYS HEALTHY, which is the only
// version of this test that proves anything. A dead connection fails the write
// phase too, so a test built on one passes with the guard deleted — the sweep
// never ran because nothing could run. Here the write phase would succeed
// perfectly well, and the only thing stopping it inactivating every drift
// finding in the tenant is `Run` returning on the read error.
//
// Mutation-proven: make Run swallow the read error and carry on with an empty
// driftInput, and this goes red with every drift finding INACTIVE — which on a
// screen is indistinguishable from "nothing has drifted".
func TestIntegration_DriftProducer_AFailedPassDoesNotSweep(t *testing.T) {
	f := newDriftFixture(t)

	f.addEndpoint(t, f.assetID, 22, "tcp", "SSH", f.daysAgo(4), f.now, "active", nil)
	f.run(t, context.Background())
	before := f.activeDriftFindings(t)
	if len(before) == 0 {
		t.Fatal("the first pass raised nothing; there is no finding for a bad sweep to inactivate")
	}

	real := f.producer.readPhase
	f.producer.readPhase = func(ctx context.Context, tenantID uuid.UUID) (*driftInput, error) {
		// Run the real read first, so everything downstream of it is exactly as
		// healthy as it was — then fail the way a scan error on row 4,000 of
		// asset_endpoints would. Retried past the shared-database race, which is
		// not what this test is about and would otherwise report the deadlock as
		// the failure under test.
		testdb.RetryTransient(t, func() error {
			_, err := real(ctx, tenantID)
			return err
		})
		return nil, errReadDiedPartWay
	}
	t.Cleanup(func() { f.producer.readPhase = real })

	_, err := f.producer.Run(context.Background(), f.tenant)
	if err == nil {
		t.Fatal("a pass whose read failed reported success — a partial answer presented as a full statement is what makes the sweep unsafe")
	}
	if !errors.Is(err, errReadDiedPartWay) {
		t.Errorf("the error does not name what went wrong: %v", err)
	}

	after := f.activeDriftFindings(t)
	if len(after) != len(before) {
		t.Fatalf("the failed pass changed the ACTIVE drift count from %d to %d — a run that did not complete swept on a partial answer, "+
			"which inactivates live findings and re-raises them tomorrow with their workflow status reset", len(before), len(after))
	}
	for id, kind := range after {
		if before[id] != kind {
			t.Errorf("finding %s (%s) changed during a failed pass", id, kind)
		}
	}
}

// The other half: a pass that genuinely sees nothing MUST sweep. Without this
// the test above is satisfied by a producer that never sweeps at all.
func TestIntegration_DriftProducer_ACompletedPassWithNothingToSayDoesSweep(t *testing.T) {
	f := newDriftFixture(t)
	ctx := context.Background()

	f.addEndpoint(t, f.assetID, 22, "tcp", "SSH", f.daysAgo(4), f.now, "active", nil)
	f.run(t, ctx)
	if len(f.activeDriftFindings(t)) == 0 {
		t.Fatal("the first pass raised nothing")
	}

	// Everything ages into the baseline at once.
	exec(t, f.owner, `UPDATE asset_endpoints SET first_seen_at = $2 WHERE tenant_id = $1`, f.tenant, f.daysAgo(settledDays))

	run := f.run(t, ctx)
	if run.Resolved == 0 {
		t.Error("the pass reported 0 resolved; a producer that no longer sees a condition has to say so")
	}
	if n := len(f.activeDriftFindings(t)); n != 0 {
		t.Errorf("%d drift findings are still ACTIVE after a completed pass that saw nothing", n)
	}
}

// The write phase is ONE transaction: a failure part way through it must leave
// neither the upserts that preceded it NOR the sweep behind.
func TestIntegration_DriftProducer_AFailedWriteCommitsNothing(t *testing.T) {
	f := newDriftFixture(t)
	ctx := context.Background()

	f.addEndpoint(t, f.assetID, 22, "tcp", "SSH", f.daysAgo(4), f.now, "active", nil)
	f.run(t, ctx)
	before := f.activeDriftFindings(t)
	if len(before) == 0 {
		t.Fatal("the first pass raised nothing")
	}

	// A plan whose FIRST entry is valid and whose second is not a registered
	// kind. The writer refuses the second; everything the transaction had
	// already done — including the first upsert — must go with it, and the
	// sweep must never run.
	good := plannedDrift{
		finding: producer.Finding{
			Kind:         findings.KindNewIssuer,
			Subject:      producer.Subject{Type: findings.SubjectAsset, ID: f.baselineAsset},
			SubjectLabel: "settled-peer",
			Severity:     producer.SeverityMedium,
			Score:        30,
			Summary:      "a valid finding that must not survive its transaction",
			Evidence:     map[string]any{"observation_key": "x"},
		},
		observationKey: "x",
	}
	bad := good
	bad.finding.Kind = "not_a_drift_kind"

	var run DriftRun
	if err := f.producer.write(ctx, f.tenant, []plannedDrift{good, bad},
		[]uuid.UUID{f.baselineAsset}, &run); err == nil {
		t.Fatal("the write phase accepted an unregistered kind")
	}
	if got := f.finding(t, findings.KindNewIssuer, f.baselineAsset); got != nil {
		t.Error("an upsert from a failed write phase was committed — the upserts and the sweep are not one transaction")
	}
	after := f.activeDriftFindings(t)
	if len(after) != len(before) {
		t.Fatalf("the failed write changed the ACTIVE drift count from %d to %d — a sweep landed without the upserts that justify it",
			len(before), len(after))
	}
}

// --- reachability -----------------------------------------------------------

// A drift finding has to be reachable from the asset it is about, through the
// SAME predicate the inventory's `finding:(…)` sub-query compiles to. Without
// this the findings exist and are invisible from the inventory.
func TestIntegration_DriftProducer_FindingsAreReachableFromTheAsset(t *testing.T) {
	f := newDriftFixture(t)
	f.addEndpoint(t, f.assetID, 22, "tcp", "SSH", f.daysAgo(4), f.now, "active", nil)
	f.run(t, context.Background())

	clause := findings.AssetSubjectClause("fnd", "a", aliasCounter(), func(s string) string {
		return "'" + s + "'"
	})
	q := `SELECT count(DISTINCT a.id) FROM assets a WHERE a.tenant_id = $1
	      AND EXISTS (SELECT 1 FROM findings fnd
	                  WHERE fnd.tenant_id = a.tenant_id
	                    AND fnd.producer = 'drift' AND fnd.kind = $2
	                    AND ` + findings.OpenSQL("fnd") + ` AND (` + clause + `))`

	// Same treatment as the pass itself: this reads `assets` and `findings` in
	// one statement, which is exactly the shape that deadlocks against another
	// binary's schema apply — and did, four attempts in a row.
	var n int
	testdb.WithSchemaShareLock(t, f.owner, func() {
		testdb.RetryTransient(t, func() error {
			return f.owner.QueryRow(q, f.tenant, findings.KindUnexpectedProtocol).Scan(&n)
		})
	})
	if n != 1 {
		t.Errorf("%d assets reachable from an open unexpected_protocol finding, want 1 — the inventory's finding:(…) predicate cannot see it", n)
	}
}

// --- the tenant setting -----------------------------------------------------

// The window is read PER PASS. A cached one would keep answering with the value
// the service booted on, and the settings page would silently do nothing.
func TestIntegration_DriftProducer_ReadsTheWindowEveryPass(t *testing.T) {
	f := newDriftFixture(t)
	ctx := context.Background()

	// 60 days ago: outside the default 30-day window, inside a 90-day one.
	f.addEndpoint(t, f.assetID, 22, "tcp", "SSH", f.daysAgo(60), f.now, "active", nil)

	run := f.run(t, ctx)
	if run.BaselineDays != driftsettings.DefaultBaselineDays {
		t.Errorf("a tenant who has never set the window got %d days, want %d", run.BaselineDays, driftsettings.DefaultBaselineDays)
	}
	if got := f.finding(t, findings.KindUnexpectedProtocol, f.assetID); got != nil {
		t.Fatalf("a protocol first seen 60 days ago is inside a 30-day BASELINE, not its window")
	}

	f.setBaselineDays(t, 90)
	run2 := f.run(t, ctx)
	if run2.BaselineDays != 90 {
		t.Fatalf("the pass used a %d-day window after the tenant set 90 — the setting is cached", run2.BaselineDays)
	}
	if got := f.finding(t, findings.KindUnexpectedProtocol, f.assetID); got == nil {
		t.Error("no finding under a 90-day window for a protocol first seen 60 days ago")
	}
}

// --- coverage (workstream 3.2) ----------------------------------------------

// addAssetWithoutSegment puts an asset on NO network segment, so
// `new_class_in_segment` has nowhere to place it. Combined with a first
// sighting inside the window it makes a subject NO drift kind can compare —
// which is the case the coverage rule exists for.
func (f *driftFixture) addAssetWithoutSegment(t *testing.T, class string, firstSeen time.Time, name string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	path := class
	if c, ok := assetclass.Get(class); ok && c.Path != "" {
		path = c.Path
	}
	exec(t, f.owner, `INSERT INTO assets (id, tenant_id, class_key, class_path, display_name, hostname,
	                                      network_segment_id, asset_status, first_discovered_at, last_seen_at)
	                  VALUES ($1, $2, $3, $4, $5, $5, NULL, 'monitoring', $6, now())`,
		id, f.tenant, class, path, name, firstSeen)
	return id
}

// coverage reads this producer's rows of `producer_assessments`.
func (f *driftFixture) coverage(t *testing.T) map[uuid.UUID]bool {
	t.Helper()
	out := map[uuid.UUID]bool{}
	testdb.RetryTransient(t, func() error {
		clear(out)
		rows, err := f.owner.Query(`
			SELECT asset_id FROM producer_assessments
			WHERE tenant_id = $1 AND producer = $2`, f.tenant, findings.ProducerDrift)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out[id] = true
		}
		return rows.Err()
	})
	return out
}

// assessedBy reads one asset's risk_assessed_by — what the rollup derives from
// the coverage rows, and what the inventory actually shows.
func (f *driftFixture) assessedBy(t *testing.T, assetID uuid.UUID) []string {
	t.Helper()
	var out []string
	testdb.RetryTransient(t, func() error {
		return f.owner.QueryRow(`SELECT coalesce(risk_assessed_by, '{}') FROM assets WHERE id = $1`,
			assetID).Scan(pq.Array(&out))
	})
	return out
}

// recomputeRisk runs the generic post-pass rollup the finding-producer job runs,
// so the assertion is about what a deployment would actually show rather than
// about the coverage table alone.
func (f *driftFixture) recomputeRisk(t *testing.T) {
	t.Helper()
	testdb.WithSchemaShareLock(t, f.owner, func() {
		testdb.RetryTransient(t, func() error {
			return shareddatabase.WithTenantTx(context.Background(), f.app, f.tenant, func(tx *sql.Tx) error {
				_, err := riskrollup.Recompute(context.Background(), tx, f.tenant, uuid.Nil)
				return err
			})
		})
	})
}

// Coverage is what the pass could COMPARE, not what it found.
//
// `producer_assessments` is how "drift looked at this asset and it is fine"
// stops being spelled the same way as "drift has never looked" (workstream 3.2,
// ADR-0005 D4). Drift has to be stricter with itself than the catalogue
// producers, because it judges the tenant against their own history: an asset
// with no history is not one it examined and found clean, it is one it could
// not examine at all.
//
// Both directions are asserted. A test that only demanded coverage would pass a
// producer that claimed every asset in the tenant, which is the failure mode
// that matters — an over-claimed asset reads "assessed clean" and is silent,
// while an under-claimed one reads "not assessed", which is true and visible.
func TestIntegration_DriftProducer_CoverageRecordsOnlyWhatCouldBeCompared(t *testing.T) {
	f := newDriftFixture(t)
	ctx := context.Background()

	// No segment to be new on, and first seen inside the window, so it has no
	// protocol, port or issuer history either.
	orphan := f.addAssetWithoutSegment(t, assetclass.KeyServer, f.daysAgo(2), "no-history-host")
	f.addEndpoint(t, orphan, 22, "tcp", "SSH", f.daysAgo(2), f.now, "active", nil)

	// Something for the settled asset to have drifted, so the pass has work.
	f.addEndpoint(t, f.assetID, 3389, "tcp", "SMB", f.daysAgo(3), f.now, "active", nil)

	run := f.run(t, ctx)
	if run.Assessed == 0 {
		t.Fatal("a completed pass claimed coverage of nothing")
	}
	if run.NoBaseline == 0 {
		t.Error("the orphan was skipped without being counted — \"could not compare\" has to be reported")
	}

	covered := f.coverage(t)
	if !covered[f.assetID] {
		t.Error("the settled asset was compared against its own baseline and is not recorded as assessed")
	}
	// The settled PEER has been in the inventory for 400 days but has no
	// endpoint, crypto configuration or certificate of its own, so drift has
	// nothing about IT to compare — being on a segment with history is the
	// segment's baseline, not the asset's. Not covered, deliberately: the class
	// question is answerable for every asset on a settled segment, and counting
	// it would make "drift assessed this" true of assets drift knows nothing
	// about. An asset a finding IS raised on is covered by the separate rule
	// the test below pins.
	if covered[f.baselineAsset] {
		t.Error("an asset with no observations of its own is recorded as assessed by drift")
	}
	if covered[orphan] {
		t.Error("an asset with no baseline for any kind is recorded as assessed — " +
			"\"we could not compare\" must not read as \"we compared and it was fine\"")
	}

	// And what the inventory shows, through the rollup rather than the table.
	f.recomputeRisk(t)
	if got := f.assessedBy(t, f.assetID); !slices.Contains(got, findings.ProducerDrift) {
		t.Errorf("risk_assessed_by = %v on the settled asset; drift's coverage never reached the rollup", got)
	}
	if got := f.assessedBy(t, orphan); slices.Contains(got, findings.ProducerDrift) {
		t.Errorf("risk_assessed_by = %v on an asset drift could not judge", got)
	}
}

// An asset drift RAISED on is covered even where the per-kind gates would not
// have said so on their own — `new_class_in_segment`'s subject is by definition
// too young to have a baseline of its own. Without this the rollup can put a
// drift SCORE on an asset whose risk_assessed_by does not mention drift, which
// the inventory renders as "not assessed" beside a number drift supplied.
func TestIntegration_DriftProducer_AnAssetItRaisedOnIsAlwaysCovered(t *testing.T) {
	f := newDriftFixture(t)
	ctx := context.Background()

	printer := f.addAsset(t, assetclass.KeyPrinter, f.daysAgo(5), "lobby-printer")

	f.run(t, ctx)
	if got := f.finding(t, findings.KindNewClassInSegment, printer); got == nil {
		t.Fatal("no new_class_in_segment finding for the first printer on a server VLAN")
	}
	if !f.coverage(t)[printer] {
		t.Fatal("drift raised a finding on this asset and did not record having assessed it")
	}

	f.recomputeRisk(t)
	var score int
	testdb.RetryTransient(t, func() error {
		return f.owner.QueryRow(`SELECT coalesce(risk_score, 0) FROM assets WHERE id = $1`, printer).Scan(&score)
	})
	if score == 0 {
		t.Fatalf("risk_score = %d after a scoring drift finding; the rollup did not pick it up", score)
	}
	if got := f.assessedBy(t, printer); !slices.Contains(got, findings.ProducerDrift) {
		t.Errorf("risk_score = %d with risk_assessed_by = %v — a score from drift beside \"nobody assessed this\"",
			score, got)
	}
}

// A pass that could not evaluate covers nothing. Same rule as not sweeping, and
// the same reason: it has made no statement.
func TestIntegration_DriftProducer_WarmUpCoversNothing(t *testing.T) {
	f := newDriftFixture(t)
	ctx := context.Background()

	exec(t, f.owner, `UPDATE assets SET first_discovered_at = $2 WHERE tenant_id = $1`, f.tenant, f.daysAgo(1))

	run := f.run(t, ctx)
	if !run.WarmingUp {
		t.Fatal("a tenant whose oldest observation is a day old reported a full baseline")
	}
	if run.Assessed != 0 {
		t.Errorf("the warm-up pass claimed coverage of %d assets", run.Assessed)
	}
	if n := len(f.coverage(t)); n != 0 {
		t.Errorf("%d coverage rows after a pass that could not evaluate anything, want 0 — "+
			"every asset of a brand-new organization would read \"drift assessed this\" on day one", n)
	}
}

// A write phase that fails AFTER the coverage claim leaves none of it behind.
//
// This is the structural claim — MarkAssessed runs inside the SAME transaction
// as the upserts and the sweep — and a cancelled context cannot prove it: that
// kills the read, the write never runs, and the assertion passes however the
// claim is arranged. The sweep is the last statement of the write phase, so a
// trigger that refuses the sweep's UPDATE is a faithful stand-in for "the
// transaction died after MarkAssessed". Same pattern as
// TestIntegration_CryptoProducer_AFailedWritePhaseClaimsNoCoverage, scoped to
// this test's tenant and dropped afterwards.
//
// Mutation-proven: claim the coverage in its own transaction before write() and
// this goes red with the coverage rows present.
func TestIntegration_DriftProducer_AFailedWritePhaseClaimsNoCoverage(t *testing.T) {
	f := newDriftFixture(t)
	ctx := context.Background()

	f.addEndpoint(t, f.assetID, 3389, "tcp", "SMB", f.daysAgo(3), f.now, "active", nil)

	// A stale finding of a kind this pass will NOT re-assert, so the sweep has a
	// row to inactivate and therefore a statement to execute.
	exec(t, f.owner, `
		INSERT INTO findings (id, tenant_id, producer, kind, subject_type, subject_id,
		                      severity, score, summary, detection_state, workflow_status)
		VALUES ($1, $2, 'drift', 'new_issuer', 'asset', $3,
		        'medium', 30, 'stale, to be swept', 'ACTIVE', 'NEW')`,
		uuid.New(), f.tenant, f.baselineAsset)

	trigger := "rev1675_" + strings.ReplaceAll(uuid.New().String(), "-", "")[:12]
	dropTrigger := func() {
		_, _ = f.owner.Exec(`DROP TRIGGER IF EXISTS ` + trigger + ` ON findings`)
		_, _ = f.owner.Exec(`DROP FUNCTION IF EXISTS ` + trigger + `()`)
	}
	t.Cleanup(dropTrigger)

	// DDL on `findings` against a database other package binaries are applying
	// schema.sql to, so it lives and dies inside the SHARED schema lock — which
	// does not serialize this test against anything except an applier.
	testdb.WithSchemaShareLock(t, f.owner, func() {
		exec(t, f.owner, `
			CREATE OR REPLACE FUNCTION `+trigger+`() RETURNS trigger AS $$
			BEGIN RAISE EXCEPTION 'sweep refused by the test'; END $$ LANGUAGE plpgsql`)
		exec(t, f.owner, `
			CREATE TRIGGER `+trigger+` BEFORE UPDATE ON findings
			FOR EACH ROW WHEN (NEW.detection_state = 'INACTIVE' AND NEW.tenant_id = '`+f.tenant.String()+`')
			EXECUTE FUNCTION `+trigger+`()`)

		if _, err := f.producer.Run(ctx, f.tenant); err == nil {
			t.Error("a pass whose write phase failed reported success")
		}
		dropTrigger()
	})
	if t.Failed() {
		t.FailNow()
	}

	if n := len(f.coverage(t)); n != 0 {
		t.Fatalf("a write phase that failed AFTER the coverage claim left %d coverage rows, want 0 — "+
			"the claim is not inside the pass's transaction, so an asset nothing assessed reads "+
			"\"assessed clean\" from then on", n)
	}
	if got := f.finding(t, findings.KindPortProfileChanged, f.assetID); got != nil {
		t.Error("a finding survived the failed write phase — the upserts are in the same transaction " +
			"and must roll back with it")
	}
}

// A `host_key_changed` finding must SURVIVE a baseline drift pass (H7).
//
// The kind belongs to the `drift` producer because a device presenting a new
// SSH host key IS drift, but it is raised by device-interrogation-service, not
// by this pass. A Sweep is a full statement — "everything of this kind I did
// not re-assert has gone away" — so sweeping a kind this pass cannot evaluate
// would inactivate every open row of it on the next run, silently, and the
// operator would lose the only signal that a managed device's identity changed.
//
// Mutation-proven: delete the driftKindsNotFromBaseline entry (so the kind
// falls back into driftKinds) and this goes red with the row INACTIVE.
func TestIntegration_DriftProducer_DoesNotSweepHostKeyChanged(t *testing.T) {
	f := newDriftFixture(t)
	ctx := context.Background()

	// Something for the pass to actually do, so the write phase — and its
	// sweep — runs rather than short-circuiting.
	f.addEndpoint(t, f.assetID, 3389, "tcp", "SMB", f.daysAgo(3), f.now, "active", nil)

	hostKeyFinding := uuid.New()
	exec(t, f.owner, `
		INSERT INTO findings (id, tenant_id, producer, kind, subject_type, subject_id,
		                      severity, score, summary, detection_state, workflow_status)
		VALUES ($1, $2, 'drift', 'host_key_changed', 'asset', $3,
		        'high', 70, 'device presented a different SSH host key', 'ACTIVE', 'NEW')`,
		hostKeyFinding, f.tenant, f.baselineAsset)

	// A kind this pass DOES own, left stale, so the assertion below distinguishes
	// "the sweep did not run" from "the sweep ran and correctly skipped ours".
	sweepable := uuid.New()
	exec(t, f.owner, `
		INSERT INTO findings (id, tenant_id, producer, kind, subject_type, subject_id,
		                      severity, score, summary, detection_state, workflow_status)
		VALUES ($1, $2, 'drift', 'new_issuer', 'asset', $3,
		        'medium', 30, 'stale, to be swept', 'ACTIVE', 'NEW')`,
		sweepable, f.tenant, f.baselineAsset)

	f.run(t, ctx)

	var hostKeyState, sweepableState string
	if err := f.owner.QueryRow(`SELECT detection_state FROM findings WHERE id = $1`, hostKeyFinding).
		Scan(&hostKeyState); err != nil {
		t.Fatalf("read host_key_changed finding: %v", err)
	}
	if err := f.owner.QueryRow(`SELECT detection_state FROM findings WHERE id = $1`, sweepable).
		Scan(&sweepableState); err != nil {
		t.Fatalf("read new_issuer finding: %v", err)
	}

	if sweepableState != producer.StateInactive {
		t.Fatalf("new_issuer detection_state = %q, want %q — the sweep did not run, so this test proves nothing",
			sweepableState, producer.StateInactive)
	}
	if hostKeyState != producer.StateActive {
		t.Errorf("host_key_changed detection_state = %q, want %q — the baseline pass swept a finding it cannot evaluate",
			hostKeyState, producer.StateActive)
	}
}

// Every `drift` kind is either swept by this pass or explicitly excluded, and
// every exclusion names a kind that still exists.
//
// Two polarities, because an exclusion list is exactly the kind of guard that
// rots into a no-op: a kind renamed in the registry leaves a stale entry here
// that matches nothing and quietly stops protecting anything.
func TestDriftSweepKindPartitionIsComplete(t *testing.T) {
	registered := map[string]bool{}
	for _, k := range findings.All {
		if k.Producer == findings.ProducerDrift {
			registered[k.Key] = true
		}
	}
	if len(registered) == 0 {
		t.Fatal("no drift kinds in the registry")
	}

	for excluded := range driftKindsNotFromBaseline {
		if !registered[excluded] {
			t.Errorf("driftKindsNotFromBaseline names %q, which is not a registered `drift` kind — "+
				"a stale exclusion protects nothing", excluded)
		}
		if slices.Contains(driftKinds, excluded) {
			t.Errorf("kind %q is both excluded and swept", excluded)
		}
	}

	for kind := range registered {
		if driftKindsNotFromBaseline[kind] {
			continue
		}
		if !slices.Contains(driftKinds, kind) {
			t.Errorf("registered drift kind %q is neither swept nor explicitly excluded", kind)
		}
	}
}
