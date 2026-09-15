package producers

// The `configuration` producer end to end, against a real Postgres under RLS.
//
// configuration_rules_test.go covers the DECISION — which rule fires on which
// signal. What only a database can show is the LIFECYCLE: that a finding raised
// by one pass is resolved by the next when the condition goes away, that the
// two subject types (asset and endpoint) of one kind coexist and are swept by
// the same statement, and that a pass which FAILED sweeps nothing.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer/producertest"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// configFixture is one tenant with a managed switch and a handful of endpoints
// — the smallest inventory that exercises both kinds and both signals.
type configFixture struct {
	owner  *sql.DB
	app    *sql.DB
	tenant uuid.UUID

	// switchID is managed over Telnet, per its interrogation facts, and also
	// has the Telnet socket.
	switchID  uuid.UUID
	telnetEP  uuid.UUID
	redisEP   uuid.UUID
	loopbackR uuid.UUID
	tlsESEP   uuid.UUID

	// cleanID is managed over HTTPS: an explicit mgmt.plaintext = false, which
	// is an ANSWER and must raise nothing.
	cleanID uuid.UUID

	producer *ConfigurationProducer
}

func newConfigFixture(t *testing.T) *configFixture {
	t.Helper()
	owner := testdb.Connect(t)
	// No testdb.ApplySchema: the runner applies the schema once per database,
	// and re-applying it per fixture takes ACCESS EXCLUSIVE locks across the
	// whole schema while other package binaries of the same `go test ./...` are
	// querying it.
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)

	f := &configFixture{owner: owner, app: app, tenant: tenant}

	f.switchID = uuid.New()
	exec(t, owner, `INSERT INTO assets (id, tenant_id, hostname, display_name, class_key, class_path, asset_status)
	                VALUES ($1, $2, 'core-sw-1', 'core-sw-1', 'switch', 'hardware.network_device.switch', 'monitoring')`,
		f.switchID, tenant)
	fact(t, owner, tenant, f.switchID, "mgmt.plaintext", `true`)
	fact(t, owner, tenant, f.switchID, "mgmt.protocol", `"telnet"`)

	f.cleanID = uuid.New()
	exec(t, owner, `INSERT INTO assets (id, tenant_id, hostname, display_name, class_key, class_path, asset_status)
	                VALUES ($1, $2, 'fw-1', 'fw-1', 'firewall', 'hardware.network_device.firewall', 'monitoring')`,
		f.cleanID, tenant)
	fact(t, owner, tenant, f.cleanID, "mgmt.plaintext", `false`)
	fact(t, owner, tenant, f.cleanID, "mgmt.protocol", `"https"`)

	// Telnet, named by a banner — the strong signal.
	f.telnetEP = endpoint(t, owner, tenant, f.switchID, "198.51.100.4", 23, "tcp",
		"telnetd", "banner", nil)
	// Redis on its registered port with nothing measured — the port signal.
	f.redisEP = endpoint(t, owner, tenant, f.switchID, "198.51.100.5", 6379, "tcp",
		"", "", nil)
	// The same service bound to loopback: reachable only from the host, so not
	// an exposure.
	loopback := true
	f.loopbackR = endpoint(t, owner, tenant, f.switchID, "127.0.0.1", 6379, "tcp",
		"redis-server", "host_socket_owner", &loopback)
	// Elasticsearch behind TLS: a configuration somebody made deliberately.
	f.tlsESEP = endpoint(t, owner, tenant, f.cleanID, "198.51.100.9", 9200, "tcp",
		"", "", nil)
	exec(t, owner, `UPDATE asset_endpoints SET protocol = 'TLS' WHERE id = $1 AND tenant_id = $2`, f.tlsESEP, tenant)

	p, err := NewConfigurationProducer(app)
	if err != nil {
		t.Fatalf("NewConfigurationProducer: %v", err)
	}
	f.producer = p
	return f
}

// run is one pass, taken under the schema share lock and retried past the
// cross-binary races the shared test database produces — see driftFixture.run
// for why both halves are needed, and
// TestIntegration_Producers_PassHelpersTakeTheSchemaShareLock for the proof
// that every helper here takes the lock.
//
// Used wherever a pass is EXPECTED to succeed. The cases that expect an error
// call Run directly, because a retry there would hide the thing under test.
func (f *configFixture) run(t *testing.T, ctx context.Context) ConfigRun {
	t.Helper()
	var out ConfigRun
	testdb.WithSchemaShareLock(t, f.owner, func() {
		testdb.RetryTransient(t, func() error {
			var err error
			out, err = f.producer.Run(ctx, f.tenant)
			return err
		})
	})
	return out
}

func TestIntegration_ConfigurationProducer_WriterContract(t *testing.T) {
	owner := testdb.Connect(t)
	app := testdb.ConnectAsAppRole(t, owner)

	// The contract suite with THIS producer's key and kinds. `endpoint` is the
	// subject type BOTH kinds allow — insecure_service_exposed permits only
	// that one — so it is what the suite can drive both with.
	producertest.Run(t, producertest.Config{
		DB:          app,
		Owner:       owner,
		Producer:    findings.ProducerConfiguration,
		Kind:        findings.KindPlaintextManagement,
		OtherKind:   findings.KindInsecureServiceExposed,
		SubjectType: findings.SubjectEndpoint,
	})
}

func TestIntegration_ConfigurationProducer_RaisesResolvesAndReturns(t *testing.T) {
	f := newConfigFixture(t)
	ctx := context.Background()

	run := f.run(t, ctx)

	// --- the management plane, from the facts, on the ASSET.
	mgmt := f.finding(t, findings.KindPlaintextManagement, findings.SubjectAsset, f.switchID)
	if mgmt == nil {
		t.Fatal("no plaintext_management finding on the switch; its mgmt.plaintext fact is true")
	}
	k, _ := findings.Get(findings.ProducerConfiguration, findings.KindPlaintextManagement)
	if mgmt.severity != k.DefaultSeverity || mgmt.score != k.Score {
		t.Errorf("severity/score = %s/%d, want the registry's %s/%d",
			mgmt.severity, mgmt.score, k.DefaultSeverity, k.Score)
	}
	if got := mgmt.evidence["matched_by"]; got != signalFact {
		t.Errorf("evidence.matched_by = %v, want %q", got, signalFact)
	}
	if got := mgmt.evidence["mgmt_protocol"]; got != "telnet" {
		t.Errorf("evidence.mgmt_protocol = %v, want telnet", got)
	}

	// --- an explicit `false` is an ANSWER and raises nothing.
	if clean := f.finding(t, findings.KindPlaintextManagement, findings.SubjectAsset, f.cleanID); clean != nil {
		t.Error("a device whose mgmt.plaintext fact is explicitly FALSE raised a finding")
	}
	if run.PlaintextAssessed != 2 {
		t.Errorf("run reports %d assets assessed for plaintext management, want 2 — an explicit false is assessed, and the coverage number is how an operator tells an assessed-clean estate from an unlooked-at one",
			run.PlaintextAssessed)
	}

	// --- the Telnet socket, on the ENDPOINT. Same kind, different subject:
	// both must exist, which is what proves the unique index is per-subject.
	ep := f.finding(t, findings.KindPlaintextManagement, findings.SubjectEndpoint, f.telnetEP)
	if ep == nil {
		t.Fatal("no plaintext_management finding on the telnet endpoint")
	}
	if got := ep.evidence["rule_id"]; got != "mgmt-telnet" {
		t.Errorf("evidence.rule_id = %v, want mgmt-telnet — the citation is what makes a disputed finding checkable", got)
	}
	if got := ep.evidence["matched_by"]; got != signalServiceName {
		t.Errorf("evidence.matched_by = %v, want %q", got, signalServiceName)
	}
	if got := ep.evidence["asset_id"]; got != f.switchID.String() {
		t.Errorf("the endpoint finding does not name its host: %v", got)
	}

	// --- Redis on its port, with nothing measured.
	redis := f.finding(t, findings.KindInsecureServiceExposed, findings.SubjectEndpoint, f.redisEP)
	if redis == nil {
		t.Fatal("no insecure_service_exposed finding on the redis endpoint")
	}
	if got := redis.evidence["matched_by"]; got != signalPort {
		t.Errorf("evidence.matched_by = %v, want %q — a port-derived finding must say so", got, signalPort)
	}
	if _, ok := redis.evidence["bound_local"]; !ok {
		t.Error("evidence carries no bound_local; whether exposure was MEASURED or assumed is part of the claim")
	}

	// --- what must NOT be raised.
	if l := f.finding(t, findings.KindInsecureServiceExposed, findings.SubjectEndpoint, f.loopbackR); l != nil {
		t.Error("a loopback-bound Redis raised an exposure finding; it is reachable only from the host and is the recommended configuration")
	}
	if e := f.finding(t, findings.KindInsecureServiceExposed, findings.SubjectEndpoint, f.tlsESEP); e != nil {
		t.Error("an Elasticsearch behind TLS raised the unauthenticated-default finding")
	}
	if run.Raised != 3 {
		t.Errorf("run raised %d findings, want 3 (asset plaintext, endpoint plaintext, redis)", run.Raised)
	}

	// --- a converged re-run changes nothing but the counters.
	run2 := f.run(t, ctx)
	if run2.Resolved != 0 {
		t.Errorf("a converged re-run resolved %d findings; nothing changed", run2.Resolved)
	}
	again := f.finding(t, findings.KindPlaintextManagement, findings.SubjectEndpoint, f.telnetEP)
	if again.id != ep.id {
		t.Fatalf("the second pass wrote a NEW row (%s, was %s)", again.id, ep.id)
	}
	if again.occurrence != 2 {
		t.Errorf("occurrence_count = %d after two passes, want 2", again.occurrence)
	}

	// --- somebody turns Telnet off and moves management to SSH.
	exec(t, f.owner, `UPDATE asset_endpoints SET status = 'closed' WHERE id = $1 AND tenant_id = $2`, f.telnetEP, f.tenant)
	exec(t, f.owner, `UPDATE asset_facts SET value = 'false' WHERE tenant_id = $1 AND asset_id = $2 AND key = 'mgmt.plaintext'`,
		f.tenant, f.switchID)

	run3 := f.run(t, ctx)
	if run3.Resolved != 2 {
		t.Errorf("run 3 resolved %d findings, want 2 (the asset's and the endpoint's)", run3.Resolved)
	}
	for _, want := range []struct {
		subjectType string
		id          uuid.UUID
	}{
		{findings.SubjectAsset, f.switchID},
		{findings.SubjectEndpoint, f.telnetEP},
	} {
		got := f.finding(t, findings.KindPlaintextManagement, want.subjectType, want.id)
		if got == nil || got.state != producer.StateInactive {
			t.Errorf("%s finding is %v after the condition went away, want INACTIVE", want.subjectType, got)
		}
	}
	// Sweeping one kind must not touch the other.
	if r := f.finding(t, findings.KindInsecureServiceExposed, findings.SubjectEndpoint, f.redisEP); r == nil || r.state != producer.StateActive {
		t.Error("the redis exposure finding was disturbed by the plaintext sweep; a sweep is scoped to its own kind")
	}

	// --- and back. The row is REUSED, not replaced.
	exec(t, f.owner, `UPDATE asset_facts SET value = 'true' WHERE tenant_id = $1 AND asset_id = $2 AND key = 'mgmt.plaintext'`,
		f.tenant, f.switchID)
	f.run(t, ctx)
	back := f.finding(t, findings.KindPlaintextManagement, findings.SubjectAsset, f.switchID)
	if back.id != mgmt.id {
		t.Fatalf("the returning condition got a NEW row %s instead of reusing %s — first_seen and occurrence_count would each describe one episode",
			back.id, mgmt.id)
	}
	if !back.resurfaced {
		t.Error("resurfaced_at is NULL on a finding that came back")
	}
}

// A pass whose READ failed must not sweep. Same property the eol producer's
// failed_pass_integration_test.go pins, driven differently: this producer has
// no catalogue to break, so the failure is injected into ONE query part way
// through the read — see failing_handle_integration_test.go for why a closed
// pool is not good enough.
//
// Mutation-proven: delete the `if err != nil { return }` after p.read and this
// goes red with every finding in the fixture INACTIVE — which is precisely the
// production symptom (everything disappears from the page overnight and comes
// back tomorrow with its workflow status reset and its notification re-sent).
func TestIntegration_ConfigurationProducer_AFailedPassDoesNotSweep(t *testing.T) {
	f := newConfigFixture(t)
	ctx := context.Background()

	f.run(t, ctx)
	before := activeFindingsFor(t, f.owner, f.tenant, findings.ProducerConfiguration)
	if len(before) == 0 {
		t.Fatal("the first pass raised nothing; there is no finding for a bad sweep to inactivate")
	}

	failing := &ConfigurationProducer{
		repo:   pgidentity.New(failingHandle(t)),
		writer: f.producer.writer,
	}
	// The SECOND query of the read: the assets are loaded, the endpoints never
	// arrive. A partial answer, and a pass that has made no full statement.
	armQueryFailure(t, 2)
	_, err := failing.Run(ctx, f.tenant)
	if err == nil {
		t.Fatal("a pass whose read failed reported success — a partial answer presented as a full statement is exactly what makes the sweep unsafe")
	}
	if !errors.Is(err, errInjectedReadFailure) {
		t.Errorf("the error does not name what went wrong: %v", err)
	}

	after := activeFindingsFor(t, f.owner, f.tenant, findings.ProducerConfiguration)
	if len(after) != len(before) {
		t.Fatalf("the failed pass changed the ACTIVE finding count from %d to %d — a run that did not complete swept on a partial answer",
			len(before), len(after))
	}
	for id, state := range after {
		if before[id] != state {
			t.Errorf("finding %s moved from %q to %q during a failed pass", id, before[id], state)
		}
	}
}

// The other polarity. Without this, the test above is satisfied by a producer
// that never sweeps at all — which would leave every resolved condition ACTIVE
// forever.
func TestIntegration_ConfigurationProducer_ACompletedPassWithNothingToSayDoesSweep(t *testing.T) {
	f := newConfigFixture(t)
	ctx := context.Background()

	f.run(t, ctx)
	if len(activeFindingsFor(t, f.owner, f.tenant, findings.ProducerConfiguration)) == 0 {
		t.Fatal("the first pass raised nothing")
	}

	// Everything cleaned up at once: the sockets closed and the management
	// plane moved. The pass completes and its statement is "I see nothing".
	exec(t, f.owner, `UPDATE asset_endpoints SET status = 'closed' WHERE tenant_id = $1`, f.tenant)
	exec(t, f.owner, `UPDATE asset_facts SET value = 'false' WHERE tenant_id = $1 AND key = 'mgmt.plaintext'`, f.tenant)

	run := f.run(t, ctx)
	if run.Resolved == 0 {
		t.Error("the pass reported 0 resolved; a producer that no longer sees a condition has to say so")
	}
	if n := len(activeFindingsFor(t, f.owner, f.tenant, findings.ProducerConfiguration)); n != 0 {
		t.Errorf("%d findings are still ACTIVE after a completed pass that saw nothing", n)
	}
}

// Coverage: the pass claims the assets it EXAMINED, and `mgmt_plaintext`
// becomes answerable for them.
//
// Three-valued in both directions, and the narrowing is the interesting half. An
// asset with neither a management fact nor an active endpoint gave this producer
// nothing to look at; claiming it would turn "nothing was collected about this
// host" into "we looked and it is fine" on the control.
func TestIntegration_ConfigurationProducer_CoverageIsWhatItExamined(t *testing.T) {
	f := newConfigFixture(t)
	ctx := context.Background()

	// A third asset: read by the pass, examined by nothing.
	bare := uuid.New()
	exec(t, f.owner, `INSERT INTO assets (id, tenant_id, hostname, display_name, class_key, class_path, asset_status)
	                  VALUES ($1, $2, 'bare-1', 'bare-1', 'server', 'hardware.computer.server', 'monitoring')`,
		bare, f.tenant)

	mgmt := loadMeasurementSQL(t, "mgmt_plaintext")

	// Before the pass: nothing has evaluated anything, so NO ROWS. Not zero.
	if n := countMeasurementRows(t, f.owner, f.tenant, mgmt); n != 0 {
		t.Fatalf("mgmt_plaintext produced %d measurements before the producer ran; an asset nobody has evaluated must read NOT ASSESSED", n)
	}

	run := f.run(t, ctx)
	if run.Assets != 3 {
		t.Fatalf("the pass read %d assets, want 3", run.Assets)
	}
	if run.Assessed != 2 {
		t.Errorf("the pass claimed %d assets, want 2 — the host with no management fact and no endpoint was read and must NOT be claimed", run.Assessed)
	}
	covered := assessedAssets(t, f.owner, f.tenant, findings.ProducerConfiguration)
	for _, id := range covered {
		if id == bare.String() {
			t.Error("the pass claimed coverage of a host it had nothing to look at; 'nothing was collected' would then read as 'we looked and it is fine'")
		}
	}

	// After: a measurement for each CLAIMED monitoring asset, and none for the
	// unexamined one.
	values := measurementValues(t, f.owner, f.tenant, mgmt)
	if len(values) != 2 {
		t.Fatalf("mgmt_plaintext produced %d measurements, want 2 (the two examined assets): %v", len(values), values)
	}
	if _, present := values[bare.String()]; present {
		t.Error("the unexamined host produced a measurement")
	}
	// The switch carries the asset-subject finding AND the endpoint-subject one,
	// which is what `via: asset_or_endpoint` is for.
	if got := values[f.switchID.String()]; got != 2 {
		t.Errorf("mgmt_plaintext counts %d for the switch, want 2 — one on the asset (its mgmt.plaintext fact) "+
			"and one on the Telnet endpoint. A count of 1 means the control cannot see a listener recorded "+
			"against the socket", got)
	}
	// The firewall answered explicitly false and has no plaintext endpoint:
	// assessed clean, which is a real answer and not the same as not assessed.
	if got, present := values[f.cleanID.String()]; !present || got != 0 {
		t.Errorf("mgmt_plaintext for the HTTPS-managed firewall = %v (present=%v), want 0 — an explicit "+
			"mgmt.plaintext:false is an ANSWER", got, present)
	}
}

// A pass whose WRITE PHASE failed claims no coverage. The contract on
// Writer.MarkAssessed asks every producer for this, and asks that it not be
// driven by a cancelled context — see the hygiene twin for why.
func TestIntegration_ConfigurationProducer_AFailedWritePhaseClaimsNoCoverage(t *testing.T) {
	f := newConfigFixture(t)
	ctx := context.Background()

	failing := &ConfigurationProducer{
		repo:   pgidentity.New(failingHandle(t)),
		writer: f.producer.writer,
	}
	// The read phase issues two queries (assets, endpoints); the write phase's
	// Upserts and the coverage INSERT are Execs, so the first Sweep is the third
	// QUERY. Failing it rolls the write transaction back with the coverage claim
	// already issued inside it.
	armQueryFailure(t, configSweepQueryOrdinal)
	if _, err := failing.Run(ctx, f.tenant); err == nil {
		t.Fatal("a pass whose write phase failed reported success")
	}

	if got := assessedAssets(t, f.owner, f.tenant, findings.ProducerConfiguration); len(got) != 0 {
		t.Errorf("a failed write phase left %d coverage rows: %v", len(got), got)
	}
	if n := len(activeFindingsFor(t, f.owner, f.tenant, findings.ProducerConfiguration)); n != 0 {
		t.Errorf("a failed write phase left %d ACTIVE findings", n)
	}
}

// configSweepQueryOrdinal is which QUERY of the pass the first Sweep is: the
// read phase's two SELECTs, then the sweep. Upsert and MarkAssessed are Execs
// and are not counted.
const configSweepQueryOrdinal = 3

// Archived assets are not judged. The tenant took them out of the queue; a
// producer putting fresh work back in would undo that.
func TestIntegration_ConfigurationProducer_ArchivedAssetsAreLeftAlone(t *testing.T) {
	f := newConfigFixture(t)
	ctx := context.Background()

	f.run(t, ctx)
	exec(t, f.owner, `UPDATE assets SET asset_status = 'archived' WHERE id = $1 AND tenant_id = $2`, f.switchID, f.tenant)

	f.run(t, ctx)
	for _, c := range []struct {
		kind        string
		subjectType string
		id          uuid.UUID
	}{
		{findings.KindPlaintextManagement, findings.SubjectAsset, f.switchID},
		{findings.KindPlaintextManagement, findings.SubjectEndpoint, f.telnetEP},
		{findings.KindInsecureServiceExposed, findings.SubjectEndpoint, f.redisEP},
	} {
		got := f.finding(t, c.kind, c.subjectType, c.id)
		if got == nil {
			t.Errorf("%s/%s vanished; an archived asset's findings go INACTIVE, they are not deleted", c.kind, c.subjectType)
			continue
		}
		if got.state != producer.StateInactive {
			t.Errorf("%s/%s is %q after the asset was archived, want INACTIVE", c.kind, c.subjectType, got.state)
		}
	}
}

// ---------------------------------------------------------- fixture helpers

func (f *configFixture) finding(t *testing.T, kind, subjectType string, subjectID uuid.UUID) *storedFinding {
	t.Helper()
	return loadFinding(t, f.owner, f.tenant, findings.ProducerConfiguration, kind, subjectType, subjectID)
}

// loadFinding reads one producer's finding for a subject, or nil.
//
// A generalisation of the eol fixture's own reader, shared by the two producers
// added in workstream 3.5 rather than copied twice.
func loadFinding(t *testing.T, db *sql.DB, tenant uuid.UUID, producerKey, kind, subjectType string, subjectID uuid.UUID) *storedFinding {
	t.Helper()
	var out storedFinding
	var raw []byte
	var resurfaced sql.NullTime
	var err error
	testdb.RetryTransient(t, func() error {
		err = db.QueryRow(`
			SELECT id, detection_state, severity, score, occurrence_count, resurfaced_at, summary, evidence
			FROM findings
			WHERE tenant_id = $1 AND producer = $2 AND kind = $3
			  AND subject_type = $4 AND subject_id = $5`,
			tenant, producerKey, kind, subjectType, subjectID).
			Scan(&out.id, &out.state, &out.severity, &out.score, &out.occurrence, &resurfaced, &out.summary, &raw)
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

// activeFindingsFor is one producer's ACTIVE rows for a tenant, by id.
func activeFindingsFor(t *testing.T, db *sql.DB, tenant uuid.UUID, producerKey string) map[string]string {
	t.Helper()
	out := map[string]string{}
	testdb.RetryTransient(t, func() error {
		clear(out)
		rows, err := db.Query(`
			SELECT id::text, detection_state FROM findings
			WHERE tenant_id = $1 AND producer = $2 AND detection_state = 'ACTIVE'`, tenant, producerKey)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id, state string
			if err := rows.Scan(&id, &state); err != nil {
				return err
			}
			out[id] = state
		}
		return rows.Err()
	})
	return out
}

// endpoint inserts one asset_endpoints row and returns its id.
func endpoint(t *testing.T, db *sql.DB, tenant, asset uuid.UUID, addr string, port int, transport, serviceName, method string, boundLocal *bool) uuid.UUID {
	t.Helper()
	id := uuid.New()
	exec(t, db, `INSERT INTO asset_endpoints
	               (id, tenant_id, asset_id, address, port, transport,
	                service_name, service_identification_method, service_confidence, bound_local, status)
	             VALUES ($1, $2, $3, $4::inet, $5, $6,
	                     NULLIF($7, ''), NULLIF($8, ''), CASE WHEN $7 = '' THEN 'none' ELSE 'reported' END, $9, 'active')`,
		id, tenant, asset, addr, port, transport, serviceName, method, boundLocal)
	return id
}
