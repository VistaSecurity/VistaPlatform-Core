package jobs

import (
	"bytes"
	"database/sql"
	"go/parser"
	"go/printer"
	"go/token"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// These run in the plain unit suite — no TEST_DATABASE_URL, so they run on
// every PR. The end-to-end proof that the predicate matches real rows is
// TestIntegration_*OfflineScan_FiresOn*NeverReported in
// heartbeat_offline_never_reported_integration_test.go, which needs a database
// and therefore only runs nightly and locally via
// `make test-integration-db`. Both halves fail on the same mutation
// (restoring `AND last_heartbeat IS NOT NULL`), which is the point: the PR gate
// alone has to be able to catch a revert.

const (
	// The whole bug, in one line of SQL. A subject with no heartbeat is exactly
	// the one that most needs an offline alert — an agent that registered and
	// then failed to start — and this predicate excluded it forever.
	nullHeartbeatExclusion = "last_heartbeat IS NOT NULL"
	// The fix, and the form sensor-manager's reaper has always used.
	coalescedDwell = "COALESCE(last_heartbeat, created_at) < NOW() - make_interval(mins => $2)"
)

func sensorJob() *HeartbeatOfflineScanJob {
	return NewSensorOfflineScanJob(nil, nil, nil, nil, time.Hour)
}

func agentJob() *HeartbeatOfflineScanJob {
	return NewDiscoveryAgentOfflineScanJob(nil, nil, nil, nil, time.Hour)
}

// TestHeartbeatOfflineQuery_MeasuresDwellFromRegistration pins the predicate
// scanTenant actually sends. offlineQuery has exactly one caller, so a revert
// of the SQL fails here; a revert that ALSO moves the SQL back inline is caught
// by TestHeartbeatOfflineScanJob_SourceCarriesNoNullHeartbeatExclusion below.
func TestHeartbeatOfflineQuery_MeasuresDwellFromRegistration(t *testing.T) {
	for _, tc := range []struct {
		name string
		job  *HeartbeatOfflineScanJob
	}{
		{"sensor", sensorJob()},
		{"discovery agent", agentJob()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := tc.job.offlineQuery()
			if strings.Contains(q, nullHeartbeatExclusion) {
				t.Fatalf("%s offline query still excludes never-reported subjects (%q):\n%s",
					tc.name, nullHeartbeatExclusion, q)
			}
			if !strings.Contains(q, coalescedDwell) {
				t.Fatalf("%s offline query does not measure the dwell from COALESCE(last_heartbeat, created_at):\n%s",
					tc.name, q)
			}
			// created_at has to be selected, or raise cannot say when a
			// never-reported subject registered.
			if !strings.Contains(q, "created_at\n") && !strings.Contains(q, "created_at ") && !strings.Contains(q, "created_at,") {
				t.Fatalf("%s offline query does not select created_at:\n%s", tc.name, q)
			}
			if !strings.Contains(q, "deleted_at IS NULL") {
				t.Fatalf("%s offline query dropped the soft-delete filter:\n%s", tc.name, q)
			}
		})
	}
}

// TestHeartbeatOfflineQuery_KeepsIntentionalQuietExclusions is the other
// polarity. Widening the predicate to never-reported rows is only safe while
// the rows that are quiet ON PURPOSE stay excluded — a pending registration
// key, an operator-disabled subject, a platform-owned sensor, or a sensor
// marked air-gapped (whose column means "not expected to check in"). Losing any
// of these turns the fix into the same bug pointed the other way.
func TestHeartbeatOfflineQuery_KeepsIntentionalQuietExclusions(t *testing.T) {
	sensorQ := sensorJob().offlineQuery()
	for _, want := range []string{
		"platform <> 'platform'",
		"status NOT IN ('pending', 'inactive')",
		"air_gapped = false",
	} {
		if !strings.Contains(sensorQ, want) {
			t.Fatalf("sensor offline query lost exclusion %q — intentionally quiet sensors will now alarm:\n%s", want, sensorQ)
		}
	}

	agentQ := agentJob().offlineQuery()
	if !strings.Contains(agentQ, "status <> 'inactive'") {
		t.Fatalf("agent offline query lost the inactive exclusion — disabled agents will now alarm:\n%s", agentQ)
	}
}

// TestHeartbeatOfflineScanJob_SourceCarriesNoNullHeartbeatExclusion keeps the
// query assertions from going inert. A guard that reads a builder proves
// nothing if someone puts the SQL back inline in scanTenant, so this one scans
// the file itself — comments stripped, so the doc comment explaining the bug
// (which necessarily quotes the predicate) does not trip it.
func TestHeartbeatOfflineScanJob_SourceCarriesNoNullHeartbeatExclusion(t *testing.T) {
	fset := token.NewFileSet()
	// Parsing WITHOUT parser.ParseComments drops comments from the AST.
	file, err := parser.ParseFile(fset, "heartbeat_offline_scan_job.go", nil, 0)
	if err != nil {
		t.Fatalf("parse heartbeat_offline_scan_job.go: %v", err)
	}
	var code bytes.Buffer
	if err := printer.Fprint(&code, fset, file); err != nil {
		t.Fatalf("print AST: %v", err)
	}
	if strings.Contains(code.String(), nullHeartbeatExclusion) {
		t.Fatalf("heartbeat_offline_scan_job.go carries %q in executable code — a subject that "+
			"never reported cannot be alerted on while that predicate is anywhere in the query",
			nullHeartbeatExclusion)
	}
}

// --- rendering: a NULL last_heartbeat must never surface as a zero time ------

func mustString(t *testing.T, m map[string]interface{}, key string) string {
	t.Helper()
	v, ok := m[key]
	if !ok {
		t.Fatalf("metadata has no %q key: %#v", key, m)
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("metadata %q is %T, want string", key, v)
	}
	return s
}

func TestHeartbeatOfflineRaise_NeverReportedReadsAsNeverReported(t *testing.T) {
	now := time.Date(2026, 9, 17, 14, 0, 0, 0, time.UTC)
	registered := now.Add(-40 * time.Minute)
	ev := agentJob().buildRaiseEvent(uuid.New(), offlineSubject{
		id:      uuid.New(),
		label:   "qa-agent.example.com",
		last:    sql.NullTime{},
		created: sql.NullTime{Time: registered, Valid: true},
	}, now)

	for _, bad := range []string{"0001-01-01", "1970-01-01", `since ""`, "since  "} {
		if strings.Contains(ev.Message, bad) || strings.Contains(ev.Title, bad) {
			t.Fatalf("never-reported alert rendered a placeholder timestamp (%q):\ntitle=%q\nmessage=%q",
				bad, ev.Title, ev.Message)
		}
	}
	if !strings.Contains(ev.Message, "has never sent a heartbeat") {
		t.Fatalf("never-reported message does not say so: %q", ev.Message)
	}
	if !strings.Contains(ev.Message, "40m0s ago") {
		t.Fatalf("never-reported message does not age from registration: %q", ev.Message)
	}
	if !strings.Contains(ev.Title, "never reported") {
		t.Fatalf("never-reported title does not say so: %q", ev.Title)
	}
	if got := ev.Metadata["never_reported"]; got != true {
		t.Fatalf("metadata never_reported = %v, want true", got)
	}
	if _, present := ev.Metadata["last_heartbeat"]; present {
		t.Fatalf("metadata carries a last_heartbeat for a subject that has none: %#v", ev.Metadata)
	}
	if got := mustString(t, ev.Metadata, "registered_at"); got != registered.Format(time.RFC3339) {
		t.Fatalf("metadata registered_at = %q, want %q", got, registered.Format(time.RFC3339))
	}
	if ev.SubjectLabel != "qa-agent.example.com" || ev.Severity != "high" || ev.AlertType != "discovery_agent_offline" {
		t.Fatalf("unexpected event envelope: %+v", ev)
	}
}

// TestHeartbeatOfflineRaise_StaleHeartbeatUnchanged — the pre-existing wording
// for a subject that DID report is the reference case, and must not drift.
func TestHeartbeatOfflineRaise_StaleHeartbeatUnchanged(t *testing.T) {
	now := time.Date(2026, 9, 17, 14, 0, 0, 0, time.UTC)
	last := now.Add(-2 * time.Hour)
	ev := sensorJob().buildRaiseEvent(uuid.New(), offlineSubject{
		id:      uuid.New(),
		label:   "branch-sensor",
		last:    sql.NullTime{Time: last, Valid: true},
		created: sql.NullTime{Time: now.Add(-72 * time.Hour), Valid: true},
	}, now)

	if !strings.Contains(ev.Message, "has not sent a heartbeat since") {
		t.Fatalf("stale-heartbeat message changed: %q", ev.Message)
	}
	if !strings.Contains(ev.Message, "2h0m0s ago") {
		t.Fatalf("stale-heartbeat message ages from last_heartbeat, not created_at: %q", ev.Message)
	}
	if !strings.Contains(ev.Title, "offline:") || strings.Contains(ev.Title, "never reported") {
		t.Fatalf("stale-heartbeat title changed: %q", ev.Title)
	}
	if got := ev.Metadata["never_reported"]; got != false {
		t.Fatalf("metadata never_reported = %v, want an explicit false", got)
	}
	if got := mustString(t, ev.Metadata, "last_heartbeat"); got != last.Format(time.RFC3339) {
		t.Fatalf("metadata last_heartbeat = %q, want %q", got, last.Format(time.RFC3339))
	}
	if _, present := ev.Metadata["registered_at"]; present {
		t.Fatalf("stale-heartbeat metadata should not claim a registration time: %#v", ev.Metadata)
	}
}

// TestHeartbeatOfflineRaise_UnknownRegistration — both timestamps NULL. The
// query cannot produce this row (the COALESCE is NULL, so the predicate is
// NULL and the row is not returned), but rendering it as 0001-01-01 is exactly
// the failure mode being fixed, so the fallback is pinned rather than assumed.
func TestHeartbeatOfflineRaise_UnknownRegistration(t *testing.T) {
	now := time.Date(2026, 9, 17, 14, 0, 0, 0, time.UTC)
	id := uuid.New()
	ev := sensorJob().buildRaiseEvent(uuid.New(), offlineSubject{id: id}, now)

	if strings.Contains(ev.Message, "0001-01-01") || strings.Contains(ev.Title, "0001-01-01") {
		t.Fatalf("unknown-registration alert rendered a zero time:\ntitle=%q\nmessage=%q", ev.Title, ev.Message)
	}
	if !strings.Contains(ev.Message, "registration time is unknown") {
		t.Fatalf("unknown-registration message: %q", ev.Message)
	}
	if got := ev.Metadata["never_reported"]; got != true {
		t.Fatalf("metadata never_reported = %v, want true", got)
	}
	// An unnamed subject still needs a human label.
	if !strings.Contains(ev.SubjectLabel, id.String()[:8]) {
		t.Fatalf("unnamed subject label = %q, want it to carry the id prefix", ev.SubjectLabel)
	}
}

// --- auto-resolve -----------------------------------------------------------

func TestHeartbeatOfflineResolve_FirstHeartbeatClearsNeverReported(t *testing.T) {
	now := time.Date(2026, 9, 17, 14, 0, 0, 0, time.UTC)
	j := agentJob()

	// The subject finally checked in: the first heartbeat clears a
	// never-reported alert exactly like a returning one clears a stale alert.
	obs := j.resolveObservation(true, sql.NullTime{Time: now.Add(-time.Minute), Valid: true}, now)
	if obs["observed"] != "heartbeat resumed" {
		t.Fatalf("first heartbeat did not resolve as a resumed heartbeat: %#v", obs)
	}
	if _, ok := obs["last_heartbeat"]; !ok {
		t.Fatalf("resumed-heartbeat observation has no last_heartbeat: %#v", obs)
	}

	// Still never reported, but no longer a subject of this alert (deactivated,
	// or flagged air-gapped). It must not claim a heartbeat it never got.
	obs = j.resolveObservation(true, sql.NullTime{}, now)
	if obs["observed"] == "heartbeat resumed" {
		t.Fatalf("a subject that never reported resolved as 'heartbeat resumed': %#v", obs)
	}
	if obs["never_reported"] != true {
		t.Fatalf("observation does not record that the subject never reported: %#v", obs)
	}
	if _, present := obs["last_heartbeat"]; present {
		t.Fatalf("observation carries a last_heartbeat for a subject that has none: %#v", obs)
	}

	// Removed from inventory, and a stale-but-present subject leaving the
	// predicate some other way.
	if obs := j.resolveObservation(false, sql.NullTime{}, now); !strings.Contains(obs["observed"].(string), "removed from inventory") {
		t.Fatalf("removed subject: %#v", obs)
	}
	stale := j.resolveObservation(true, sql.NullTime{Time: now.Add(-3 * time.Hour), Valid: true}, now)
	if !strings.Contains(stale["observed"].(string), "no longer monitored") || stale["never_reported"] != nil {
		t.Fatalf("stale-but-excluded subject: %#v", stale)
	}
}
