package changenotify

// A unit of work with no HTTP request around it, against a real Postgres: a
// change recorded through the real recorder (changes.InTx) inside
// Notifier.Unit is read back committed and raised; when NATS refuses the
// publish the event goes over the HTTP intake instead; when both rails fail
// the loss is logged. Skipped unless TEST_DATABASE_URL is set.
//
// Mutations (each turns a test here red): delete the col.Drain/Flush block in
// Notifier.Unit; make Unit reuse the caller's request id instead of a fresh
// one when ctx has none (the second unit then re-raises nothing new — caught
// by the two-units case); make fallback.Raise return natsErr without calling
// the intake; drop the LOST log in Flush.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type unitFix struct {
	db     *sql.DB
	tenant uuid.UUID
}

func newUnitFix(t *testing.T) unitFix {
	t.Helper()
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	return unitFix{db: db, tenant: testdb.NewTenant(t, db)}
}

func (f unitFix) rule(t *testing.T, filter string) {
	t.Helper()
	testdb.RetryTransient(t, func() error {
		_, err := f.db.Exec(`
			INSERT INTO tenant_notification_rules (tenant_id, rule_name, alert_source, alert_type, channel_ids, change_filter, enabled)
			VALUES ($1, $2, 'inventory-service', 'object_changed', ARRAY[gen_random_uuid()], $3::jsonb, true)`,
			f.tenant, "Changes "+uuid.NewString()[:8], filter)
		return err
	})
}

// recordVLAN is what a background pass does: its own tenant transaction,
// the real recorder, an intake source — and no HTTP request.
func (f unitFix) recordVLAN(ctx context.Context, name string, rollback bool) (uuid.UUID, error) {
	id := uuid.New()
	errRollback := errors.New("rolled back on purpose")
	err := database.WithTenantTx(changes.WithSource(ctx, changes.IntakeSource("lldp")), f.db, f.tenant, func(tx *sql.Tx) error {
		if err := changes.InTx(tx).Record(changes.WithSource(ctx, changes.IntakeSource("lldp")), changes.Change{
			TenantID: f.tenant, Kind: dcim.ObjectKindVlan, ID: id, Action: changes.ActionCreate,
			Post: map[string]any{"name": name, "vid": 10},
		}); err != nil {
			return err
		}
		if rollback {
			return errRollback
		}
		return nil
	})
	if errors.Is(err, errRollback) {
		err = nil
	}
	return id, err
}

type sink struct {
	mu  sync.Mutex
	evs []events.AlertRaiseEvent
}

func (s *sink) Raise(ev events.AlertRaiseEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evs = append(s.evs, ev)
	return nil
}

func (s *sink) take() []events.AlertRaiseEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.evs
	s.evs = nil
	return out
}

func TestIntegration_Unit_RaisesWhatAJobCommitted(t *testing.T) {
	f := newUnitFix(t)
	f.rule(t, `{"include_intake": true}`)
	pub := &sink{}
	n := New(f.db)
	n.SetPublisher(pub)
	ctx := WithNotifier(context.Background(), n)

	var id uuid.UUID
	if err := Unit(ctx, func(ctx context.Context) error {
		var err error
		id, err = f.recordVLAN(ctx, "Vlan10", false)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	evs := pub.take()
	if len(evs) != 1 {
		t.Fatalf("raised %d events, want 1: %+v", len(evs), evs)
	}
	ev := evs[0]
	if ev.SubjectType != string(dcim.ObjectKindVlan) || ev.SubjectID == nil || *ev.SubjectID != id ||
		ev.Metadata["source"] != "intake:lldp" || ev.Metadata["action"] != "create" || ev.Metadata["actor"] != nil ||
		ev.Metadata["link"] != "/inventory/vlans/"+id.String() {
		t.Fatalf("event = %+v", ev)
	}

	// A rolled-back write raises nothing; a second unit raises only its own.
	if err := Unit(ctx, func(ctx context.Context) error { _, err := f.recordVLAN(ctx, "Vlan20", true); return err }); err != nil {
		t.Fatal(err)
	}
	if evs := pub.take(); len(evs) != 0 {
		t.Fatalf("a rolled-back change raised %d event(s)", len(evs))
	}
	if err := Unit(ctx, func(ctx context.Context) error { _, err := f.recordVLAN(ctx, "Vlan30", false); return err }); err != nil {
		t.Fatal(err)
	}
	if evs := pub.take(); len(evs) != 1 || evs[0].SubjectLabel != "Vlan30" {
		t.Fatalf("second unit raised %+v, want only Vlan30", evs)
	}

	// Without the unit the same write raises nothing at all — the gap this
	// closes.
	if _, err := f.recordVLAN(ctx, "Vlan40", false); err != nil {
		t.Fatal(err)
	}
	if evs := pub.take(); len(evs) != 0 {
		t.Fatalf("a change outside any unit raised %d event(s)", len(evs))
	}
}

// Intake stays opt-in outside a request too.
func TestIntegration_Unit_IntakeNeedsARuleThatIncludesIt(t *testing.T) {
	f := newUnitFix(t)
	f.rule(t, `{"include_intake": false}`)
	pub := &sink{}
	n := New(f.db)
	n.SetPublisher(pub)
	if err := n.Unit(context.Background(), func(ctx context.Context) error { _, err := f.recordVLAN(ctx, "Vlan10", false); return err }); err != nil {
		t.Fatal(err)
	}
	if evs := pub.take(); len(evs) != 0 {
		t.Fatalf("an intake change raised %d event(s) with no rule including intake", len(evs))
	}
}

// NATS down: the event reaches compliance-engine's intake over HTTP instead.
// Both down: the loss is logged, once, with the object it was about.
func TestIntegration_Unit_FallsBackToHTTPAndLogsOnlyARealLoss(t *testing.T) {
	f := newUnitFix(t)
	f.rule(t, `{"include_intake": true}`)

	var mu sync.Mutex
	var posted []events.AlertRaiseEvent
	status := http.StatusAccepted
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev events.AlertRaiseEvent
		_ = json.NewDecoder(r.Body).Decode(&ev)
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == AlertIntakePath && r.Header.Get("X-Tenant-ID") == ev.TenantID.String() {
			posted = append(posted, ev)
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()

	natsCalls := 0
	n := New(f.db)
	n.SetPublisher(fallback{
		link:    link(true),
		publish: func(events.AlertRaiseEvent) error { natsCalls++; return errors.New("nats: timeout") },
		intake:  &HTTPAlertIntake{BaseURL: srv.URL, Client: srv.Client(), Sign: func(*http.Request) {}},
	})

	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(prev)

	id := uuid.Nil
	if err := n.Unit(context.Background(), func(ctx context.Context) error {
		var err error
		id, err = f.recordVLAN(ctx, "Vlan10", false)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := posted
	posted = nil
	status = http.StatusServiceUnavailable
	mu.Unlock()
	if natsCalls != 1 || len(got) != 1 || got[0].SubjectID == nil || *got[0].SubjectID != id {
		t.Fatalf("NATS calls = %d; HTTP intake got %+v — want the one event over HTTP", natsCalls, got)
	}
	if strings.Contains(logs.String(), "LOST") {
		t.Fatalf("a notification the HTTP rail delivered was logged as lost:\n%s", logs.String())
	}

	if err := n.Unit(context.Background(), func(ctx context.Context) error {
		var err error
		id, err = f.recordVLAN(ctx, "Vlan20", false)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	out := logs.String()
	if strings.Count(out, "CHANGE NOTIFICATION LOST") != 1 || !strings.Contains(out, id.String()) || !strings.Contains(out, "both failed") {
		t.Fatalf("both rails down: want one LOST line naming %s, got:\n%s", id, out)
	}
}
