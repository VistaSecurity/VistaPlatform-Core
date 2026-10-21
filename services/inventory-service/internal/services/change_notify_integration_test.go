package services

// Inventory change notifications (DCIM gap 5) driven through the REAL path: the
// change notifier's middleware on a gin router, a handler calling the real
// InterfaceService / CableService (so the recorder call sites that ship are the
// ones noting changes), the notifier reading object_changes and the routing
// rules on the NON-OWNER app role, and a capturing publisher standing in for
// NATS. Skipped unless TEST_DATABASE_URL is set; run with make
// test-integration-db.
//
// Mutations (each must turn a test here red): delete the
// collectorFrom(ctx).note(row) line in shared/dcim/changes; delete the
// pub.Raise(ev) call in changenotify.Flush; drop the rule pre-check's
// include_intake column; make Events skip the committed-row read.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changenotify"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

type raised struct {
	mu  sync.Mutex
	evs []events.AlertRaiseEvent
}

func (r *raised) Raise(ev events.AlertRaiseEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, ev)
	return nil
}

func (r *raised) take() []events.AlertRaiseEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.evs
	r.evs = nil
	return out
}

func (r *raised) of(kind dcim.ObjectKind) []events.AlertRaiseEvent {
	var out []events.AlertRaiseEvent
	for _, ev := range r.take() {
		if ev.SubjectType == string(kind) {
			out = append(out, ev)
		}
	}
	return out
}

// changeRule inserts an enabled Inventory-changes routing rule for the tenant.
func changeRule(t *testing.T, owner *sql.DB, tenant uuid.UUID, filter string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := owner.QueryRow(`
		INSERT INTO tenant_notification_rules (tenant_id, rule_name, alert_source, alert_type, channel_ids, change_filter, enabled)
		VALUES ($1, $2, 'inventory-service', 'object_changed', ARRAY[gen_random_uuid()], $3::jsonb, true) RETURNING id`,
		tenant, "Changes "+uuid.NewString()[:8], filter).Scan(&id); err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	return id
}

// notifyRouter is a gin router with the notifier mounted exactly as main()
// mounts it, around one handler.
func notifyRouter(n *changenotify.Notifier, h func(ctx context.Context) error) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(n.Middleware())
	r.Use(changes.Middleware())
	r.POST("/do", func(c *gin.Context) {
		if err := h(c.Request.Context()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.Status(http.StatusNoContent)
	})
	return r
}

func hit(t *testing.T, r *gin.Engine) int {
	t.Helper()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/do", nil))
	return w.Code
}

func TestIntegration_ChangeNotify_RealServicePathRaisesOneEventPerObject(t *testing.T) {
	f := newCableFix(t)
	pub := &raised{}
	n := changenotify.New(f.app)
	n.Synchronous = true
	n.SetPublisher(pub)

	asset := f.asset(t)
	actor := changes.Actor{UserID: uuid.New(), UserName: "a.person@example.test"}
	asPerson := func(ctx context.Context) context.Context {
		return changes.WithSource(changes.WithActor(ctx, actor), changes.SourceUI)
	}

	// No routing rule yet: nothing is read and nothing is raised.
	var ifaceID uuid.UUID
	r := notifyRouter(n, func(ctx context.Context) error {
		i, err := f.ifaces.Create(asPerson(ctx), f.tenant, actor.UserID, InterfaceInput{AssetID: asset, Name: "Gi1/0/1", Type: "1000base-t"})
		ifaceID = i.ID
		return err
	})
	if code := hit(t, r); code != http.StatusNoContent {
		t.Fatalf("create interface: %d", code)
	}
	if evs := pub.take(); len(evs) != 0 {
		t.Fatalf("raised %d event(s) for a tenant with no Inventory-changes rule", len(evs))
	}

	changeRule(t, f.owner, f.tenant, `{"include_intake": false, "include_sync": false}`)

	// A person's create: one event, the change fields at top level of the
	// metadata, a link to the interface's own page.
	if code := hit(t, notifyRouter(n, func(ctx context.Context) error {
		_, err := f.ifaces.Create(asPerson(ctx), f.tenant, actor.UserID, InterfaceInput{AssetID: asset, Name: "Gi1/0/2", Type: "1000base-t"})
		return err
	})); code != http.StatusNoContent {
		t.Fatalf("create interface: %d", code)
	}
	evs := pub.of(dcim.ObjectKindInterface)
	if len(evs) != 1 {
		t.Fatalf("interface events = %d, want 1", len(evs))
	}
	ev := evs[0]
	md := ev.Metadata
	if ev.AlertType != "object_changed" || ev.Severity != "info" || md["action"] != "create" || md["source"] != "ui" || md["object_label"] != "Gi1/0/2" {
		t.Fatalf("event = %+v", ev)
	}
	if md["link"] != "/inventory/interfaces/"+ev.SubjectID.String() {
		t.Errorf("link = %v, want the interface's page", md["link"])
	}
	if a, _ := md["actor"].(map[string]any); a == nil || a["user_name"] != actor.UserName {
		t.Errorf("actor = %#v", md["actor"])
	}
	if raw, _ := json.Marshal(md); notifyHasAny(string(raw), "prechange", "postchange", `"custom_fields":`) {
		t.Errorf("metadata carries an image: %s", raw)
	}

	// Three patches of the same interface in ONE request: one update event,
	// changed_fields the union.
	if code := hit(t, notifyRouter(n, func(ctx context.Context) error {
		ctx = asPerson(ctx)
		for _, p := range []string{`{"description":"uplink"}`, `{"mtu":9000}`, `{"description":"uplink to core"}`} {
			var patch map[string]json.RawMessage
			_ = json.Unmarshal([]byte(p), &patch)
			if _, err := f.ifaces.Patch(ctx, f.tenant, ifaceID, patch); err != nil {
				return err
			}
		}
		return nil
	})); code != http.StatusNoContent {
		t.Fatalf("patch interface: %d", code)
	}
	evs = pub.of(dcim.ObjectKindInterface)
	if len(evs) != 1 || evs[0].Metadata["action"] != "update" {
		t.Fatalf("update events = %+v, want exactly one update", evs)
	}
	fields, _ := evs[0].Metadata["changed_fields"].([]string)
	if !notifyHasAll(fields, "description", "mtu") {
		t.Errorf("changed_fields = %v, want the union of the three patches", fields)
	}

	// A transaction that records a change and then rolls back raises nothing.
	if code := hit(t, notifyRouter(n, func(ctx context.Context) error {
		return database.WithTenantTx(asPerson(ctx), f.app, f.tenant, func(tx *sql.Tx) error {
			if err := changes.InTx(tx).Record(asPerson(ctx), changes.Change{TenantID: f.tenant, Kind: dcim.ObjectKindCable,
				ID: uuid.New(), Action: changes.ActionCreate, Post: map[string]any{"label": "never"}}); err != nil {
				return err
			}
			return errors.New("roll it back")
		})
	})); code != http.StatusInternalServerError {
		t.Fatalf("rolled-back request: %d", code)
	}
	if evs := pub.take(); len(evs) != 0 {
		t.Fatalf("a rolled-back change raised %d event(s): %+v", len(evs), evs)
	}
}

func TestIntegration_ChangeNotify_IntakeOnlyWhenARuleIncludesIt(t *testing.T) {
	f := newCableFix(t)
	pub := &raised{}
	n := changenotify.New(f.app)
	n.Synchronous = true
	n.SetPublisher(pub)
	asset := f.asset(t)

	intake := func(name string) *gin.Engine {
		return notifyRouter(n, func(ctx context.Context) error {
			_, err := f.ifaces.UpsertObserved(ctx, f.tenant, asset, "snmp", []ObservedInterface{{Name: name, Vendor: "cisco"}})
			return err
		})
	}

	rule := changeRule(t, f.owner, f.tenant, `{"include_intake": false, "include_sync": false}`)
	if code := hit(t, intake("Vlan10")); code != http.StatusNoContent {
		t.Fatalf("intake: %d", code)
	}
	if evs := pub.of(dcim.ObjectKindInterface); len(evs) != 0 {
		t.Fatalf("an intake change raised %d event(s) with no rule including intake", len(evs))
	}

	if _, err := f.owner.Exec(`UPDATE tenant_notification_rules SET change_filter = '{"include_intake": true, "include_sync": false}' WHERE id = $1`, rule); err != nil {
		t.Fatal(err)
	}
	if code := hit(t, intake("Vlan20")); code != http.StatusNoContent {
		t.Fatalf("intake: %d", code)
	}
	evs := pub.of(dcim.ObjectKindInterface)
	if len(evs) != 1 || evs[0].Metadata["source"] != "intake:snmp" || evs[0].Metadata["actor"] != nil {
		t.Fatalf("intake events = %+v, want one from intake:snmp with no actor", evs)
	}
}

func notifyHasAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

func notifyHasAll(list []string, want ...string) bool {
	have := map[string]bool{}
	for _, s := range list {
		have[s] = true
	}
	for _, w := range want {
		if !have[w] {
			return false
		}
	}
	return true
}
