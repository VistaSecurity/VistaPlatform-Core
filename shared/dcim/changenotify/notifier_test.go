package changenotify

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

func noted(tenant, rid uuid.UUID, keys ...changes.NotedKey) changes.Noted {
	return changes.Noted{NotedRequest: changes.NotedRequest{TenantID: tenant, RequestID: rid}, Keys: keys}
}

var everyone = ruleDemand{rules: 1}

// Only keys THIS request noted are raised: a caller-supplied X-Request-ID that
// an earlier request also used finds that request's rows too, and they must
// not be re-announced. Mutation: drop the wanted[k] check → red.
func TestBuildEvents_OnlyTheKeysThisRequestNoted(t *testing.T) {
	tenant, rid, mine, earlier := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	k := changes.NotedKey{Kind: dcim.ObjectKindCable, ObjectID: mine, Action: changes.ActionUpdate}
	rows := []changeRow{
		{kind: dcim.ObjectKindCable, objectID: earlier, action: changes.ActionUpdate, source: "ui", label: "OLD"},
		{kind: dcim.ObjectKindCable, objectID: mine, action: changes.ActionUpdate, source: "ui", label: "CBL-1", changedFields: []string{"status"}},
	}
	evs := buildEvents(noted(tenant, rid, k), rows, everyone)
	if len(evs) != 1 || *evs[0].SubjectID != mine {
		t.Fatalf("events = %+v, want only the noted cable", evs)
	}
}

func TestBuildEvents_FoldsRepeatsAndUnionsFields(t *testing.T) {
	tenant, rid, id := uuid.New(), uuid.New(), uuid.New()
	uid := uuid.New()
	k := changes.NotedKey{Kind: dcim.ObjectKindPrefix, ObjectID: id, Action: changes.ActionUpdate}
	rows := []changeRow{
		{kind: k.Kind, objectID: id, action: k.Action, source: "ui", userID: &uid, userName: "p@example.test", changedFields: []string{"status"}, label: "10.0.0.0/24"},
		{kind: k.Kind, objectID: id, action: k.Action, source: "ui", userID: &uid, userName: "p@example.test", changedFields: []string{"description", "status"}, label: "10.0.0.0/24"},
	}
	evs := buildEvents(noted(tenant, rid, k), rows, everyone)
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1", len(evs))
	}
	md := evs[0].Metadata
	fields := md["changed_fields"].([]string)
	if len(fields) != 2 || fields[0] != "description" || fields[1] != "status" {
		t.Errorf("changed_fields = %v", fields)
	}
	if md["object_label"] != "10.0.0.0/24" || md["request_id"] != rid.String() || md["link"] != "/inventory/prefixes/"+id.String() {
		t.Errorf("metadata = %#v", md)
	}
	if evs[0].Title != "Prefix updated: 10.0.0.0/24" {
		t.Errorf("title = %q", evs[0].Title)
	}
	// Deterministic id: the same change re-raised carries the same event id.
	if again := buildEvents(noted(tenant, rid, k), rows, everyone); again[0].EventID != evs[0].EventID {
		t.Error("event id is not stable for the same change")
	}
}

func TestBuildEvents_IntakeAndSyncNeedARuleThatIncludesThem(t *testing.T) {
	tenant, rid := uuid.New(), uuid.New()
	a, b, c := uuid.New(), uuid.New(), uuid.New()
	keys := []changes.NotedKey{
		{Kind: dcim.ObjectKindInterface, ObjectID: a, Action: changes.ActionCreate},
		{Kind: dcim.ObjectKindSite, ObjectID: b, Action: changes.ActionUpdate},
		{Kind: dcim.ObjectKindRack, ObjectID: c, Action: changes.ActionUpdate},
	}
	rows := []changeRow{
		{kind: keys[0].Kind, objectID: a, action: keys[0].Action, source: "intake:lldp"},
		{kind: keys[1].Kind, objectID: b, action: keys[1].Action, source: "sync:netbox"},
		{kind: keys[2].Kind, objectID: c, action: keys[2].Action, source: "system"},
	}
	n := noted(tenant, rid, keys...)
	if evs := buildEvents(n, rows, everyone); len(evs) != 1 || evs[0].SubjectType != "rack" {
		t.Fatalf("default demand raised %+v, want only the system change", evs)
	}
	if evs := buildEvents(n, rows, ruleDemand{rules: 1, includeIntake: true}); len(evs) != 2 {
		t.Fatalf("include_intake raised %d, want 2", len(evs))
	}
	if evs := buildEvents(n, rows, ruleDemand{rules: 1, includeIntake: true, includeSync: true}); len(evs) != 3 {
		t.Fatalf("include both raised %d, want 3", len(evs))
	}
}

func TestBuildEvents_CapsARequest(t *testing.T) {
	tenant, rid := uuid.New(), uuid.New()
	var keys []changes.NotedKey
	var rows []changeRow
	for i := 0; i < MaxEventsPerRequest+5; i++ {
		id := uuid.New()
		keys = append(keys, changes.NotedKey{Kind: dcim.ObjectKindCable, ObjectID: id, Action: changes.ActionCreate})
		rows = append(rows, changeRow{kind: dcim.ObjectKindCable, objectID: id, action: changes.ActionCreate, source: "api"})
	}
	if evs := buildEvents(noted(tenant, rid, keys...), rows, everyone); len(evs) != MaxEventsPerRequest {
		t.Fatalf("events = %d, want the cap %d", len(evs), MaxEventsPerRequest)
	}
}

func TestLink(t *testing.T) {
	id, asset := uuid.New(), uuid.New()
	cases := []struct {
		kind    dcim.ObjectKind
		action  changes.Action
		relKind dcim.ObjectKind
		rel     *uuid.UUID
		want    string
	}{
		{dcim.ObjectKindAsset, changes.ActionUpdate, "", nil, "/inventory/assets/" + id.String()},
		{dcim.ObjectKindRack, changes.ActionCreate, "", nil, "/inventory/racks/" + id.String()},
		{dcim.ObjectKindSite, changes.ActionUpdate, "", nil, "/inventory/sites/" + id.String()},
		{dcim.ObjectKindCluster, changes.ActionUpdate, "", nil, "/inventory/clusters/" + id.String()},
		{dcim.ObjectKindInterface, changes.ActionUpdate, dcim.ObjectKindAsset, &asset, "/inventory/interfaces/" + id.String()},
		{dcim.ObjectKindIpAddress, changes.ActionUpdate, dcim.ObjectKindAsset, &asset, "/inventory/assets/" + asset.String()},
		{dcim.ObjectKindInterface, changes.ActionDelete, dcim.ObjectKindAsset, &asset, "/inventory/assets/" + asset.String()},
		{dcim.ObjectKindPrefix, changes.ActionCreate, "", nil, "/inventory/prefixes/" + id.String()},
		{dcim.ObjectKindVlan, changes.ActionUpdate, "", nil, "/inventory/vlans/" + id.String()},
		{dcim.ObjectKindCircuit, changes.ActionUpdate, "", nil, "/inventory/circuits/" + id.String()},
		{dcim.ObjectKindCable, changes.ActionUpdate, "", nil, "/inventory/cables/" + id.String()},
		{dcim.ObjectKindAsset, changes.ActionDelete, "", nil, ""}, // a deleted object has no page
		{dcim.ObjectKindCable, changes.ActionDelete, "", nil, ""},
		{dcim.ObjectKindTag, changes.ActionCreate, "", nil, ""},
	}
	for _, c := range cases {
		if got := Link(c.kind, id, c.action, c.relKind, c.rel); got != c.want {
			t.Errorf("Link(%s, %s) = %q, want %q", c.kind, c.action, got, c.want)
		}
	}
}

// The middleware raises nothing (and reads nothing) when no publisher is set
// or nothing was recorded, and always puts a request id on the context.
func TestMiddleware_NoPublisherNoWork(t *testing.T) {
	gin.SetMode(gin.TestMode)
	n := New(nil) // a nil pool would panic if anything were read
	n.Synchronous = true
	var sawRID bool
	r := gin.New()
	r.Use(n.Middleware())
	r.GET("/", func(c *gin.Context) {
		ctx := c.Request.Context()
		_, sawRID = changes.RequestIDFrom(ctx)
		c.Status(http.StatusOK)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK || !sawRID {
		t.Fatalf("code=%d rid=%v", w.Code, sawRID)
	}
	n.SetPublisher(PublisherFunc(func(events.AlertRaiseEvent) error { t.Fatal("raised with nothing recorded"); return nil }))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
}
