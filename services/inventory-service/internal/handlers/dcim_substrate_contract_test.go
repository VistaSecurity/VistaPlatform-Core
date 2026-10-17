package handlers

// The DCIM substrate routes (BUILD_PLAN row 0.3) against the spec: every
// success body and every handler-written error conforms to its schema in
// api/openapi/inventory-service.openapi.yaml, whose schemas are
// additionalProperties: false — so a renamed or extra field fails here before
// the generated client disagrees with the server.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/dcim/journal"
	"github.com/vistasecurity/vistaplatform/shared/dcim/tags"
)

type substrateStub struct {
	err        error
	lastFilter changes.Filter
	setIDs     []uuid.UUID
	patch      services.TagPatch
}

var (
	stubNow   = time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	stubUser  = uuid.New()
	stubColor = "aa1100"
)

func stubTag() tags.Tag {
	return tags.Tag{ID: uuid.New(), Name: "Core", Slug: "core", Color: &stubColor, ObjectKinds: []dcim.ObjectKind{dcim.ObjectKindAsset}, CreatedAt: stubNow, UpdatedAt: stubNow}
}

func (s *substrateStub) ListChanges(_ context.Context, f changes.Filter) ([]changes.ObjectChange, int, error) {
	s.lastFilter = f
	if s.err != nil {
		return nil, 0, s.err
	}
	name := "op@example.test"
	rid := uuid.New()
	return []changes.ObjectChange{
		{ID: uuid.New(), ObjectKind: dcim.ObjectKindAsset, ObjectID: uuid.New(), Action: changes.ActionUpdate,
			PrechangeData: json.RawMessage(`{"tags":[]}`), PostchangeData: json.RawMessage(`{"tags":["core"]}`),
			ChangedFields: []string{"tags"}, UserID: &stubUser, UserName: &name, RequestID: &rid, Source: changes.SourceUI, CreatedAt: stubNow},
		{ID: uuid.New(), ObjectKind: dcim.ObjectKindTag, ObjectID: uuid.New(), Action: changes.ActionCreate,
			PostchangeData: json.RawMessage(`{"name":"core"}`), ChangedFields: []string{"name"}, Source: changes.IntakeSource("lldp"), CreatedAt: stubNow},
	}, 3, nil
}
func (s *substrateStub) GetChange(_ context.Context, _, id uuid.UUID) (changes.ObjectChange, error) {
	if s.err != nil {
		return changes.ObjectChange{}, s.err
	}
	return changes.ObjectChange{ID: id, ObjectKind: dcim.ObjectKindInterface, ObjectID: uuid.New(), Action: changes.ActionUpdate,
		PrechangeData:  json.RawMessage(`{"name":"eth0","psk":"[REDACTED]","mtu":1500}`),
		PostchangeData: json.RawMessage(`{"name":"eth0","psk":"[REDACTED]","mtu":9000}`),
		ChangedFields:  []string{"mtu", "psk"}, Source: changes.SourceUI, CreatedAt: stubNow}, nil
}
func (s *substrateStub) ListJournal(_ context.Context, _ uuid.UUID, k dcim.ObjectKind, id uuid.UUID, _, _ int) ([]journal.Entry, int, error) {
	if s.err != nil {
		return nil, 0, s.err
	}
	return []journal.Entry{{ID: uuid.New(), ObjectKind: k, ObjectID: id, Kind: journal.KindWarning, Comments: "fan tray", CreatedBy: &stubUser, CreatedAt: stubNow}}, 1, nil
}
func (s *substrateStub) AddJournal(_ context.Context, _ uuid.UUID, k dcim.ObjectKind, id uuid.UUID, ek journal.Kind, c string) (journal.Entry, error) {
	if s.err != nil {
		return journal.Entry{}, s.err
	}
	if ek == "" {
		ek = journal.KindInfo
	}
	return journal.Entry{ID: uuid.New(), ObjectKind: k, ObjectID: id, Kind: ek, Comments: c, CreatedAt: stubNow}, nil
}
func (s *substrateStub) ObjectTags(context.Context, uuid.UUID, dcim.ObjectKind, uuid.UUID) ([]tags.Tag, error) {
	if s.err != nil {
		return nil, s.err
	}
	return []tags.Tag{stubTag()}, nil
}
func (s *substrateStub) SetObjectTags(_ context.Context, _ uuid.UUID, _ dcim.ObjectKind, _ uuid.UUID, ids []uuid.UUID) ([]tags.Tag, error) {
	s.setIDs = ids
	if s.err != nil {
		return nil, s.err
	}
	return []tags.Tag{}, nil
}
func (s *substrateStub) ListTags(context.Context, uuid.UUID) ([]tags.Tag, error) {
	if s.err != nil {
		return nil, s.err
	}
	return []tags.Tag{stubTag()}, nil
}
func (s *substrateStub) CreateTag(_ context.Context, _ uuid.UUID, in tags.Input) (tags.Tag, error) {
	if s.err != nil {
		return tags.Tag{}, s.err
	}
	t := stubTag()
	t.Name = in.Name
	return t, nil
}
func (s *substrateStub) UpdateTag(_ context.Context, _, _ uuid.UUID, p services.TagPatch) (tags.Tag, error) {
	s.patch = p
	if s.err != nil {
		return tags.Tag{}, s.err
	}
	return stubTag(), nil
}
func (s *substrateStub) DeleteTag(context.Context, uuid.UUID, uuid.UUID) error { return s.err }

func newSubstrateEngine(store DcimSubstrateStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/api/v2/inventory-service/dcim")
	g.Use(func(c *gin.Context) { c.Set("tenantID", uuid.New()); c.Set("userID", uuid.New()); c.Next() })
	h := NewDcimSubstrateHandler(store)
	g.GET("/changes", h.ListChanges)
	g.GET("/changes/:id", h.GetChange)
	g.GET("/objects/:kind/:id/journal", h.ListJournal)
	g.POST("/objects/:kind/:id/journal", h.AddJournal)
	g.GET("/objects/:kind/:id/tags", h.GetObjectTags)
	g.PUT("/objects/:kind/:id/tags", h.SetObjectTags)
	g.GET("/tags", h.ListTags)
	g.POST("/tags", h.CreateTag)
	g.PATCH("/tags/:id", h.UpdateTag)
	g.DELETE("/tags/:id", h.DeleteTag)
	return r
}

const dcimBase = "/api/v2/inventory-service/dcim"

func TestContract_DcimSubstrate_Success(t *testing.T) {
	sv := loadSpec(t)
	store := &substrateStub{}
	eng := newSubstrateEngine(store)
	obj := dcimBase + "/objects/asset/" + uuid.NewString()

	cases := []struct {
		method, path, body, schema string
		want                       int
	}{
		{http.MethodGet, dcimBase + "/changes?object_kind=asset&limit=2", "", "ObjectChangeListResponse", http.StatusOK},
		{http.MethodGet, dcimBase + "/changes/" + uuid.NewString(), "", "ObjectChangeDetailResponse", http.StatusOK},
		{http.MethodGet, obj + "/journal", "", "JournalEntryListResponse", http.StatusOK},
		{http.MethodPost, obj + "/journal", `{"kind":"warning","comments":"replaced PSU"}`, "JournalEntryResponse", http.StatusCreated},
		{http.MethodGet, obj + "/tags", "", "TagListResponse", http.StatusOK},
		{http.MethodPut, obj + "/tags", `{"tag_ids":[]}`, "TagListResponse", http.StatusOK},
		{http.MethodGet, dcimBase + "/tags", "", "TagListResponse", http.StatusOK},
		{http.MethodPost, dcimBase + "/tags", `{"name":"Core","object_kinds":["asset"]}`, "TagResponse", http.StatusCreated},
		{http.MethodPatch, dcimBase + "/tags/" + uuid.NewString(), `{"color":"00ff00"}`, "TagResponse", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			var w = do(eng, tc.method, tc.path, nil)
			if tc.body != "" {
				w = do(eng, tc.method, tc.path, strings.NewReader(tc.body))
			}
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tc.want, w.Body.String())
			}
			sv.assertConforms(t, tc.schema, w.Body.Bytes())
		})
	}
	// Pagination: 3 total, a page of 2 at 0 → next_offset 2.
	w := do(eng, http.MethodGet, dcimBase+"/changes?limit=2", nil)
	var body struct {
		Pagination struct {
			Total      int  `json:"total"`
			NextOffset *int `json:"next_offset"`
		} `json:"pagination"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.Pagination.Total != 3 || body.Pagination.NextOffset == nil || *body.Pagination.NextOffset != 2 {
		t.Errorf("pagination = %+v", body.Pagination)
	}
	if w := do(eng, http.MethodDelete, dcimBase+"/tags/"+uuid.NewString(), nil); w.Code != http.StatusNoContent {
		t.Errorf("delete = %d", w.Code)
	}
}

func TestContract_DcimSubstrate_ChangeFilters(t *testing.T) {
	store := &substrateStub{}
	eng := newSubstrateEngine(store)
	obj, user := uuid.New(), uuid.New()
	w := do(eng, http.MethodGet, dcimBase+"/changes?object_kind=asset&object_id="+obj.String()+"&user="+user.String()+"&since=2026-10-01T00:00:00Z&offset=5", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	f := store.lastFilter
	if f.ObjectKind != dcim.ObjectKindAsset || f.ObjectID != obj || f.UserID != user || f.Offset != 5 || f.Limit != dcimDefaultLimit ||
		!f.Since.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) || f.TenantID == uuid.Nil {
		t.Errorf("filter reached the store as %+v", f)
	}
}

// The Changes lens filters and the per-change diff.
func TestContract_DcimSubstrate_ChangeLensFilters(t *testing.T) {
	store := &substrateStub{}
	eng := newSubstrateEngine(store)
	obj := uuid.New()
	w := do(eng, http.MethodGet, dcimBase+"/changes?object_kind=asset&object_id="+obj.String()+"&include_related=true&action=update&source=intake:&q=core%20sw&until=2026-10-02T00:00:00Z", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	f := store.lastFilter
	if !f.IncludeRelated || f.Action != changes.ActionUpdate || f.Source != "intake:" || f.Query != "core sw" ||
		!f.Until.Equal(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("filter reached the store as %+v", f)
	}
	for _, q := range []string{"include_related=true", "action=explode", "source=bogus", "until=soon"} {
		if w := do(eng, http.MethodGet, dcimBase+"/changes?"+q, nil); w.Code != http.StatusBadRequest {
			t.Errorf("?%s = %d, want 400", q, w.Code)
		}
	}
}

// GET /dcim/changes/{id} lists the changed fields with before and after, and a
// secret's field is listed with only its redaction marker on both sides.
func TestContract_DcimSubstrate_ChangeDiff(t *testing.T) {
	eng := newSubstrateEngine(&substrateStub{})
	w := do(eng, http.MethodGet, dcimBase+"/changes/"+uuid.NewString(), nil)
	var body struct {
		Data struct {
			Diff []struct {
				Field         string
				Before, After any
			}
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || len(body.Data.Diff) != 2 {
		t.Fatalf("diff = %s (%v)", w.Body.String(), err)
	}
	if d := body.Data.Diff[0]; d.Field != "mtu" || d.Before != float64(1500) || d.After != float64(9000) {
		t.Errorf("mtu diff = %+v", d)
	}
	if d := body.Data.Diff[1]; d.Field != "psk" || d.Before != "[REDACTED]" || d.After != "[REDACTED]" {
		t.Errorf("psk diff = %+v", d)
	}
	if w := do(eng, http.MethodGet, dcimBase+"/changes/nope", nil); w.Code != http.StatusBadRequest {
		t.Errorf("bad id = %d", w.Code)
	}
	nf := newSubstrateEngine(&substrateStub{err: changes.ErrNotFound})
	if w := do(nf, http.MethodGet, dcimBase+"/changes/"+uuid.NewString(), nil); w.Code != http.StatusNotFound {
		t.Errorf("missing change = %d", w.Code)
	}
}

func TestContract_DcimSubstrate_Errors(t *testing.T) {
	sv := loadSpec(t)
	obj := dcimBase + "/objects/asset/" + uuid.NewString()
	cases := []struct {
		name, method, path, body string
		storeErr                 error
		want                     int
		code                     string
	}{
		{"unknown kind", http.MethodGet, dcimBase + "/objects/switch_port/" + uuid.NewString() + "/journal", "", nil, http.StatusBadRequest, "invalid_object_kind"},
		{"bad id", http.MethodGet, dcimBase + "/objects/asset/nope/tags", "", nil, http.StatusBadRequest, "invalid_object_id"},
		{"bad filter kind", http.MethodGet, dcimBase + "/changes?object_kind=rack_thing", "", nil, http.StatusBadRequest, "invalid_object_kind"},
		{"bad since", http.MethodGet, dcimBase + "/changes?since=yesterday", "", nil, http.StatusBadRequest, "invalid_since"},
		{"bad limit", http.MethodGet, dcimBase + "/changes?limit=0", "", nil, http.StatusBadRequest, "invalid_pagination"},
		{"non-numeric limit", http.MethodGet, dcimBase + "/changes?limit=all", "", nil, http.StatusBadRequest, "invalid_pagination"},
		{"negative offset", http.MethodGet, dcimBase + "/changes?offset=-1", "", nil, http.StatusBadRequest, "invalid_pagination"},
		{"journal bad limit", http.MethodGet, obj + "/journal?limit=-5", "", nil, http.StatusBadRequest, "invalid_pagination"},
		{"unknown body field", http.MethodPost, obj + "/journal", `{"comment":"typo"}`, nil, http.StatusBadRequest, "invalid_request"},
		{"tag_ids missing", http.MethodPut, obj + "/tags", `{}`, nil, http.StatusBadRequest, "invalid_request"},
		{"create without name", http.MethodPost, dcimBase + "/tags", `{"slug":"x"}`, nil, http.StatusBadRequest, "invalid_request"},
		{"object missing", http.MethodGet, obj + "/journal", "", services.ErrDcimObjectNotFound, http.StatusNotFound, "object_not_found"},
		{"tag missing", http.MethodPatch, dcimBase + "/tags/" + uuid.NewString(), `{}`, tags.ErrNotFound, http.StatusNotFound, "tag_not_found"},
		{"duplicate tag", http.MethodPost, dcimBase + "/tags", `{"name":"x"}`, tags.ErrDuplicate, http.StatusConflict, "tag_exists"},
		{"restricted tag", http.MethodPut, obj + "/tags", `{"tag_ids":[]}`, tags.ErrNotApplicable, http.StatusBadRequest, "invalid_request"},
		{"empty journal", http.MethodPost, obj + "/journal", `{"comments":""}`, journal.ErrInvalid, http.StatusBadRequest, "invalid_request"},
		{"store failure", http.MethodGet, dcimBase + "/tags", "", errors.New("db down: secret detail"), http.StatusInternalServerError, "internal_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := newSubstrateEngine(&substrateStub{err: tc.storeErr})
			var w = do(eng, tc.method, tc.path, nil)
			if tc.body != "" {
				w = do(eng, tc.method, tc.path, strings.NewReader(tc.body))
			}
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tc.want, w.Body.String())
			}
			sv.assertConforms(t, "Error", w.Body.Bytes())
			if !strings.Contains(w.Body.String(), `"code":"`+tc.code+`"`) {
				t.Errorf("body = %s, want code %s", w.Body.String(), tc.code)
			}
			if strings.Contains(w.Body.String(), "secret detail") {
				t.Errorf("an internal error leaked to the client: %s", w.Body.String())
			}
		})
	}
}

// A limit over the maximum is clamped, not honoured: one request cannot ask
// for the whole change log. Mutation: drop dcimMaxLimit from the
// ParseLimitOffsetStrict call (pass a huge max) → the store sees 100000.
func TestContract_DcimSubstrate_ChangeLimitClamped(t *testing.T) {
	store := &substrateStub{}
	w := do(newSubstrateEngine(store), http.MethodGet, dcimBase+"/changes?limit=100000", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if store.lastFilter.Limit != dcimMaxLimit {
		t.Errorf("limit reached the store as %d, want the %d cap", store.lastFilter.Limit, dcimMaxLimit)
	}
	if !strings.Contains(w.Body.String(), `"limit":200`) {
		t.Errorf("pagination does not report the clamped limit: %s", w.Body.String())
	}
}
