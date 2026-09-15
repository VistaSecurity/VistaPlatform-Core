package handlers

// Contract tests for Catalog ▸ Classification rules.
//
// They drive the REAL gin handlers over httptest with an in-memory store — the
// house pattern from entitlements_contract_test.go and catalogs_contract_test.go
// — so a handler that stopped validating, stopped paginating or started
// answering 500 where it used to answer 409 fails here rather than in the
// console.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/classificationrules"
)

// --- stub store --------------------------------------------------------------

type stubRuleStore struct {
	rules   []classificationrules.Rule
	listErr error
	nextID  int
}

func (s *stubRuleStore) List(_ context.Context, q classificationrules.Query) ([]classificationrules.Rule, int64, error) {
	if s.listErr != nil {
		return nil, 0, s.listErr
	}
	var out []classificationrules.Rule
	for _, r := range s.rules {
		if q.Kind != "" && r.RuleKind != q.Kind {
			continue
		}
		if q.Search != "" && !strings.Contains(strings.ToLower(r.Pattern), strings.ToLower(q.Search)) {
			continue
		}
		out = append(out, r)
	}
	return out, int64(len(out)), nil
}

func (s *stubRuleStore) Get(_ context.Context, id string) (classificationrules.Rule, error) {
	for _, r := range s.rules {
		if r.ID == id {
			return r, nil
		}
	}
	return classificationrules.Rule{}, classificationrules.ErrNotFound
}

func (s *stubRuleStore) Create(_ context.Context, in classificationrules.Input) (classificationrules.Rule, error) {
	for _, r := range s.rules {
		if r.RuleKind == in.RuleKind && r.Pattern == in.Pattern {
			return classificationrules.Rule{}, classificationrules.ErrDuplicate
		}
	}
	s.nextID++
	r := classificationrules.Rule{
		ID: "id-" + itoa(s.nextID), RuleKind: in.RuleKind, Pattern: in.Pattern,
		ClassKey: in.ClassKey, Vendor: in.Vendor, Model: in.Model,
		Confidence: in.Confidence, SourceURL: in.SourceURL,
	}
	s.rules = append(s.rules, r)
	return r, nil
}

func (s *stubRuleStore) Update(_ context.Context, id string, in classificationrules.Input) (classificationrules.Rule, error) {
	for i, r := range s.rules {
		if r.ID != id {
			continue
		}
		s.rules[i] = classificationrules.Rule{
			ID: id, RuleKind: in.RuleKind, Pattern: in.Pattern,
			ClassKey: in.ClassKey, Vendor: in.Vendor, Model: in.Model,
			Confidence: in.Confidence, SourceURL: in.SourceURL,
		}
		return s.rules[i], nil
	}
	return classificationrules.Rule{}, classificationrules.ErrNotFound
}

func (s *stubRuleStore) Delete(_ context.Context, id string) error {
	for i, r := range s.rules {
		if r.ID == id {
			s.rules = append(s.rules[:i], s.rules[i+1:]...)
			return nil
		}
	}
	return classificationrules.ErrNotFound
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func ptr(s string) *string { return &s }

func ruleRouter(store ClassificationRuleStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/admin/catalogs")
	g.GET("/classification-rules", ListClassificationRules(store))
	g.POST("/classification-rules", CreateClassificationRule(store))
	g.GET("/classification-rules/:id", GetClassificationRule(store))
	g.PUT("/classification-rules/:id", UpdateClassificationRule(store))
	g.DELETE("/classification-rules/:id", DeleteClassificationRule(store))
	return r
}

func doJSON(t *testing.T, r *gin.Engine, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		blob, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		rdr = bytes.NewReader(blob)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// --- tests -------------------------------------------------------------------

func TestClassificationRules_ListShapeAndFilters(t *testing.T) {
	store := &stubRuleStore{rules: []classificationrules.Rule{
		{ID: "a", RuleKind: "oui", Pattern: "00000C", ClassKey: ptr("network_device"), Vendor: ptr("Cisco Systems"), Confidence: 0.7},
		{ID: "b", RuleKind: "cloud_type", Pattern: "aws_s3_bucket", ClassKey: ptr("object_storage"), Confidence: 0.95},
	}}
	r := ruleRouter(store)

	w := doJSON(t, r, http.MethodGet, "/admin/catalogs/classification-rules", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body)
	}
	var got struct {
		Rules    []classificationrules.Rule `json:"rules"`
		Total    int64                      `json:"total"`
		Page     int                        `json:"page"`
		PageSize int                        `json:"page_size"`
		Kinds    []string                   `json:"kinds"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Total != 2 || len(got.Rules) != 2 {
		t.Errorf("got %d rules / total %d, want 2/2", len(got.Rules), got.Total)
	}
	if got.Page != 1 || got.PageSize != classificationrules.DefaultPageSize {
		t.Errorf("page echo = %d/%d, want 1/%d", got.Page, got.PageSize, classificationrules.DefaultPageSize)
	}
	// The kind vocabulary ships WITH the list, so the console's filter and form
	// cannot carry their own copy and drift from the engine.
	wantKinds := classificationrules.Kinds()
	sort.Strings(wantKinds)
	gotKinds := append([]string(nil), got.Kinds...)
	sort.Strings(gotKinds)
	if strings.Join(gotKinds, ",") != strings.Join(wantKinds, ",") {
		t.Errorf("kinds = %v, want %v", got.Kinds, wantKinds)
	}

	w = doJSON(t, r, http.MethodGet, "/admin/catalogs/classification-rules?kind=oui", nil)
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if len(got.Rules) != 1 || got.Rules[0].RuleKind != "oui" {
		t.Errorf("kind filter returned %+v", got.Rules)
	}
}

// An empty result is an empty ARRAY, never null. The two render identically in
// a table and mean different things to a client.
func TestClassificationRules_EmptyListIsAnArray(t *testing.T) {
	w := doJSON(t, ruleRouter(&stubRuleStore{}), http.MethodGet, "/admin/catalogs/classification-rules", nil)
	if !strings.Contains(w.Body.String(), `"rules":[]`) {
		t.Errorf("empty list is not an empty array:\n%s", w.Body)
	}
}

func TestClassificationRules_RejectsAnUnknownKindFilter(t *testing.T) {
	w := doJSON(t, ruleRouter(&stubRuleStore{}), http.MethodGet, "/admin/catalogs/classification-rules?kind=astrology", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	// The error names the vocabulary, so the next request can be right.
	if !strings.Contains(w.Body.String(), "sysobjectid") {
		t.Errorf("the error does not list the valid kinds:\n%s", w.Body)
	}
}

func TestClassificationRules_CreateReadUpdateDelete(t *testing.T) {
	store := &stubRuleStore{}
	r := ruleRouter(store)

	create := classificationrules.Input{
		RuleKind: "oui", Pattern: "00188B", Vendor: ptr("Dell Inc."),
		Confidence: 0.85, SourceURL: ptr("https://standards-oui.ieee.org/"),
	}
	w := doJSON(t, r, http.MethodPost, "/admin/catalogs/classification-rules", create)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: status = %d, body %s", w.Code, w.Body)
	}
	var made classificationrules.Rule
	if err := json.Unmarshal(w.Body.Bytes(), &made); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if made.ID == "" {
		t.Fatal("create returned no id")
	}
	// A vendor-only rule keeps a NULL class, not an empty string: the null is
	// what says "this rule deliberately asserts no class".
	if made.ClassKey != nil {
		t.Errorf("ClassKey = %v, want null for a vendor-only rule", *made.ClassKey)
	}

	w = doJSON(t, r, http.MethodGet, "/admin/catalogs/classification-rules/"+made.ID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get: status = %d", w.Code)
	}

	update := create
	update.ClassKey = ptr("server")
	update.Confidence = 0.75
	w = doJSON(t, r, http.MethodPut, "/admin/catalogs/classification-rules/"+made.ID, update)
	if w.Code != http.StatusOK {
		t.Fatalf("update: status = %d, body %s", w.Code, w.Body)
	}
	var updated classificationrules.Rule
	_ = json.Unmarshal(w.Body.Bytes(), &updated)
	if updated.ClassKey == nil || *updated.ClassKey != "server" || updated.Confidence != 0.75 {
		t.Errorf("update did not take: %+v", updated)
	}

	w = doJSON(t, r, http.MethodDelete, "/admin/catalogs/classification-rules/"+made.ID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("delete: status = %d", w.Code)
	}
	w = doJSON(t, r, http.MethodGet, "/admin/catalogs/classification-rules/"+made.ID, nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("get after delete: status = %d, want 404", w.Code)
	}
}

// The handler runs the ENGINE'S validator, not a looser copy of it. A rule the
// API accepts and the engine then refuses is a rule an admin sees saved, sees
// listed, and never sees fire.
func TestClassificationRules_RejectsWhatTheEngineWouldRefuse(t *testing.T) {
	cases := []struct {
		name string
		in   classificationrules.Input
		want string
	}{
		{"lowercase oui", classificationrules.Input{RuleKind: "oui", Pattern: "00188b", Vendor: ptr("Dell"), Confidence: 0.85}, "uppercase hex"},
		{"oui with separators", classificationrules.Input{RuleKind: "oui", Pattern: "00:18:8B", Vendor: ptr("Dell"), Confidence: 0.85}, "separators"},
		{"unknown kind", classificationrules.Input{RuleKind: "astrology", Pattern: "x", Vendor: ptr("v"), Confidence: 0.8}, "unknown kind"},
		{"unknown class", classificationrules.Input{RuleKind: "oui", Pattern: "00188B", ClassKey: ptr("toaster"), Confidence: 0.85}, "asset-classes.yaml"},
		{"confidence out of range", classificationrules.Input{RuleKind: "oui", Pattern: "00188B", Vendor: ptr("Dell"), Confidence: 1.0}, "outside"},
		{"asserts nothing", classificationrules.Input{RuleKind: "oui", Pattern: "00188B", Confidence: 0.85}, "asserts nothing"},
		{"banner that does not compile", classificationrules.Input{RuleKind: "banner", Pattern: "(unclosed", ClassKey: ptr("web_application"), Confidence: 0.6}, "does not compile"},
		{"single-port profile", classificationrules.Input{RuleKind: "port_profile", Pattern: "9100", ClassKey: ptr("printer"), Confidence: 0.8}, "not a profile"},
		{"oid outside the enterprise arc", classificationrules.Input{RuleKind: "sysobjectid", Pattern: "1.3.6.1.2.1.1", Vendor: ptr("v"), Confidence: 0.8}, "private-enterprise arc"},
		{"no pattern", classificationrules.Input{RuleKind: "oui", Vendor: ptr("Dell"), Confidence: 0.85}, "pattern is required"},
	}

	r := ruleRouter(&stubRuleStore{})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := doJSON(t, r, http.MethodPost, "/admin/catalogs/classification-rules", tc.in)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", w.Code, w.Body)
			}
			// The engine's own message reaches the admin: it says what to type
			// next, where "invalid rule" says guess again.
			if !strings.Contains(w.Body.String(), tc.want) {
				t.Errorf("error does not mention %q:\n%s", tc.want, w.Body)
			}
			if strings.Contains(w.Body.String(), "classify:") {
				t.Errorf("the package prefix leaked into an admin-facing message:\n%s", w.Body)
			}
		})
	}
}

// A collision with the (rule_kind, pattern) unique index is a 409, not a 500:
// the admin's next move is to edit the rule that already claims the pattern.
func TestClassificationRules_DuplicatePatternIsAConflict(t *testing.T) {
	store := &stubRuleStore{}
	r := ruleRouter(store)
	in := classificationrules.Input{RuleKind: "oui", Pattern: "00188B", Vendor: ptr("Dell Inc."), Confidence: 0.85}

	if w := doJSON(t, r, http.MethodPost, "/admin/catalogs/classification-rules", in); w.Code != http.StatusCreated {
		t.Fatalf("first create: %d %s", w.Code, w.Body)
	}
	w := doJSON(t, r, http.MethodPost, "/admin/catalogs/classification-rules", in)
	if w.Code != http.StatusConflict {
		t.Fatalf("second create: status = %d, want 409 (body %s)", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "already exists") {
		t.Errorf("the 409 does not say what collided:\n%s", w.Body)
	}
}

// A blank optional field posts as "" and must become NULL, not an empty string.
// The null is the difference between "this rule asserts no class" and "this
// rule asserts a class whose key is the empty string", and only one of those is
// a thing.
func TestClassificationRules_BlankOptionalFieldsBecomeNull(t *testing.T) {
	store := &stubRuleStore{}
	r := ruleRouter(store)

	w := doJSON(t, r, http.MethodPost, "/admin/catalogs/classification-rules", map[string]any{
		"rule_kind": "oui", "pattern": "00188B",
		"class_key": "  ", "vendor": "Dell Inc.", "model": "",
		"confidence": 0.85, "source_url": "",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %s", w.Code, w.Body)
	}
	var made classificationrules.Rule
	_ = json.Unmarshal(w.Body.Bytes(), &made)
	if made.ClassKey != nil || made.Model != nil || made.SourceURL != nil {
		t.Errorf("a blank field became an empty string rather than NULL: %+v", made)
	}
}

func TestClassificationRules_MissingRuleIs404NotAnError(t *testing.T) {
	r := ruleRouter(&stubRuleStore{})
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/admin/catalogs/classification-rules/nope"},
		{http.MethodDelete, "/admin/catalogs/classification-rules/nope"},
	} {
		w := doJSON(t, r, tc.method, tc.path, nil)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s %s: status = %d, want 404", tc.method, tc.path, w.Code)
		}
	}
	w := doJSON(t, r, http.MethodPut, "/admin/catalogs/classification-rules/nope",
		classificationrules.Input{RuleKind: "oui", Pattern: "00188B", Vendor: ptr("Dell"), Confidence: 0.85})
	if w.Code != http.StatusNotFound {
		t.Errorf("PUT missing: status = %d, want 404", w.Code)
	}
}
