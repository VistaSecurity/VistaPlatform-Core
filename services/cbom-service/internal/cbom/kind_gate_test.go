package cbom

// The kind gate, driven through the REAL router.
//
// Every test here goes through RegisterRoutes and a real gin engine rather than
// calling a helper, because the wiring is what has failed before in this
// codebase: a helper pinned in isolation while the line that actually closed
// the hole lived at a call site, and deleting that line left the suite green.
// Delete `formatKindMismatch`'s call in download(), or the kind argument in
// generate(), and something below must go red.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// newKindEngine mounts the real routes over stubs, with the artifact's kind and
// the OCSF renderer under the test's control.
func newKindEngine(a *Artifact, ocsf ocsfRenderer, formatter ArtifactFormatter) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/cbom-service")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New().String())
		c.Set("userID", uuid.New().String())
		c.Next()
	})
	h := &Handler{
		repo: &stubArtifactStore{
			getResult:     a,
			inlineContent: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.7","components":[]}`),
		},
		formatter: formatter,
		ocsf:      ocsf,
	}
	h.SetFeatureChecker(&stubFeatureChecker{allowed: true})
	h.RegisterRoutes(grp)
	return r
}

func artifactOfKind(kind ArtifactKind) *Artifact {
	a := sampleArtifact()
	a.ArtifactKind = kind
	return &a
}

// stubOCSF records that it was called and returns a recognisable stream.
func stubOCSF(called *bool) ocsfRenderer {
	return func(_ []byte) ([]byte, string, error) {
		*called = true
		return []byte("{\"class_uid\":5001}\n"), "application/x-ndjson", nil
	}
}

// --- OCSF: both polarities ------------------------------------------------

// TestDownloadOCSF_ReachableForInventory is the positive half. Without it the
// negative tests below would pass on a handler that refused OCSF outright.
func TestDownloadOCSF_ReachableForInventory(t *testing.T) {
	called := false
	eng := newKindEngine(artifactOfKind(KindInventory), stubOCSF(&called), nil)

	w := do(eng, http.MethodGet, "/api/v1/cbom-service/cbom/artifacts/"+aUUID+"/download?format=ocsf", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if !called {
		t.Error("the OCSF renderer was never called")
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/x-ndjson") {
		t.Errorf("content-type = %q, want application/x-ndjson", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, ".ocsf.ndjson") {
		t.Errorf("content-disposition = %q, want an .ocsf.ndjson filename", cd)
	}
}

// TestDownloadOCSF_RefusedForOtherKinds is the negative half. An empty stream
// would read as "this tenant has no assets", which is a far worse answer than a
// refusal — so the refusal is the behaviour, and it is pinned per kind.
func TestDownloadOCSF_RefusedForOtherKinds(t *testing.T) {
	for _, kind := range []ArtifactKind{KindCBOM, KindSBOM, KindHBOM} {
		t.Run(string(kind), func(t *testing.T) {
			called := false
			eng := newKindEngine(artifactOfKind(kind), stubOCSF(&called), nil)

			w := do(eng, http.MethodGet, "/api/v1/cbom-service/cbom/artifacts/"+aUUID+"/download?format=ocsf", nil)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
			}
			if called {
				t.Error("the OCSF renderer ran for a kind it is not defined for")
			}
			// The message has to name the kind — the caller picked this
			// artifact from a list and needs to know why it cannot be exported.
			if !strings.Contains(w.Body.String(), string(kind)) {
				t.Errorf("body %q does not name the artifact's kind", w.Body.String())
			}
		})
	}
}

// TestDownloadOCSF_UnwiredRendererIs501 — a wiring fault, not a subscription
// one. Answering 402 would send an operator to buy something they already have.
func TestDownloadOCSF_UnwiredRendererIs501(t *testing.T) {
	eng := newKindEngine(artifactOfKind(KindInventory), nil, nil)
	w := do(eng, http.MethodGet, "/api/v1/cbom-service/cbom/artifacts/"+aUUID+"/download?format=ocsf", nil)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501; body=%s", w.Code, w.Body.String())
	}
}

// --- SPDX/PDF: the edition gate still wins, then the kind gate ------------

// TestDownloadSPDX_CoreStill402RegardlessOfKind. The edition gate is checked
// FIRST and before the artifact is loaded, so a Core install's answer does not
// change with the kind — which is the behaviour every existing client has.
func TestDownloadSPDX_CoreStill402RegardlessOfKind(t *testing.T) {
	for _, kind := range AllArtifactKinds {
		t.Run(string(kind), func(t *testing.T) {
			eng := newKindEngine(artifactOfKind(kind), nil, nil) // Core: no formatter
			w := do(eng, http.MethodGet, "/api/v1/cbom-service/cbom/artifacts/"+aUUID+"/download?format=spdx", nil)
			if w.Code != http.StatusPaymentRequired {
				t.Fatalf("status = %d, want 402; body=%s", w.Code, w.Body.String())
			}
		})
	}
}

// TestDownloadSPDX_EnterpriseRefusesNonCBOMKinds. With the renderer present the
// edition gate opens and the kind gate is what answers: the SPDX and PDF
// projections walk the crypto component model, so pointing them at an inventory
// snapshot produces a document that is empty where it matters and says so
// nowhere.
func TestDownloadSPDX_EnterpriseRefusesNonCBOMKinds(t *testing.T) {
	for _, format := range []string{"spdx", "pdf"} {
		for _, kind := range []ArtifactKind{KindSBOM, KindHBOM, KindInventory} {
			t.Run(format+"/"+string(kind), func(t *testing.T) {
				f := &fakeFormatter{body: []byte("rendered"), mime: "application/spdx+json"}
				eng := newKindEngine(artifactOfKind(kind), nil, f)
				w := do(eng, http.MethodGet, "/api/v1/cbom-service/cbom/artifacts/"+aUUID+"/download?format="+format, nil)
				if w.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
				}
				if f.gotFormat != "" {
					t.Error("the Enterprise renderer ran for a kind it is not defined for")
				}
			})
		}
	}
}

// TestDownloadSPDX_EnterpriseStillServesCBOM is that gate's other polarity: the
// kind check must not have broken the case it was added around.
func TestDownloadSPDX_EnterpriseStillServesCBOM(t *testing.T) {
	f := &fakeFormatter{body: []byte("rendered"), mime: "application/spdx+json"}
	eng := newKindEngine(artifactOfKind(KindCBOM), nil, f)
	w := do(eng, http.MethodGet, "/api/v1/cbom-service/cbom/artifacts/"+aUUID+"/download?format=spdx", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if f.gotFormat != "spdx" {
		t.Errorf("renderer saw format %q, want spdx", f.gotFormat)
	}
}

// TestDownloadCycloneDX_ServesEveryKind. CycloneDX is the canonical form of all
// four kinds; a kind gate that caught it too would make three of them
// undownloadable.
func TestDownloadCycloneDX_ServesEveryKind(t *testing.T) {
	for _, kind := range AllArtifactKinds {
		t.Run(string(kind), func(t *testing.T) {
			eng := newKindEngine(artifactOfKind(kind), nil, nil)
			w := do(eng, http.MethodGet, "/api/v1/cbom-service/cbom/artifacts/"+aUUID+"/download?format=cyclonedx", nil)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
			}
		})
	}
}

// TestDownload_UnknownFormatIs400 — distinct from 402 (valid format, wrong
// edition) and from the kind 400. Collapsing them is how "you cannot afford
// this" and "that is not a thing" become the same message.
func TestDownload_UnknownFormatIs400(t *testing.T) {
	eng := newKindEngine(artifactOfKind(KindInventory), stubOCSF(new(bool)), nil)
	w := do(eng, http.MethodGet, "/api/v1/cbom-service/cbom/artifacts/"+aUUID+"/download?format=parquet", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

// --- generate: the kind reaches the builder ------------------------------

func newGenerateEngine(builder *stubBuilder, persister *stubPersister) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/cbom-service")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New().String())
		c.Set("userID", uuid.New().String())
		c.Request.Header.Set("Authorization", "Bearer test-token")
		c.Next()
	})
	h := &Handler{
		repo:      &stubArtifactStore{},
		scopeRepo: &stubScopeGetter{result: sampleScope()},
		builder:   builder,
		persister: persister,
	}
	h.SetFeatureChecker(&stubFeatureChecker{allowed: false})
	h.RegisterRoutes(grp)
	return r
}

// TestGenerate_KindReachesTheBuilder, for every kind in the vocabulary plus the
// omitted case.
//
// The omitted case is the compatibility guarantee: a client that predates kinds
// sends no `kind`, and must still get a CBOM. Asserting the builder SAW `cbom`
// — not that the request succeeded — is what makes that a real check; a handler
// that passed "" through would also return 202.
func TestGenerate_KindReachesTheBuilder(t *testing.T) {
	cases := map[string]ArtifactKind{
		`{"scope_id":"%s"}`:                    KindCBOM,
		`{"scope_id":"%s","kind":"cbom"}`:      KindCBOM,
		`{"scope_id":"%s","kind":"sbom"}`:      KindSBOM,
		`{"scope_id":"%s","kind":"hbom"}`:      KindHBOM,
		`{"scope_id":"%s","kind":"inventory"}`: KindInventory,
	}
	scope := sampleScope()
	for tmpl, want := range cases {
		t.Run(string(want)+tmpl, func(t *testing.T) {
			persisted := sampleArtifact()
			builder := &stubBuilder{out: &BuildOutput{CanonicalBytes: []byte("{}"), ContentHash: "deadbeef"}}
			h := &Handler{
				repo:      &stubArtifactStore{},
				scopeRepo: &stubScopeGetter{result: scope},
				builder:   builder,
				persister: &stubPersister{out: &persisted},
			}
			h.SetFeatureChecker(&stubFeatureChecker{allowed: false})
			gin.SetMode(gin.TestMode)
			r := gin.New()
			grp := r.Group("/api/v1/cbom-service")
			grp.Use(func(c *gin.Context) {
				c.Set("tenantID", scope.TenantID.String())
				c.Set("userID", uuid.New().String())
				c.Request.Header.Set("Authorization", "Bearer test-token")
				c.Next()
			})
			h.RegisterRoutes(grp)

			body := strings.NewReader(strings.Replace(tmpl, "%s", scope.ID.String(), 1))
			w := do(r, http.MethodPost, "/api/v1/cbom-service/cbom/generate", body)
			if w.Code != http.StatusAccepted {
				t.Fatalf("status = %d, want 202; body=%s", w.Code, w.Body.String())
			}
			if builder.lastKind != want {
				t.Errorf("builder saw kind %q, want %q", builder.lastKind, want)
			}
		})
	}
}

// TestGenerate_UnknownKindIs400. A typo'd "sboM" that quietly produced a CBOM
// would be discovered by an auditor, not by the person who typed it.
func TestGenerate_UnknownKindIs400(t *testing.T) {
	builder := &stubBuilder{out: &BuildOutput{CanonicalBytes: []byte("{}"), ContentHash: "deadbeef"}}
	persisted := sampleArtifact()
	eng := newGenerateEngine(builder, &stubPersister{out: &persisted})

	body := strings.NewReader(`{"scope_id":"` + sampleScope().ID.String() + `","kind":"sboM"}`)
	w := do(eng, http.MethodPost, "/api/v1/cbom-service/cbom/generate", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if builder.lastKind != "" {
		t.Errorf("the builder ran with kind %q for an unrecognised request", builder.lastKind)
	}
	// The message must list the vocabulary — that is the whole value of
	// refusing rather than defaulting.
	for _, k := range AllArtifactKinds {
		if !strings.Contains(w.Body.String(), string(k)) {
			t.Errorf("body %q does not list %q", w.Body.String(), k)
		}
	}
}

// TestGenerate_UnavailableKindIs501. The kind is recognised, the request is
// well-formed, the deployment has no assembler wired. Reporting that as a
// client error would send someone to fix a request that was correct.
func TestGenerate_UnavailableKindIs501(t *testing.T) {
	builder := &stubBuilder{err: ErrKindUnavailable}
	persisted := sampleArtifact()
	eng := newGenerateEngine(builder, &stubPersister{out: &persisted})

	body := strings.NewReader(`{"scope_id":"` + sampleScope().ID.String() + `","kind":"inventory"}`)
	w := do(eng, http.MethodPost, "/api/v1/cbom-service/cbom/generate", body)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501; body=%s", w.Code, w.Body.String())
	}
}

// --- list: the ?kind= filter reaches the store ---------------------------

// TestList_KindFilterReachesTheStore, and an absent one means EVERY kind.
//
// Defaulting the filter to `cbom` would hide the SBOM someone just generated
// behind a filter they never set, which is the kind of "works, shows nothing"
// bug that takes a support ticket to find.
func TestList_KindFilterReachesTheStore(t *testing.T) {
	cases := map[string]ArtifactKind{
		"":                                  "",
		"?kind=cbom":                        KindCBOM,
		"?kind=sbom":                        KindSBOM,
		"?kind=inventory":                   KindInventory,
		"?scope_id=" + aUUID + "&kind=hbom": KindHBOM,
	}
	for query, want := range cases {
		t.Run("list"+query, func(t *testing.T) {
			store := &stubArtifactStore{}
			gin.SetMode(gin.TestMode)
			r := gin.New()
			grp := r.Group("/api/v1/cbom-service")
			grp.Use(func(c *gin.Context) {
				c.Set("tenantID", uuid.New().String())
				c.Next()
			})
			h := &Handler{repo: store}
			h.RegisterRoutes(grp)

			w := do(r, http.MethodGet, "/api/v1/cbom-service/cbom/artifacts"+query, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
			}
			if store.lastKindFilter != want {
				t.Errorf("store saw kind filter %q, want %q", store.lastKindFilter, want)
			}
		})
	}
}

// TestList_UnknownKindIs400 — not an empty list, which would read as "you have
// no artifacts".
func TestList_UnknownKindIs400(t *testing.T) {
	store := &stubArtifactStore{}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/cbom-service")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New().String())
		c.Next()
	})
	h := &Handler{repo: store}
	h.RegisterRoutes(grp)

	w := do(r, http.MethodGet, "/api/v1/cbom-service/cbom/artifacts?kind=xbom", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

// --- the pure predicate, both directions ---------------------------------

// TestFormatKindMismatch is the table the two gates above consult. It is here
// as well as at the HTTP surface because the HTTP tests cannot practically
// cover all 16 (format, kind) pairs, and an over-strict gate — refusing a
// combination that is fine — is the same bug pointed the other way.
func TestFormatKindMismatch(t *testing.T) {
	allowed := map[DownloadFormat]map[ArtifactKind]bool{
		FormatCycloneDX: {KindCBOM: true, KindSBOM: true, KindHBOM: true, KindInventory: true},
		FormatOCSF:      {KindInventory: true},
		FormatSPDX:      {KindCBOM: true},
		FormatPDF:       {KindCBOM: true},
	}
	for format, kinds := range allowed {
		for _, kind := range AllArtifactKinds {
			msg, ok := formatKindMismatch(format, kind)
			if want := kinds[kind]; ok != want {
				t.Errorf("formatKindMismatch(%s, %s) ok = %v, want %v (msg=%q)", format, kind, ok, want, msg)
			}
			if !ok && msg == "" {
				t.Errorf("formatKindMismatch(%s, %s) refused with no reason", format, kind)
			}
		}
		// An artifact row that predates the column reads back as 'cbom'; an
		// Artifact built in memory may leave it empty. Empty must behave as
		// cbom, or every historical artifact becomes undownloadable.
		if _, ok := formatKindMismatch(format, ""); ok != kinds[KindCBOM] {
			t.Errorf("formatKindMismatch(%s, \"\") disagrees with cbom", format)
		}
	}
}
