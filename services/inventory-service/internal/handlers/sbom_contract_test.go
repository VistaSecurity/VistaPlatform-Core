package handlers

// Contract tests for the SBOM upload surface and the two software reads
// (workstream 2.6b). Extends the inventory-service spec-first contract
// (ADR-0001) and reuses the shared harness from asset_contract_test.go
// (loadSpec / assertConforms / do).
//
// The handler takes the narrow `sbomIngester` interface, so these drive the
// REAL handlers with an in-memory stub and no database.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/sbom"
)

type stubIngester struct {
	result    *services.SBOMIngestResult
	err       error
	installs  []services.SoftwareInstallRow
	total     int
	listErr   error
	products  []services.SoftwareProductRow
	prodTotal int
	prodErr   error

	// What the handler actually passed through, so the tests can assert on the
	// wiring rather than only on the shape of the answer.
	gotAsset  uuid.UUID
	gotActor  uuid.UUID
	gotBody   string
	gotFile   string
	gotStatus string
	gotQuery  string
	gotSort   string
	gotLimit  int
	gotOffset int
}

func (s *stubIngester) Ingest(_ context.Context, _, assetID, actorUserID uuid.UUID, filename string, r io.Reader) (*services.SBOMIngestResult, error) {
	s.gotAsset, s.gotActor, s.gotFile = assetID, actorUserID, filename
	b, _ := io.ReadAll(r)
	s.gotBody = string(b)
	return s.result, s.err
}

func (s *stubIngester) ListAssetSoftware(_ context.Context, _, assetID uuid.UUID, q, status, sortKey string, limit, offset int) ([]services.SoftwareInstallRow, int, error) {
	s.gotAsset, s.gotQuery, s.gotStatus, s.gotSort = assetID, q, status, sortKey
	s.gotLimit, s.gotOffset = limit, offset
	return s.installs, s.total, s.listErr
}

func (s *stubIngester) ListProducts(_ context.Context, _ uuid.UUID, q, sortKey string, limit, offset int) ([]services.SoftwareProductRow, int, error) {
	s.gotQuery, s.gotSort, s.gotLimit, s.gotOffset = q, sortKey, limit, offset
	return s.products, s.prodTotal, s.prodErr
}

const sbomActor = "8c2f0e4a-1d3b-4a5c-9e6f-0b1c2d3e4f50"

// newSBOMEngine takes the INTERFACE, not the concrete stub, so a test that
// needs a different fake (the parsing ingester below, which exercises the real
// byte cap) uses the same router the rest of the file does.
func newSBOMEngine(ing sbomIngester) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2/inventory-service")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.MustParse(sbomActor))
		c.Next()
	})
	h := NewSBOMHandler(ing)
	grp.GET("/infrastructure-assets/:id/software", h.GetAssetSoftware)
	grp.POST("/infrastructure-assets/:id/sbom", h.UploadAssetSBOM)
	grp.POST("/sbom", h.UploadSBOM)
	grp.GET("/software/products", h.GetSoftwareProducts)
	return r
}

const sbomBase = "/api/v2/inventory-service"

func sampleIngestResult() *services.SBOMIngestResult {
	return &services.SBOMIngestResult{
		UploadID:               uuid.New().String(),
		Filename:               "billing.cdx.json",
		Format:                 "cyclonedx",
		SpecVersion:            "1.6",
		DocumentSerial:         "urn:uuid:" + uuid.New().String(),
		AssetID:                uuid.New().String(),
		AssetName:              "billing-api 1.0.0",
		AssetCreated:           true,
		AssetStatus:            "pending_approval",
		ComponentCount:         480,
		ProductsCreated:        400,
		ProductsMatched:        12,
		InstallsCreated:        412,
		InstallsUpdated:        0,
		InstallsRemoved:        3,
		ComponentsExcluded:     12,
		DependencyEdgesIgnored: 56,
		Warnings:               []string{"1284 cryptographic components skipped"},
	}
}

func sampleInstall() services.SoftwareInstallRow {
	now := time.Now().UTC()
	purl := "pkg:generic/openssl@3.0.13"
	cpe := "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*"
	vendor, version, sort := "OpenSSL Project", "3.0.13", "00000003.00000000.00000013"
	licence := "Apache-2.0"
	ref := "sbom:" + uuid.New().String()
	eolDate, eolSev, vulnSev := "2026-11-14", "medium", "critical"
	days, cvss := -87, 9.8
	eolFinding, vulnFinding := uuid.New(), uuid.New()
	return services.SoftwareInstallRow{
		InstallID: uuid.New(), ProductID: uuid.New(),
		Name: "openssl", Vendor: &vendor, Version: &version, VersionSort: &sort,
		PURL: &purl, CPE: &cpe, LicenseID: &licence,
		SourceKind: "imported", SourceRef: &ref, Status: "active",
		FirstSeenAt: now, LastSeenAt: now, UpdatedAt: &now,
		// The rollup, populated: this row is both end of life and vulnerable,
		// which is the shape the Software tab's two new columns render.
		EOLState: services.SoftwareEOLEndOfLife, EOLDate: &eolDate,
		EOLDaysRemaining: &days, EOLSeverity: &eolSev, EOLFindingID: &eolFinding,
		VulnerabilityState: services.SoftwareVulnVulnerable, VulnerabilityCount: 12,
		WorstCVSS: &cvss, VulnSeverity: &vulnSev, VulnFindingID: &vulnFinding,
	}
}

// unidentifiableInstall is the third value on the vulnerability axis: a product
// with neither a PURL nor a CPE, which the vulnerability producer skips. It is
// in the fixtures because `none_known` and `not_assessed` are the pair a client
// most easily flattens into "0", and the spec has to carry a row of each.
func unidentifiableInstall() services.SoftwareInstallRow {
	now := time.Now().UTC()
	return services.SoftwareInstallRow{
		InstallID: uuid.New(), ProductID: uuid.New(),
		Name: "in-house-shim", SourceKind: "declared", Status: "active",
		FirstSeenAt: now, LastSeenAt: now,
		EOLState:           services.SoftwareEOLNotAssessed,
		VulnerabilityState: services.SoftwareVulnNotAssessed,
	}
}

// The three recorded end-of-life answers that are not a finding. The `eol`
// producer writes them on `software_install_lifecycle`, the list reads them,
// and the spec has to carry each as its own value — `supported` in particular
// used to be indistinguishable from `not_assessed`, which is the collapse the
// record was added to undo.
func supportedInstall() services.SoftwareInstallRow {
	now := time.Now().UTC()
	purl := "pkg:generic/zlib@1.3.1"
	until := "2028-04-01"
	return services.SoftwareInstallRow{
		InstallID: uuid.New(), ProductID: uuid.New(),
		Name: "zlib", PURL: &purl, SourceKind: "imported", Status: "active",
		FirstSeenAt: now, LastSeenAt: now,
		EOLState: services.SoftwareEOLSupported, EOLDate: &until, EOLAssessedAt: &now,
		VulnerabilityState: services.SoftwareVulnNoneKnown,
	}
}

func noDateInstall() services.SoftwareInstallRow {
	now := time.Now().UTC()
	return services.SoftwareInstallRow{
		InstallID: uuid.New(), ProductID: uuid.New(),
		Name: "libfoo", SourceKind: "imported", Status: "active",
		FirstSeenAt: now, LastSeenAt: now,
		EOLState: services.SoftwareEOLNoDate, EOLAssessedAt: &now,
		VulnerabilityState: services.SoftwareVulnNotAssessed,
	}
}

func uncataloguedInstall() services.SoftwareInstallRow {
	now := time.Now().UTC()
	return services.SoftwareInstallRow{
		InstallID: uuid.New(), ProductID: uuid.New(),
		Name: "acme-internal-tool", SourceKind: "measured", Status: "active",
		FirstSeenAt: now, LastSeenAt: now,
		EOLState: services.SoftwareEOLNotInCatalogue, EOLAssessedAt: &now,
		VulnerabilityState: services.SoftwareVulnNotAssessed,
	}
}

// minimalInstall leaves every nullable column absent — the purl-less,
// vendor-less, unversioned product the NULL rule exists for. The spec has to
// accept it, or a real tenant's catalogue fails validation the day it holds one.
func minimalInstall() services.SoftwareInstallRow {
	now := time.Now().UTC()
	return services.SoftwareInstallRow{
		InstallID: uuid.New(), ProductID: uuid.New(),
		Name: "mystery-lib", SourceKind: "imported", Status: "removed",
		FirstSeenAt: now, LastSeenAt: now,
		EOLState:           services.SoftwareEOLNotAssessed,
		VulnerabilityState: services.SoftwareVulnNoneKnown,
	}
}

func TestContract_GetAssetSoftware_200(t *testing.T) {
	sv := loadSpec(t)
	stub := &stubIngester{installs: []services.SoftwareInstallRow{
		sampleInstall(), minimalInstall(), unidentifiableInstall(),
		supportedInstall(), noDateInstall(), uncataloguedInstall(),
	}, total: 6}
	eng := newSBOMEngine(stub)

	w := do(eng, http.MethodGet, sbomBase+"/infrastructure-assets/"+uuid.New().String()+"/software?q=ssl&status=active&sort=version&limit=10&offset=5", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SoftwareInstallListResponse", w.Body.Bytes())

	// The five end-of-life states have to survive serialisation as five
	// distinct values, with the supported row carrying its date and every
	// recorded row its timestamp. A spec that still listed two would have
	// failed assertConforms above; this pins that the rows actually carry them.
	for _, want := range []string{
		`"eol_state":"supported"`, `"eol_state":"no_date"`, `"eol_state":"not_in_catalogue"`,
		`"eol_date":"2028-04-01"`, `"eol_assessed_at":`,
	} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("the response does not carry %s; the recorded answer it stands for cannot be drawn", want)
		}
	}

	// The wiring, not just the shape: every documented query parameter has to
	// reach the service, or the spec documents a filter that does nothing.
	if stub.gotQuery != "ssl" || stub.gotStatus != "active" || stub.gotSort != "version" {
		t.Errorf("q/status/sort reached the service as %q/%q/%q", stub.gotQuery, stub.gotStatus, stub.gotSort)
	}
	if stub.gotLimit != 10 || stub.gotOffset != 5 {
		t.Errorf("limit/offset reached the service as %d/%d, want 10/5", stub.gotLimit, stub.gotOffset)
	}

	// The three-valued pair has to SURVIVE serialisation as three distinct
	// values. A client that sees `none_known` and `not_assessed` as the same
	// string renders both as "0 vulnerabilities" — the exact collapse the
	// producer refuses to make, undone one layer up.
	body := w.Body.String()
	for _, want := range []string{
		`"vulnerability_state":"vulnerable"`,
		`"vulnerability_state":"none_known"`,
		`"vulnerability_state":"not_assessed"`,
		`"eol_state":"end_of_life"`,
		`"eol_state":"not_assessed"`,
		`"worst_cvss":9.8`,
		`"vulnerability_count":12`,
		`"eol_date":"2026-11-14"`,
		`"eol_days_remaining":-87`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the response does not carry %s; the column it feeds cannot be drawn: %s", want, body)
		}
	}
	// An UNSCORED vulnerability must not arrive as 0.0. The two rows that are
	// not `vulnerable` carry no worst_cvss at all — `omitempty` on a nil
	// pointer — rather than a zero a reader would take for "harmless".
	if strings.Contains(body, `"worst_cvss":0`) {
		t.Errorf("worst_cvss serialised as 0; NULL and 0.0 are different answers: %s", body)
	}
}

// An empty list serialises as [] and not null. `null` is what a nil Go slice
// marshals to, and a client reading `software.length` on it throws.
func TestContract_GetAssetSoftware_EmptyIsAnArray(t *testing.T) {
	sv := loadSpec(t)
	eng := newSBOMEngine(&stubIngester{installs: []services.SoftwareInstallRow{}, total: 0})
	w := do(eng, http.MethodGet, sbomBase+"/infrastructure-assets/"+uuid.New().String()+"/software", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"software":[]`) {
		t.Errorf("empty list did not serialise as []: %s", w.Body.String())
	}
	sv.assertConforms(t, "SoftwareInstallListResponse", w.Body.Bytes())
}

func TestContract_GetAssetSoftware_DefaultPaging(t *testing.T) {
	stub := &stubIngester{installs: []services.SoftwareInstallRow{}}
	eng := newSBOMEngine(stub)
	do(eng, http.MethodGet, sbomBase+"/infrastructure-assets/"+uuid.New().String()+"/software?limit=0&offset=-3", nil)
	if stub.gotLimit != 50 || stub.gotOffset != 0 {
		t.Fatalf("limit/offset = %d/%d; a garbage limit must fall back to the default, not fetch everything",
			stub.gotLimit, stub.gotOffset)
	}
	do(eng, http.MethodGet, sbomBase+"/infrastructure-assets/"+uuid.New().String()+"/software?limit=99999", nil)
	if stub.gotLimit != 500 {
		t.Fatalf("limit = %d; an asset with 40,000 components must not be one response", stub.gotLimit)
	}
}

func TestContract_GetAssetSoftware_UnknownSortIs400(t *testing.T) {
	eng := newSBOMEngine(&stubIngester{listErr: errors.New(`unknown sort "nope"`)})
	w := do(eng, http.MethodGet, sbomBase+"/infrastructure-assets/"+uuid.New().String()+"/software?sort=nope", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestContract_ListSoftwareProducts_200(t *testing.T) {
	sv := loadSpec(t)
	vendor := "OpenSSL Project"
	eolDate, eolSev, vulnSev := "2026-11-14", "medium", "critical"
	cvss := 9.8
	purl := "pkg:generic/openssl@3.0.13"
	supportedUntil, checkedAt := "2028-04-01", time.Now().UTC()
	stub := &stubIngester{
		products: []services.SoftwareProductRow{
			{
				ProductID: uuid.New(), Name: "openssl", Vendor: &vendor, PURL: &purl,
				SourceKind: "imported", InstallCount: 7, AssetCount: 5,
				EOLState: services.SoftwareEOLEndOfLife, EOLInstallCount: 7,
				EOLDate: &eolDate, EOLSeverity: &eolSev,
				VulnerabilityState: services.SoftwareVulnVulnerable, VulnerableInstallCount: 7,
				VulnerabilityCount: 12, WorstCVSS: &cvss, VulnSeverity: &vulnSev,
			},
			// Every install removed: reported as 0 and still listed, because
			// "we used to run this" is a real answer. No purl and no cpe, so
			// the vulnerability producer never had anything to match on.
			{
				ProductID: uuid.New(), Name: "mystery-lib", SourceKind: "imported",
				InstallCount: 0, AssetCount: 0,
				EOLState: services.SoftwareEOLNotAssessed, VulnerabilityState: services.SoftwareVulnNotAssessed,
			},
			// A supported product: the eol producer's record resolved every
			// active install to a cycle beyond the warning window, and the
			// catalogue row carries the soonest date and the latest check.
			{
				ProductID: uuid.New(), Name: "zlib", SourceKind: "imported",
				InstallCount: 3, AssetCount: 3,
				EOLState: services.SoftwareEOLSupported, EOLDate: &supportedUntil, EOLAssessedAt: &checkedAt,
				VulnerabilityState: services.SoftwareVulnNotAssessed,
			},
		},
		prodTotal: 3,
	}
	eng := newSBOMEngine(stub)
	w := do(eng, http.MethodGet, sbomBase+"/software/products?q=ssl&sort=installs", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SoftwareProductListResponse", w.Body.Bytes())
	if stub.gotQuery != "ssl" || stub.gotSort != "installs" {
		t.Errorf("q/sort reached the service as %q/%q", stub.gotQuery, stub.gotSort)
	}
	body := w.Body.String()
	for _, want := range []string{
		`"eol_state":"end_of_life"`, `"eol_install_count":7`,
		`"eol_state":"supported"`, `"eol_date":"2028-04-01"`, `"eol_assessed_at":`,
		`"vulnerability_state":"vulnerable"`, `"vulnerable_install_count":7`,
		`"vulnerability_state":"not_assessed"`, `"worst_cvss":9.8`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the catalogue response does not carry %s: %s", want, body)
		}
	}
}

// A multipart upload — the browser's shape.
func TestContract_UploadAssetSbom_201_Multipart(t *testing.T) {
	sv := loadSpec(t)
	stub := &stubIngester{result: sampleIngestResult()}
	eng := newSBOMEngine(stub)

	assetID := uuid.New()
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	part, err := mw.CreateFormFile("file", "billing.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`)); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, sbomBase+"/infrastructure-assets/"+assetID.String()+"/sbom", body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SbomIngestResult", w.Body.Bytes())

	if stub.gotAsset != assetID {
		t.Errorf("the handler passed asset %s, want %s", stub.gotAsset, assetID)
	}
	if stub.gotFile != "billing.cdx.json" {
		t.Errorf("filename reached the service as %q", stub.gotFile)
	}
	if !strings.Contains(stub.gotBody, "CycloneDX") {
		t.Errorf("the file part did not reach the service: %q", stub.gotBody)
	}
	// The actor is what makes the history row name a person rather than nobody.
	if stub.gotActor != uuid.MustParse(sbomActor) {
		t.Errorf("actor reached the service as %s, want %s", stub.gotActor, sbomActor)
	}
}

// A raw JSON body — the build pipeline's shape. Refusing it would mean a CI
// integration needs a multipart encoder to say one thing.
func TestContract_UploadSbom_201_RawBody(t *testing.T) {
	sv := loadSpec(t)
	stub := &stubIngester{result: sampleIngestResult()}
	eng := newSBOMEngine(stub)

	doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`
	w := do(eng, http.MethodPost, sbomBase+"/sbom?filename=ci.cdx.json", strings.NewReader(doc))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SbomIngestResult", w.Body.Bytes())

	if stub.gotAsset != uuid.Nil {
		t.Errorf("POST /sbom passed asset %s; it must pass the nil UUID so the subject decides", stub.gotAsset)
	}
	if stub.gotBody != doc {
		t.Errorf("the raw body did not reach the service verbatim: %q", stub.gotBody)
	}
	if stub.gotFile != "ci.cdx.json" {
		t.Errorf("filename = %q; on a raw body it comes from the query parameter, not a guess", stub.gotFile)
	}
}

// Every refusal the parser can produce maps to a status without matching on
// message text. A 500 here would tell a user with a malformed document that the
// platform is broken.
func TestContract_UploadSbom_ErrorStatuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{"XML", sbom.ErrUnsupportedEncoding, http.StatusBadRequest},
		{"SPDX 3.0", sbom.ErrUnsupportedSpecVersion, http.StatusBadRequest},
		{"not an SBOM", sbom.ErrUnknownFormat, http.StatusBadRequest},
		{"not JSON", sbom.ErrMalformed, http.StatusBadRequest},
		{"asset gone", services.ErrSBOMAssetNotFound, http.StatusNotFound},
		{"subject is a library", services.ErrSBOMSubjectNotAnAsset, http.StatusUnprocessableEntity},
		// Bytes is a transport limit; components is a statement about content.
		{"too many bytes", &sbom.LimitError{Limit: "bytes", Max: sbom.MaxDocumentBytes, Got: -1}, http.StatusRequestEntityTooLarge},
		{"too many components", &sbom.LimitError{Limit: "components", Max: sbom.MaxComponents, Got: 430000}, http.StatusUnprocessableEntity},
		{"anything else", errors.New("boom"), http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eng := newSBOMEngine(&stubIngester{err: tc.err})
			w := do(eng, http.MethodPost, sbomBase+"/sbom", strings.NewReader("{}"))
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

// The cap message carries the numbers, so a user can be told "430000
// components, limit 100000" rather than "too big".
func TestContract_UploadSbom_LimitErrorCarriesTheNumbers(t *testing.T) {
	eng := newSBOMEngine(&stubIngester{err: &sbom.LimitError{Limit: "components", Max: sbom.MaxComponents, Got: 430000}})
	w := do(eng, http.MethodPost, sbomBase+"/sbom", strings.NewReader("{}"))
	body := w.Body.String()
	if !strings.Contains(body, "430000") || !strings.Contains(body, "100000") {
		t.Fatalf("the refusal does not name the observed value and the cap: %s", body)
	}
}

// A multipart request with no `file` part is a 400 naming what was expected,
// not a 500 and not an empty-document parse error.
func TestContract_UploadSbom_MultipartWithoutAFilePartIs400(t *testing.T) {
	eng := newSBOMEngine(&stubIngester{result: sampleIngestResult()})

	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	if err := mw.WriteField("notafile", "x"); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, sbomBase+"/sbom", body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "file") {
		t.Errorf("the message does not name the expected part: %s", w.Body.String())
	}
}

func TestContract_UploadAssetSbom_BadAssetIdIs400(t *testing.T) {
	eng := newSBOMEngine(&stubIngester{result: sampleIngestResult()})
	w := do(eng, http.MethodPost, sbomBase+"/infrastructure-assets/not-a-uuid/sbom", strings.NewReader("{}"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

// bigReader yields n bytes without allocating them, so a 32 MiB test body costs
// nothing but time.
type bigReader struct{ left int64 }

func (b *bigReader) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, io.EOF
	}
	n := int64(len(p))
	if n > b.left {
		n = b.left
	}
	for i := int64(0); i < n; i++ {
		p[i] = 'a'
	}
	b.left -= n
	return int(n), nil
}

// parsingIngester runs the REAL parser over whatever the handler hands it.
//
// The stub above returns a canned result and reads the body with the error
// discarded, which is right for testing status mapping and wrong for testing
// the transport ceiling: it answers 201 for a body the server never accepted.
// This one does the first thing SBOMIngestService.Ingest does — sbom.Parse(r) —
// so the cap is exercised where it actually lives.
type parsingIngester struct{ stubIngester }

func (p *parsingIngester) Ingest(_ context.Context, _, _, _ uuid.UUID, _ string, r io.Reader) (*services.SBOMIngestResult, error) {
	if _, err := sbom.Parse(r); err != nil {
		return nil, err
	}
	return sampleIngestResult(), nil
}

// An over-cap MULTIPART upload is a 413 naming the cap, not a 400 saying the
// form had no file.
//
// This is the path a BROWSER takes — the Upload SBOM page posts a file input —
// and it fails in a different place from the raw one. The MaxBytesReader trips
// while FormFile is still reading the envelope, so the document never reaches
// the parser and FormFile simply reports an error. Mapped as "no file part",
// that told a user whose form was perfectly well-formed that it was malformed,
// and left the real answer — "your document is bigger than 32 MiB" — unsaid.
func TestContract_UploadSbom_OverCapMultipartIs413(t *testing.T) {
	eng := newSBOMEngine(&stubIngester{result: sampleIngestResult()})

	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		part, err := mw.CreateFormFile("file", "big.cdx.json")
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		_, _ = io.Copy(part, &bigReader{left: maxSBOMUpload + 4096})
		_ = mw.Close()
		_ = pw.Close()
	}()

	req := httptest.NewRequest(http.MethodPost, sbomBase+"/sbom", pr)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%s", w.Code, w.Body.String())
	}
	// The body names the cap. "Too large" without a number is not something a
	// user can act on, and the same number has to come back from both paths.
	if !strings.Contains(w.Body.String(), "32 MiB") {
		t.Errorf("the refusal does not name the cap: %s", w.Body.String())
	}
}

// An over-cap RAW body is a 413 naming the same cap.
//
// It refuses in a different place: sbom.Parse reads at most MaxDocumentBytes+1
// itself and returns a LimitError, below the transport ceiling, so the
// MaxBytesReader never trips. Driven through the real parser rather than the
// canned stub, because a stub that discards the read error answers 201 for a
// body the server never accepted — which is what this test would otherwise
// prove.
func TestContract_UploadSbom_OverCapRawBodyIs413(t *testing.T) {
	eng := newSBOMEngine(&parsingIngester{})

	req := httptest.NewRequest(http.MethodPost, sbomBase+"/sbom", &bigReader{left: int64(sbom.MaxDocumentBytes) + 4096})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "32") {
		t.Errorf("the refusal does not name the cap: %s", w.Body.String())
	}
}

// A document at the documented maximum is ACCEPTED — the other polarity, and
// the one an over-strict ceiling breaks.
//
// The multipart ceiling is the cap PLUS an envelope allowance precisely so a
// document of exactly the documented size is not refused by the transport that
// carries it. Without the allowance this test fails while the one above still
// passes, which is the shape of an over-strict guard nobody notices.
func TestContract_UploadSbom_AtTheCapIsAccepted(t *testing.T) {
	eng := newSBOMEngine(&parsingIngester{})

	// Valid CycloneDX padded to exactly MaxDocumentBytes with whitespace, which
	// JSON ignores and the byte cap does not.
	head := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`
	padded := head + strings.Repeat(" ", sbom.MaxDocumentBytes-len(head))
	if len(padded) != sbom.MaxDocumentBytes {
		t.Fatalf("fixture is %d bytes, want exactly %d", len(padded), sbom.MaxDocumentBytes)
	}

	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	part, err := mw.CreateFormFile("file", "exact.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(part, padded); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, sbomBase+"/sbom", body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("a document of exactly the documented maximum was refused: status = %d, body=%s",
			w.Code, w.Body.String())
	}
}

// A body-too-large error that arrives WRAPPED as a malformed document is still
// a 413.
//
// readCapped wraps whatever io.ReadAll returns in ErrMalformed, so when the
// MaxBytesReader ceiling is reached during the parse the error satisfies
// errors.Is(err, sbom.ErrMalformed) — and a mapping that tests for that first
// answers 400 "Could not read this document" for a document whose only problem
// is its size. The user is told their file is corrupt.
//
// It is not reachable on the raw path with today's two constants, because the
// parser stops reading below the transport ceiling. That is a coincidence of
// numbers rather than a property of this mapping, so the ordering is pinned
// here: moving the too-large case back below the ErrMalformed branch fails this
// test.
func TestContract_UploadSbom_WrappedBodyTooLargeIsStill413(t *testing.T) {
	wrapped := fmt.Errorf("sbom: %w: read: %w", sbom.ErrMalformed,
		&http.MaxBytesError{Limit: maxSBOMUpload})

	eng := newSBOMEngine(&stubIngester{err: wrapped})
	w := do(eng, http.MethodPost, sbomBase+"/sbom", strings.NewReader("{}"))

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "32 MiB") {
		t.Errorf("the refusal does not name the cap: %s", w.Body.String())
	}

	// The other polarity: a genuinely malformed document is still a 400, not a
	// 413. A too-large test that swallowed every parse failure would pass the
	// assertion above and be useless.
	eng = newSBOMEngine(&stubIngester{err: fmt.Errorf("sbom: %w: unexpected end of JSON input", sbom.ErrMalformed)})
	w = do(eng, http.MethodPost, sbomBase+"/sbom", strings.NewReader("{}"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a malformed document = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

// The catalogue's `sort` vocabulary, in BOTH directions.
//
// `sort=eol_checked` ("least recently checked") shipped as a spec enum value, a
// generated TypeScript union member, and a `case` in
// `SBOMIngestService.ListProducts`. Those are three places and nothing held
// them together: the integration test pins the ORDERING the case produces and
// would stay green with the value missing from the spec, at which point the
// generated client no longer offers it and the column header sorts by a key
// TypeScript refuses. The reverse is worse — a value in the spec with no case
// 400s from a header the lens renders as sortable.
//
// So this reads the REAL spec and the REAL switch and requires them to agree.
func TestContract_SoftwareProducts_SortVocabularyMatchesTheService(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..")

	raw, err := os.ReadFile(filepath.Join(root, "api", "openapi", "inventory-service.openapi.yaml"))
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	var doc struct {
		Paths map[string]struct {
			Get struct {
				Parameters []struct {
					Name   string `yaml:"name"`
					Schema struct {
						Enum []string `yaml:"enum"`
					} `yaml:"schema"`
				} `yaml:"parameters"`
			} `yaml:"get"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	var specSorts []string
	for _, p := range doc.Paths["/software/products"].Get.Parameters {
		if p.Name == "sort" {
			specSorts = p.Schema.Enum
		}
	}
	if len(specSorts) == 0 {
		t.Fatal("the spec declares no `sort` enum for /software/products — every assertion below would be vacuous")
	}

	src, err := os.ReadFile(filepath.Join(root, "services", "inventory-service", "internal", "services", "sbom_ingest.go"))
	if err != nil {
		t.Fatalf("read sbom_ingest.go: %v", err)
	}
	body := string(src)
	start := strings.Index(body, "func (s *SBOMIngestService) ListProducts(")
	if start < 0 {
		t.Fatal("ListProducts not found in sbom_ingest.go — this test needs updating")
	}
	sw := body[start:]
	if end := strings.Index(sw, `return nil, 0, fmt.Errorf("unknown sort %q", sortKey)`); end > 0 {
		sw = sw[:end]
	}

	for _, want := range specSorts {
		// `name` is the default arm, spelled `case "", "name":`.
		if !strings.Contains(sw, `case "`+want+`"`) && !strings.Contains(sw, `, "`+want+`":`) {
			t.Errorf("the spec offers sort=%q and ListProducts has no case for it — the request 400s "+
				"from a column header the lens renders as sortable", want)
		}
	}
	for _, cs := range regexp.MustCompile(`case "([a-z_]*)"`).FindAllStringSubmatch(sw, -1) {
		key := cs[1]
		if key == "" {
			continue // the default arm
		}
		if !slices.Contains(specSorts, key) {
			t.Errorf("ListProducts accepts sort=%q but the spec's enum does not list it — the generated "+
				"client's union omits it, so no UI can ask for it", key)
		}
	}
}

// …and the handler passes the new key through rather than dropping it.
//
// `softwarePaging` silently defaults a bad limit, which is right for a number;
// doing the same to `sort` would answer a different question in name order and
// look like it worked.
func TestContract_GetSoftwareProducts_200_eolCheckedSortReachesTheService(t *testing.T) {
	sv := loadSpec(t)
	stub := &stubIngester{products: []services.SoftwareProductRow{}, prodTotal: 0}
	eng := newSBOMEngine(stub)

	w := do(eng, http.MethodGet, sbomBase+"/software/products?sort=eol_checked", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SoftwareProductListResponse", w.Body.Bytes())
	if stub.gotSort != "eol_checked" {
		t.Errorf("sort reached the service as %q, want %q — the freshness sort never leaves the handler",
			stub.gotSort, "eol_checked")
	}
}
