package catalogfeeds

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

func seededStore(t *testing.T) *memStore {
	t.Helper()
	store := newMemStore()
	eol := time.Date(2029, 5, 31, 0, 0, 0, 0, time.UTC)
	if _, err := store.UpsertEOL(context.Background(), []EOLEntry{
		{ProductKind: KindOS, Vendor: ptr("Canonical"), Product: "ubuntu", Cycle: "24.04",
			EOLDate: &eol, SourceURL: ptr("https://endoflife.date/ubuntu"), SourceKind: "imported"},
		{ProductKind: KindSoftware, Product: "nginx", Cycle: "1.24", SourceKind: "imported"},
	}); err != nil {
		t.Fatalf("seed eol: %v", err)
	}
	published := time.Date(2024, 3, 29, 17, 15, 21, 0, time.UTC)
	if _, _, err := store.UpsertVulnerabilities(context.Background(), []Vulnerability{
		{
			CVEID: "CVE-2024-3094", CVSSVersion: ptr("3.1"), CVSSScore: ptr(10.0),
			CVSSVector: ptr("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
			Severity:   ptr(SeverityCritical), PublishedAt: &published,
			Description: ptr("Malicious code in xz."), SourceKind: "imported",
			Matches: []VulnerabilityMatch{
				{CPEMatch: ptr(`{"cpe":"cpe:2.3:a:tukaani:xz:5.6.0:*:*:*:*:*:*:*"}`)},
				{PURLRange: ptr(`{"purl":"pkg:deb/debian/xz-utils","fixed":"5.6.2"}`)},
			},
		},
		{CVEID: "CVE-2023-0001", Severity: ptr(SeverityMedium), SourceKind: "imported"},
	}); err != nil {
		t.Fatalf("seed vulns: %v", err)
	}
	return store
}

func TestBundle_roundTripRestoresEveryRow(t *testing.T) {
	source := seededStore(t)
	var buf bytes.Buffer
	manifest, err := BuildBundle(context.Background(), source, &buf)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(manifest.Files) != 3 {
		t.Fatalf("manifest lists %d files, want 3 (attribution + two catalogues)", len(manifest.Files))
	}
	for _, f := range manifest.Files {
		if len(f.SHA256) != 64 {
			t.Fatalf("%s: sha256 %q is not a hex digest", f.Name, f.SHA256)
		}
	}

	target := newMemStore()
	res, err := ImportBundle(context.Background(), target, bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if res.EOLRows != 2 || res.VulnerabilityRows != 2 {
		t.Fatalf("imported eol=%d vulns=%d, want 2 and 2", res.EOLRows, res.VulnerabilityRows)
	}
	if res.MatchRows != 2 {
		t.Fatalf("imported %d match rules, want 2", res.MatchRows)
	}

	before, err := source.ExportAll(context.Background())
	if err != nil {
		t.Fatalf("export source: %v", err)
	}
	after, err := target.ExportAll(context.Background())
	if err != nil {
		t.Fatalf("export target: %v", err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("round trip lost or changed rows:\n before = %+v\n after  = %+v", before, after)
	}
}

// The whole point of the manifest: two exports of the same data must produce
// the same hashes, or "did this file change on the way across the gap" is
// unanswerable.
func TestBundle_exportIsDeterministic(t *testing.T) {
	source := seededStore(t)
	var a, b bytes.Buffer
	ma, err := BuildBundle(context.Background(), source, &a)
	if err != nil {
		t.Fatalf("build a: %v", err)
	}
	mb, err := BuildBundle(context.Background(), source, &b)
	if err != nil {
		t.Fatalf("build b: %v", err)
	}
	for i := range ma.Files {
		if ma.Files[i].SHA256 != mb.Files[i].SHA256 {
			t.Fatalf("%s hashed differently across two exports of the same data", ma.Files[i].Name)
		}
		if ma.Files[i].Rows != mb.Files[i].Rows {
			t.Fatalf("%s row count differed across two exports", ma.Files[i].Name)
		}
	}
}

// makeBundle writes an arbitrary tarball so the verification failures can be
// provoked directly rather than by hoping a mutation lands somewhere useful.
func makeBundle(t *testing.T, manifest any, files map[string][]byte, order []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	write := func(name string, body []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Format: tar.FormatPAX}); err != nil {
			t.Fatalf("header %s: %v", name, err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if manifest != nil {
		raw, err := json.Marshal(manifest)
		if err != nil {
			t.Fatalf("marshal manifest: %v", err)
		}
		write(ManifestName, raw)
	}
	for _, name := range order {
		write(name, files[name])
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

func eolLine(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(EOLEntry{ProductKind: KindOS, Product: "ubuntu", Cycle: "24.04", SourceKind: "imported"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return append(raw, '\n')
}

// A corrupt payload must be caught BEFORE anything is written. A half-imported
// catalogue behind a corruption error is the failure mode an air-gap transfer is
// most likely to hit.
func TestBundle_import_rejectsHashMismatchBeforeWritingAnything(t *testing.T) {
	body := eolLine(t)
	manifest := BundleManifest{
		Format: BundleFormat, Version: BundleVersion, GeneratedAt: time.Now().UTC(),
		Files: []BundleFile{
			{Name: EOLFileName, SHA256: strings.Repeat("0", 64), Rows: 1, Bytes: int64(len(body))},
		},
	}
	raw := makeBundle(t, manifest, map[string][]byte{EOLFileName: body}, []string{EOLFileName})

	target := newMemStore()
	_, err := ImportBundle(context.Background(), target, bytes.NewReader(raw))
	if err == nil {
		t.Fatal("a sha256 mismatch must fail the import")
	}
	if !strings.Contains(err.Error(), "sha256 mismatch") || !strings.Contains(err.Error(), EOLFileName) {
		t.Fatalf("the error must name the check and the file, got %v", err)
	}
	if target.countEOL() != 0 {
		t.Fatalf("%d rows were applied before verification failed — verification must come first", target.countEOL())
	}
}

// The row count is a second, independent check: a truncation that happened to
// keep a valid hash is not a thing, but a manifest edited by hand is.
func TestBundle_import_rejectsRowCountMismatch(t *testing.T) {
	body := eolLine(t)
	manifest := BundleManifest{
		Format: BundleFormat, Version: BundleVersion, GeneratedAt: time.Now().UTC(),
		Files: []BundleFile{{Name: EOLFileName, SHA256: sha256Hex(body), Rows: 99, Bytes: int64(len(body))}},
	}
	raw := makeBundle(t, manifest, map[string][]byte{EOLFileName: body}, []string{EOLFileName})

	target := newMemStore()
	_, err := ImportBundle(context.Background(), target, bytes.NewReader(raw))
	if err == nil || !strings.Contains(err.Error(), "99 rows") {
		t.Fatalf("a row-count mismatch must fail with the declared count, got %v", err)
	}
	if target.countEOL() != 0 {
		t.Fatal("nothing may be applied when the manifest disagrees with the payload")
	}
}

// A file the manifest does not list is unverified content. Applying it would
// make the manifest a suggestion rather than a contract.
func TestBundle_import_rejectsUnlistedFile(t *testing.T) {
	body := eolLine(t)
	manifest := BundleManifest{
		Format: BundleFormat, Version: BundleVersion, GeneratedAt: time.Now().UTC(),
		Files: []BundleFile{},
	}
	raw := makeBundle(t, manifest, map[string][]byte{EOLFileName: body}, []string{EOLFileName})

	_, err := ImportBundle(context.Background(), newMemStore(), bytes.NewReader(raw))
	if err == nil || !strings.Contains(err.Error(), "manifest does not list") {
		t.Fatalf("an unlisted file must be refused, got %v", err)
	}
}

func TestBundle_import_rejectsMissingFile(t *testing.T) {
	manifest := BundleManifest{
		Format: BundleFormat, Version: BundleVersion, GeneratedAt: time.Now().UTC(),
		Files: []BundleFile{{Name: VulnFileName, SHA256: strings.Repeat("a", 64), Rows: 0}},
	}
	raw := makeBundle(t, manifest, nil, nil)

	_, err := ImportBundle(context.Background(), newMemStore(), bytes.NewReader(raw))
	if err == nil || !strings.Contains(err.Error(), "does not contain it") {
		t.Fatalf("a manifest entry with no payload must be refused, got %v", err)
	}
}

func TestBundle_import_rejectsMissingManifest(t *testing.T) {
	raw := makeBundle(t, nil, map[string][]byte{EOLFileName: eolLine(t)}, []string{EOLFileName})
	_, err := ImportBundle(context.Background(), newMemStore(), bytes.NewReader(raw))
	if err == nil || !strings.Contains(err.Error(), ManifestName) {
		t.Fatalf("a bundle with no manifest must be refused, got %v", err)
	}
}

func TestBundle_import_rejectsForeignFormatAndFutureVersion(t *testing.T) {
	raw := makeBundle(t, map[string]any{"format": "something-else", "version": 1}, nil, nil)
	if _, err := ImportBundle(context.Background(), newMemStore(), bytes.NewReader(raw)); err == nil ||
		!strings.Contains(err.Error(), BundleFormat) {
		t.Fatalf("a foreign format must be refused, got %v", err)
	}

	raw = makeBundle(t, map[string]any{"format": BundleFormat, "version": BundleVersion + 1}, nil, nil)
	if _, err := ImportBundle(context.Background(), newMemStore(), bytes.NewReader(raw)); err == nil ||
		!strings.Contains(err.Error(), "not supported by this release") {
		t.Fatalf("a newer format version must be refused rather than guessed at, got %v", err)
	}
}

func TestBundle_import_rejectsNonGzipAndEmpty(t *testing.T) {
	if _, err := ImportBundle(context.Background(), newMemStore(), strings.NewReader("")); err == nil ||
		!strings.Contains(err.Error(), "empty") {
		t.Fatalf("an empty upload must be refused, got %v", err)
	}
	if _, err := ImportBundle(context.Background(), newMemStore(), strings.NewReader("plain text")); err == nil ||
		!strings.Contains(err.Error(), "gzip") {
		t.Fatalf("a non-gzip upload must be refused, got %v", err)
	}
}

// A path-shaped entry name says the file is not one of ours.
func TestBundle_import_rejectsNestedEntryNames(t *testing.T) {
	raw := makeBundle(t, nil, map[string][]byte{"../escape.jsonl": eolLine(t)}, []string{"../escape.jsonl"})
	_, err := ImportBundle(context.Background(), newMemStore(), bytes.NewReader(raw))
	if err == nil || !strings.Contains(err.Error(), "flat file name") {
		t.Fatalf("a nested entry name must be refused, got %v", err)
	}
}

// Re-importing the same bundle must leave the catalogue where it was.
func TestBundle_importIsIdempotent(t *testing.T) {
	var buf bytes.Buffer
	if _, err := BuildBundle(context.Background(), seededStore(t), &buf); err != nil {
		t.Fatalf("build: %v", err)
	}
	target := newMemStore()
	for i := range 2 {
		if _, err := ImportBundle(context.Background(), target, bytes.NewReader(buf.Bytes())); err != nil {
			t.Fatalf("import %d: %v", i, err)
		}
	}
	if target.countEOL() != 2 || target.countVulns() != 2 {
		t.Fatalf("double import changed the catalogue: eol=%d vulns=%d", target.countEOL(), target.countVulns())
	}
	if target.countMatches("CVE-2024-3094") != 2 {
		t.Fatalf("double import duplicated match rules: %d", target.countMatches("CVE-2024-3094"))
	}
}

// The reported match count must be what the DATABASE wrote, not what the file
// listed. Match rules are INSERT … DO NOTHING, so the second import of the same
// bundle writes none — and reporting the file's count there tells an operator
// tens of thousands of rules were imported when nothing changed.
func TestBundle_import_reportsMatchRowsActuallyWrittenNotRulesInFile(t *testing.T) {
	var buf bytes.Buffer
	if _, err := BuildBundle(context.Background(), seededStore(t), &buf); err != nil {
		t.Fatalf("build: %v", err)
	}
	target := newMemStore()

	first, err := ImportBundle(context.Background(), target, bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("first import: %v", err)
	}
	if first.MatchRows != 2 {
		t.Fatalf("first import wrote %d match rules, want 2", first.MatchRows)
	}

	second, err := ImportBundle(context.Background(), target, bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("second import: %v", err)
	}
	if second.MatchRows != 0 {
		t.Fatalf("re-import reported %d match rules written; DO NOTHING wrote none, so it must report 0",
			second.MatchRows)
	}
	// The CVE and EOL counters are the OTHER case and must not be "fixed" to
	// match: those statements are ON CONFLICT DO UPDATE, so a re-import does
	// affect every row, and reporting 0 would read as a feed that had stopped
	// working.
	if second.VulnerabilityRows != 2 || second.EOLRows != 2 {
		t.Fatalf("re-import reported eol=%d vulns=%d; DO UPDATE affects every row, so both stay 2",
			second.EOLRows, second.VulnerabilityRows)
	}
}

// The line reader must REPORT an oversize line, not silently stop — the
// bufio.Scanner default would turn a malformed bundle into a short, successful
// import.
func TestEachJSONLine_reportsOversizeLine(t *testing.T) {
	long := bytes.Repeat([]byte("x"), maxJSONLineBytes+10)
	err := eachJSONLine(bytes.NewReader(long), func([]byte) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Fatalf("an oversize line must be an error, got %v", err)
	}
}

func TestEachJSONLine_skipsBlankLinesAndFinalWithoutNewline(t *testing.T) {
	var seen int
	err := eachJSONLine(strings.NewReader("{\"a\":1}\n\n\n{\"b\":2}"), func(b []byte) error {
		seen++
		if len(b) == 0 {
			t.Fatal("a blank line should have been skipped")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if seen != 2 {
		t.Fatalf("read %d lines, want 2 (a trailing line with no newline still counts)", seen)
	}
}

// tarEntry is an ORDERED archive member, so the same name can appear twice —
// which a map-keyed helper cannot express and which is exactly the case the
// verification has to refuse.
type tarEntry struct {
	name string
	body []byte
}

func makeRawBundle(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Format: tar.FormatPAX}); err != nil {
			t.Fatalf("header %s: %v", e.name, err)
		}
		if _, err := tw.Write(e.body); err != nil {
			t.Fatalf("write %s: %v", e.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

// A second member under the same name overwrote the first's digest in the verify
// pass while applyPass — which does not stop at the first match — applied BOTH.
// A bundle shaped [tampered, genuine] therefore verified against the genuine
// copy and imported the tampered one, defeating the manifest entirely. That is
// the one thing this format exists to provide, so the case is pinned.
func TestBundle_import_rejectsDuplicateEntryNames(t *testing.T) {
	good := eolLine(t)
	smuggled, err := json.Marshal(EOLEntry{
		ProductKind: KindOS, Product: "smuggled-past-the-manifest", Cycle: "9.9", SourceKind: "imported",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	smuggled = append(smuggled, '\n')

	// The manifest describes ONLY the genuine payload.
	raw, err := json.Marshal(BundleManifest{
		Format: BundleFormat, Version: BundleVersion, GeneratedAt: time.Now().UTC(),
		Files: []BundleFile{{Name: EOLFileName, SHA256: sha256Hex(good), Rows: 1, Bytes: int64(len(good))}},
	})
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	body := makeRawBundle(t, []tarEntry{
		{ManifestName, raw},
		{EOLFileName, smuggled}, // unverified — applied first, before the fix
		{EOLFileName, good},     // genuine — the copy the manifest describes
	})

	store := newMemStore()
	_, err = ImportBundle(context.Background(), store, bytes.NewReader(body))
	if err == nil {
		t.Fatalf("a duplicate entry name must be refused; it imported %d rows instead", store.countEOL())
	}
	if !strings.Contains(err.Error(), "more than one entry named") {
		t.Fatalf("want a duplicate-name refusal, got %v", err)
	}
	if store.countEOL() != 0 {
		t.Fatalf("nothing may be written when verification refuses the bundle, got %d rows", store.countEOL())
	}
}

// The cap on the COMPRESSED upload does not bound the DECOMPRESSED member count:
// tar headers compress to almost nothing and the verify pass keeps a map entry
// per member.
func TestBundle_import_rejectsTooManyEntries(t *testing.T) {
	entries := make([]tarEntry, 0, maxBundleEntries+2)
	for i := range maxBundleEntries + 2 {
		entries = append(entries, tarEntry{fmt.Sprintf("filler-%d.jsonl", i), []byte("{}\n")})
	}
	_, err := ImportBundle(context.Background(), newMemStore(), bytes.NewReader(makeRawBundle(t, entries)))
	if err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("an archive with too many members must be refused, got %v", err)
	}
}

// A failure AFTER verification is not "the bundle was refused": rows are already
// in the catalogue. The console renders a different sentence for each, so the two
// must be distinguishable at the error rather than merged into one 400.
func TestBundle_import_applyFailureIsDistinguishableFromARefusal(t *testing.T) {
	var buf bytes.Buffer
	if _, err := BuildBundle(context.Background(), seededStore(t), &buf); err != nil {
		t.Fatalf("build: %v", err)
	}
	target := newMemStore()
	target.upsertVulnErr = errors.New("connection reset by peer")

	_, err := ImportBundle(context.Background(), target, bytes.NewReader(buf.Bytes()))
	if err == nil {
		t.Fatal("an apply failure must be reported")
	}
	if !errors.Is(err, ErrBundleApplyFailed) {
		t.Fatalf("an apply failure must be distinguishable from a verification refusal, got %v", err)
	}
	// It must also SAY what got through — "nothing was applied" is false here.
	if !strings.Contains(err.Error(), "2 end-of-life rows") {
		t.Fatalf("the error must name the rows already written, got %v", err)
	}
	if target.countEOL() == 0 {
		t.Fatal("the premise of this test is that rows landed before the failure")
	}

	// A verification refusal, by contrast, must NOT carry the marker.
	refused := makeBundle(t, BundleManifest{
		Format: BundleFormat, Version: BundleVersion, GeneratedAt: time.Now().UTC(),
		Files: []BundleFile{{Name: EOLFileName, SHA256: strings.Repeat("0", 64), Rows: 1}},
	}, map[string][]byte{EOLFileName: eolLine(t)}, []string{EOLFileName})
	_, err = ImportBundle(context.Background(), newMemStore(), bytes.NewReader(refused))
	if err == nil || errors.Is(err, ErrBundleApplyFailed) {
		t.Fatalf("a hash mismatch is a refusal, not a partial apply, got %v", err)
	}
}

// The attribution travels WITH the data. A bundle is a file an operator carries
// across an air gap and may hand on; a NOTICE that stays in the repository does
// not reach whoever ends up holding the tarball. Owner decision.
//
// Mutation: delete the AttributionFileName entry from BuildBundle's manifest or
// its tar entry and this test goes red - the manifest/member cross-check in
// verifyPass makes a half-removal an import refusal rather than a silent pass.
func TestBundle_carriesUpstreamAttributionWithTheData(t *testing.T) {
	var buf bytes.Buffer
	manifest, err := BuildBundle(context.Background(), seededStore(t), &buf)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	var listed *BundleFile
	for i := range manifest.Files {
		if manifest.Files[i].Name == AttributionFileName {
			listed = &manifest.Files[i]
		}
	}
	if listed == nil {
		t.Fatalf("manifest does not list %s; it lists %+v", AttributionFileName, manifest.Files)
	}

	body, ok := bundleMember(t, buf.Bytes(), AttributionFileName)
	if !ok {
		t.Fatalf("bundle has no %s member", AttributionFileName)
	}
	if got := string(body); got != BundleAttribution {
		t.Fatalf("%s member is not BundleAttribution:\n%s", AttributionFileName, got)
	}

	// The obligations the owner's decision recorded. Each is a
	// separate check so a reworded file that drops one fails on that one.
	for _, want := range []string{
		"not endorsed or\n  certified by the NVD",
		"CC-BY-4.0",
		"https://osv.dev",
		"endoflife.date",
	} {
		if !strings.Contains(BundleAttribution, want) {
			t.Errorf("attribution text does not state %q", want)
		}
	}

	// And it must not break the importer: an unknown member is ignored by the
	// apply pass but still cross-checked by the verify pass.
	target := newMemStore()
	if _, err := ImportBundle(context.Background(), target, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("import a bundle carrying attribution: %v", err)
	}
}

func bundleMember(t *testing.T, bundle []byte, name string) ([]byte, bool) {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(bundle))
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err != nil {
			return nil, false
		}
		if hdr.Name != name {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return body, true
	}
}
