package catalogs

// The rule/lookup enricher, against in-memory catalogue rows.
//
// The matching rules are the whole substance of this implementation, so they
// are tested at the level they are written: which row answers which version,
// when a vendor disagreement excludes a row, and — the one that matters most —
// that a near miss produces NOTHING and a gap-list entry rather than the
// neighbouring cycle's date.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
	"github.com/vistasecurity/vistaplatform/shared/facts"
)

type stubLookupStore struct {
	rows    []EOLRow
	rowsErr error

	cpe      string
	cpeCVE   string
	cpeErr   error
	cpeCalls []string

	misses   []MissSubject
	missErr  error
	lastLook EOLLookup
}

func (s *stubLookupStore) LookupEOL(_ context.Context, q EOLLookup) ([]EOLRow, error) {
	s.lastLook = q
	return s.rows, s.rowsErr
}

func (s *stubLookupStore) LookupCPE(_ context.Context, vendor, product string) (string, string, error) {
	s.cpeCalls = append(s.cpeCalls, vendor+":"+product)
	return s.cpe, s.cpeCVE, s.cpeErr
}

func (s *stubLookupStore) RecordMiss(_ context.Context, m MissSubject) error {
	s.misses = append(s.misses, m)
	return s.missErr
}

func day(y int, m time.Month, d int) *time.Time {
	t := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	return &t
}

func ubuntuRows() []EOLRow {
	return []EOLRow{
		{ID: "row-2204", ProductKind: KindOS, Vendor: "Canonical", Product: "ubuntu", Cycle: "22.04",
			EOLDate: day(2027, time.April, 1), SourceURL: "https://endoflife.date/ubuntu"},
		{ID: "row-2404", ProductKind: KindOS, Vendor: "Canonical", Product: "ubuntu", Cycle: "24.04",
			EOLDate: day(2029, time.May, 31), SourceURL: "https://endoflife.date/ubuntu"},
	}
}

func TestLookupEnricher_HitReturnsTheCatalogueRowWithItsProvenance(t *testing.T) {
	store := &stubLookupStore{rows: ubuntuRows()}
	out, err := NewLookupEnricher(store).Enrich(context.Background(), seams.EnrichmentSubject{
		Class: "os", Vendor: "Canonical", Model: "Ubuntu", Version: "24.04.1 LTS",
	})
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("facts = %d, want 1: %+v", len(out), out)
	}
	f := out[0]
	if f.Key != facts.KeyEOLOSDate {
		t.Errorf("Key = %q, want %q", f.Key, facts.KeyEOLOSDate)
	}
	if f.Value != "2029-05-31" {
		t.Errorf("Value = %v, want the 24.04 date, not 22.04's", f.Value)
	}
	if f.SourceURL != "https://endoflife.date/ubuntu" {
		t.Errorf("SourceURL = %q", f.SourceURL)
	}

	// Provenance, all four fields. A lookup repeats an IMPORTED row; calling it
	// inferred would understate its provenance as badly as the reverse
	// overstates, and source_ref has to name the row so a disputed date is
	// traceable to the exact thing that said it.
	p := f.Provenance()
	if p.SourceKind != seams.SourceKindImported {
		t.Errorf("SourceKind = %q, want %q", p.SourceKind, seams.SourceKindImported)
	}
	if p.SourceRef != "catalog:eol:row-2404" {
		t.Errorf("SourceRef = %q, want the matched row's id", p.SourceRef)
	}
	if p.ModelID != "" {
		t.Errorf("ModelID = %q, want empty — no model was involved", p.ModelID)
	}
	if p.Confidence != 0 {
		t.Errorf("Confidence = %v, want 0 — a lookup made no estimate", p.Confidence)
	}
	if len(store.misses) != 0 {
		t.Errorf("recorded %d misses on a hit", len(store.misses))
	}
}

// The failure this implementation exists to avoid: answering a question about
// one release with a neighbouring release's date.
func TestLookupEnricher_NearMissReturnsNothingAndRecordsAGap(t *testing.T) {
	store := &stubLookupStore{rows: ubuntuRows()}
	out, err := NewLookupEnricher(store).Enrich(context.Background(), seams.EnrichmentSubject{
		Class: "os", Vendor: "Canonical", Model: "Ubuntu", Version: "25.10",
	})
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("facts = %+v, want none: 25.10 is not in the catalogue and 24.04's date is not its answer", out)
	}
	if len(store.misses) != 1 {
		t.Fatalf("misses = %d, want 1", len(store.misses))
	}
	got := store.misses[0]
	// The subject is recorded VERBATIM, not normalised: a reviewer has to see
	// what was actually asked, because a vendor-name mismatch is one of the
	// commonest causes of a miss and a normalised display would hide it.
	if got.Vendor != "Canonical" || got.Product != "Ubuntu" || got.Version != "25.10" {
		t.Errorf("miss = %+v, want the subject verbatim", got)
	}
	if got.Kind != KindOS {
		t.Errorf("miss kind = %q, want os", got.Kind)
	}
}

func TestLookupEnricher_CycleMatching(t *testing.T) {
	rows := []EOLRow{
		{ID: "exact", ProductKind: KindSoftware, Product: "nginx", Cycle: "1.27.3",
			EOLDate: day(2027, time.January, 1), SourceURL: "https://x/1"},
		{ID: "minor", ProductKind: KindSoftware, Product: "nginx", Cycle: "1.27",
			EOLDate: day(2027, time.February, 1), SourceURL: "https://x/2"},
		{ID: "major", ProductKind: KindSoftware, Product: "nginx", Cycle: "1",
			EOLDate: day(2027, time.March, 1), SourceURL: "https://x/3"},
	}
	cases := []struct {
		name    string
		version string
		wantRow string
	}{
		{"the whole version wins over major.minor", "1.27.3", "exact"},
		{"major.minor when the exact cycle is absent", "1.27.9", "minor"},
		{"major alone as the last resort", "1.99", "major"},
		{"trailing text is not part of the cycle", "1.27.3-alpine", "exact"},
		{"a version nothing matches is a miss", "2.0.1", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &stubLookupStore{rows: rows}
			out, err := NewLookupEnricher(store).Enrich(context.Background(), seams.EnrichmentSubject{
				Class: "software", Model: "nginx", Version: tc.version,
			})
			if err != nil {
				t.Fatalf("Enrich: %v", err)
			}
			if tc.wantRow == "" {
				if len(out) != 0 {
					t.Fatalf("facts = %+v, want none", out)
				}
				return
			}
			if len(out) != 1 {
				t.Fatalf("facts = %d, want 1", len(out))
			}
			if ref := out[0].Provenance().SourceRef; ref != "catalog:eol:"+tc.wantRow {
				t.Errorf("matched %q, want row %q", ref, tc.wantRow)
			}
		})
	}
}

// A leading zero is part of the cycle's NAME. Ubuntu's is "22.04"; a "tidy"
// numeric parse to 22.4 matches nothing, silently, forever.
func TestLookupEnricher_LeadingZerosSurviveTheCycleParse(t *testing.T) {
	store := &stubLookupStore{rows: ubuntuRows()}
	out, err := NewLookupEnricher(store).Enrich(context.Background(), seams.EnrichmentSubject{
		Class: "os", Model: "ubuntu", Version: "22.04.5",
	})
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(out) != 1 || out[0].Provenance().SourceRef != "catalog:eol:row-2204" {
		t.Fatalf("facts = %+v, want the 22.04 row", out)
	}
}

func TestLookupEnricher_VendorAgreement(t *testing.T) {
	rows := []EOLRow{
		{ID: "acme", ProductKind: KindHardware, Vendor: "Acme", Product: "switch 9000", Cycle: "1",
			EOLDate: day(2028, time.June, 1), SourceURL: "https://x/acme"},
		{ID: "unknown-vendor", ProductKind: KindHardware, Product: "router 100", Cycle: "1",
			EOLDate: day(2028, time.July, 1), SourceURL: "https://x/anon"},
	}
	cases := []struct {
		name     string
		vendor   string
		product  string
		wantHit  bool
		wantRow  string
		wantMiss bool
	}{
		{"both sides agree", "Acme", "switch 9000", true, "acme", false},
		{"a different vendor excludes the row", "Globex", "switch 9000", false, "", true},
		{"the caller not knowing a vendor cannot contradict one", "", "switch 9000", true, "acme", false},
		{"a catalogue row with no vendor cannot contradict one", "Acme", "router 100", true, "unknown-vendor", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Only the rows for the product under test, as the store's own
			// product predicate would return.
			var subset []EOLRow
			for _, r := range rows {
				if Normalize(r.Product) == Normalize(tc.product) {
					subset = append(subset, r)
				}
			}
			store := &stubLookupStore{rows: subset}
			out, err := NewLookupEnricher(store).Enrich(context.Background(), seams.EnrichmentSubject{
				Class: "hardware", Vendor: tc.vendor, Model: tc.product, Version: "1",
			})
			if err != nil {
				t.Fatalf("Enrich: %v", err)
			}
			if tc.wantHit {
				if len(out) != 1 {
					t.Fatalf("facts = %+v, want one", out)
				}
				if ref := out[0].Provenance().SourceRef; ref != "catalog:eol:"+tc.wantRow {
					t.Errorf("matched %q, want %q", ref, tc.wantRow)
				}
				if out[0].Key != facts.KeyEOLHWDate {
					t.Errorf("Key = %q, want %q", out[0].Key, facts.KeyEOLHWDate)
				}
			} else if len(out) != 0 {
				t.Fatalf("facts = %+v, want none", out)
			}
			if got := len(store.misses) > 0; got != tc.wantMiss {
				t.Errorf("recorded a miss = %v, want %v", got, tc.wantMiss)
			}
		})
	}
}

// An empty version resolves only when there is nothing to choose between.
func TestLookupEnricher_EmptyVersion(t *testing.T) {
	single := []EOLRow{{ID: "only", ProductKind: KindHardware, Vendor: "Acme", Product: "r650", Cycle: "all",
		EOLDate: day(2030, time.January, 1), SourceURL: "https://x/only"}}
	store := &stubLookupStore{rows: single}
	out, err := NewLookupEnricher(store).Enrich(context.Background(), seams.EnrichmentSubject{
		Class: "hardware", Vendor: "Acme", Model: "R650",
	})
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("one row and no version should resolve; got %+v", out)
	}

	two := append(single, EOLRow{ID: "second", ProductKind: KindHardware, Vendor: "Acme", Product: "r650",
		Cycle: "gen2", EOLDate: day(2032, time.January, 1), SourceURL: "https://x/second"})
	store2 := &stubLookupStore{rows: two}
	out2, err := NewLookupEnricher(store2).Enrich(context.Background(), seams.EnrichmentSubject{
		Class: "hardware", Vendor: "Acme", Model: "R650",
	})
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(out2) != 0 {
		t.Fatalf("two rows and no version is ambiguous, not a hit: %+v", out2)
	}
	if len(store2.misses) != 1 {
		t.Errorf("an ambiguous lookup is a gap; misses = %d", len(store2.misses))
	}
}

// "No end-of-life date published" is not a fact with a null value. The row
// matched; there is simply nothing to state.
func TestLookupEnricher_MatchedRowWithNoDateEmitsNoFact(t *testing.T) {
	store := &stubLookupStore{rows: []EOLRow{
		{ID: "dateless", ProductKind: KindOS, Product: "ubuntu", Cycle: "24.04",
			SourceURL: "https://endoflife.date/ubuntu"},
	}}
	out, err := NewLookupEnricher(store).Enrich(context.Background(), seams.EnrichmentSubject{
		Class: "os", Model: "ubuntu", Version: "24.04",
	})
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("facts = %+v, want none", out)
	}
}

// Cite or refuse binds the lookup exactly as it binds the model: a catalogue
// row with no source URL is one somebody hand-entered without evidence.
func TestLookupEnricher_UncitedRowEmitsNoFact(t *testing.T) {
	store := &stubLookupStore{rows: []EOLRow{
		{ID: "uncited", ProductKind: KindOS, Product: "ubuntu", Cycle: "24.04", EOLDate: day(2029, time.May, 31)},
	}}
	out, err := NewLookupEnricher(store).Enrich(context.Background(), seams.EnrichmentSubject{
		Class: "os", Model: "ubuntu", Version: "24.04",
	})
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("facts = %+v, want none from an uncited row", out)
	}
}

// Lookup answers the two questions the seam's []Fact cannot, and they are not
// derivable from each other.
//
// "The catalogue has never heard of this product" and "the catalogue has it and
// the upstream source publishes no date" both produce zero facts and are
// different answers with different fixes — and only the first is a gap. Reading
// `matched` off `len(facts) > 0` collapsed them, and made the console tell an
// operator their product had gone on the gap list when nothing had.
func TestLookupEnricher_MatchedIsAboutTheRowNotTheFact(t *testing.T) {
	subject := seams.EnrichmentSubject{Class: "os", Model: "ubuntu", Version: "24.04"}

	t.Run("a matched row that states nothing is matched, and not a gap", func(t *testing.T) {
		store := &stubLookupStore{rows: []EOLRow{
			{ID: "dateless", ProductKind: KindOS, Product: "ubuntu", Cycle: "24.04",
				SourceURL: "https://endoflife.date/ubuntu"},
		}}
		out, err := NewLookupEnricher(store).Lookup(context.Background(), subject)
		if err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		if len(out.Facts) != 0 {
			t.Fatalf("facts = %+v, want none", out.Facts)
		}
		if !out.Matched {
			t.Error("a row resolved; Matched must say so even though it stated nothing")
		}
		if out.MissRecorded {
			t.Error("a matched row is not a gap and must not be counted as one")
		}
		if len(store.misses) != 0 {
			t.Errorf("recorded %d misses for a product the catalogue has", len(store.misses))
		}
	})

	t.Run("nothing resolved is a gap, and says the gap was counted", func(t *testing.T) {
		store := &stubLookupStore{}
		out, err := NewLookupEnricher(store).Lookup(context.Background(), subject)
		if err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		if out.Matched {
			t.Error("nothing resolved; Matched must be false")
		}
		if !out.MissRecorded {
			t.Error("the gap was written, so MissRecorded must say so")
		}
	})

	t.Run("a gap the list refused is NOT reported as counted", func(t *testing.T) {
		// The console tells an operator their product went on the gap list.
		// Saying so when the write failed is a claim about something that did
		// not happen — the shape this whole feature is written against.
		store := &stubLookupStore{missErr: errors.New("disk full")}
		out, err := NewLookupEnricher(store).Lookup(context.Background(), subject)
		if err != nil {
			t.Fatalf("a bookkeeping failure must not fail the lookup: %v", err)
		}
		if out.Matched || out.MissRecorded {
			t.Errorf("out = %+v, want neither matched nor recorded", out)
		}
	})
}

func TestLookupEnricher_CPEIsResolvedOnlyFromAnExistingMatchRule(t *testing.T) {
	t.Run("a match rule yields a cited cpe fact", func(t *testing.T) {
		store := &stubLookupStore{
			cpe:    "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
			cpeCVE: "CVE-2022-3602",
		}
		out, err := NewLookupEnricher(store).Enrich(context.Background(), seams.EnrichmentSubject{
			Class: "software", Vendor: "OpenSSL", Model: "OpenSSL", Version: "3.0.6",
		})
		if err != nil {
			t.Fatalf("Enrich: %v", err)
		}
		var cpe *seams.Fact
		for i := range out {
			if out[i].Key == facts.KeySWCPE {
				cpe = &out[i]
			}
		}
		if cpe == nil {
			t.Fatalf("no sw.cpe fact in %+v", out)
		}
		if cpe.Value != "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*" {
			t.Errorf("Value = %v", cpe.Value)
		}
		if cpe.SourceURL != "https://nvd.nist.gov/vuln/detail/CVE-2022-3602" {
			t.Errorf("SourceURL = %q, want the CVE's own page", cpe.SourceURL)
		}
		if ref := cpe.Provenance().SourceRef; ref != "catalog:vulnerability_match:CVE-2022-3602" {
			t.Errorf("SourceRef = %q", ref)
		}
	})

	t.Run("no match rule means no cpe, not a constructed one", func(t *testing.T) {
		store := &stubLookupStore{}
		out, err := NewLookupEnricher(store).Enrich(context.Background(), seams.EnrichmentSubject{
			Class: "software", Vendor: "Obscure Co", Model: "widget",
		})
		if err != nil {
			t.Fatalf("Enrich: %v", err)
		}
		for _, f := range out {
			if f.Key == facts.KeySWCPE {
				t.Fatalf("constructed a CPE with no match rule behind it: %v", f.Value)
			}
		}
	})

	t.Run("a match with no CVE id cannot be cited, so there is no fact", func(t *testing.T) {
		store := &stubLookupStore{cpe: "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*", cpeCVE: "GHSA-xxxx"}
		out, err := NewLookupEnricher(store).Enrich(context.Background(), seams.EnrichmentSubject{
			Class: "software", Vendor: "x", Model: "y",
		})
		if err != nil {
			t.Fatalf("Enrich: %v", err)
		}
		for _, f := range out {
			if f.Key == facts.KeySWCPE {
				t.Fatalf("emitted an uncitable CPE fact: %+v", f)
			}
		}
	})
}

// A store failure is an error about the DATABASE. Swallowing it would report
// "the catalogue does not know" for a product the catalogue may know perfectly
// well, which is the difference this whole codebase keeps paying for.
func TestLookupEnricher_StoreErrorIsReturnedNotSwallowed(t *testing.T) {
	store := &stubLookupStore{rowsErr: errors.New("connection refused")}
	if _, err := NewLookupEnricher(store).Enrich(context.Background(), seams.EnrichmentSubject{
		Class: "os", Model: "ubuntu", Version: "24.04",
	}); err == nil {
		t.Fatal("want an error when the lookup query fails")
	}
	if len(store.misses) != 0 {
		t.Error("a database failure is not a catalogue gap and must not be recorded as one")
	}
}

// A subject with no product name is a caller with nothing to ask, not a gap.
// Counting it would put noise at the top of the list the model works from.
func TestLookupEnricher_EmptyProductAsksAndRecordsNothing(t *testing.T) {
	store := &stubLookupStore{rows: ubuntuRows()}
	out, err := NewLookupEnricher(store).Enrich(context.Background(), seams.EnrichmentSubject{Class: "os"})
	if err != nil || len(out) != 0 {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	if len(store.misses) != 0 || len(store.cpeCalls) != 0 {
		t.Errorf("touched the store for an empty subject: misses=%d cpe=%d", len(store.misses), len(store.cpeCalls))
	}
}

// An unrecognised class searches every kind and lets the MATCHED row decide the
// fact key, rather than being placed wrongly before looking.
func TestLookupEnricher_UnknownClassSearchesEveryKind(t *testing.T) {
	store := &stubLookupStore{rows: []EOLRow{
		{ID: "hw", ProductKind: KindHardware, Product: "catalyst 9300", Cycle: "1",
			EOLDate: day(2030, time.October, 31), SourceURL: "https://x/c9300"},
	}}
	out, err := NewLookupEnricher(store).Enrich(context.Background(), seams.EnrichmentSubject{
		Class: "network_switch", Model: "Catalyst 9300", Version: "1",
	})
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if store.lastLook.Kind != "" {
		t.Errorf("Kind = %q, want an unfiltered search", store.lastLook.Kind)
	}
	if len(out) != 1 || out[0].Key != facts.KeyEOLHWDate {
		t.Fatalf("facts = %+v, want eol.hw.date from the matched row's kind", out)
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"  Ubuntu  ":      "ubuntu",
		"Red_Hat":         "red hat",
		"Red   Hat":       "red hat",
		"IOS-XE":          "ios-xe",
		"":                "",
		"   ":             "",
		"Windows Server ": "windows server",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}
