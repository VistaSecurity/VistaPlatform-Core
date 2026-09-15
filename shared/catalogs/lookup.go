package catalogs

// The rule/lookup default behind BOTH the Enricher seam (ADR-0008 D1, the
// "null / rule-based default" column: *static catalogue lookups*) and the `eol`
// finding producer (ADR-0005 D3, workstream 3.3 part 2).
//
// It is not a stub and it is not an AI. It reads `eol_catalogue` and
// `vulnerability_matches` — rows a mirror job imported or an operator curated —
// and returns what it finds, with the row that said it. It makes no network
// call, needs no provider, and runs in every edition. A deployment with AI
// switched off gets exactly this, and it is the only enricher most deployments
// will ever run.
//
// # What it will not do
//
// It will not return the nearest row. "Ubuntu 22.04" does not answer a question
// about "Ubuntu 24.04", and a lookup that falls back to a neighbouring cycle
// produces a support date that is wrong in the direction of reassurance. A
// question it cannot answer exactly is recorded on the gap list and answered
// with nothing.
//
// It will not derive a date from a version number, a release cadence, or the
// dates of adjacent cycles. Those are inferences, and an inference made in Go
// is no more measured than one made by a model — it just has no model id on it
// to warn a reader.

import (
	"context"
	"fmt"
	"log"
	"strings"
	"unicode"

	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
	"github.com/vistasecurity/vistaplatform/shared/facts"
)

// logger is the package's log sink.
var logger = log.New(log.Writer(), "[catalogs] ", log.LstdFlags)

// ImplLookup is the implementation name the rule/lookup enricher registers
// under. It is a real, selectable implementation rather than the `none` null
// default: `none` means "no proposals at all", and this one genuinely answers.
const ImplLookup = "catalog-lookup"

// LookupStore is every database touch the lookup enricher makes. An interface
// so the whole matching layer — normalisation, vendor agreement, cycle
// selection — is tested against in-memory rows, and the SQL is tested
// separately against a real Postgres.
type LookupStore interface {
	// LookupEOL returns every catalogue row for a product, across cycles. The
	// cycle is chosen in Go rather than in SQL because choosing it is the part
	// with rules in it, and rules belong where they can be read.
	LookupEOL(ctx context.Context, q EOLLookup) ([]EOLRow, error)

	// LookupCPE returns the CPE 2.3 name an advisory already uses for this
	// vendor:product, and the CVE that uses it. Empty cpe means no advisory in
	// this deployment's mirror names the product — which is an answer, not a
	// reason to construct one.
	LookupCPE(ctx context.Context, vendor, product string) (cpe string, cveID string, err error)

	// RecordMiss counts one unanswerable lookup on the gap list.
	RecordMiss(ctx context.Context, m MissSubject) error
}

// LookupEnricher is the Core [seams.Enricher].
type LookupEnricher struct {
	store LookupStore
}

// NewLookupEnricher builds the rule/lookup enricher over store.
func NewLookupEnricher(store LookupStore) *LookupEnricher {
	return &LookupEnricher{store: store}
}

var _ seams.Enricher = (*LookupEnricher)(nil)

// LookupResult is the whole answer to "what does the platform know about this
// product" — the facts, plus the two things a `[]Fact` cannot say.
//
// They are three different questions and the console has to tell them apart:
//
//   - **Facts** — what can be stated, with provenance.
//   - **Matched** — a catalogue row resolved for this subject, whether or not
//     it yielded a fact. A row whose `eol_date` is NULL, or which carries no
//     source_url, MATCHES and produces nothing: "the catalogue has never heard
//     of this product" and "the catalogue has it and publishes no date" are
//     different facts with different fixes, and only the second means the gap
//     list is the wrong place to look.
//   - **MissRecorded** — nothing resolved AND the gap was counted. Kept
//     separate because the console tells an operator their product went on the
//     gap list, and a message that says so when the write failed is a claim
//     about something that did not happen.
type LookupResult struct {
	Facts        []seams.Fact
	Matched      bool
	MissRecorded bool
}

// Enrich resolves a subject against the platform catalogues.
//
// Returns nil, nil when nothing resolves — the honest empty answer, identical
// in shape to [seams.NullEnricher]'s, which is what makes "a caller that
// handles the null default handles a real one" true here. A store error is
// returned rather than swallowed: "the database is down" and "the catalogue
// does not know" are different facts and only one of them is about the product.
//
// This is the SEAM, and the seam's shape is `[]Fact`. A caller that needs to
// tell an empty answer's three causes apart calls [LookupEnricher.Lookup]
// instead — the same split the gap pass makes between [seams.Enricher] and
// [Proposer], and for the same reason: the interface is the contract, and the
// richer thing beside it is what a particular consumer needs.
func (e *LookupEnricher) Enrich(ctx context.Context, subject seams.EnrichmentSubject) ([]seams.Fact, error) {
	out, err := e.Lookup(ctx, subject)
	return out.Facts, err
}

// Lookup is Enrich, with the two answers the seam's signature cannot carry.
func (e *LookupEnricher) Lookup(ctx context.Context, subject seams.EnrichmentSubject) (LookupResult, error) {
	var out LookupResult

	res, err := e.ResolveEOL(ctx, subject)
	if err != nil {
		return LookupResult{}, err
	}
	// Matched is set from the ROW, not from whether a fact came out of it.
	// Deriving it from len(facts) would collapse the distinction this field
	// exists to make — and the console would tell an operator their product had
	// gone on the gap list when nothing had.
	out.Matched = res.Row != nil
	out.MissRecorded = res.MissRecorded
	if res.Row != nil {
		if f, ok := EOLFact(*res.Row); ok {
			out.Facts = append(out.Facts, f)
		}
	}

	product := normalize(subject.Model)
	if product == "" {
		return out, nil
	}
	// CPE resolution is independent of the EOL answer: a product can be in an
	// advisory's match rules and absent from the lifecycle catalogue, and vice
	// versa. Running it only on an EOL hit would make the sw.cpe fact appear
	// and disappear for reasons that have nothing to do with CPEs.
	if cpe, cveID, err := e.store.LookupCPE(ctx, normalize(subject.Vendor), product); err != nil {
		return LookupResult{}, fmt.Errorf("catalogs: cpe lookup for %q: %w", product, err)
	} else if f, ok := cpeFact(cpe, cveID); ok {
		out.Facts = append(out.Facts, f)
	}

	return out, nil
}

// Resolution is what the catalogue had to say about one subject.
//
// Row is nil when nothing resolved — and nil is the ONLY way this package says
// "I do not know". It never carries a neighbouring cycle, and it never carries
// a row it is unsure about with a confidence beside it.
type Resolution struct {
	// Row is the catalogue row that answers this subject, or nil.
	Row *EOLRow
	// MissRecorded is true when nothing resolved AND the gap was counted on
	// catalog_lookup_misses. Kept separate from `Row == nil` because the write
	// can fail, and a caller telling an operator their product went on the gap
	// list when it did not is a claim about something that never happened.
	MissRecorded bool
}

// ResolveEOL resolves one subject to a catalogue row, or records the gap.
//
// This is THE resolution — [LookupEnricher.Lookup] turns its answer into facts
// for the Enricher seam, and the `eol` finding producer reads the row directly
// so its finding can cite the row id and the source URL. Both call this, which
// is what makes "the date on the asset page and the end-of-life finding beside
// it came from the same row" true by construction rather than by review.
func (e *LookupEnricher) ResolveEOL(ctx context.Context, subject seams.EnrichmentSubject) (Resolution, error) {
	product := normalize(subject.Model)
	if product == "" {
		// Nothing to look up and nothing to record: a subject with no product
		// name is not a gap in the catalogue, it is a caller with nothing to
		// ask. Counting it would put noise at the top of the list the
		// generative pass works from.
		return Resolution{}, nil
	}
	vendor := normalize(subject.Vendor)
	kind := kindFor(subject.Class)

	rows, err := e.store.LookupEOL(ctx, EOLLookup{Kind: kind, Vendor: vendor, Product: product})
	if err != nil {
		return Resolution{}, fmt.Errorf("catalogs: eol lookup for %q: %w", product, err)
	}
	if row, ok := selectCycle(rows, vendor, subject.Version); ok {
		return Resolution{Row: &row}, nil
	}

	var out Resolution
	if err := e.store.RecordMiss(ctx, MissSubject{
		Kind: missKind(kind), Vendor: subject.Vendor, Product: subject.Model, Version: subject.Version,
	}); err != nil {
		// A gap list that cannot be written is a smaller problem than a lookup
		// that fails, and failing the enrichment over it would turn a
		// bookkeeping error into "this asset has no EOL data". Logged by the
		// caller through the returned error only when the LOOKUP failed.
		lookupLogf("could not record a catalogue miss for %q: %v", product, err)
	} else {
		out.MissRecorded = true
	}
	return out, nil
}

// EOLFact turns a catalogue row into the fact for its product kind.
//
// A row with no eol_date yields NOTHING. endoflife.date publishes `true` for
// "support has ended, date unknown" and `false` for "not announced", and the
// mirror stores both as NULL rather than inventing a date — so there is no date
// to state, and stating the absence as a fact with a null value would put a
// hole in `asset_facts` that reads like a measurement of nothing.
//
// A row with no source_url likewise yields nothing: D4.4 is cite or refuse, and
// it binds the lookup exactly as it binds the model. A catalogue row with no
// citation is one an operator hand-entered without one, and it is not evidence.
func EOLFact(row EOLRow) (seams.Fact, bool) {
	if row.EOLDate == nil || strings.TrimSpace(row.SourceURL) == "" {
		return seams.Fact{}, false
	}
	key, ok := factKeyFor(row.ProductKind)
	if !ok {
		return seams.Fact{}, false
	}
	return seams.Fact{
		// imported, not inferred. The date was read out of a catalogue row a
		// mirror imported; calling it inferred would understate its provenance
		// as badly as the reverse overstates. source_ref names the row, so a
		// disputed date is traceable to the exact thing that said it.
		Proposal:  seams.NewLookupProposal(seams.SourceKindImported, "catalog:eol:"+row.ID),
		Key:       key,
		Value:     row.EOLDate.UTC().Format("2006-01-02"),
		SourceURL: row.SourceURL,
	}, true
}

// cpeFact states the CPE name an advisory uses for this product.
//
// The citation is the CVE's own NVD page: the claim being made is "this is the
// name CVE-X uses for this product", and that page is where a reviewer checks
// it. A match whose cve_id is not a CVE id gets no fact — there is no page to
// cite, and D4.4 does not have a "close enough" clause.
func cpeFact(cpe, cveID string) (seams.Fact, bool) {
	cpe = strings.TrimSpace(cpe)
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if cpe == "" || !strings.HasPrefix(cveID, "CVE-") {
		return seams.Fact{}, false
	}
	return seams.Fact{
		Proposal:  seams.NewLookupProposal(seams.SourceKindImported, "catalog:vulnerability_match:"+cveID),
		Key:       facts.KeySWCPE,
		Value:     cpe,
		SourceURL: "https://nvd.nist.gov/vuln/detail/" + cveID,
	}, true
}

// factKeyFor maps a catalogue product kind to the fact key for its lifecycle
// date. The mapping is from the kind of the row that MATCHED, never from the
// class the caller guessed at, so a hardware row found under an empty class
// still lands on eol.hw.date.
func factKeyFor(kind string) (string, bool) {
	switch kind {
	case KindOS:
		return facts.KeyEOLOSDate, true
	case KindSoftware:
		return facts.KeyEOLSWDate, true
	case KindHardware:
		return facts.KeyEOLHWDate, true
	}
	return "", false
}

// kindFor maps an [seams.EnrichmentSubject.Class] onto a catalogue product
// kind, or "" meaning "look in all three".
//
// Deliberately a short, closed list. The asset-class vocabulary is large and
// still growing (ADR-0004), and a mapping that tried to place every class would
// be a guess that silently narrows the search: a class this does not recognise
// searches everywhere and lets the matched row decide, which is both wider and
// more honest than placing it wrongly.
func kindFor(class string) string {
	switch strings.ToLower(strings.TrimSpace(class)) {
	case KindOS, "operating_system", "operating-system":
		return KindOS
	case KindSoftware, "application", "package":
		return KindSoftware
	case KindHardware, "appliance", "device":
		return KindHardware
	}
	return ""
}

// missKind is the kind recorded on the gap list when the lookup searched every
// kind and found nothing.
//
// `catalog_lookup_misses.product_kind` is NOT NULL with the same three-value
// CHECK the catalogue has, so an unplaceable subject has to be filed somewhere.
// It is filed as software, which is the kind the overwhelming majority of
// unplaceable subjects are, and the proposal a reviewer sees carries the
// subject verbatim beside the kind so a wrong filing is visible and correctable
// rather than hidden.
func missKind(kind string) string {
	if kind == "" {
		return KindSoftware
	}
	return kind
}

// selectCycle picks the catalogue row that answers a version, or reports that
// none does.
//
// The order is most-specific-first and there is no fallback past it:
//
//  1. the whole normalised version ("22.04.3" matches a cycle "22.04.3")
//  2. major.minor ("22.04.3" → "22.04"), which is how endoflife.date names
//     nearly every cycle
//  3. major alone ("17.9.4a" → "17"), for products cycled by major release
//
// A version that matches none of those is a miss. Adjacent cycles are never
// consulted: the support date of the release beside yours is not your support
// date, and returning it would be wrong in the reassuring direction.
//
// An EMPTY version resolves only when the product has exactly one row. That is
// not a guess — there is nothing to choose between — and it is how a hardware
// model with a single end-of-support announcement resolves. Two or more rows
// and an empty version is ambiguous, which is a miss.
func selectCycle(rows []EOLRow, vendor, version string) (EOLRow, bool) {
	candidates := make([]EOLRow, 0, len(rows))
	for _, r := range rows {
		if matchesVendor(r.Vendor, vendor) {
			candidates = append(candidates, r)
		}
	}
	if len(candidates) == 0 {
		return EOLRow{}, false
	}

	wanted := cycleKeys(version)
	if len(wanted) == 0 {
		if len(candidates) == 1 {
			return candidates[0], true
		}
		return EOLRow{}, false
	}

	for _, want := range wanted {
		for _, r := range candidates {
			if normalize(r.Cycle) == want {
				return r, true
			}
		}
	}
	return EOLRow{}, false
}

// matchesVendor reports whether a catalogue row's vendor can be the subject's.
//
// A NULL/empty vendor on either side makes NO claim about the vendor, so it
// cannot contradict one — the mirror leaves vendor null for "unknown", not for
// "none" (see the schema note), and a caller that does not know the vendor has
// not asserted there isn't one. Where both sides name a vendor they must agree
// exactly after normalisation. What this rules out is the case that matters:
// two different companies' products sharing a name.
func matchesVendor(rowVendor, subjectVendor string) bool {
	rv, sv := normalize(rowVendor), normalize(subjectVendor)
	if rv == "" || sv == "" {
		return true
	}
	return rv == sv
}

// cycleKeys returns the cycle names a version could name, most specific first.
//
// Numeric components are kept VERBATIM, leading zeros and all: endoflife.date
// names Ubuntu's cycle "22.04", and a "tidy" parse to 22.4 matches nothing.
// Non-numeric trailing text ("22.04.3 LTS", "17.9.4a") is dropped, because it
// is a label on the release rather than part of the cycle's name.
func cycleKeys(version string) []string {
	parts := numericParts(version)
	if len(parts) == 0 {
		// A version with no numeric component at all ("stable", "current") is
		// still a name a cycle could carry, so it is tried verbatim.
		if v := normalize(version); v != "" {
			return []string{v}
		}
		return nil
	}
	full := normalize(version)
	keys := make([]string, 0, 4)
	seen := map[string]bool{}
	add := func(k string) {
		if k != "" && !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	add(full)
	// The numeric prefix on its own, so "1.27.3-alpine" still finds the cycle
	// named "1.27.3" before falling back to "1.27". Without it a build-suffixed
	// version skips its own exact cycle and lands one level up — which is a
	// DIFFERENT row with a different date, arrived at silently.
	add(strings.Join(parts, "."))
	if len(parts) >= 2 {
		add(parts[0] + "." + parts[1])
	}
	add(parts[0])
	return keys
}

// numericParts splits a version into its leading run of numeric components.
// "22.04.3 LTS" → ["22","04","3"]; "17.9.4a" → ["17","9","4"]; "IOS-XE" → [].
func numericParts(version string) []string {
	var out []string
	cur := strings.Builder{}
	for _, r := range version {
		switch {
		case unicode.IsDigit(r):
			cur.WriteRune(r)
		case r == '.':
			if cur.Len() == 0 {
				return out
			}
			out = append(out, cur.String())
			cur.Reset()
		default:
			// Any other rune ends the numeric run. The component being built is
			// kept when it has digits ("4" out of "4a") and the rest of the
			// string is discarded.
			if cur.Len() > 0 {
				out = append(out, cur.String())
			}
			return out
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// normalize is the single normalisation used on every side of every comparison
// in this file: case-folded, trimmed, internal whitespace and underscores
// collapsed to one space.
//
// Deliberately shallow. It does NOT strip corporate suffixes, expand
// abbreviations, or fuzzy-match — each of those turns an exact match into a
// judgement call, and a judgement call about which vendor a product belongs to
// is how one company's end-of-support date gets attached to another company's
// hardware. Anything beyond this belongs to the generative enricher, whose
// output a person reviews.
func normalize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for _, r := range s {
		if unicode.IsSpace(r) || r == '_' {
			space = b.Len() > 0
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Normalize is the exported form, for the store's SQL predicates and for the
// tests that pin them. The comparison has to be the same on both sides of the
// wire or the Go matcher would be judging rows SQL had already filtered
// differently.
func Normalize(s string) string { return normalize(s) }

// lookupLogf is the package's log line for the things that are noted and not
// returned. A variable rather than a direct call so a test can assert one was
// emitted — a bookkeeping failure that is only logged is exactly the kind that
// goes unnoticed until someone asks why the gap list stopped growing.
var lookupLogf = logger.Printf
