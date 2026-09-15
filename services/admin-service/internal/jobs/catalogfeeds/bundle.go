package catalogfeeds

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// The offline bundle: how an air-gapped install gets these catalogues.
//
// Modelled on the Enterprise content bundle (services/compliance-engine/ee/
// content/README.md) but deliberately SIMPLER in one respect. That bundle is
// signed with the edition key because it carries licensed content and the
// signature is what makes it revocable by non-renewal. These catalogues are
// CORE — free, in every edition — so there is nothing to revoke and no
// entitlement to prove. What a bundle still needs is INTEGRITY: an operator
// carrying a file across an air gap must be able to tell that it arrived whole.
// So: a manifest with a SHA-256 and a row count per file, verified before a
// single row is applied. Hash, not signature.
//
// (An operator who wants provenance as well can sign the tarball out of band
// with their own key and verify it before import — the format does not prevent
// it, it just does not require a key this product would then have to manage.)

// Bundle format identifiers. Version is bumped only for a BREAKING change to
// the file set or the row shapes; an importer refusing a version it does not
// know is better than one guessing at a shape it has never seen.
const (
	BundleFormat  = "vista-catalog-bundle"
	BundleVersion = 1

	ManifestName = "manifest.json"
	EOLFileName  = "eol_catalogue.jsonl"
	VulnFileName = "vulnerability_catalogue.jsonl"

	// AttributionFileName carries the upstream sources' attribution INSIDE the
	// bundle, not only in the product's own NOTICE. A bundle is a file an
	// operator carries across an air gap and may hand on; the obligations of
	// NVD, OSV and endoflife.date travel with the data, so the statement of
	// them has to travel in the same tarball or it does not travel at all.
	// Owner decision (ADR-0001 follow-up): redistribution is
	// permitted by both sources; what was owed is this wording.
	AttributionFileName = "ATTRIBUTION.md"

	// MaxBundleBytes bounds an uploaded bundle. The full NVD + OSV catalogue is
	// large; this is the guard against an upload that fills the pod's disk.
	MaxBundleBytes int64 = 1 << 30 // 1 GiB

	// maxBundleEntries bounds the tar members verifyPass will walk. The cap on
	// the COMPRESSED upload does not bound the DECOMPRESSED member count — a
	// gzip bomb of tar headers is small on the wire and unbounded off it, and
	// the verify pass keeps a map entry per member. A well-formed bundle has
	// four.
	maxBundleEntries = 64
)

// BundleAttribution is the text written to AttributionFileName. It is a
// constant rather than a generated file so that the bytes the test asserts on
// are the bytes the bundle carries.
//
// Keep it in step with public/NOTICE's "Third-party data" section and
// docsv4/core/operate/catalogs.md's "Attribution and terms".
const BundleAttribution = `# Attribution — upstream data sources

This bundle carries catalogue data mirrored from third-party sources. Each
source remains under its own terms, and those terms travel with this file.

- **NVD (NIST).** This product uses data from the NVD API but is not endorsed or
  certified by the NVD. See <https://nvd.nist.gov/developers/terms-of-use>.
- **OSV (osv.dev).** The aggregated database is published under CC-BY-4.0 —
  attribution: OSV, <https://osv.dev>, and the upstream database named on each
  record. See <https://github.com/google/osv.dev>.
- **endoflife.date.** A community-maintained dataset, mirrored under its
  published API terms. See <https://endoflife.date/docs/api>.

If you redistribute this bundle beyond your own organization, these attribution
obligations are yours to carry. Nothing here is legal advice.
`

// BundleFile is one entry of the manifest.
type BundleFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Rows   int64  `json:"rows"`
	Bytes  int64  `json:"bytes"`
}

// BundleManifest is manifest.json.
type BundleManifest struct {
	Format      string       `json:"format"`
	Version     int          `json:"version"`
	GeneratedAt time.Time    `json:"generated_at"`
	Files       []BundleFile `json:"files"`
}

// ImportResult is what the import endpoint reports back.
type ImportResult struct {
	Files             []BundleFile `json:"files"`
	EOLRows           int64        `json:"eol_rows"`
	VulnerabilityRows int64        `json:"vulnerability_rows"`
	MatchRows         int64        `json:"match_rows"`
	GeneratedAt       *time.Time   `json:"generated_at,omitempty"`
}

// BuildBundle writes a gzip-compressed tar of the catalogues to w and returns
// the manifest it wrote.
//
// The manifest is the FIRST tar entry, so a reader can learn what to expect
// before it has seen the payload. Rows are emitted in the store's deterministic
// export order, so two exports of the same database produce identical bytes and
// therefore identical hashes — which is what makes "did this file change on the
// way across the gap" answerable at all.
func BuildBundle(ctx context.Context, store Store, w io.Writer) (*BundleManifest, error) {
	export, err := store.ExportAll(ctx)
	if err != nil {
		return nil, err
	}

	eolBytes, eolRows, err := marshalJSONL(export.EOL)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", EOLFileName, err)
	}
	vulnBytes, vulnRows, err := marshalJSONL(export.Vulns)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", VulnFileName, err)
	}

	attribBytes := []byte(BundleAttribution)

	manifest := &BundleManifest{
		Format:      BundleFormat,
		Version:     BundleVersion,
		GeneratedAt: time.Now().UTC().Truncate(time.Second),
		Files: []BundleFile{
			{Name: AttributionFileName, SHA256: sha256Hex(attribBytes),
				Rows: int64(bytes.Count(attribBytes, []byte{'\n'})), Bytes: int64(len(attribBytes))},
			{Name: EOLFileName, SHA256: sha256Hex(eolBytes), Rows: eolRows, Bytes: int64(len(eolBytes))},
			{Name: VulnFileName, SHA256: sha256Hex(vulnBytes), Rows: vulnRows, Bytes: int64(len(vulnBytes))},
		},
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')

	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	for _, entry := range []struct {
		name string
		body []byte
	}{
		{ManifestName, manifestBytes},
		{AttributionFileName, attribBytes},
		{EOLFileName, eolBytes},
		{VulnFileName, vulnBytes},
	} {
		hdr := &tar.Header{
			Name:    entry.name,
			Mode:    0o644,
			Size:    int64(len(entry.body)),
			ModTime: manifest.GeneratedAt,
			Format:  tar.FormatPAX,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("write %s header: %w", entry.name, err)
		}
		if _, err := tw.Write(entry.body); err != nil {
			return nil, fmt.Errorf("write %s: %w", entry.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("close gzip: %w", err)
	}
	return manifest, nil
}

// ImportBundle verifies a bundle and applies it.
//
// Two passes over a spooled copy, and the order is the point: EVERY file's
// SHA-256 and row count is checked BEFORE the first row is written. Verifying
// while applying would leave a half-imported catalogue behind a corruption
// error, which is the failure mode an air-gap transfer is most likely to hit.
func ImportBundle(ctx context.Context, store Store, r io.Reader) (*ImportResult, error) {
	spool, err := os.CreateTemp("", "catalog-bundle-*.tar.gz")
	if err != nil {
		return nil, fmt.Errorf("spool bundle: %w", err)
	}
	defer func() {
		_ = spool.Close()
		_ = os.Remove(spool.Name())
	}()

	written, err := io.Copy(spool, io.LimitReader(r, MaxBundleBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read bundle: %w", err)
	}
	if written > MaxBundleBytes {
		return nil, fmt.Errorf("bundle exceeds the %d-byte limit", MaxBundleBytes)
	}
	if written == 0 {
		return nil, fmt.Errorf("bundle is empty")
	}

	// --- pass 1: manifest + hashes ----------------------------------------
	manifest, hashes, counts, err := verifyPass(spool)
	if err != nil {
		return nil, err
	}
	byName := map[string]BundleFile{}
	for _, f := range manifest.Files {
		byName[f.Name] = f
	}
	for name, declared := range byName {
		actual, ok := hashes[name]
		if !ok {
			return nil, fmt.Errorf("manifest lists %q but the bundle does not contain it", name)
		}
		if !strings.EqualFold(actual, declared.SHA256) {
			return nil, fmt.Errorf("%s: sha256 mismatch — manifest says %s, bundle contains %s",
				name, declared.SHA256, actual)
		}
		if declared.Rows != counts[name] {
			return nil, fmt.Errorf("%s: manifest declares %d rows, bundle contains %d",
				name, declared.Rows, counts[name])
		}
	}
	for name := range hashes {
		if _, ok := byName[name]; !ok {
			return nil, fmt.Errorf("bundle contains %q, which the manifest does not list", name)
		}
	}

	// --- pass 2: apply ------------------------------------------------------
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind bundle: %w", err)
	}
	result := &ImportResult{Files: manifest.Files, GeneratedAt: &manifest.GeneratedAt}
	if err := applyPass(ctx, store, spool, result); err != nil {
		// The partial result travels WITH the error. A caller that must record
		// what landed — the audit trail — would otherwise have to scrape the
		// counts back out of the message, and a write that happened must be
		// auditable with numbers rather than prose.
		// Verification already passed, so this failure happened WITH ROWS
		// ALREADY WRITTEN — a dropped connection, a cancelled request, a
		// constraint the catalogue rejected. Distinguishing it is not
		// pedantry: the console's refusal banner says "nothing was applied",
		// which is true of every verification failure and false of this one,
		// and telling an operator their catalogue is untouched when it is
		// half-written is the exact shape of the reassuring-but-wrong report
		// this codebase keeps paying for.
		return result, fmt.Errorf("%w after %d end-of-life rows and %d vulnerabilities: %w",
			ErrBundleApplyFailed, result.EOLRows, result.VulnerabilityRows, err)
	}
	return result, nil
}

// ErrBundleApplyFailed marks a failure that happened AFTER the manifest
// verified, i.e. once rows had begun to land. Re-importing the same bundle is
// the repair — import is idempotent.
var ErrBundleApplyFailed = errors.New("the bundle verified but applying it failed partway")

func verifyPass(spool *os.File) (*BundleManifest, map[string]string, map[string]int64, error) {
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		return nil, nil, nil, fmt.Errorf("rewind bundle: %w", err)
	}
	gz, err := gzip.NewReader(spool)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("bundle is not gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	var manifest *BundleManifest
	hashes := map[string]string{}
	counts := map[string]int64{}
	seen := map[string]bool{}
	entries := 0

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, nil, fmt.Errorf("read bundle: %w", err)
		}
		entries++
		if entries > maxBundleEntries {
			return nil, nil, nil, fmt.Errorf("bundle holds more than %d entries", maxBundleEntries)
		}
		// Entry names are used as MAP KEYS only — nothing here writes a file to
		// disk under a name from the archive, so there is no path-traversal
		// surface. Reject anything with a separator anyway: a well-formed
		// bundle is flat, and an entry that is not says the file is not one of
		// ours.
		name := hdr.Name
		if strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
			return nil, nil, nil, fmt.Errorf("bundle entry %q is not a flat file name", hdr.Name)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// A name may appear ONCE, and this check is load-bearing rather than
		// tidiness. hashes/counts are keyed by name, so a second member under
		// the same name would OVERWRITE the first member's digest: a bundle
		// carrying [tampered, genuine] under one name verifies against the
		// genuine copy while applyPass — which switches on the name and does not
		// stop at the first match — applies BOTH. That defeats the manifest
		// entirely, which is the one thing this format exists to provide.
		if seen[name] {
			return nil, nil, nil, fmt.Errorf(
				"bundle contains more than one entry named %q; a bundle carries each file once", hdr.Name)
		}
		seen[name] = true

		if name == ManifestName {
			raw, err := io.ReadAll(io.LimitReader(tr, 1<<20))
			if err != nil {
				return nil, nil, nil, fmt.Errorf("read manifest: %w", err)
			}
			var m BundleManifest
			if err := json.Unmarshal(raw, &m); err != nil {
				return nil, nil, nil, fmt.Errorf("parse manifest: %w", err)
			}
			if m.Format != BundleFormat {
				return nil, nil, nil, fmt.Errorf("not a %s (manifest says %q)", BundleFormat, m.Format)
			}
			if m.Version != BundleVersion {
				return nil, nil, nil, fmt.Errorf("bundle format version %d is not supported by this release (expected %d)", m.Version, BundleVersion)
			}
			manifest = &m
			continue
		}

		h := sha256.New()
		var rows int64
		lr := &lineCounter{}
		if _, err := io.Copy(io.MultiWriter(h, lr), io.LimitReader(tr, MaxBundleBytes)); err != nil {
			return nil, nil, nil, fmt.Errorf("read %s: %w", name, err)
		}
		rows = lr.lines
		hashes[name] = hex.EncodeToString(h.Sum(nil))
		counts[name] = rows
	}

	if manifest == nil {
		return nil, nil, nil, fmt.Errorf("bundle has no %s", ManifestName)
	}
	return manifest, hashes, counts, nil
}

func applyPass(ctx context.Context, store Store, spool *os.File, result *ImportResult) error {
	gz, err := gzip.NewReader(spool)
	if err != nil {
		return fmt.Errorf("bundle is not gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read bundle: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		switch hdr.Name {
		case EOLFileName:
			n, err := importEOL(ctx, store, tr)
			result.EOLRows += n
			if err != nil {
				return err
			}
		case VulnFileName:
			n, matches, err := importVulns(ctx, store, tr)
			result.VulnerabilityRows += n
			result.MatchRows += matches
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// importBatchSize keeps one transaction's worth of rows in memory rather than
// the whole catalogue.
const importBatchSize = 500

func importEOL(ctx context.Context, store Store, r io.Reader) (int64, error) {
	var total int64
	batch := make([]EOLEntry, 0, importBatchSize)
	err := eachJSONLine(r, func(line []byte) error {
		var e EOLEntry
		if err := json.Unmarshal(line, &e); err != nil {
			return fmt.Errorf("parse %s row: %w", EOLFileName, err)
		}
		batch = append(batch, e)
		if len(batch) >= importBatchSize {
			n, err := store.UpsertEOL(ctx, batch)
			total += n
			batch = batch[:0]
			return err
		}
		return nil
	})
	if err != nil {
		return total, err
	}
	n, err := store.UpsertEOL(ctx, batch)
	return total + n, err
}

// importVulns applies the vulnerability file, returning the CVE rows and the
// match rules THE DATABASE WROTE.
//
// The match count used to be len(v.Matches) summed over the file, which is not
// the same question. Match rules are INSERT … DO NOTHING, so re-importing a
// bundle into a catalogue that already holds it writes zero of them while the
// file still lists tens of thousands — and the console reported those as
// "imported". A number nobody can act on is worse than no number.
func importVulns(ctx context.Context, store Store, r io.Reader) (int64, int64, error) {
	var total, matches int64
	batch := make([]Vulnerability, 0, importBatchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		n, m, err := store.UpsertVulnerabilities(ctx, batch)
		total += n
		matches += m
		batch = batch[:0]
		return err
	}
	err := eachJSONLine(r, func(line []byte) error {
		var v Vulnerability
		if err := json.Unmarshal(line, &v); err != nil {
			return fmt.Errorf("parse %s row: %w", VulnFileName, err)
		}
		batch = append(batch, v)
		if len(batch) >= importBatchSize {
			return flush()
		}
		return nil
	})
	if err != nil {
		return total, matches, err
	}
	return total, matches, flush()
}

// --- helpers ---------------------------------------------------------------

// marshalJSONL renders rows one JSON object per line. Returns the bytes and the
// row count, which the manifest carries so a truncated file is caught by the
// count as well as by the hash.
func marshalJSONL[T any](rows []T) ([]byte, int64, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, row := range rows {
		if err := enc.Encode(row); err != nil {
			return nil, 0, err
		}
	}
	return buf.Bytes(), int64(len(rows)), nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// lineCounter counts newline-terminated records without holding the payload.
type lineCounter struct{ lines int64 }

func (l *lineCounter) Write(p []byte) (int, error) {
	l.lines += int64(bytes.Count(p, []byte{'\n'}))
	return len(p), nil
}

// eachJSONLine calls fn for every non-blank line. maxJSONLineBytes is generous
// because a CVE description plus its match rules is not small.
const maxJSONLineBytes = 8 << 20

func eachJSONLine(r io.Reader, fn func([]byte) error) error {
	dec := newLineReader(r, maxJSONLineBytes)
	for {
		line, err := dec.next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if err := fn(line); err != nil {
			return err
		}
	}
}

// lineReader is a bufio.Scanner that reports the oversize line as an error
// instead of silently stopping, which is bufio.Scanner's default and exactly
// the "a check that cannot fail" shape to avoid: a truncated import that
// reports success.
type lineReader struct {
	r     io.Reader
	buf   []byte
	max   int
	start int
	end   int
	eof   bool
}

func newLineReader(r io.Reader, max int) *lineReader {
	return &lineReader{r: r, max: max, buf: make([]byte, 64<<10)}
}

func (l *lineReader) next() ([]byte, error) {
	for {
		if i := bytes.IndexByte(l.buf[l.start:l.end], '\n'); i >= 0 {
			line := l.buf[l.start : l.start+i]
			l.start += i + 1
			return line, nil
		}
		if l.eof {
			if l.start >= l.end {
				return nil, io.EOF
			}
			line := l.buf[l.start:l.end]
			l.start = l.end
			return line, nil
		}
		// Compact, then grow if the line still does not fit.
		if l.start > 0 {
			copy(l.buf, l.buf[l.start:l.end])
			l.end -= l.start
			l.start = 0
		}
		if l.end == len(l.buf) {
			if len(l.buf) >= l.max {
				return nil, fmt.Errorf("bundle contains a line longer than %d bytes", l.max)
			}
			grown := make([]byte, min(len(l.buf)*2, l.max))
			copy(grown, l.buf[:l.end])
			l.buf = grown
		}
		n, err := l.r.Read(l.buf[l.end:])
		l.end += n
		if err == io.EOF {
			l.eof = true
			continue
		}
		if err != nil {
			return nil, err
		}
	}
}

// BundleImporter adapts the package-level ImportBundle to the interface the
// HTTP handler depends on, so the handler never sees a Store.
type BundleImporter struct{ Store Store }

// ImportBundle verifies and applies an uploaded bundle.
func (b BundleImporter) ImportBundle(ctx context.Context, r io.Reader) (*ImportResult, error) {
	return ImportBundle(ctx, b.Store, r)
}

// SortedFileNames is the manifest order the bundle writes and the docs quote.
func SortedFileNames() []string {
	names := []string{AttributionFileName, EOLFileName, VulnFileName}
	sort.Strings(names)
	return names
}
