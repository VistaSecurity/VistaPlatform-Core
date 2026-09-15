package catalogfeeds

import (
	"context"
	"errors"
	"sort"
	"sync"
)

// memStore is an in-memory Store used by every unit test in this package. It
// keeps the same identity rules as the real SQL — upsert on
// (product_kind, vendor, product, cycle) for EOL, on cve_id for vulnerabilities,
// and on (cve_id, cpe, purl) for matches — so an "idempotent re-run" assertion
// here means the same thing it means in Postgres. The TestIntegration_* tests
// prove the SQL agrees.
type memStore struct {
	mu      sync.Mutex
	eol     map[string]EOLEntry
	vulns   map[string]Vulnerability
	matches map[string]map[string]VulnerabilityMatch
	states  map[string]FeedState

	upsertEOLErr  error
	upsertVulnErr error
	feedStatesErr error

	// Call log, so a test can assert WHICH feed-state writes happened rather
	// than only their end result.
	markedRunning []string
	results       []markedResult
}

type markedResult struct {
	feed string
	res  SyncResult
	err  error
}

func newMemStore() *memStore {
	return &memStore{
		eol:     map[string]EOLEntry{},
		vulns:   map[string]Vulnerability{},
		matches: map[string]map[string]VulnerabilityMatch{},
		states:  map[string]FeedState{},
	}
}

func eolKey(e EOLEntry) string {
	vendor := ""
	if e.Vendor != nil {
		vendor = *e.Vendor
	}
	return e.ProductKind + "\x00" + vendor + "\x00" + e.Product + "\x00" + e.Cycle
}

func matchKey(m VulnerabilityMatch) string {
	cpe, purl := "", ""
	if m.CPEMatch != nil {
		cpe = *m.CPEMatch
	}
	if m.PURLRange != nil {
		purl = *m.PURLRange
	}
	return cpe + "\x00" + purl
}

func (s *memStore) UpsertEOL(_ context.Context, entries []EOLEntry) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.upsertEOLErr != nil {
		return 0, s.upsertEOLErr
	}
	var n int64
	for _, e := range entries {
		if e.ProductKind == "" || e.Product == "" || e.Cycle == "" {
			continue
		}
		if e.SourceKind == "" {
			e.SourceKind = "imported"
		}
		s.eol[eolKey(e)] = e
		n++
	}
	return n, nil
}

// UpsertVulnerabilities mirrors the real SQL's two DIFFERENT write semantics,
// because the counts it returns are what the console shows:
//   - the CVE row is ON CONFLICT DO UPDATE, so a re-run affects it again (1);
//   - a match rule is ON CONFLICT DO NOTHING, so a re-run writes nothing (0).
//
// A stub that counted len(v.Matches) for the second would make an "idempotent
// re-import reports 0 new rules" test pass here and fail against Postgres.
func (s *memStore) UpsertVulnerabilities(_ context.Context, vulns []Vulnerability) (int64, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.upsertVulnErr != nil {
		return 0, 0, s.upsertVulnErr
	}
	var n, matches int64
	for _, v := range vulns {
		if v.CVEID == "" {
			continue
		}
		if v.SourceKind == "" {
			v.SourceKind = "imported"
		}
		stored := v
		stored.Matches = nil
		s.vulns[v.CVEID] = stored
		if s.matches[v.CVEID] == nil {
			s.matches[v.CVEID] = map[string]VulnerabilityMatch{}
		}
		for _, m := range v.Matches {
			if (m.CPEMatch == nil) == (m.PURLRange == nil) {
				continue
			}
			k := matchKey(m)
			if _, exists := s.matches[v.CVEID][k]; exists {
				continue // DO NOTHING: no row affected
			}
			s.matches[v.CVEID][k] = m
			matches++
		}
		n++
	}
	return n, matches, nil
}

func (s *memStore) ListEOL(_ context.Context, q EOLQuery) ([]EOLEntry, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []EOLEntry{}
	for _, e := range s.eol {
		if q.Kind != "" && e.ProductKind != q.Kind {
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return eolKey(out[i]) < eolKey(out[j]) })
	return out, int64(len(out)), nil
}

func (s *memStore) ListVulnerabilities(_ context.Context, q VulnQuery) ([]Vulnerability, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Vulnerability{}
	for _, v := range s.vulns {
		if q.Severity != "" && (v.Severity == nil || *v.Severity != q.Severity) {
			continue
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CVEID < out[j].CVEID })
	return out, int64(len(out)), nil
}

func (s *memStore) FeedStates(context.Context) ([]FeedState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.feedStatesErr != nil {
		return nil, s.feedStatesErr
	}
	out := make([]FeedState, 0, len(FeedNames))
	for _, name := range FeedNames {
		if st, ok := s.states[name]; ok {
			out = append(out, st)
			continue
		}
		out = append(out, FeedState{Feed: name, LastStatus: StatusNever})
	}
	return out, nil
}

func (s *memStore) MarkRunning(_ context.Context, feed string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.markedRunning = append(s.markedRunning, feed)
	st := s.states[feed]
	st.Feed, st.LastStatus = feed, StatusRunning
	s.states[feed] = st
	return nil
}

// MarkResult mirrors SQLStore.MarkResult's one load-bearing rule: the cursor
// advances ONLY on success.
func (s *memStore) MarkResult(_ context.Context, feed string, res SyncResult, runErr error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results = append(s.results, markedResult{feed: feed, res: res, err: runErr})
	st := s.states[feed]
	st.Feed = feed
	if runErr != nil {
		st.LastStatus = StatusError
		msg := runErr.Error()
		st.LastError = &msg
		s.states[feed] = st
		return nil
	}
	st.LastStatus = StatusOK
	st.LastError = nil
	st.RowCount = res.Rows
	if res.Cursor != "" {
		c := res.Cursor
		st.Cursor = &c
	}
	s.states[feed] = st
	return nil
}

func (s *memStore) ExportAll(context.Context) (*Export, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	export := &Export{EOL: []EOLEntry{}, Vulns: []Vulnerability{}}
	keys := make([]string, 0, len(s.eol))
	for k := range s.eol {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		export.EOL = append(export.EOL, s.eol[k])
	}

	cves := make([]string, 0, len(s.vulns))
	for k := range s.vulns {
		cves = append(cves, k)
	}
	sort.Strings(cves)
	for _, cve := range cves {
		v := s.vulns[cve]
		v.Matches = []VulnerabilityMatch{}
		mkeys := make([]string, 0, len(s.matches[cve]))
		for k := range s.matches[cve] {
			mkeys = append(mkeys, k)
		}
		sort.Strings(mkeys)
		for _, k := range mkeys {
			v.Matches = append(v.Matches, s.matches[cve][k])
		}
		export.Vulns = append(export.Vulns, v)
	}
	return export, nil
}

func (s *memStore) countEOL() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.eol)
}

func (s *memStore) countVulns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.vulns)
}

func (s *memStore) countMatches(cve string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.matches[cve])
}

func (s *memStore) get(key string) (EOLEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.eol[key]
	return e, ok
}

var errStubStore = errors.New("stub store failure")
