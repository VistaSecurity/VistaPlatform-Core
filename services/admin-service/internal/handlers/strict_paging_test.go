package handlers

// Strict paging on the admin list endpoints: a non-numeric, negative or zero
// limit / offset / page / page_size answers 400 before the store is touched,
// an oversized value is clamped, a valid one answers 200. Each case drives the
// real handler through a gin engine and asserts the value that reaches the
// store, so a handler that quietly parses leniently again fails here.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func get(eng *gin.Engine, path string) *httptest.ResponseRecorder {
	return doRequest(eng, http.MethodGet, path, nil)
}

func TestStrictPaging_SecurityEvents(t *testing.T) {
	for _, q := range []string{"?limit=-1", "?limit=0", "?limit=abc", "?offset=x", "?offset=-3"} {
		svc := &stubSecurityProvider{gotLimit: -99}
		w := get(securityEngine(svc), securityBase+"/events"+q)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", q, w.Code)
		}
		if svc.gotLimit != -99 {
			t.Errorf("%s: store was queried", q)
		}
	}
	svc := &stubSecurityProvider{}
	if w := get(securityEngine(svc), securityBase+"/events?limit=100000&offset=7"); w.Code != http.StatusOK ||
		svc.gotLimit != 100 || svc.gotOffset != 7 {
		t.Errorf("huge limit: status %d limit %d offset %d, want 200/100/7", w.Code, svc.gotLimit, svc.gotOffset)
	}
	svc = &stubSecurityProvider{}
	if w := get(securityEngine(svc), securityBase+"/events"); w.Code != http.StatusOK || svc.gotLimit != 50 || svc.gotOffset != 0 {
		t.Errorf("default: status %d limit %d offset %d, want 200/50/0", w.Code, svc.gotLimit, svc.gotOffset)
	}
	svc = &stubSecurityProvider{}
	if w := get(securityEngine(svc), securityBase+"/events?limit=25"); w.Code != http.StatusOK || svc.gotLimit != 25 {
		t.Errorf("valid: status %d limit %d", w.Code, svc.gotLimit)
	}
}

var badPageQueries = []string{"?page=-1", "?page=0", "?page=abc", "?page_size=-1", "?page_size=0", "?page_size=x"}

func TestStrictPaging_Catalogues(t *testing.T) {
	for _, path := range []string{"/eol", "/vulnerabilities"} {
		for _, q := range badPageQueries {
			store := &stubCatalogStore{}
			store.lastEOLQuery.Page, store.lastVulnQuery.Page = -99, -99
			w := get(catalogEngine(store, &stubFeedRunner{}, nil), catalogBase+path+q)
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s%s: status %d, want 400", path, q, w.Code)
			}
			if store.lastEOLQuery.Page != -99 || store.lastVulnQuery.Page != -99 {
				t.Errorf("%s%s: store was queried", path, q)
			}
		}
	}
	store := &stubCatalogStore{}
	if w := get(catalogEngine(store, &stubFeedRunner{}, nil), catalogBase+"/eol?page=2&page_size=25"); w.Code != http.StatusOK ||
		store.lastEOLQuery.Page != 2 || store.lastEOLQuery.PageSize != 25 {
		t.Errorf("valid eol: status %d query %+v", w.Code, store.lastEOLQuery)
	}
	store = &stubCatalogStore{}
	if w := get(catalogEngine(store, &stubFeedRunner{}, nil), catalogBase+"/vulnerabilities?page=5000000"); w.Code != http.StatusOK || store.lastVulnQuery.Page != 1_000_000 {
		t.Errorf("huge page: status %d page %d, want 200/1000000", w.Code, store.lastVulnQuery.Page)
	}
}

func TestStrictPaging_CatalogueProposalsAndMisses(t *testing.T) {
	for _, path := range []string{"/proposals", "/misses"} {
		for _, q := range badPageQueries {
			store := &stubProposalStore{}
			store.lastQuery.Page, store.lastMissQ.Page = -99, -99
			w := get(proposalEngine(store, &stubEnrichRunner{}, &stubSeamEnricher{}, CatalogEnrichAvailability{}), proposalBase+path+q)
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s%s: status %d, want 400", path, q, w.Code)
			}
			if store.lastQuery.Page != -99 || store.lastMissQ.Page != -99 {
				t.Errorf("%s%s: store was queried", path, q)
			}
		}
	}
	store := &stubProposalStore{}
	eng := proposalEngine(store, &stubEnrichRunner{}, &stubSeamEnricher{}, CatalogEnrichAvailability{})
	if w := get(eng, proposalBase+"/proposals?page=3&page_size=10"); w.Code != http.StatusOK || store.lastQuery.Page != 3 || store.lastQuery.PageSize != 10 {
		t.Errorf("valid proposals: status %d query %+v", w.Code, store.lastQuery)
	}
	if w := get(eng, proposalBase+"/misses?page=3&page_size=10"); w.Code != http.StatusOK || store.lastMissQ.Page != 3 || store.lastMissQ.PageSize != 10 {
		t.Errorf("valid misses: status %d query %+v", w.Code, store.lastMissQ)
	}
}

func TestStrictPaging_ClassificationRules(t *testing.T) {
	for _, q := range badPageQueries {
		store := &stubRuleStore{}
		store.lastListQuery.Page = -99
		w := get(ruleRouter(store), "/admin/catalogs/classification-rules"+q)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", q, w.Code)
		}
		if store.lastListQuery.Page != -99 {
			t.Errorf("%s: store was queried", q)
		}
	}
	store := &stubRuleStore{}
	if w := get(ruleRouter(store), "/admin/catalogs/classification-rules?page=2&page_size=500"); w.Code != http.StatusOK ||
		store.lastListQuery.Page != 2 {
		t.Errorf("valid: status %d query %+v", w.Code, store.lastListQuery)
	}
}
