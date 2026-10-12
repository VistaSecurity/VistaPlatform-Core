package handlers

import (
	"net/http"
	"strings"
	"testing"
)

// A negative page_size used to skip the `== 0 || > 100` reset and reach SQL as
// LIMIT -n (a 500). Every admin list endpoint now reads paging through
// ParseListPaging: malformed or non-positive is 400, an oversize page_size is
// clamped, and the older `limit` spelling still works.
func TestListPlatformUsers_PagingIsValidated(t *testing.T) {
	eng := platformUserEngine(&stubPlatformUserStore{}, nil, "")
	base := apiBase + "/admin/users"
	for _, q := range []string{"page_size=-5", "page_size=0", "page_size=abc", "page=-1", "page=0", "limit=-3"} {
		w := doRequest(eng, http.MethodGet, base+"?"+q, nil)
		if w.Code != http.StatusBadRequest {
			t.Errorf("?%s: status %d, want 400; body %s", q, w.Code, w.Body.String())
		}
	}
	for _, q := range []string{"", "page_size=500", "limit=5", "page=2&page_size=10"} {
		w := doRequest(eng, http.MethodGet, base+"?"+q, nil)
		if w.Code != http.StatusOK {
			t.Errorf("?%s: status %d, want 200; body %s", q, w.Code, w.Body.String())
		}
	}
	if w := doRequest(eng, http.MethodGet, base+"?page_size=500", nil); !strings.Contains(w.Body.String(), `"page_size":100`) {
		t.Errorf("an oversize page_size should clamp to 100: %s", w.Body.String())
	}
}
