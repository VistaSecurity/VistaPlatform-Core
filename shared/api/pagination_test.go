package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func ctxWithQuery(q string) *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/x?"+q, nil)
	return c
}

func TestParsePagination_PageIsCapped(t *testing.T) {
	for _, tc := range []struct {
		name, query     string
		page, size, off int
	}{
		{"defaults", "", 1, 20, 0},
		{"plain", "page=3&page_size=10", 3, 10, 20},
		{"at the cap", "page=1000000&page_size=100", 1_000_000, 100, 99_999_900},
		{"just over the cap", "page=1000001&page_size=100", 1_000_000, 100, 99_999_900},
		{"max int64 would overflow OFFSET", "page=9223372036854775807&page_size=100", 1_000_000, 100, 99_999_900},
		{"page_size clamped", "page_size=100000", 1, 100, 0},
		{"garbage falls back", "page=abc&page_size=-4", 1, 20, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := ParsePagination(ctxWithQuery(tc.query))
			if p.Page != tc.page || p.PageSize != tc.size || p.Offset != tc.off {
				t.Fatalf("got page=%d size=%d offset=%d, want %d/%d/%d", p.Page, p.PageSize, p.Offset, tc.page, tc.size, tc.off)
			}
			if p.Offset < 0 {
				t.Fatalf("negative offset %d", p.Offset)
			}
		})
	}
}

func TestParsePaginationStrict(t *testing.T) {
	for _, tc := range []struct {
		name, query string
		wantErr     bool
	}{
		{"absent is fine", "", false},
		{"valid", "page=2&page_size=50", false},
		{"huge page is clamped not rejected", "page=9223372036854775807", false},
		{"non-numeric page", "page=abc", true},
		{"non-numeric page_size", "page_size=abc", true},
		{"zero page", "page=0", true},
		{"negative page_size", "page_size=-1", true},
		{"empty value", "page=", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParsePaginationStrict(ctxWithQuery(tc.query))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tc.wantErr)
			}
			if err == nil && (p.Page < 1 || p.Page > MaxPage || p.PageSize < 1 || p.PageSize > MaxPageSize || p.Offset < 0) {
				t.Fatalf("out-of-range result %+v", p)
			}
		})
	}
}

func TestParseLimitOffsetStrict(t *testing.T) {
	for _, q := range []string{"limit=-1", "limit=0", "limit=abc", "limit=", "offset=x", "offset=-1", "limit=5&offset=-1"} {
		if _, _, err := ParseLimitOffsetStrict(ctxWithQuery(q), 20, 100); err == nil {
			t.Errorf("%q: want an error", q)
		}
	}
	for _, tc := range []struct {
		query         string
		limit, offset int
	}{
		{"", 20, 0},
		{"limit=5&offset=10", 5, 10},
		{"limit=100000", 100, 0},
		{"offset=0", 20, 0},
		{"offset=999999999999", 20, MaxOffset},
	} {
		l, o, err := ParseLimitOffsetStrict(ctxWithQuery(tc.query), 20, 100)
		if err != nil || l != tc.limit || o != tc.offset {
			t.Errorf("%q: got %d/%d/%v, want %d/%d", tc.query, l, o, err, tc.limit, tc.offset)
		}
	}
}

func TestRequirePositiveIntQuery(t *testing.T) {
	if err := RequirePositiveIntQuery(ctxWithQuery("a=1"), "a", "b"); err != nil {
		t.Errorf("valid/absent: %v", err)
	}
	for _, q := range []string{"a=0", "a=-1", "a=x", "b=x"} {
		if err := RequirePositiveIntQuery(ctxWithQuery(q), "a", "b"); err == nil {
			t.Errorf("%q: want an error", q)
		}
	}
}
