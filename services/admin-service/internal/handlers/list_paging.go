package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
)

// ParseListPaging reads page / page_size for an admin list endpoint through
// sharedapi.ParsePaginationStrict: absent takes the default (page 1, 20 rows),
// a present value must be a positive integer, and page_size above 100 is
// clamped. A malformed or non-positive value answers 400 — it used to fall
// through to a negative LIMIT, which Postgres rejects as a 500.
//
// "limit" is accepted as the older spelling of page_size (the tenant and
// platform-user lists have always taken both); page_size wins when both are
// present.
//
// It writes the 400 itself and returns ok=false when the request is refused.
func ParseListPaging(c *gin.Context) (p sharedapi.Pagination, ok bool) {
	q := c.Request.URL.Query()
	if !q.Has("page_size") && q.Has("limit") {
		q.Set("page_size", q.Get("limit"))
		q.Del("limit")
		c.Request.URL.RawQuery = q.Encode()
	}
	p, err := sharedapi.ParsePaginationStrict(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return p, false
	}
	return p, true
}
