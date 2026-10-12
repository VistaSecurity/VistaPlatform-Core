package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	sharedapi "github.com/vistasecurity/vistaplatform/shared/api"
)

// parsePageDefaulting parses page/page_size with sharedapi.ParsePaginationStrict
// (garbage answers 400, page_size is capped at sharedapi.MaxPageSize) but takes
// defaultSize, not the shared 20, when page_size is absent. It is for endpoints
// whose callers predate pagination and read the whole list in one call: they
// keep getting a full page rather than a surprise 20. It writes the 400 itself
// and reports false when it did.
func parsePageDefaulting(c *gin.Context, defaultSize int) (sharedapi.Pagination, bool) {
	p, err := sharedapi.ParsePaginationStrict(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return p, false
	}
	if _, given := c.GetQuery("page_size"); !given {
		if defaultSize > sharedapi.MaxPageSize {
			defaultSize = sharedapi.MaxPageSize
		}
		p.PageSize = defaultSize
		p.Offset = (p.Page - 1) * p.PageSize
	}
	return p, true
}
