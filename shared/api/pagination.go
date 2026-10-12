package api

import (
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"
)

// Pagination holds parsed and validated pagination parameters.
type Pagination struct {
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
	Offset   int `json:"-"`
}

// DefaultPageSize is used when the caller doesn't specify one.
const DefaultPageSize = 20

// MaxPageSize prevents excessively large pages.
const MaxPageSize = 100

// MaxPage caps the page number so (page-1)*pageSize can never overflow an int
// into a negative OFFSET (which Postgres rejects, surfacing as a 500).
const MaxPage = 1_000_000

// MaxOffset caps a limit/offset endpoint's offset; see ParseLimitOffsetStrict.
const MaxOffset = 1_000_000_000

// ParsePaginationStrict is ParsePagination for endpoints that must answer 400
// to a malformed value rather than silently fall back to the default. An
// absent parameter takes the default; a present one must be a positive
// integer. page_size above MaxPageSize is clamped, page above MaxPage is
// clamped, both as in ParsePagination.
func ParsePaginationStrict(c *gin.Context) (Pagination, error) {
	if err := RequirePositiveIntQuery(c, "page", "page_size"); err != nil {
		return Pagination{}, err
	}
	return ParsePagination(c), nil
}

// RequirePositiveIntQuery returns an error naming the first of the given query
// parameters that is present but not a positive integer. An absent parameter
// passes. It is the validation half of ParsePaginationStrict, for list
// endpoints whose store does its own clamping and defaulting.
func RequirePositiveIntQuery(c *gin.Context, names ...string) error {
	for _, name := range names {
		if v, ok := c.GetQuery(name); ok {
			if n, err := strconv.Atoi(v); err != nil || n < 1 {
				return fmt.Errorf("invalid %s: must be a positive integer", name)
			}
		}
	}
	return nil
}

// ParseLimitOffsetStrict is ParsePaginationStrict for limit/offset endpoints.
// Absent limit takes defaultLimit and absent offset takes 0. A present limit
// must be a positive integer and a present offset a non-negative one, else the
// error is for the caller to answer as 400. A limit above maxLimit is clamped
// to it. An offset beyond MaxOffset is clamped so it cannot overflow downstream
// arithmetic.
func ParseLimitOffsetStrict(c *gin.Context, defaultLimit, maxLimit int) (limit, offset int, err error) {
	limit = defaultLimit
	if v, ok := c.GetQuery("limit"); ok {
		n, e := strconv.Atoi(v)
		if e != nil || n < 1 {
			return 0, 0, fmt.Errorf("invalid limit: must be a positive integer")
		}
		limit = n
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	if v, ok := c.GetQuery("offset"); ok {
		n, e := strconv.Atoi(v)
		if e != nil || n < 0 {
			return 0, 0, fmt.Errorf("invalid offset: must be a non-negative integer")
		}
		offset = n
	}
	if offset > MaxOffset {
		offset = MaxOffset
	}
	return limit, offset, nil
}

// ParsePagination extracts page/page_size from query params with defaults and bounds.
func ParsePagination(c *gin.Context) Pagination {
	page := 1
	if v, err := strconv.Atoi(c.Query("page")); err == nil && v > 0 {
		page = v
	}
	if page > MaxPage {
		page = MaxPage
	}
	pageSize := DefaultPageSize
	if v, err := strconv.Atoi(c.Query("page_size")); err == nil && v > 0 {
		pageSize = v
	}
	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}
	return Pagination{
		Page:     page,
		PageSize: pageSize,
		Offset:   (page - 1) * pageSize,
	}
}

// PaginatedResponse is the standard envelope for paginated results.
type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Page       int         `json:"page"`
	PageSize   int         `json:"page_size"`
	Total      int64       `json:"total"`
	TotalPages int         `json:"total_pages"`
	HasNext    bool        `json:"has_next"`
	HasPrev    bool        `json:"has_prev"`
}

// PaginationMeta contains only the pagination metadata fields, suitable for
// embedding in custom response shapes (e.g. gin.H{"assets": ..., "pagination": meta}).
type PaginationMeta struct {
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"total_pages"`
	HasNext    bool  `json:"has_next"`
	HasPrev    bool  `json:"has_prev"`
}

// BuildPaginationMeta computes pagination metadata from the current page params
// and total row count. Use this when the handler needs a custom response shape.
func BuildPaginationMeta(p Pagination, total int64) PaginationMeta {
	totalPages := int(total) / p.PageSize
	if int(total)%p.PageSize > 0 {
		totalPages++
	}
	return PaginationMeta{
		Page:       p.Page,
		PageSize:   p.PageSize,
		Total:      total,
		TotalPages: totalPages,
		HasNext:    p.Page < totalPages,
		HasPrev:    p.Page > 1,
	}
}

// NewPaginatedResponse builds a standard paginated response envelope.
func NewPaginatedResponse(data interface{}, p Pagination, total int64) PaginatedResponse {
	totalPages := int(total) / p.PageSize
	if int(total)%p.PageSize > 0 {
		totalPages++
	}
	return PaginatedResponse{
		Data:       data,
		Page:       p.Page,
		PageSize:   p.PageSize,
		Total:      total,
		TotalPages: totalPages,
		HasNext:    p.Page < totalPages,
		HasPrev:    p.Page > 1,
	}
}
