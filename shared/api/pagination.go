package api

import (
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

// ParsePagination extracts page/page_size from query params with defaults and bounds.
func ParsePagination(c *gin.Context) Pagination {
	page := 1
	if v, err := strconv.Atoi(c.Query("page")); err == nil && v > 0 {
		page = v
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
