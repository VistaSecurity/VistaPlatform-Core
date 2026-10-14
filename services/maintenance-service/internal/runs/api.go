package runs

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ListResponse is the body of GET /admin/maintenance/runs.
type ListResponse struct {
	Runs []Run `json:"runs"`
}

// DefaultListLimit is the console's Run history length (spec §1: last 20).
const DefaultListLimit = 20

// ListHandler serves GET /runs?limit=N (1..100, default 20), newest first.
func ListHandler(store Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		limit := DefaultListLimit
		if v := c.Query("limit"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 100 {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_limit", "message": "limit must be 1..100"})
				return
			}
			limit = n
		}
		if store == nil {
			c.JSON(http.StatusOK, ListResponse{Runs: []Run{}})
			return
		}
		list, err := store.List(c.Request.Context(), limit)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal_error", "message": "could not list runs"})
			return
		}
		c.JSON(http.StatusOK, ListResponse{Runs: list})
	}
}

// GetHandler serves GET /runs/:id.
func GetHandler(store Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := uuid.Parse(c.Param("id"))
		if err != nil || store == nil {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "not_found", "message": "no such run"})
			return
		}
		run, err := store.Get(c.Request.Context(), id)
		if errors.Is(err, ErrNotFound) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "not_found", "message": "no such run"})
			return
		}
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal_error", "message": "could not read the run"})
			return
		}
		c.JSON(http.StatusOK, run)
	}
}
