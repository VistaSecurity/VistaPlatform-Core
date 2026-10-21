package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// GetLocationFloorPlan handles GET /dcim/locations/:id/floor-plan (DCIM gap
// 9): the location's plan size and every rack in the location, placed or not,
// with its footprint, utilisation and power budget. Racks are placed through
// the rack PATCH (floor_x / floor_y / floor_rotation).
func (h *SiteHandler) GetLocationFloorPlan(c *gin.Context) {
	tid, ok := getTenantID(c)
	id, ok2 := pathID(c)
	if !ok || !ok2 {
		return
	}
	v, err := h.svc.LocationFloorPlan(c.Request.Context(), tid, id)
	respond(c, http.StatusOK, v, err)
}
