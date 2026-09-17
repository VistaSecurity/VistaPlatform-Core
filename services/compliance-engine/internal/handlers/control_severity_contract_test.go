package handlers

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// Drive the actual authoring handler: deleting its bind validation lets the
// request through to a nil service and fails this test instead of staying green.
func TestContract_PlatformControlRejectsNoncanonicalSeverity(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewPlatformFrameworkHandlers(nil)
	for _, value := range []string{"High", "Med", "info", "bogus", ""} {
		router := gin.New()
		router.POST("/frameworks/:id/controls", handler.CreateControl)
		w := do(router, http.MethodPost, "/frameworks/"+aUUID+"/controls", strings.NewReader(`{"control_id":"C-1","title":"Invalid grade","baseline_severity":"`+value+`"}`))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("severity %q accepted: %d %s", value, w.Code, w.Body.String())
		}
	}
}
