package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAccessLog_KeepsThePathAndDropsTheQuery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var logs bytes.Buffer
	prev := gin.DefaultWriter
	gin.DefaultWriter = &logs
	t.Cleanup(func() { gin.DefaultWriter = prev })

	r := gin.New()
	r.Use(AccessLog())
	r.GET("/cb", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/cb?code=SECRET&%63ode=ENCODED&state=X", nil))

	out := logs.String()
	if !strings.Contains(out, "/cb") || !strings.Contains(out, "204") {
		t.Fatalf("log line lost the path or status: %q", out)
	}
	for _, leak := range []string{"SECRET", "ENCODED", "state=", "code="} {
		if strings.Contains(out, leak) {
			t.Errorf("log line contains %q: %q", leak, out)
		}
	}
}
