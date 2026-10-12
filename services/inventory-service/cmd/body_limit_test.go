package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}

func bodyLimitRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(requestBodyLimit())
	r.POST("/bind", func(c *gin.Context) {
		var v map[string]any
		if err := c.ShouldBindJSON(&v); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "bad"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

// A 100 MB body declared up front is refused 413 before a byte is read.
func TestRequestBodyLimit_RefusesOversizeBody(t *testing.T) {
	r := bodyLimitRouter()
	req := httptest.NewRequest(http.MethodPost, "/bind", io.LimitReader(zeroReader{}, 100<<20))
	req.ContentLength = 100 << 20
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", w.Code)
	}
}

func TestRequestBodyLimit_AcceptsNormalBody(t *testing.T) {
	r := bodyLimitRouter()
	req := httptest.NewRequest(http.MethodPost, "/bind", strings.NewReader(`{"a":1}`))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

// The unit tests above prove the middleware; this pins that the real router in
// main.go mounts it, ahead of the audit and resource-tracking middleware that
// can touch the body. Delete the r.Use line and this fails.
func TestMainMountsTheRequestBodyLimitFirst(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	use := strings.Index(s, "r.Use(requestBodyLimit())")
	if use < 0 {
		t.Fatal("main.go no longer calls r.Use(requestBodyLimit())")
	}
	for _, later := range []string{"r.Use(resourcetracking.Middleware(", "r.Use(auditMiddleware.LogRequest())"} {
		i := strings.Index(s, later)
		if i < 0 {
			t.Fatalf("main.go no longer contains %q", later)
		}
		if use > i {
			t.Errorf("requestBodyLimit must be mounted before %q", later)
		}
	}
}
