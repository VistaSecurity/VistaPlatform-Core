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

// A body declared above the ceiling is refused 413 before a byte is read.
func TestRequestBodyLimit_RefusesDeclaredOversizeBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/bind", io.LimitReader(zeroReader{}, 100<<20))
	req.ContentLength = 100 << 20
	w := httptest.NewRecorder()
	bodyLimitRouter().ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", w.Code)
	}
}

// A chunked body declares no length; the reader stops it at the ceiling and the
// handler's bind fails rather than buffering it all.
func TestRequestBodyLimit_StopsAnUndeclaredStream(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/bind", io.LimitReader(zeroReader{}, 100<<20))
	req.ContentLength = -1
	w := httptest.NewRecorder()
	bodyLimitRouter().ServeHTTP(w, req)
	if w.Code == http.StatusOK {
		t.Fatalf("an undeclared 100 MiB body was accepted")
	}
}

func TestRequestBodyLimit_AcceptsANormalBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/bind", strings.NewReader(`{"title":"a ticket"}`))
	w := httptest.NewRecorder()
	bodyLimitRouter().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

// The tests above prove the middleware; this pins that the real router in
// main.go mounts it, ahead of the audit and resource-tracking middleware that
// can touch the body. Delete the router.Use line and this fails.
func TestMainMountsTheRequestBodyLimitFirst(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	use := strings.Index(s, "router.Use(requestBodyLimit())")
	if use < 0 {
		t.Fatal("main.go no longer calls router.Use(requestBodyLimit())")
	}
	for _, later := range []string{"router.Use(resourcetracking.Middleware(", "router.Use(auditMiddleware.LogRequest())"} {
		i := strings.Index(s, later)
		if i < 0 {
			t.Fatalf("main.go no longer contains %q", later)
		}
		if use > i {
			t.Errorf("requestBodyLimit must be mounted before %q", later)
		}
	}
}

// 1 MiB is the documented ceiling: a body just over it is refused, one just
// under it is read.
func TestRequestBodyLimit_CeilingIsOneMiB(t *testing.T) {
	if maxRequestBodyBytes != 1<<20 {
		t.Fatalf("maxRequestBodyBytes = %d, want 1 MiB", maxRequestBodyBytes)
	}
}
