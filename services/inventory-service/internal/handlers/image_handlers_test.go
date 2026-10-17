package handlers

// The image upload endpoint through the real handler and the real
// ImageService (no database is reached: the size and type checks run before
// any query). Mutation: remove the size check in the handler AND sniffImage →
// the 6 MB case answers 201 path; remove the type check → the .exe is accepted.

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

func uploadRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set(sharedmw.CtxKeyTenantID, uuid.New()) })
	h := NewImageHandler(services.NewImageService(nil, services.NewMemoryBlobStore()))
	r.POST("/objects/:kind/:id/images", h.Upload)
	return r
}

func postFile(t *testing.T, r http.Handler, name string, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	fw, _ := w.CreateFormFile("file", name)
	_, _ = fw.Write(data)
	_ = w.Close()
	req := httptest.NewRequest(http.MethodPost, "/objects/site/"+uuid.NewString()+"/images", &b)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestImageUpload_RejectsOversizeAndNonImages(t *testing.T) {
	r := uploadRouter()
	if rec := postFile(t, r, "big.png", append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 6<<20)...)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("6 MB upload: %d %s, want 413", rec.Code, rec.Body.String())
	}
	if rec := postFile(t, r, "tool.exe", []byte("MZ\x90\x00 program")); rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf(".exe upload: %d %s, want 415", rec.Code, rec.Body.String())
	}
	if rec := postFile(t, r, "x.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg" onload="x()"/>`)); rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("scripted svg: %d, want 415", rec.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "/objects/site/"+uuid.NewString()+"/images", bytes.NewReader(nil))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("no multipart body: %d, want 400", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/objects/nonsense/"+uuid.NewString()+"/images", nil)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown kind: %d, want 400", rec.Code)
	}
}
