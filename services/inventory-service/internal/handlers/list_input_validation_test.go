package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// recordingCertStore records the arguments the expiring handler passes down.
type recordingCertStore struct {
	*stubCertificateStore
	called       bool
	days, limit  int
	gotFilters   models.CertificateFilters
	filtersCalls int
}

func (s *recordingCertStore) GetExpiringCertificates(_ uuid.UUID, days, limit int, _ ...int) ([]models.Certificate, error) {
	s.called, s.days, s.limit = true, days, limit
	return nil, nil
}

func (s *recordingCertStore) GetCertificates(_ uuid.UUID, f models.CertificateFilters) ([]models.Certificate, int, error) {
	s.filtersCalls++
	s.gotFilters = f
	return nil, 0, nil
}

func listInputEngine(cert *recordingCertStore, op *stubOperationalStore, ph *AssetPhase1Handler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})
	ch := NewCertificateHandler(cert)
	r.GET("/certificates/expiring", ch.GetExpiringCertificates)
	r.GET("/certificates/search", ch.SearchCertificates)
	oh := &OperationalHandler{operational: op}
	r.GET("/locations/:id/environments/:env/assets", oh.GetEnvironmentAssets)
	r.GET("/merge-proposals", ph.ListMergeProposals)
	r.GET("/merge-proposals/auto-accepted", ph.ListAutoAcceptedMerges)
	return r
}

func getStatus(r *gin.Engine, path string) int {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w.Code
}

func TestListInputs_GarbageIs400AndNeverReachesTheService(t *testing.T) {
	loc := uuid.NewString()
	for _, tc := range []struct{ name, path string }{
		{"expiring days non-numeric", "/certificates/expiring?days=abc"},
		{"expiring days zero", "/certificates/expiring?days=0"},
		{"expiring days beyond bound", "/certificates/expiring?days=9223372036854775807"},
		{"expiring limit non-numeric", "/certificates/expiring?limit=lots"},
		{"expiring limit negative", "/certificates/expiring?limit=-5"},
		{"expiring lookback_days garbage", "/certificates/expiring?lookback_days=x"},
		{"search key_size_min garbage", "/certificates/search?key_size_min=big"},
		{"search expiring_days garbage", "/certificates/search?expiring_days=soon"},
		{"env assets page_size garbage", "/locations/" + loc + "/environments/production/assets?page_size=abc"},
		{"env assets page_size zero", "/locations/" + loc + "/environments/production/assets?page_size=0"},
		{"env assets page negative", "/locations/" + loc + "/environments/production/assets?page=-1"},
		{"merge proposals limit garbage", "/merge-proposals?limit=ten"},
		{"merge proposals offset garbage", "/merge-proposals?offset=zz"},
		{"auto-accepted limit garbage", "/merge-proposals/auto-accepted?limit=ten"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := &recordingCertStore{stubCertificateStore: &stubCertificateStore{}}
			ph := NewAssetPhase1Handler(&stubChildStore{}, &stubClassStore{}, &stubSavedViewStore{}, &stubProposalStore{})
			r := listInputEngine(cert, &stubOperationalStore{}, ph)
			if got := getStatus(r, tc.path); got != http.StatusBadRequest {
				t.Fatalf("GET %s = %d, want 400", tc.path, got)
			}
			if cert.called || cert.filtersCalls > 0 {
				t.Fatalf("a rejected request must not reach the store")
			}
		})
	}
}

func TestExpiringCertificates_ClampsLimitAndAcceptsBoundaryDays(t *testing.T) {
	cert := &recordingCertStore{stubCertificateStore: &stubCertificateStore{}}
	ph := NewAssetPhase1Handler(&stubChildStore{}, &stubClassStore{}, &stubSavedViewStore{}, &stubProposalStore{})
	r := listInputEngine(cert, &stubOperationalStore{}, ph)
	if got := getStatus(r, "/certificates/expiring?days=3650&limit=1000000"); got != http.StatusOK {
		t.Fatalf("status = %d, want 200", got)
	}
	if cert.days != 3650 || cert.limit != 500 {
		t.Fatalf("days=%d limit=%d, want 3650 and limit clamped to 500", cert.days, cert.limit)
	}
}

func TestExpiringCertificates_DefaultsUnchanged(t *testing.T) {
	cert := &recordingCertStore{stubCertificateStore: &stubCertificateStore{}}
	ph := NewAssetPhase1Handler(&stubChildStore{}, &stubClassStore{}, &stubSavedViewStore{}, &stubProposalStore{})
	r := listInputEngine(cert, &stubOperationalStore{}, ph)
	if got := getStatus(r, "/certificates/expiring"); got != http.StatusOK {
		t.Fatalf("status = %d, want 200", got)
	}
	if cert.days != 30 || cert.limit != 100 {
		t.Fatalf("days=%d limit=%d, want defaults 30 and 100", cert.days, cert.limit)
	}
}

func TestSearchCertificates_ValidFiltersStillApplied(t *testing.T) {
	cert := &recordingCertStore{stubCertificateStore: &stubCertificateStore{}}
	ph := NewAssetPhase1Handler(&stubChildStore{}, &stubClassStore{}, &stubSavedViewStore{}, &stubProposalStore{})
	r := listInputEngine(cert, &stubOperationalStore{}, ph)
	if got := getStatus(r, "/certificates/search?key_size_min=2048&expiring_days=30&page=9223372036854775807"); got != http.StatusOK {
		t.Fatalf("status = %d, want 200", got)
	}
	f := cert.gotFilters
	if f.KeySizeMin == nil || *f.KeySizeMin != 2048 || f.ExpiringDays == nil || *f.ExpiringDays != 30 {
		t.Fatalf("filters not applied: %+v", f)
	}
	if f.Page != 1_000_000 {
		t.Fatalf("page = %d, want the cap 1000000 (an uncapped page overflows OFFSET)", f.Page)
	}
}
