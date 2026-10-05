package services

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jmoiron/sqlx"

	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// NewPlanJobProcessorForTest is a job processor over db whose scan-plan engine
// reaches the network only through dialer (a FakeNet), with an alert service
// whose notification endpoint answers 200.
func NewPlanJobProcessorForTest(t *testing.T, db *sqlx.DB, svc *DiscoveryService, dialer shareddisc.Dialer) *JobProcessor {
	t.Helper()
	notify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(notify.Close)
	t.Setenv("NOTIFICATION_SERVICE_URL", notify.URL)
	return &JobProcessor{
		db: db, bypassDB: db, discoveryService: svc, rateLimiter: NewRateLimiter(db),
		alertService:      &AlertService{db: db, httpClient: notify.Client()},
		planEngineOptions: []shareddisc.Option{shareddisc.WithDialer(dialer)},
	}
}

// DeliverJobForTest hands jobID's message to the processor exactly as
// JetStream does (handleDiscoveryJob, the real entry point).
func (jp *JobProcessor) DeliverJobForTest(t *testing.T, jobID string) error {
	return jp.handleDiscoveryJob(jobMessage(t, jobID), &countingLease{})
}
