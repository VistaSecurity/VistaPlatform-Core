package resourcetracking

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func ctxFor(method, path string) *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(method, path, nil)
	return c
}

// TestExtractDatabaseQueries_NotCountedIsNotMeasured pins the deletion of the
// query-count fabrication (audit finding B-38, defect 3).
//
// The previous implementation guessed the number of database queries a request
// made from its HTTP method and THE LENGTH OF ITS URL PATH: a GET to a path
// longer than ten characters "was" one query, a write "was" two. Every
// database_queries value the platform ever stored came from that guess and was
// then priced per query as though counted. No service instruments the counter
// today, so the honest answer is nil.
func TestExtractDatabaseQueries_NotCountedIsNotMeasured(t *testing.T) {
	tr := &Tracker{}

	cases := []struct{ method, path string }{
		{"GET", "/api/v1/inventory-service/assets"},   // long path: guessed 1
		{"POST", "/api/v1/inventory-service/assets"},  // write: guessed 2
		{"DELETE", "/api/v1/inventory-service/a/b/c"}, // guessed 1
		{"GET", "/x"}, // short path: guessed 1
	}

	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			if got := tr.extractDatabaseQueries(ctxFor(tc.method, tc.path)); got != nil {
				t.Fatalf("query count %d was invented from the request shape; nothing counted it", *got)
			}
		})
	}
}

// TestExtractDatabaseQueries_InstrumentedServiceIsCounted keeps the opt-in path
// working: a service that actually counts its queries reports the real number.
func TestExtractDatabaseQueries_InstrumentedServiceIsCounted(t *testing.T) {
	tr := &Tracker{}

	c := ctxFor("GET", "/api/v1/inventory-service/assets")
	c.Set("db_queries", 7)

	got := tr.extractDatabaseQueries(c)
	if got == nil {
		t.Fatal("an instrumented service's count was dropped")
	}
	if *got != 7 {
		t.Fatalf("db queries = %d, want 7", *got)
	}
}

// TestSendBatch_AggregatesCountersAndPreservesUnmeasured pins the batch
// aggregation. API calls and payload bytes are counters and sum; a request that
// did not count its queries must not fold in as a zero.
func TestBatchAggregation_CountersSumAndUnmeasuredStaysNil(t *testing.T) {
	tenant := uuid.New()

	metrics := []ResourceMetrics{
		{TenantID: tenant, APICalls: 1, NetworkBytes: 500},
		{TenantID: tenant, APICalls: 1, NetworkBytes: 250},
		{TenantID: tenant, APICalls: 1, NetworkBytes: 125},
	}

	agg := aggregateByTenant(metrics)[tenant]

	if agg.APICalls != 3 {
		t.Fatalf("api calls = %d, want 3", agg.APICalls)
	}
	if agg.NetworkBytes != 875 {
		t.Fatalf("network bytes = %d, want 875", agg.NetworkBytes)
	}
	if agg.DatabaseQueries != nil {
		t.Fatalf("database queries = %d; no request in the batch counted any", *agg.DatabaseQueries)
	}
}

// TestBatchAggregation_PartialCountsSumOverReportersOnly checks that a batch
// where only some requests instrumented their queries reports the sum of those
// that did, rather than nil or a zero-padded total.
func TestBatchAggregation_PartialCountsSumOverReportersOnly(t *testing.T) {
	tenant := uuid.New()
	four, six := int64(4), int64(6)

	metrics := []ResourceMetrics{
		{TenantID: tenant, APICalls: 1, DatabaseQueries: &four},
		{TenantID: tenant, APICalls: 1}, // did not count
		{TenantID: tenant, APICalls: 1, DatabaseQueries: &six},
	}

	agg := aggregateByTenant(metrics)[tenant]

	if agg.DatabaseQueries == nil {
		t.Fatal("counts reported by two of three requests were discarded entirely")
	}
	if *agg.DatabaseQueries != 10 {
		t.Fatalf("database queries = %d, want 10", *agg.DatabaseQueries)
	}
}
