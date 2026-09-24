package service

import (
	"database/sql"
	"io"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"

	"github.com/vistasecurity/vistaplatform/services/resource-tracker-service/internal/repository"
)

// RC-14: when the usage read fails, the resource summary must FAIL, not answer
// with defaults. It used to return 200 with resource_efficiency_score 75 and
// zero cost, which tenant-health-service scored as a measurement — so the cost
// factor of the health index came from the default. An error makes the caller
// list resource-tracker-service as unavailable and report the factor unknown.
func TestGetTenantResourceHealthSummary_ReadFailureIsAnErrorNotDefaults(t *testing.T) {
	// sql.Open is lazy: this pool never connects, so every query errors.
	db, err := sql.Open("postgres", "postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	log := logrus.New()
	log.SetOutput(io.Discard)
	svc := NewResourceService(repository.NewResourceRepository(db, db), nil, nil, false, log)

	summary, err := svc.GetTenantResourceHealthSummary(uuid.New())
	if err == nil {
		t.Fatalf("usage read failed but the summary succeeded with %+v — a default is indistinguishable from a measurement", summary)
	}
	if summary != nil {
		t.Fatalf("summary = %+v on error, want nil", summary)
	}
}
