package jobs

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
)

type fakeSweeper struct {
	out []services.ExpiredSuppression
	err error
}

func (f fakeSweeper) ExpireSuppressions(context.Context) ([]services.ExpiredSuppression, error) {
	return f.out, f.err
}

// Each affected tenant is reconciled once, however many findings it had, and a
// failed later batch does not strand the tenants already reopened.
func TestSuppressionExpiryJob_EnqueuesEachTenantOnce(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	got := map[uuid.UUID]int{}
	job := NewSuppressionExpiryJob(fakeSweeper{
		out: []services.ExpiredSuppression{{TenantID: a}, {TenantID: a}, {TenantID: b}},
		err: errors.New("batch 2 failed"),
	}, func(tenant uuid.UUID, _ string) { got[tenant]++ })

	if err := job.Run(context.Background()); err == nil {
		t.Fatal("the sweep error was swallowed")
	}
	if got[a] != 1 || got[b] != 1 || len(got) != 2 {
		t.Fatalf("enqueued = %v, want each tenant exactly once", got)
	}
}

func TestSuppressionExpiryJob_NilEnqueuerIsFine(t *testing.T) {
	job := NewSuppressionExpiryJob(fakeSweeper{out: []services.ExpiredSuppression{{TenantID: uuid.New()}}}, nil)
	if err := job.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
}
