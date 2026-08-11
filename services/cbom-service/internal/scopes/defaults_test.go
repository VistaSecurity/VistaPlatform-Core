package scopes

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// The default scopes are seeded lazily on a tenant's first GET /scopes. Two
// concurrent first requests both read a count of zero and both insert; the
// loser hit the (tenant_id, name) UNIQUE constraint and the error was returned
// verbatim, so an ordinary first page load 500'd. The row it collided with is
// the row it wanted, so the collision is success.

func expectSeedInsert(mock sqlmock.Sqlmock, tenantID uuid.UUID, err error) {
	mock.ExpectBegin()
	mock.ExpectExec("set_config").WithArgs(tenantID.String()).
		WillReturnResult(sqlmock.NewResult(0, 0))
	q := mock.ExpectQuery("INSERT INTO public.scopes")
	if err != nil {
		q.WillReturnError(err)
		mock.ExpectRollback()
		return
	}
	q.WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at", "version"}).
		AddRow(uuid.New(), time.Now(), time.Now(), 1))
	mock.ExpectCommit()
}

func expectCount(mock sqlmock.Sqlmock, tenantID uuid.UUID, count int) {
	mock.ExpectBegin()
	mock.ExpectExec("set_config").WithArgs(tenantID.String()).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT COUNT").WillReturnRows(
		sqlmock.NewRows([]string{"count"}).AddRow(count))
	mock.ExpectCommit()
}

func TestSeedDefaults_ConcurrentSeedIsNotAnError(t *testing.T) {
	repo, mock := newMockRepo(t)
	tenantID := uuid.New()
	seededBy := uuid.New()

	expectCount(mock, tenantID, 0)
	// Another request wins the race on the second and third scopes.
	expectSeedInsert(mock, tenantID, nil)
	expectSeedInsert(mock, tenantID, &pq.Error{Code: "23505", Message: `duplicate key value violates unique constraint "scopes_tenant_id_name_key"`})
	expectSeedInsert(mock, tenantID, &pq.Error{Code: "23505"})

	seeded, err := repo.SeedDefaultsIfMissing(context.Background(), tenantID, seededBy)
	if err != nil {
		t.Fatalf("a concurrent seed must not fail the request: %v", err)
	}
	if !seeded {
		t.Error("seeded = false although one scope was created by this call")
	}
}

func TestSeedDefaults_RealErrorsStillSurface(t *testing.T) {
	repo, mock := newMockRepo(t)
	tenantID := uuid.New()

	expectCount(mock, tenantID, 0)
	expectSeedInsert(mock, tenantID, errors.New("connection reset by peer"))

	_, err := repo.SeedDefaultsIfMissing(context.Background(), tenantID, uuid.New())
	if err == nil {
		t.Fatal("a genuine failure must not be swallowed by the duplicate-key tolerance")
	}
}

func TestSeedDefaults_SkipsWhenScopesExist(t *testing.T) {
	repo, mock := newMockRepo(t)
	tenantID := uuid.New()

	expectCount(mock, tenantID, 3)

	seeded, err := repo.SeedDefaultsIfMissing(context.Background(), tenantID, uuid.New())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if seeded {
		t.Error("seeded = true for a tenant that already has scopes")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations (an insert was attempted?): %v", err)
	}
}

func TestIsDuplicateScope(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"pq unique violation", &pq.Error{Code: "23505"}, true},
		{"pq other violation", &pq.Error{Code: "23503"}, false},
		{"wrapped pq unique violation", fmt.Errorf("seed: %w", &pq.Error{Code: "23505"}), true},
		{"driver-agnostic text", errors.New(`pq: duplicate key (SQLSTATE 23505)`), true},
		{"unrelated", errors.New("connection reset"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsDuplicateScope(c.err); got != c.want {
				t.Fatalf("IsDuplicateScope(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// TestSystemDefaults_NonDevTestIsExcludeShaped guards the seed itself: the
// scope's whole meaning is its Exclude clause, which the generator ignored
// until the scope-evaluation fix.
func TestSystemDefaults_NonDevTestIsExcludeShaped(t *testing.T) {
	defaults := systemDefaults(uuid.New(), uuid.New())
	var nonDevTest *Scope
	for i := range defaults {
		if defaults[i].Name == string(DefaultNonDevTest) {
			nonDevTest = &defaults[i]
		}
	}
	if nonDevTest == nil {
		t.Fatal("Non-Dev/Test default is missing")
	}
	if nonDevTest.Predicate.Exclude == nil {
		t.Fatal("Non-Dev/Test has no Exclude clause")
	}
	if len(nonDevTest.Predicate.Exclude.TagsAnyOf) == 0 {
		t.Error("Non-Dev/Test lost its tag arm — assets with no environment column would slip in")
	}
	if nonDevTest.Predicate.IsEmpty() {
		t.Error("Non-Dev/Test reads as an empty predicate, which would make it identical to All")
	}
}
