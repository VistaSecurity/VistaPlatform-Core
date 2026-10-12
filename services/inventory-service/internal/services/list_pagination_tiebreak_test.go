package services

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// captureListSQL runs fn against a sqlmock pool whose count query answers 1 and
// whose second statement (the page query) fails after being recorded. It
// returns that page query's text, so a test can assert on the ORDER BY a list
// endpoint really sends — LIMIT/OFFSET only partitions a result set when the
// ordering is total, and a non-unique sort key makes rows repeat or vanish
// across pages.
func captureListSQL(t *testing.T, fn func(db *database.DB)) string {
	t.Helper()
	var seen []string
	matcher := sqlmock.QueryMatcherFunc(func(_, actual string) error {
		seen = append(seen, actual)
		return nil
	})
	raw, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(matcher))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	mock.ExpectBegin()
	mock.ExpectExec("set_tenant_context").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("count").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery("page").WillReturnError(errors.New("stop after capture"))
	mock.ExpectRollback()

	fn(&database.DB{DB: sqlx.NewDb(raw, "postgres")})

	var page string
	for _, q := range seen {
		if strings.Contains(q, "LIMIT") && !strings.Contains(q, "COUNT(*)") {
			page = q
		}
	}
	if page == "" {
		t.Fatalf("no paged query captured; saw %d statements: %v", len(seen), seen)
	}
	return regexp.MustCompile(`\s+`).ReplaceAllString(page, " ")
}

func assertOrderEndsWith(t *testing.T, sql, tiebreak string) {
	t.Helper()
	re := regexp.MustCompile(`ORDER BY [^;]*?` + regexp.QuoteMeta(tiebreak) + `\s+LIMIT`)
	if !re.MatchString(sql) {
		t.Fatalf("ORDER BY must end with the unique tie-breaker %q before LIMIT; query: %s", tiebreak, sql)
	}
}

func TestListQueries_OrderByCarriesUniqueTieBreaker(t *testing.T) {
	tenant := uuid.New()

	t.Run("certificates", func(t *testing.T) {
		for _, sortBy := range []string{"", "not_after", "common_name", "issuer", "key_size", "created_at", "deployment_count", "data_source"} {
			for _, order := range []string{"asc", "desc"} {
				sql := captureListSQL(t, func(db *database.DB) {
					_, _, _ = NewCertificateService(db, nil).GetCertificates(tenant, models.CertificateFilters{Page: 2, PageSize: 10, SortBy: sortBy, SortOrder: order})
				})
				assertOrderEndsWith(t, sql, ", id")
			}
		}
	})

	t.Run("crypto implementations", func(t *testing.T) {
		for _, sortBy := range []string{"", "last_verified_at", "first_discovered_at", "risk_score", "protocol", "protocol_version", "created_at"} {
			sql := captureListSQL(t, func(db *database.DB) {
				_, _, _ = NewCryptoImplementationService(db).GetCryptoImplementations(tenant, models.CryptoImplementationFilters{Page: 1, PageSize: 10, SortBy: sortBy, SortOrder: "desc"})
			})
			assertOrderEndsWith(t, sql, ", ci.id")
		}
	})

	t.Run("external connections", func(t *testing.T) {
		for _, sortBy := range []string{"", "last_seen_at", "dest_hostname", "dest_ip", "source_ip", "protocol", "observation_count", "strength"} {
			for _, order := range []string{"asc", "desc"} {
				sql := captureListSQL(t, func(db *database.DB) {
					_, _, _ = NewExternalConnectionsService(db, nil).List(tenant, models.ExternalConnectionFilters{Page: 1, PageSize: 10, SortBy: sortBy, SortOrder: order})
				})
				assertOrderEndsWith(t, sql, ", id")
			}
		}
	})
}

// The list projection must not carry the certificate PEM: a kilobyte or more
// per row, times a full page, for a column no list consumer reads. The detail
// endpoint (GetByID) still returns it.
func TestExternalConnectionsList_DoesNotSelectCertPEM(t *testing.T) {
	sql := captureListSQL(t, func(db *database.DB) {
		_, _, _ = NewExternalConnectionsService(db, nil).List(uuid.New(), models.ExternalConnectionFilters{Page: 1, PageSize: 10})
	})
	if strings.Contains(sql, "cert_pem") {
		t.Fatalf("external-connections list query must not select cert_pem; query: %s", sql)
	}
}

// The remediation queue bound its page_size with no maximum, so ?page_size=1e9
// asked Postgres for the whole materialized view, and an unbounded page
// overflowed OFFSET.
func TestRemediationQueue_ClampsPageSizeAndPage(t *testing.T) {
	raw, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	tenant := uuid.New()
	mock.ExpectBegin()
	mock.ExpectExec("set_tenant_context").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT COUNT\(\*\)`).WithArgs(tenant).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	// LIMIT clamped to 100; OFFSET = (1_000_000-1)*100, positive.
	mock.ExpectQuery(`LIMIT`).WithArgs(tenant, 100, 99_999_900).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}))
	mock.ExpectCommit()

	svc := NewOperationalService(&database.DB{DB: sqlx.NewDb(raw, "postgres")})
	_, _, err = svc.GetRemediationQueue(tenant, models.RemediationQueueFilters{Page: 1 << 62, PageSize: 1_000_000_000})
	if err != nil {
		t.Fatalf("GetRemediationQueue: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
