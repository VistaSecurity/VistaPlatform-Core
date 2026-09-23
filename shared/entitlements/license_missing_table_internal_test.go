package entitlements

import (
	"bytes"
	"context"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
)

// A database with no platform_license table (a new image running before the
// schema migration has created it) is Core, not a resolver error that would
// fail every gate closed. Only that SQLSTATE: any other error is still an
// error. Logged once per process, not once per resolution.
func TestLoadLicense_UndefinedTableIsCore(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	FlushLicenseCache()
	t.Cleanup(FlushLicenseCache)
	missingTableLogged = sync.Once{}

	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	q := regexp.QuoteMeta(selectLicenseSQL)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		FlushLicenseCache()
		mock.ExpectQuery(q).WillReturnError(&pq.Error{Code: "42P01", Message: `relation "platform_license" does not exist`})
		lic, err := LoadLicense(ctx, db)
		if err != nil || lic != nil {
			t.Fatalf("load %d with no platform_license table: lic=%+v err=%v, want nil, nil (Core)", i, lic, err)
		}
	}
	if n := strings.Count(logs.String(), "platform_license does not exist yet"); n != 1 {
		t.Errorf("missing-table log lines = %d, want exactly 1:\n%s", n, logs.String())
	}

	// Positive control: a different SQLSTATE (permission denied) is NOT Core.
	FlushLicenseCache()
	mock.ExpectQuery(q).WillReturnError(&pq.Error{Code: "42501", Message: "permission denied for table platform_license"})
	if _, err := LoadLicense(ctx, db); err == nil {
		t.Fatal("permission denied on platform_license was read as Core — only undefined_table may be")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
