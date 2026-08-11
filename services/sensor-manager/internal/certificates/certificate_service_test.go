package certificates

import (
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

func TestRevokeCertificatesExceptKeepsReplacementSerialActive(t *testing.T) {
	bypassDB, bypassMock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock bypass db: %v", err)
	}
	defer func() { _ = bypassDB.Close() }()

	sensorID := uuid.New()
	service := NewCertificateService(bypassDB, bypassDB, "test-key")

	bypassMock.ExpectExec(`UPDATE sensor_certificates\s+SET revoked_at = NOW\(\), revocation_reason = \$1\s+WHERE sensor_id = \$2\s+AND serial_number <> \$3\s+AND revoked_at IS NULL`).
		WithArgs("rotated", sensorID, "replacement-serial").
		WillReturnResult(sqlmock.NewResult(0, 2))

	if err := service.RevokeCertificatesExcept(sensorID, "replacement-serial", "rotated"); err != nil {
		t.Fatalf("RevokeCertificatesExcept returned error: %v", err)
	}
	if err := bypassMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("bypass expectations: %v", err)
	}
}
