package services

// A failed registration-key lookup used to write the key it was handed, whole,
// into the pod log — an enrolment credential readable by anyone who can read
// sensor-manager's logs, while every other place that prints the key masks it.
// Driven through RegisterSensor itself so the log line the service really
// writes is what is inspected.

import (
	"bytes"
	"database/sql"
	"log"
	"os"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
)

func TestRegisterSensor_FailedKeyLookupDoesNotLogTheKey(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	const key = "abcd1234-NEAR-MISS-OF-A-LIVE-KEY-5678"
	mock.ExpectBegin()
	mock.ExpectQuery(`FROM pending_sensor_registrations p`).WithArgs(key).WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`FROM pending_sensor_registrations WHERE registration_key`).WithArgs(key).WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	svc := &SensorService{db: db, bypassDB: db}
	if _, err := svc.RegisterSensor(&models.SensorRegistration{RegistrationKey: key}); err == nil {
		t.Fatal("registering with an unknown key succeeded")
	}

	out := logged.String()
	if !strings.Contains(out, "Registration key lookup failed") {
		t.Fatalf("the failed-lookup diagnostic is gone; the test is not exercising the branch. log=%q", out)
	}
	if strings.Contains(out, key) || strings.Contains(out, "NEAR-MISS") {
		t.Fatalf("the registration key was written to the log: %q", out)
	}
	if !strings.Contains(out, "abcd") {
		t.Fatalf("the masked prefix is gone, so the diagnostic cannot be correlated: %q", out)
	}
}
