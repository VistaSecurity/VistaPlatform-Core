package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/database"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
)

// fakeSensorRepo implements only the two methods DeleteSensor touches. The
// interface is embedded (nil) so the rest of it stays unimplemented — calling
// anything else panics loudly rather than silently succeeding.
type fakeSensorRepo struct {
	database.SensorRepository
	sensor     *models.Sensor
	getErr     error
	deleteCall int
}

func (f *fakeSensorRepo) GetSensorByIDForTenant(_ context.Context, _, _ uuid.UUID) (*models.Sensor, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.sensor, nil
}

func (f *fakeSensorRepo) DeleteSensor(_ context.Context, _, _ uuid.UUID) error {
	f.deleteCall++
	return nil
}

// The server-side guard is the authoritative one — the UI hiding the button is a
// convenience, and the DELETE route is reachable directly. Both polarities are
// asserted: the platform row must be refused AND the ordinary sensor must still
// delete. An over-strict guard that blocks legitimate deletion is the same bug
// pointed the other way.
func TestDeleteSensor_PlatformGuard(t *testing.T) {
	cases := []struct {
		name       string
		sensor     *models.Sensor
		wantRefuse bool
	}{
		{"platform discovery sensor", &models.Sensor{Platform: "platform", Tags: []string{"system", "platform", "discovery"}}, true},
		{"platform interrogation agent", &models.Sensor{Platform: "platform", Tags: []string{"system", "platform", "device_interrogation"}}, true},
		{"system tag only", &models.Sensor{Platform: "linux", Tags: []string{"system"}}, true},

		{"customer linux sensor", &models.Sensor{Platform: "linux", Tags: []string{"edge"}}, false},
		{"customer sensor with interrogation profile", &models.Sensor{Platform: "linux", Profile: "device_interrogation"}, false},
		{"customer sensor, no tags", &models.Sensor{Platform: "windows"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeSensorRepo{sensor: tc.sensor}
			svc := NewSensorServiceV2(repo)

			err := svc.DeleteSensor(context.Background(), uuid.New(), uuid.New())

			if tc.wantRefuse {
				if !errors.Is(err, ErrPlatformSensorProtected) {
					t.Fatalf("want ErrPlatformSensorProtected, got %v", err)
				}
				if repo.deleteCall != 0 {
					t.Errorf("repo.DeleteSensor was called %d times; the row must not be touched", repo.deleteCall)
				}
				return
			}

			if err != nil {
				t.Fatalf("ordinary sensor must still delete, got %v", err)
			}
			if repo.deleteCall != 1 {
				t.Errorf("repo.DeleteSensor called %d times, want 1", repo.deleteCall)
			}
		})
	}
}

// A lookup failure must not read as "not platform-managed" and fall through to
// the delete — failing open on the guard's own input is how a guard becomes
// inert.
func TestDeleteSensor_LookupFailureDoesNotDelete(t *testing.T) {
	repo := &fakeSensorRepo{getErr: errors.New("database is on fire")}
	svc := NewSensorServiceV2(repo)

	if err := svc.DeleteSensor(context.Background(), uuid.New(), uuid.New()); err == nil {
		t.Fatal("want an error when the sensor cannot be loaded")
	}
	if repo.deleteCall != 0 {
		t.Errorf("repo.DeleteSensor was called %d times after a failed lookup", repo.deleteCall)
	}
}
