package handlers

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
)

// PUT /sensors/:id/config used to replace a sensor's tags wholesale, so a
// tenant could tag its own sensor `system` and pass every check that recognised
// the platform's sensors by that tag ( review B1). Driven through the REAL
// handler: deleting the ReplaceTenantTags call fails both cases.
func TestUpdateSensorConfig_CannotSetOrStripPlatformMarkers(t *testing.T) {
	put := func(t *testing.T, sensor *models.Sensor, tags string) []string {
		t.Helper()
		eng := newSensorConfigEngine(&stubLegacySensorService{getSensor: sensor}, &stubSensorRepo{getSensor: sensor})
		w := do(eng, http.MethodPut, "/api/v1/sensor-manager/sensors/"+sensor.ID.String()+"/config",
			strings.NewReader(`{"tags":`+tags+`}`))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
		}
		return sensor.Tags
	}

	tenantSensor := &models.Sensor{ID: uuid.New(), Profile: "device_interrogation", Tags: []string{"prod"}}
	if got := put(t, tenantSensor, `["prod","system","platform"]`); !reflect.DeepEqual(got, []string{"prod"}) {
		t.Errorf("a tenant sensor self-tagged as the platform: tags = %v", got)
	}

	platformSensor := &models.Sensor{ID: uuid.New(), Platform: "platform", Profile: "device_interrogation",
		Tags: []string{"system", "platform", "device_interrogation"}}
	got := put(t, platformSensor, `["renamed"]`)
	for _, want := range []string{"renamed", "system", "platform"} {
		found := false
		for _, g := range got {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("platform sensor tags after a tenant retag = %v, missing %q", got, want)
		}
	}
}
