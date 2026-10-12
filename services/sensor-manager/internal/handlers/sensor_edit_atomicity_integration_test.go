package handlers_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/database"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// afterReadRepo runs hook once, right after the handler's tenant-scoped read of
// the sensor: the exact window in which a heartbeat (or a second edit) can
// land between the handler's read and its write.
type afterReadRepo struct {
	database.SensorRepository
	fired atomic.Bool
	hook  func()
}

func (r *afterReadRepo) GetSensorByIDForTenant(ctx context.Context, id, tenantID uuid.UUID) (*models.Sensor, error) {
	s, err := r.SensorRepository.GetSensorByIDForTenant(ctx, id, tenantID)
	// CompareAndSwap, not sync.Once: the hook may itself issue a request that
	// reads through this repo, and a re-entrant Once.Do would deadlock.
	if r.fired.CompareAndSwap(false, true) && r.hook != nil {
		r.hook()
	}
	return s, err
}

func editRouter(h *afterReadHandlerSet, tenant uuid.UUID) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("tenantID", tenant); c.Set("userID", uuid.New()); c.Next() })
	r.PUT("/sensors/:sensor_id/config", h.config)
	r.PUT("/sensors/:sensor_id/interfaces", h.interfaces)
	return r
}

type afterReadHandlerSet struct{ config, interfaces gin.HandlerFunc }

func put(r *gin.Engine, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

// Editing a sensor must not write status / last_heartbeat back from the
// handler's earlier read. The heartbeat lands after the read and before the
// write; the edit must leave it alone.
//
// Mutation check: make UpdateSensorConfig call h.sensorService.UpdateSensor
// (the full-row UPDATE) instead of UpdateSensorFields: status regresses to
// 'active' and last_heartbeat to NULL, and this test fails.
func TestIntegration_SensorEditDoesNotClobberHeartbeatState(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	sensorID := seedSensor(t, admin, tenant) // status 'active', last_heartbeat NULL

	base := database.NewSensorRepository(admin, admin)
	repo := &afterReadRepo{SensorRepository: base, hook: func() {
		if _, err := admin.Exec(`UPDATE public.sensors SET status = 'error', last_heartbeat = now() WHERE id = $1`, sensorID); err != nil {
			t.Errorf("simulated heartbeat: %v", err)
		}
	}}
	h := newHeartbeatHandlerWithRepo(t, admin, repo)
	r := editRouter(&afterReadHandlerSet{config: h.UpdateSensorConfig, interfaces: h.UpdateSensorInterfaces}, tenant)

	w := put(r, "/sensors/"+sensorID.String()+"/config", `{"description":"edited while a heartbeat landed","tags":["edge"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("config edit = %d: %s", w.Code, w.Body.String())
	}

	var status, desc string
	var hbSet bool
	if err := admin.QueryRow(`SELECT status, COALESCE(description,''), last_heartbeat IS NOT NULL FROM public.sensors WHERE id = $1`, sensorID).Scan(&status, &desc, &hbSet); err != nil {
		t.Fatal(err)
	}
	if status != "error" || !hbSet {
		t.Errorf("heartbeat state clobbered by the edit: status=%q last_heartbeat set=%v (want error, true)", status, hbSet)
	}
	if desc != "edited while a heartbeat landed" {
		t.Errorf("description = %q, edit was lost", desc)
	}
}

// A soft-deleted sensor must not be edited or resurrected by a stale handler.
func TestIntegration_SensorEditSkipsSoftDeleted(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	sensorID := seedSensor(t, admin, tenant)

	base := database.NewSensorRepository(admin, admin)
	repo := &afterReadRepo{SensorRepository: base, hook: func() {
		if _, err := admin.Exec(`UPDATE public.sensors SET deleted_at = now() WHERE id = $1`, sensorID); err != nil {
			t.Errorf("soft delete: %v", err)
		}
	}}
	h := newHeartbeatHandlerWithRepo(t, admin, repo)
	r := editRouter(&afterReadHandlerSet{config: h.UpdateSensorConfig, interfaces: h.UpdateSensorInterfaces}, tenant)

	w := put(r, "/sensors/"+sensorID.String()+"/config", `{"description":"too late"}`)
	if w.Code == http.StatusOK {
		t.Errorf("edit of a sensor deleted mid-request = 200, want an error: %s", w.Body.String())
	}
	var desc string
	if err := admin.QueryRow(`SELECT COALESCE(description,'') FROM public.sensors WHERE id = $1`, sensorID).Scan(&desc); err != nil {
		t.Fatal(err)
	}
	if desc == "too late" {
		t.Error("a soft-deleted sensor was edited")
	}
}

// Two interface edits that interleave (the second lands between the first's
// read and write) must both persist.
//
// Mutation check: restore the handler's read-modify-write (compute the list
// from sensor.NetworkInterfaces and write it back): eth2 is lost.
func TestIntegration_ConcurrentInterfaceAddsBothPersist(t *testing.T) {
	admin := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, admin)
	tenant := testdb.NewTenant(t, admin)
	sensorID := seedSensor(t, admin, tenant)
	if _, err := admin.Exec(`UPDATE public.sensors SET network_interfaces = ARRAY['eth0'] WHERE id = $1`, sensorID); err != nil {
		t.Fatal(err)
	}

	base := database.NewSensorRepository(admin, admin)
	var second *gin.Engine
	repo := &afterReadRepo{SensorRepository: base}
	repo.hook = func() {
		// The second edit runs to completion inside the first one's window.
		w := put(second, "/sensors/"+sensorID.String()+"/interfaces", `{"add":["eth2"]}`)
		if w.Code != http.StatusOK {
			t.Errorf("second edit = %d: %s", w.Code, w.Body.String())
		}
	}
	h := newHeartbeatHandlerWithRepo(t, admin, repo)
	r := editRouter(&afterReadHandlerSet{config: h.UpdateSensorConfig, interfaces: h.UpdateSensorInterfaces}, tenant)
	second = r

	w := put(r, "/sensors/"+sensorID.String()+"/interfaces", `{"add":["eth1"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("first edit = %d: %s", w.Code, w.Body.String())
	}

	var got []string
	if err := admin.QueryRow(`SELECT network_interfaces FROM public.sensors WHERE id = $1`, sensorID).Scan(pq.Array(&got)); err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, g := range got {
		have[g] = true
	}
	if !have["eth0"] || !have["eth1"] || !have["eth2"] || len(got) != 3 {
		t.Errorf("interfaces = %v, want eth0, eth1 and eth2 all present", got)
	}
}
