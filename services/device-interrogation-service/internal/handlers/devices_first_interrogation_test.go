package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// A device added in the UI used to be saved and never interrogated: nothing
// queued the first run, so no device-level posture was collected until someone
// found the Interrogate button. These drive the real handlers.

type historyJobCreator struct {
	recordingJobCreator
	err        error
	hasHistory bool
	historyErr error
}

func (h *historyJobCreator) CreateJob(ctx context.Context, req models.CreateDeviceJobRequest) (*models.DeviceJob, error) {
	if h.err != nil {
		return nil, h.err
	}
	return h.recordingJobCreator.CreateJob(ctx, req)
}

func (h *historyJobCreator) HasInterrogationJob(context.Context, uuid.UUID, uuid.UUID) (bool, error) {
	return h.hasHistory, h.historyErr
}

func firstRunEngine(store *stubDeviceStore, jobs jobCreator) *gin.Engine {
	gin.SetMode(gin.TestMode)
	h := &DeviceHandlers{
		deviceService: store,
		jobQueue:      jobs,
		discovery:     services.NewDeviceDiscoveryService().WithTimeout(5 * time.Second),
		auditSink:     (&auditRecorder{}).sink,
	}
	r := gin.New()
	grp := r.Group(base)
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", deviceTestTenant)
		c.Set(sharedmw.CtxKeyUserID, "11111111-1111-1111-1111-111111111111")
		c.Next()
	})
	grp.POST("/devices", h.CreateDevice)
	grp.PUT("/devices/:id", h.UpdateDevice)
	grp.POST("/devices/discover-and-create", h.DiscoverAndCreateDevice)
	return r
}

func withCredentials() services.StoredDeviceCredentials {
	return services.StoredDeviceCredentials{Username: "admin", EncryptedPassword: "ciphertext", ManagementURL: "https://192.0.2.10", DeviceType: "unifi"}
}

const createBody = `{"device_type":"unifi","management_url":"https://192.0.2.10","username":"admin","password":"pw"}`

// MUTATION-VERIFIED: remove the startFirstInterrogation call from CreateDevice
// and the "with credentials" case goes red.
func TestCreateDevice_QueuesFirstInterrogation(t *testing.T) {
	t.Setenv("ENCRYPTION_MASTER_KEY", "unused-by-embedded-credentials")
	cloud := sampleDevice()
	cloud.DeviceType = "aws_alb"
	noType := sampleDevice()
	noType.DeviceType = "unifi"
	cases := []struct {
		name     string
		device   *models.Device
		stored   services.StoredDeviceCredentials
		jobErr   error
		wantJobs int
	}{
		{"with credentials", noType, withCredentials(), nil, 1},
		{"without credentials", noType, services.StoredDeviceCredentials{}, nil, 0},
		{"cloud resource", cloud, withCredentials(), nil, 0},
		{"enqueue failure still creates the device", noType, withCredentials(), errors.New("queue down"), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &stubDeviceStore{created: tc.device, stored: tc.stored}
			jobs := &historyJobCreator{err: tc.jobErr}
			w := do(firstRunEngine(store, jobs), http.MethodPost, base+"/devices", strings.NewReader(createBody))
			if w.Code != http.StatusCreated {
				t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
			}
			if got := len(jobs.reqs); got != tc.wantJobs {
				t.Fatalf("jobs queued = %d, want %d", got, tc.wantJobs)
			}
			if tc.wantJobs == 1 {
				req := jobs.reqs[0]
				if req.JobType != models.JobTypeDeviceInterrogation || req.AssetID == nil || *req.AssetID != tc.device.ID ||
					req.AgentID != nil || req.TenantID != deviceTestTenant || req.Credentials["username"] != "admin" {
					t.Fatalf("job = %+v", req)
				}
			}
		})
	}
}

func TestCreateDevice_WithoutAJobQueueStillCreates(t *testing.T) {
	store := &stubDeviceStore{created: sampleDevice(), stored: withCredentials()}
	w := do(firstRunEngine(store, nil), http.MethodPost, base+"/devices", strings.NewReader(createBody))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
}

// Add device (probe, then create) is the path the live gap came from.
func TestDiscoverAndCreate_QueuesFirstInterrogation(t *testing.T) {
	t.Setenv("ENCRYPTION_MASTER_KEY", "unused-by-embedded-credentials")
	addr, _ := startCiscoFake(t)
	store := &stubDeviceStore{created: sampleDevice(), stored: withCredentials()}
	jobs := &historyJobCreator{}
	w := do(firstRunEngine(store, jobs), http.MethodPost, base+"/devices/discover-and-create",
		discoverBody("cisco", "ssh://"+addr, "correct-horse", false))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	if len(jobs.reqs) != 1 {
		t.Fatalf("jobs queued = %d, want 1", len(jobs.reqs))
	}
}

func TestUpdateDevice_QueuesFirstInterrogationOnlyWhenNeverInterrogated(t *testing.T) {
	t.Setenv("ENCRYPTION_MASTER_KEY", "unused-by-embedded-credentials")
	dev := sampleDevice()
	dev.DeviceType = "unifi"
	cases := []struct {
		name     string
		body     string
		jobs     *historyJobCreator
		wantJobs int
	}{
		{"credentials set, no history", `{"username":"admin","password":"pw"}`, &historyJobCreator{}, 1},
		{"credentials set, already interrogated", `{"username":"admin","password":"pw"}`, &historyJobCreator{hasHistory: true}, 0},
		{"history unreadable", `{"username":"admin","password":"pw"}`, &historyJobCreator{historyErr: errors.New("db down")}, 0},
		{"unrelated edit", `{"hostname":"unifi.example.test"}`, &historyJobCreator{}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &stubDeviceStore{device: dev, updated: dev, stored: withCredentials()}
			w := do(firstRunEngine(store, tc.jobs), http.MethodPut, base+"/devices/"+dev.ID.String(), strings.NewReader(tc.body))
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
			}
			if got := len(tc.jobs.reqs); got != tc.wantJobs {
				t.Fatalf("jobs queued = %d, want %d", got, tc.wantJobs)
			}
		})
	}
}
