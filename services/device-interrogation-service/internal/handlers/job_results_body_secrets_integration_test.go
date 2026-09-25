package handlers

// Vendor error bodies never reach the stored job or the job detail (review B1
// on), end to end, for the three collectors whose errors used to carry
// the body: F5, FortiOS and UniFi.
//
// Each case runs the REAL collector through the Registry against a fake
// appliance that refuses one endpoint with a body carrying secrets — named
// ones (a token, a PSK, a password) and one unnamed free-text value that only
// keeping the body out of the error can stop — submits the result through the
// REAL agent intake, and reads it back through the REAL GET /jobs/:id/results.
// Neither the stored row nor the response may carry any of them; the warning
// itself, with the vendor's code, must be there.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/devicetest"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type bodySecretCase struct {
	name, deviceType, endpoint, wantDetail string
	secrets                                []string
	handler                                http.HandlerFunc
}

func bodySecretCases() []bodySecretCase {
	jsonOK := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
	return []bodySecretCase{
		{
			name: "F5", deviceType: "f5_bigip", endpoint: "/mgmt/tm/net/vlan", wantDetail: "F5 code 401",
			secrets: []string{"F5TOKSECRET1", "F5PWSECRET3", "F5FREETEXT9"},
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/mgmt/shared/authn/login"):
					jsonOK(w, `{"token":{"token":"FAKE-SESSION"}}`)
				case strings.HasSuffix(r.URL.Path, "/net/vlan"):
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte(`{"code":401,"message":"session F5FREETEXT9 rejected",` +
						`"X-F5-Auth-Token":"F5TOKSECRET1","password":"F5PWSECRET3"}`))
				default:
					jsonOK(w, `{"items":[]}`)
				}
			},
		},
		{
			name: "FortiOS", deviceType: "fortigate", endpoint: "/api/v2/cmdb/system/interface", wantDetail: "FortiOS error -5",
			secrets: []string{"FGPSKSECRET1", "FGFREETEXT9"},
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/cmdb/system/status"):
					jsonOK(w, `{"status":"success","serial":"FGT60F0000000001","version":"v7.4.4",`+
						`"results":[{"hostname":"fw-branch-01","model_name":"FortiGate 60F"}]}`)
				case strings.HasSuffix(r.URL.Path, "/cmdb/system/interface"):
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`{"status":"error","error":-5,"psksecret":"ENC FGPSKSECRET1",` +
						`"error_message":"tunnel uses FGFREETEXT9"}`))
				default:
					jsonOK(w, `{"status":"success","results":[]}`)
				}
			},
		},
		{
			name: "UniFi", deviceType: "unifi", endpoint: "/proxy/network/api/s/default/stat/sta", wantDetail: "unrecognised controller error",
			secrets: []string{"UNIFIPW1", "UNIFIFREETEXT9"},
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/api/auth/login":
					http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "session"})
					w.WriteHeader(http.StatusOK)
				case strings.HasSuffix(r.URL.Path, "/stat/sta"):
					jsonOK(w, `{"meta":{"rc":"error","msg":"password: UNIFIPW1 for UNIFIFREETEXT9"},"data":[]}`)
				default:
					jsonOK(w, `{"meta":{"rc":"ok"},"data":[]}`)
				}
			},
		},
	}
}

func TestIntegration_JobResults_VendorErrorBodiesNeverStoredOrServed(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) { c.Set("tenantID", tenant); c.Next() })
	router.GET("/jobs/:id/results", NewJobHandlers(app, owner).GetJobResults)

	for _, c := range bodySecretCases() {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(c.handler)
			defer srv.Close()
			devicetest.AllowListener(t, srv.Listener.Addr().String())

			// The collector, through the Registry, as the device agent runs it.
			interrogator, err := di.NewRegistry().Get(c.deviceType)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			collected, err := interrogator.Interrogate(ctx,
				di.DeviceInfo{DeviceType: c.deviceType, ManagementURL: srv.URL},
				di.Credentials{Username: "readonly", Password: "readonly-password", InsecureSkipVerify: true})
			if err != nil {
				t.Fatalf("Interrogate: %v", err)
			}

			// A job for it, and the result submitted as an agent POSTs it.
			agentID := seedIntakeAgent(t, owner, tenant)
			assetID := uuid.New()
			if _, err := owner.ExecContext(ctx, `
				INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status)
				VALUES ($1, $2, $3, 'network_device', 'hardware.network_device', 'monitoring')`,
				assetID, tenant, strings.ToLower(c.name)+"-"+uuid.NewString()[:8]+".corp.example.test"); err != nil {
				t.Fatalf("seed asset: %v", err)
			}
			jobID := uuid.New()
			if _, err := owner.ExecContext(ctx, `INSERT INTO device_jobs (id, tenant_id, job_type, agent_id, asset_id, status)
				VALUES ($1, $2, 'device_interrogation', $3, $4, 'in_progress')`, jobID, tenant, agentID, assetID); err != nil {
				t.Fatalf("seed job: %v", err)
			}
			posted, _ := json.Marshal(map[string]any{
				"job_id": jobID, "success": true, "completed_at": time.Now().UTC(),
				"facts": collected.Facts, "warnings": collected.Warnings, "metadata": collected.DeviceInfo,
			})
			var result models.JobResult
			if err := json.Unmarshal(posted, &result); err != nil {
				t.Fatalf("decode payload: %v", err)
			}
			if err := services.NewAgentService(app, owner, nil).SubmitJobResult(ctx, agentID, &result); err != nil {
				t.Fatalf("SubmitJobResult: %v", err)
			}

			// Nothing from the body on the stored row…
			var row string
			if err := owner.QueryRowContext(ctx, `SELECT row_to_json(j)::text FROM device_jobs j WHERE id = $1`, jobID).Scan(&row); err != nil {
				t.Fatalf("read job row: %v", err)
			}
			// …nor in the job detail.
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/jobs/"+jobID.String()+"/results", nil))
			if w.Code != http.StatusOK {
				t.Fatalf("GET results = %d: %s", w.Code, w.Body.String())
			}
			for _, secret := range c.secrets {
				if strings.Contains(row, secret) {
					t.Errorf("%q from the error body was stored on the job", secret)
				}
				if strings.Contains(w.Body.String(), secret) {
					t.Errorf("%q from the error body was served by the job detail", secret)
				}
			}

			// And the warning itself is there, with the vendor's code.
			var got JobResultsResponse
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			found := false
			for _, cw := range got.CollectionWarnings {
				if cw.Endpoint == c.endpoint {
					found = true
					if !strings.Contains(cw.Detail, c.wantDetail) {
						t.Errorf("served detail = %q; want %q", cw.Detail, c.wantDetail)
					}
				}
			}
			if !found {
				t.Errorf("no warning for %s in the job detail: %+v", c.endpoint, got.CollectionWarnings)
			}
		})
	}
}
