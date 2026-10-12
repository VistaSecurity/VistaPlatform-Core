package devices

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/agentcreds"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/devicetest"
)

//the WIRING: the executor opens a job's credential envelope with the
// secrets Config.CredentialSecrets reports — the agent secret, or for an agent
// that has not rotated yet its registration key. A test of the config helper
// alone stays green if the executor goes back to reading RegistrationKey.
// Driven through the real Execute dispatch and the real Fortinet collector.
func TestExecute_OpensCredentialsWithTheAgentSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/system/status") {
			body, _ := json.Marshal(map[string]interface{}{
				"status": "success", "serial": "FGT60F0000000001", "version": "v7.4.4",
				"results": []map[string]interface{}{{"hostname": "fw-branch-01", "model_name": "FortiGate 60F", "version": "v7.4.4"}},
			})
			_, _ = w.Write(body)
			return
		}
		_, _ = w.Write([]byte(`{"status":"success","results":[]}`))
	}))
	defer srv.Close()
	devicetest.AllowListener(t, srv.Listener.Addr().String())

	const regKey = "REG-0123456789abcdef0123456789abcdef"
	const agentSecret = "per-agent-secret-value"

	run := func(t *testing.T, cfg *config.Config, sealedUnder string) *models.JobResult {
		t.Helper()
		jobID := uuid.New()
		env, err := agentcreds.Seal(map[string]interface{}{"username": "readonly", "password": "device-password-123"}, jobID.String(), sealedUnder)
		if err != nil {
			t.Fatal(err)
		}
		rec := &recordingClient{}
		exec := &JobExecutor{submitter: rec, config: cfg, registry: di.NewRegistry()}
		job := &models.Job{
			ID: jobID, Type: di.JobTypeDeviceDiscovery, DeviceType: "fortinet", Credentials: env,
			Parameters: map[string]interface{}{"device_type": "fortinet", "management_url": srv.URL},
		}
		if err := exec.Execute(context.Background(), job); err != nil {
			t.Fatalf("Execute: %v", err)
		}
		return rec.last()
	}

	t.Run("an enrolled agent opens what is sealed under its agent secret", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.SetEnrolledAgentSecret(agentSecret, 1)
		if got := run(t, cfg, agentSecret); got == nil || !got.Success {
			t.Fatalf("the agent could not use credentials sealed under its agent secret: %+v", got)
		}
	})
	t.Run("a spent registration key opens nothing once the agent holds a secret", func(t *testing.T) {
		cfg := &config.Config{RegistrationKey: regKey}
		cfg.SetEnrolledAgentSecret(agentSecret, 1)
		if got := run(t, cfg, regKey); got == nil || got.Success {
			t.Fatalf("credentials sealed under the spent registration key were accepted: %+v", got)
		}
	})
	t.Run("an agent that has not rotated yet still opens what is sealed under its registration key", func(t *testing.T) {
		cfg := &config.Config{RegistrationKey: regKey}
		if got := run(t, cfg, regKey); got == nil || !got.Success {
			t.Fatalf("a pre-change agent could not use registration-key credentials: %+v", got)
		}
	})
}

// The other two sites that open a job's envelope — device interrogation and
// remote host inventory — read the same secrets. Each is driven far enough to
// pass the decrypt and then fail on something else; a decrypt failure is
// reported as such, so "does not say decrypt" is the assertion.
func TestExecute_OtherJobTypesOpenCredentialsWithTheAgentSecret(t *testing.T) {
	const agentSecret = "per-agent-secret-value"
	cases := []struct {
		name string
		job  func(id uuid.UUID, env map[string]interface{}) *models.Job
	}{
		{"device_interrogation", func(id uuid.UUID, env map[string]interface{}) *models.Job {
			return &models.Job{ID: id, Type: "device_interrogation", DeviceType: "no-such-type", Credentials: env,
				Parameters: map[string]interface{}{"device_type": "no-such-type"}}
		}},
		{"host_inventory", func(id uuid.UUID, env map[string]interface{}) *models.Job {
			return &models.Job{ID: id, Type: JobTypeHostInventory, Credentials: env,
				Parameters: map[string]interface{}{"mode": "remote", "transport": "ssh"}}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id := uuid.New()
			env, err := agentcreds.Seal(map[string]interface{}{"username": "u", "password": "device-password-123"}, id.String(), agentSecret)
			if err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{RegistrationKey: "REG-spent-registration-key-0123456789"}
			cfg.SetEnrolledAgentSecret(agentSecret, 1)
			rec := &recordingClient{}
			exec := &JobExecutor{submitter: rec, config: cfg, registry: di.NewRegistry()}
			if err := exec.Execute(context.Background(), c.job(id, env)); err != nil {
				t.Fatalf("Execute: %v", err)
			}
			got := rec.last()
			if got == nil {
				t.Fatal("no result was submitted")
			}
			if strings.Contains(strings.ToLower(got.Error), "decrypt") {
				t.Fatalf("the agent could not open credentials sealed under its agent secret: %q", got.Error)
			}
		})
	}
}
