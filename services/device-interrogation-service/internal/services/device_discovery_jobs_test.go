package services

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/security/credentials"
)

const discoveryTestMasterKey = "device-discovery-test-master-key-0123456789"

type stubDiscoveryCreator struct {
	created  models.CreateDeviceRequest
	calls    int
	err      error
	deviceID uuid.UUID
	pins     []string
}

func (s *stubDiscoveryCreator) CreateDevice(_ context.Context, _ uuid.UUID, req models.CreateDeviceRequest) (*models.Device, error) {
	s.calls++
	s.created = req
	if s.err != nil {
		return nil, s.err
	}
	return &models.Device{ID: s.deviceID}, nil
}

func (s *stubDiscoveryCreator) PinSSHHostKeyIfUnset(_ context.Context, _, _ uuid.UUID, fp, kt string) (bool, error) {
	s.pins = append(s.pins, fp+" "+kt)
	return true, nil
}

// discoveryJob is a device_discovery job as Enqueue stores it.
func discoveryJob(t *testing.T, deviceType, password string) *models.DeviceJob {
	t.Helper()
	cipher, err := credentials.NewCipher("job_credentials", discoveryTestMasterKey, credentials.Policy{Fields: sensitiveCredentialFields})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := cipher.EncryptValue(password)
	if err != nil {
		t.Fatal(err)
	}
	agent := uuid.New()
	return &models.DeviceJob{
		ID: uuid.New(), TenantID: uuid.New(), JobType: models.JobTypeDeviceDiscovery, AgentID: &agent,
		Credentials: models.JSONB{
			"username": "readonly", "password": sealed, "device_type": deviceType,
			"management_url": "https://192.0.2.10", "insecure_skip_verify": true, masterEncryptedFlag: true,
		},
	}
}

// A completed discovery creates the device exactly as the synchronous Add
// device does — the operator's credentials opened from the job, the identity
// from the agent's report, the probe evidence that lets enforce mode admit it
// — and what is STORED is the projection plus where the device went: never a
// credential, and nothing else the agent sent.
func TestCompleteDeviceDiscovery_CreatesDeviceAndStoresNoSecrets(t *testing.T) {
	job := discoveryJob(t, "fortinet", "device-password-123")
	creator := &stubDiscoveryCreator{deviceID: uuid.New()}
	received := &models.JobResult{
		JobID: job.ID, Success: true,
		Identification: &di.IdentificationReport{Vendor: "Fortinet", Model: "FortiGate 60F", SerialNumber: "FGT60F0000000001", Hostname: "fw-branch-01", TargetHost: "192.0.2.10", TargetPort: 443},
		// What a misbehaving agent could add. None of it may be stored.
		Metadata: map[string]interface{}{"psksecret": "branch-tunnel-psk", "config": "set password hunter2"},
		Assets:   []models.DiscoveredAsset{{Hostname: "should-not-land"}},
	}

	stored, status := completeDeviceDiscovery(context.Background(), creator, job, received, discoveryTestMasterKey)
	if status != models.JobStatusCompleted {
		t.Fatalf("status = %s, want completed (stored %+v)", status, stored)
	}
	if creator.calls != 1 {
		t.Fatalf("CreateDevice called %d times", creator.calls)
	}
	c := creator.created
	if c.Password == nil || *c.Password != "device-password-123" || c.Username == nil || *c.Username != "readonly" {
		t.Errorf("device created without the operator's credentials: %+v", c)
	}
	if c.SerialNumber == nil || *c.SerialNumber != "FGT60F0000000001" || c.ProbeEvidence == nil || !c.ProbeEvidence.Authoritative {
		t.Errorf("serial / probe evidence not carried: serial=%v evidence=%+v", c.SerialNumber, c.ProbeEvidence)
	}
	if c.TLSInsecureSkipVerify == nil || !*c.TLSInsecureSkipVerify {
		t.Error("the TLS opt-in the agent connected under was not persisted")
	}
	if stored.Metadata["asset_id"] != creator.deviceID.String() || stored.Metadata["outcome"] != "created" {
		t.Errorf("stored metadata = %v", stored.Metadata)
	}
	if len(stored.Assets) != 0 {
		t.Error("the agent's assets were stored")
	}
	blob, _ := json.Marshal(stored)
	for _, leak := range []string{"device-password-123", "enc:v1", "branch-tunnel-psk", "hunter2", "password", "psksecret"} {
		if strings.Contains(string(blob), leak) {
			t.Errorf("stored result carries %q: %s", leak, blob)
		}
	}
}

// An SSH-managed discovery pins the host key the agent authenticated through,
// and a stored TLS opt-in is never applied to it (it would become an SSH
// host-key opt-out, review B1).
func TestCompleteDeviceDiscovery_SSHPinsHostKeyAndNeverSkipsVerify(t *testing.T) {
	job := discoveryJob(t, "cisco", "pw")
	creator := &stubDiscoveryCreator{deviceID: uuid.New()}
	_, status := completeDeviceDiscovery(context.Background(), creator, job, &models.JobResult{
		JobID: job.ID, Success: true,
		Identification: &di.IdentificationReport{Model: "C9300", SerialNumber: "FOC0000X0AA", SSHHostKeyFingerprint: "SHA256:abc", SSHHostKeyType: "ssh-ed25519"},
	}, discoveryTestMasterKey)
	if status != models.JobStatusCompleted {
		t.Fatalf("status = %s", status)
	}
	if creator.created.TLSInsecureSkipVerify == nil || *creator.created.TLSInsecureSkipVerify {
		t.Error("an SSH-managed device was created with verification skipped")
	}
	if len(creator.pins) != 1 || creator.pins[0] != "SHA256:abc ssh-ed25519" {
		t.Errorf("pins = %v", creator.pins)
	}
}

func TestCompleteDeviceDiscovery_FailuresAndHeldForReview(t *testing.T) {
	for _, c := range []struct {
		name       string
		received   models.JobResult
		createErr  error
		wantStatus models.DeviceJobStatus
		wantCode   string
		wantCreate int
		wantMeta   string
	}{
		{name: "typed failure from the agent", received: models.JobResult{FailureCode: "connection_failed", Error: "dial tcp: the device said hunter2"},
			wantStatus: models.JobStatusFailed, wantCode: "connection_failed"},
		{name: "unknown code from the agent", received: models.JobResult{FailureCode: "password=hunter2"},
			wantStatus: models.JobStatusFailed, wantCode: string(di.IdentifyFailed)},
		{name: "success that identifies nothing", received: models.JobResult{Success: true, Identification: &di.IdentificationReport{Vendor: "Fortinet"}},
			wantStatus: models.JobStatusFailed, wantCode: string(di.IdentifyUnsupportedResponse)},
		{name: "recording fails", received: models.JobResult{Success: true, Identification: &di.IdentificationReport{Model: "m"}},
			createErr: errors.New("db down"), wantStatus: models.JobStatusFailed, wantCode: CodeCreateFailed, wantCreate: 1},
		{name: "held for review (enforce, no serial)", received: models.JobResult{Success: true, Identification: &di.IdentificationReport{Model: "m"}},
			createErr:  &identity.RetainedObservation{Result: identity.IngestResult{ObservationID: "obs-1"}},
			wantStatus: models.JobStatusCompleted, wantCreate: 1, wantMeta: "retained"},
	} {
		t.Run(c.name, func(t *testing.T) {
			job := discoveryJob(t, "fortinet", "pw")
			creator := &stubDiscoveryCreator{err: c.createErr, deviceID: uuid.New()}
			c.received.JobID = job.ID
			stored, status := completeDeviceDiscovery(context.Background(), creator, job, &c.received, discoveryTestMasterKey)
			if status != c.wantStatus || stored.FailureCode != c.wantCode || creator.calls != c.wantCreate {
				t.Fatalf("got (%s, %q, %d creates), want (%s, %q, %d)", status, stored.FailureCode, creator.calls, c.wantStatus, c.wantCode, c.wantCreate)
			}
			if strings.Contains(stored.Error, "hunter2") {
				t.Errorf("the agent's free text was stored: %q", stored.Error)
			}
			if c.wantMeta != "" && stored.Metadata["outcome"] != c.wantMeta {
				t.Errorf("outcome = %v, want %s", stored.Metadata["outcome"], c.wantMeta)
			}
		})
	}
}

// Every row state the Devices page renders comes from scanDeviceDiscovery, and
// "nobody picked it up" must not read as a device failure (addendum A).
func TestScanDeviceDiscovery_States(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Minute), now.Add(time.Minute)
	long := now.Add(-2 * DeviceDiscoveryClaimWindow)
	for _, c := range []struct {
		name, status string
		results      string
		started      *time.Time
		expires      time.Time
		want, code   string
	}{
		{name: "queued", status: "pending", expires: future, want: DiscoveryQueued},
		{name: "not picked up", status: "pending", expires: past, want: DiscoveryNotPickedUp, code: CodeNotPickedUp},
		{name: "running", status: "in_progress", started: &past, expires: future, want: DiscoveryRunning},
		{name: "agent went quiet", status: "in_progress", started: &long, expires: past, want: DiscoveryFailed, code: CodeAgentNoResult},
		{name: "failed with code", status: "failed", results: `{"failure_code":"authentication_failed"}`, expires: past, want: DiscoveryFailed, code: "authentication_failed"},
		{name: "succeeded", status: "completed", results: `{"metadata":{"asset_id":"6f1c2a52-7d0e-4d0e-9a51-1d1f4f2b0c11","outcome":"created"}}`, expires: past, want: DiscoverySucceeded},
		{name: "held for review", status: "completed", results: `{"metadata":{"observation_id":"obs-1","outcome":"retained"}}`, expires: past, want: DiscoveryHeldForReview},
	} {
		t.Run(c.name, func(t *testing.T) {
			row := fakeRow{values: []interface{}{uuid.New(), c.status, []byte(`{"device_type":"fortinet","management_url":"https://192.0.2.10"}`), []byte(c.results),
				uuid.NullUUID{UUID: uuid.New(), Valid: true}, nil, now.Add(-time.Hour), c.started, nil, c.expires}}
			d, err := scanDeviceDiscovery(row, now)
			if err != nil {
				t.Fatal(err)
			}
			gotCode := ""
			if d.ErrorCode != nil {
				gotCode = *d.ErrorCode
				if d.Message == nil || *d.Message == "" {
					t.Error("a failed row has no message")
				}
			}
			if d.Status != c.want || gotCode != c.code {
				t.Fatalf("status = (%s, %q), want (%s, %q)", d.Status, gotCode, c.want, c.code)
			}
		})
	}
	if !strings.Contains(AgentDiscoveryMessage("connection_failed"), "agent") {
		t.Error("an agent-run connection failure must not say 'from the platform'")
	}
}

type fakeRow struct{ values []interface{} }

func (r fakeRow) Scan(dest ...interface{}) error {
	for i, d := range dest {
		v := r.values[i]
		switch p := d.(type) {
		case *uuid.UUID:
			*p = v.(uuid.UUID)
		case *string:
			*p = v.(string)
		case *[]byte:
			*p = v.([]byte)
		case *uuid.NullUUID:
			*p = v.(uuid.NullUUID)
		case *time.Time:
			*p = v.(time.Time)
		default:
			// sql.Null* — set through Scan.
			if s, ok := d.(interface{ Scan(interface{}) error }); ok {
				var in interface{}
				switch tv := v.(type) {
				case *time.Time:
					if tv != nil {
						in = *tv
					}
				default:
					in = tv
				}
				if err := s.Scan(in); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
