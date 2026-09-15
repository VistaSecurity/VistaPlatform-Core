package handlers

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/hostinventory"
)

// The tenant-facing job API's host-inventory validation.
//
// Every refusal here prevents a job that would be accepted and then never
// complete — which is worse than a rejection, because the operator watches a
// queue rather than reading an error.

func TestValidateHostInventoryRequest_AcceptsARemoteSSHJob(t *testing.T) {
	agentID := uuid.New()
	req := &InterrogateDeviceRequest{
		JobType: models.JobTypeHostInventory,
		Mode:    "remote",
		AgentID: &agentID,
	}
	if err := validateHostInventoryRequest(req); err != nil {
		t.Fatalf("a valid remote job was refused: %v", err)
	}
	// An unset transport defaults to ssh rather than staying empty, so the
	// stored parameters say what will actually run.
	if req.Transport != string(hostinventory.TransportSSH) {
		t.Errorf("transport = %q, want %q", req.Transport, hostinventory.TransportSSH)
	}
}

// Local collection is agent-originated. A queued local job would sit in the
// queue forever: no agent claims it, because the agent that would describe that
// host posts its inventory on its own schedule instead.
func TestValidateHostInventoryRequest_RefusesLocalMode(t *testing.T) {
	agentID := uuid.New()
	for _, mode := range []string{"local", "", "LOCAL "} {
		err := validateHostInventoryRequest(&InterrogateDeviceRequest{
			JobType: models.JobTypeHostInventory, Mode: mode, AgentID: &agentID,
		})
		if err == nil {
			t.Fatalf("mode %q was accepted", mode)
		}
		if !strings.Contains(err.Error(), "agent-originated") {
			t.Errorf("mode %q: the refusal does not explain why: %v", mode, err)
		}
	}
}

// Mode is matched case-insensitively and with surrounding space trimmed — an
// operator typing "Remote" in a JSON body should not get a queue that silently
// does nothing.
func TestValidateHostInventoryRequest_ModeIsCaseInsensitive(t *testing.T) {
	agentID := uuid.New()
	for _, mode := range []string{"remote", "Remote", " REMOTE "} {
		if err := validateHostInventoryRequest(&InterrogateDeviceRequest{
			JobType: models.JobTypeHostInventory, Mode: mode, AgentID: &agentID,
		}); err != nil {
			t.Errorf("mode %q was refused: %v", mode, err)
		}
	}
}

// The API and the agent must refuse winrm with the SAME wording, because they
// both defer to hostinventory.ParseTransport. Two copies of that message is two
// places it can go stale.
func TestValidateHostInventoryRequest_RefusesWinRMWithTheSharedMessage(t *testing.T) {
	agentID := uuid.New()
	err := validateHostInventoryRequest(&InterrogateDeviceRequest{
		JobType: models.JobTypeHostInventory, Mode: "remote", Transport: "winrm", AgentID: &agentID,
	})
	if err == nil {
		t.Fatal("winrm was accepted")
	}
	if err.Error() != hostinventory.ErrWinRMUnavailable.Error() {
		t.Errorf("the API's winrm message has drifted from the shared one:\n got: %v\nwant: %v", err, hostinventory.ErrWinRMUnavailable)
	}
}

// Without an agent there is nothing to run the collection, and device_jobs'
// valid_job_assignment CHECK would reject the row with a constraint error no
// operator could act on.
func TestValidateHostInventoryRequest_RequiresAnAgent(t *testing.T) {
	nilID := uuid.Nil
	for name, req := range map[string]*InterrogateDeviceRequest{
		"absent": {JobType: models.JobTypeHostInventory, Mode: "remote"},
		"nil":    {JobType: models.JobTypeHostInventory, Mode: "remote", AgentID: &nilID},
	} {
		err := validateHostInventoryRequest(req)
		if err == nil {
			t.Fatalf("%s agent id was accepted", name)
		}
		if !strings.Contains(err.Error(), "agent_id") {
			t.Errorf("%s: the refusal does not name the missing field: %v", name, err)
		}
	}
}

// The job-type vocabulary is spelled once, and it has to match the database
// enum exactly: a type the API accepts and the enum refuses fails at INSERT
// with a message no operator can act on.
func TestDeviceJobTypeValid(t *testing.T) {
	for _, valid := range []models.DeviceJobType{
		models.JobTypeDeviceInterrogation, models.JobTypeCloudDiscovery, models.JobTypeHostInventory,
	} {
		if !valid.Valid() {
			t.Errorf("%q should be valid", valid)
		}
	}
	for _, invalid := range []models.DeviceJobType{"", "host-inventory", "hostinventory", "HOST_INVENTORY", "sbom"} {
		if models.DeviceJobType(invalid).Valid() {
			t.Errorf("%q should not be valid", invalid)
		}
	}
}
