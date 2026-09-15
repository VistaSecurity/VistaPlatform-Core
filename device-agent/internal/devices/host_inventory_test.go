package devices

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/hostinventory"
)

// The executor's host-inventory branch: what it accepts, what it refuses, and
// why each refusal is a refusal rather than a quiet success.
//
// These drive the REAL Execute dispatch rather than calling
// executeHostInventory directly, so deleting the `case JobTypeHostInventory`
// line in executor.go fails them — the wiring is what is being tested, not only
// the helper (CLAUDE.md, "Test the WIRING, not just the helper").

// recordingClient captures what the executor submitted instead of posting it.
type recordingClient struct {
	results []*models.JobResult
}

func (c *recordingClient) SubmitResult(result *models.JobResult) error {
	c.results = append(c.results, result)
	return nil
}

func (c *recordingClient) last() *models.JobResult {
	if len(c.results) == 0 {
		return nil
	}
	return c.results[len(c.results)-1]
}

// newTestExecutor builds an executor whose submissions are captured.
func newTestExecutor() (*JobExecutor, *recordingClient) {
	rec := &recordingClient{}
	return &JobExecutor{submitter: rec, config: &config.Config{}}, rec
}

func hostInventoryJob(params map[string]interface{}) *models.Job {
	return &models.Job{
		ID:         uuid.New(),
		Type:       JobTypeHostInventory,
		Parameters: params,
	}
}

// A host_inventory job with mode=local is refused.
//
// Local collection is agent-originated and posts to its own endpoint. Running a
// local-mode JOB would produce a result the platform has no row to attach to —
// a job that appears to succeed while landing nowhere, which is worse than one
// that fails.
func TestExecute_HostInventoryRefusesLocalMode(t *testing.T) {
	for _, mode := range []string{"local", ""} {
		exec, rec := newTestExecutor()
		job := hostInventoryJob(map[string]interface{}{"mode": mode})

		if err := exec.Execute(job); err != nil {
			t.Fatalf("mode %q: execute: %v", mode, err)
		}
		res := rec.last()
		if res == nil || res.Success {
			t.Fatalf("mode %q: a local-mode job was accepted: %+v", mode, res)
		}
		if !strings.Contains(res.Error, "remote") {
			t.Errorf("mode %q: the failure does not say what to do instead: %q", mode, res.Error)
		}
	}
}

// The WinRM transport is refused with an explanation, not silently ignored and
// not silently missing. An operator who types it gets an answer.
func TestExecute_HostInventoryRefusesWinRMWithAnExplanation(t *testing.T) {
	exec, rec := newTestExecutor()
	job := hostInventoryJob(map[string]interface{}{
		"mode": "remote", "transport": "winrm", "ip_address": "198.51.100.30",
	})

	if err := exec.Execute(job); err != nil {
		t.Fatalf("execute: %v", err)
	}
	res := rec.last()
	if res == nil || res.Success {
		t.Fatalf("a winrm job was accepted: %+v", res)
	}
	// The message must name BOTH the reason and the alternative — a refusal
	// that says only "unsupported" sends the operator to the source.
	for _, want := range []string{"MPL-2.0", "ssh", "OpenSSH"} {
		if !strings.Contains(res.Error, want) {
			t.Errorf("the winrm refusal does not mention %q: %q", want, res.Error)
		}
	}
}

func TestExecute_HostInventoryRejectsAnUnknownTransport(t *testing.T) {
	exec, rec := newTestExecutor()
	job := hostInventoryJob(map[string]interface{}{
		"mode": "remote", "transport": "telnet", "ip_address": "198.51.100.30",
	})
	if err := exec.Execute(job); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res := rec.last(); res == nil || res.Success || !strings.Contains(res.Error, "telnet") {
		t.Fatalf("an unknown transport was not refused by name: %+v", res)
	}
}

// A remote job that names no target is refused before any connection is
// attempted — there is nothing to connect to, and an empty host would dial the
// local machine.
func TestExecute_HostInventoryRefusesAJobWithNoTarget(t *testing.T) {
	exec, rec := newTestExecutor()
	job := hostInventoryJob(map[string]interface{}{"mode": "remote", "transport": "ssh"})

	if err := exec.Execute(job); err != nil {
		t.Fatalf("execute: %v", err)
	}
	res := rec.last()
	if res == nil || res.Success {
		t.Fatalf("a targetless job was accepted: %+v", res)
	}
	if !strings.Contains(res.Error, "ip_address") && !strings.Contains(res.Error, "hostname") {
		t.Errorf("the failure does not name what is missing: %q", res.Error)
	}
}

// An unknown job type is still an error — adding host_inventory must not have
// turned the default branch into a catch-all.
func TestExecute_UnknownJobTypeIsStillAnError(t *testing.T) {
	exec, _ := newTestExecutor()
	if err := exec.Execute(&models.Job{ID: uuid.New(), Type: "not_a_thing"}); err == nil {
		t.Fatal("an unknown job type was accepted")
	}
}

// buildRemoteRunner reads the target and the credentials out of the job the
// same way executeDeviceInterrogation does, so an operator configures one
// device once.
func TestBuildRemoteRunner_ReadsTheJobTheSameWayInterrogationDoes(t *testing.T) {
	// A closed port on the loopback: the config is built and the dial is
	// attempted, which is as far as this can go without a server.
	_, err := buildRemoteRunner(hostinventory.TransportSSH,
		map[string]interface{}{"ip_address": "127.0.0.1", "ssh_port": float64(1)},
		map[string]interface{}{"username": "svc", "password": "pw"})
	if err == nil {
		t.Fatal("expected a dial failure against a closed port")
	}
	if !strings.Contains(err.Error(), "127.0.0.1") {
		t.Errorf("the error does not name the target it tried: %v", err)
	}
}

// A credential that will not parse must fail WITHOUT quoting the key. x/crypto
// puts the block in its error text, and an agent log is not the place for it.
func TestBuildRemoteRunner_AnUnparseableKeyIsNotQuotedBack(t *testing.T) {
	const fakeKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nNOTAREALKEYBUTSTILLSECRET\n-----END OPENSSH PRIVATE KEY-----"
	_, err := buildRemoteRunner(hostinventory.TransportSSH,
		map[string]interface{}{"ip_address": "198.51.100.30"},
		map[string]interface{}{"username": "svc", "private_key": fakeKey})
	if err == nil {
		t.Fatal("an unparseable key was accepted")
	}
	if strings.Contains(err.Error(), "NOTAREALKEYBUTSTILLSECRET") || strings.Contains(err.Error(), "BEGIN") {
		t.Fatalf("the error quotes the key material back: %v", err)
	}
}

// Local collection runs the real collector against this test host. It is not a
// fixture test — the point is that the local path works end to end on whatever
// machine CI runs on, which is the only way to catch a command that does not
// exist there.
func TestCollectLocalHostInventory_RunsOnThisHost(t *testing.T) {
	report, observations, err := CollectLocalHostInventory(t.Context(), "agent-under-test")
	if err != nil {
		t.Fatalf("local collection: %v", err)
	}
	if report.Mode != hostinventory.ModeLocal {
		t.Errorf("mode = %q", report.Mode)
	}
	if report.AgentID != "agent-under-test" {
		t.Errorf("agent id = %q", report.AgentID)
	}
	if report.Platform == "" {
		t.Error("no platform was detected")
	}
	if len(observations.Facts) == 0 {
		t.Error("a successful collection produced no facts")
	}
	// agent.mode rides on every report, because the mode bounds what the
	// absence of every other fact is allowed to mean.
	var sawMode bool
	for _, f := range observations.Facts {
		if f.Key == "agent.mode" && f.Value == "local" {
			sawMode = true
		}
	}
	if !sawMode {
		t.Error("agent.mode was not emitted")
	}
}

// TestHostInventoryJobResult_CarriesTheFacts is the regression test for a field
// that was simply MISSING from the submission.
//
// The remote executor forwarded the endpoints and the metadata blob and not
// `result.Facts`. While the platform HELD host-inventory results that cost
// nothing and showed up nowhere; the moment 2.11b lifted the hold it would have
// made every remote collection materialise into an asset with no OS, no kernel,
// no hardware identity, no package count — and, because the identifiers ride on
// each fact's SUBJECT, no identifier for the identification engine to bind the
// report to an asset by. A second collection of the same host would then have
// minted a second asset, forever.
//
// Driven by the REAL projection over a Report rather than a hand-built
// InterrogateResult, because the subject-on-every-fact arrangement is exactly
// what a hand-built one would get wrong.
//
// Mutation check: delete `Facts: result.Facts` from hostInventoryJobResult and
// this fails on the first assertion; delete `Metadata: result.DeviceInfo` and it
// fails on the package list, which is the half the platform materialises
// software installs from.
func TestHostInventoryJobResult_CarriesTheFacts(t *testing.T) {
	report := &hostinventory.Report{
		Mode:     hostinventory.ModeRemote,
		Platform: hostinventory.PlatformLinux,
		Host:     hostinventory.Host{OS: "Ubuntu", OSVersion: "24.04.1 LTS", Kernel: "6.8.0-45-generic", Hostname: "app-01"},
		Hardware: hostinventory.Hardware{Vendor: "Dell Inc.", Model: "PowerEdge R650", Serial: "CZ2X5Y3"},
		Packages: []hostinventory.Package{{Name: "openssl", Version: "3.0.13", Manager: "dpkg"}},
		Listeners: []hostinventory.Listener{
			{Proto: "tcp", Address: "0.0.0.0", Port: 22, Process: "sshd"},
		},
		Sections: map[string]string{
			hostinventory.SectionHost:      hostinventory.SectionOK,
			hostinventory.SectionHardware:  hostinventory.SectionOK,
			hostinventory.SectionPackages:  hostinventory.SectionOK,
			hostinventory.SectionListeners: hostinventory.SectionOK,
		},
	}
	obs, err := hostinventory.ToObservations(report)
	if err != nil {
		t.Fatalf("ToObservations: %v", err)
	}

	jobID := uuid.New()
	res := hostInventoryJobResult(jobID, obs)

	if res.JobID != jobID || !res.Success {
		t.Fatalf("envelope = %+v", res)
	}
	if len(res.Facts) == 0 {
		t.Fatal("the submission carries NO facts; a remote collection would materialise as an asset with no OS, " +
			"no hardware identity and nothing for the identification engine to match on")
	}
	// The specific ones, because "some facts" is not the claim: these are what a
	// host inventory is FOR.
	want := map[string]bool{"os.kernel": false, "hw.serial": false, "sw.package_count": false}
	for _, f := range res.Facts {
		if _, ok := want[f.Key]; ok {
			want[f.Key] = true
		}
	}
	for key, seen := range want {
		if !seen {
			t.Errorf("fact %s did not travel", key)
		}
	}
	// The identifiers ride on each fact's subject. Without them the platform has
	// facts about a host it cannot name.
	var withSubject int
	for _, f := range res.Facts {
		if len(f.Subject.Identifiers) > 0 {
			withSubject++
		}
	}
	if withSubject == 0 {
		t.Error("no fact carries a subject; the identifiers are the only way the engine can bind this report to an asset")
	}
	// The endpoints and the metadata half still travel too. The package list in
	// device_info is what the platform writes software_installs from, and the
	// consumer refuses to sweep when it arrives without it.
	if len(res.Assets) != 1 {
		t.Errorf("assets = %d, want one per listening socket", len(res.Assets))
	}
	if res.Metadata == nil || res.Metadata["packages"] == nil {
		t.Errorf("the package list did not travel in the metadata: %+v", res.Metadata)
	}
}
