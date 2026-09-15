package handlers

// Contract test for the host-inventory job request (asset-inventory 2.11a).
//
// It extends the device-interrogation-service spec-first contract (ADR-0001)
// and reuses the shared harness (loadSpec / assertConforms / do / base) from
// jobs_contract_test.go.
//
// The point of pinning the REQUEST shape rather than only the response: this is
// the one place a tenant asks for a host inventory, and the spec is what a
// customer's client is generated from. A field the handler reads and the spec
// does not declare is a field no generated client can send.

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// validateAgainst is assertConforms' other polarity: it RETURNS the validation
// error instead of failing on it, so a test can require that the spec REFUSES
// something. A schema that accepts everything is not a contract, and the
// harness had no way to say so.
func validateAgainst(t *testing.T, sv *specValidator, schemaName string, body []byte) error {
	t.Helper()
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/" + schemaName)
	if err != nil {
		t.Fatalf("compile schema %s: %v", schemaName, err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		// Malformed JSON is a refusal too — that is what the caller is asking.
		return err
	}
	return sch.Validate(inst)
}

// TestContract_InterrogateDeviceRequest_ConformsToTheSpec drives the request
// bodies the handler accepts and refuses through the spec's schema, so the two
// cannot disagree about which fields exist.
func TestContract_InterrogateDeviceRequest_ConformsToTheSpec(t *testing.T) {
	sv := loadSpec(t)

	valid := []struct {
		name string
		body string
	}{
		{"plain device interrogation", `{"job_type":"device_interrogation"}`},
		{"host inventory, remote, ssh", `{"job_type":"host_inventory","mode":"remote","transport":"ssh","agent_id":"3f2a1c40-0000-4000-8000-000000000001"}`},
		{"host inventory, transport defaulted", `{"job_type":"host_inventory","mode":"remote","agent_id":"3f2a1c40-0000-4000-8000-000000000001"}`},
		{"empty body object", `{}`},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			sv.assertConforms(t, "InterrogateDeviceRequest", []byte(tc.body))
		})
	}
}

// The handler and the spec must refuse the same job types. `cloud_discovery` is
// deliberately absent from the enum — it is not queued against a device.
func TestContract_InterrogateDeviceRequest_RejectsUndeclaredValues(t *testing.T) {
	sv := loadSpec(t)

	for name, body := range map[string]string{
		"unknown job type":     `{"job_type":"sbom_import"}`,
		"cloud discovery":      `{"job_type":"cloud_discovery"}`,
		"local mode":           `{"job_type":"host_inventory","mode":"local"}`,
		"winrm transport":      `{"job_type":"host_inventory","mode":"remote","transport":"winrm"}`,
		"undeclared extra key": `{"job_type":"host_inventory","mode":"remote","credentials":{"password":"x"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateAgainst(t, sv, "InterrogateDeviceRequest", []byte(body)); err == nil {
				t.Fatalf("the spec accepted %s: %s", name, body)
			}
		})
	}
}

// End to end through the REAL router: a host-inventory request missing its
// agent id must be refused with a message that names the missing field, and no
// job created.
//
// Driving newDeviceEngine rather than calling the handler keeps the route
// registration and the JSON binding in the blast radius — deleting the
// validateHostInventoryRequest call in InterrogateDevice fails this.
func TestContract_InterrogateDevice_HostInventoryWithoutAnAgentIs400(t *testing.T) {
	device := sampleDevice()
	eng := newDeviceEngine(&stubDeviceStore{device: device})

	w := do(eng, http.MethodPost, base+"/devices/"+device.ID.String()+"/interrogate",
		strings.NewReader(`{"job_type":"host_inventory","mode":"remote"}`))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "agent_id") {
		t.Errorf("the refusal does not name the missing field: %s", w.Body.String())
	}
}

// A local-mode request is refused before anything is queued.
func TestContract_InterrogateDevice_HostInventoryLocalModeIs400(t *testing.T) {
	device := sampleDevice()
	eng := newDeviceEngine(&stubDeviceStore{device: device})
	agentID := uuid.New()

	w := do(eng, http.MethodPost, base+"/devices/"+device.ID.String()+"/interrogate",
		strings.NewReader(`{"job_type":"host_inventory","mode":"local","agent_id":"`+agentID.String()+`"}`))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "agent-originated") {
		t.Errorf("the refusal does not explain why local cannot be queued: %s", w.Body.String())
	}
}

// An unknown job_type is refused by name rather than silently defaulting to a
// device interrogation — a caller who mistyped must not get a different job.
func TestContract_InterrogateDevice_UnknownJobTypeIs400(t *testing.T) {
	device := sampleDevice()
	eng := newDeviceEngine(&stubDeviceStore{device: device})

	w := do(eng, http.MethodPost, base+"/devices/"+device.ID.String()+"/interrogate",
		strings.NewReader(`{"job_type":"host-inventory"}`))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "host-inventory") {
		t.Errorf("the refusal does not quote what was sent: %s", w.Body.String())
	}
}

// A malformed body is an error, not an absent body. A caller who meant to ask
// for a host inventory and mistyped the JSON must not silently get a device
// interrogation instead.
func TestContract_InterrogateDevice_MalformedBodyIs400(t *testing.T) {
	device := sampleDevice()
	eng := newDeviceEngine(&stubDeviceStore{device: device})

	w := do(eng, http.MethodPost, base+"/devices/"+device.ID.String()+"/interrogate",
		strings.NewReader(`{"job_type": `))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}
