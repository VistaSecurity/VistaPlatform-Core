package handlers

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws/smithy-go"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
)

// slice E, the read side. The per-resource-type outcome is written into
// device_jobs.results by the cloud discovery handler; GET /jobs/{id}/results
// is a strict projection, so a field that is not named here never reaches the
// browser — which is exactly how the outcome could be stored and still be
// invisible.

// storedCloudResult builds the payload the cloud discovery handler writes.
func storedCloudResult(t *testing.T, outcomes []services.CloudResourceTypeOutcome, verdict string, success bool) string {
	t.Helper()
	payload := map[string]any{
		"success": success,
		"metadata": map[string]any{
			"devices_count":  17,
			"assets_count":   17,
			"resource_types": outcomes,
			"outcome":        verdict,
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// TestBuildJobResults_ResourceTypesRoundTripFromWriter is the writer↔reader
// shape guard. The recorder in services/ and the projection here are two
// structs with the same JSON tags; a rename on either side would quietly
// degrade every row to "not reported" — nothing would fail, the UI would just
// stop saying anything.
//
// Mutation: change any `json:` tag on services.CloudResourceTypeOutcome (or on
// the handler's JobResultResourceType) and this goes red.
func TestBuildJobResults_ResourceTypesRoundTripFromWriter(t *testing.T) {
	rec := services.NewCloudOutcomeRecorder([]string{"s3", "kms", "efs"})
	rec.Attempt("s3", "global", 4, nil)
	rec.Attempt("kms", "us-east-1", 0, awsLikeError{code: "AccessDeniedException", msg: "not authorized to perform: kms:ListKeys"})
	// "efs" was requested and nothing collected it — left not_attempted.

	stored := storedCloudResult(t, rec.Outcomes(), rec.Verdict(), rec.Succeeded())
	out := buildJobResults("job-1", "completed", stored)

	if len(out.ResourceTypes) != 3 {
		t.Fatalf("resource types = %d, want 3; the projection dropped them", len(out.ResourceTypes))
	}
	byType := map[string]JobResultResourceType{}
	for _, rt := range out.ResourceTypes {
		byType[rt.ResourceType] = rt
	}

	if got := byType["s3"]; got.Status != services.CloudTypeSucceeded || got.Found != 4 {
		t.Errorf("s3 = %s/%d, want succeeded/4", got.Status, got.Found)
	}
	kms := byType["kms"]
	if kms.Status != services.CloudTypeFailed {
		t.Errorf("kms status = %q, want failed", kms.Status)
	}
	if len(kms.Failures) != 1 || kms.Failures[0].Code != "AccessDeniedException" {
		t.Fatalf("the provider's error code did not survive the projection: %+v", kms.Failures)
	}
	if kms.Failures[0].Reason != services.CloudFailureAccessDenied {
		t.Errorf("reason = %q", kms.Failures[0].Reason)
	}
	if kms.Failures[0].Scope != "us-east-1" {
		t.Errorf("scope = %q", kms.Failures[0].Scope)
	}
	if got := byType["efs"]; got.Status != services.CloudTypeNotAttempted {
		t.Errorf("efs = %q, want not_attempted", got.Status)
	}
	if out.Outcome != services.CloudRunPartial {
		t.Errorf("outcome = %q, want partial", out.Outcome)
	}
	if out.Success == nil || *out.Success {
		t.Error("success must be false on a run where a requested type could not be collected")
	}

	// And the distinction survives end to end: found-zero and could-not-look
	// do not render the same.
	if byType["s3"].Status == byType["kms"].Status {
		t.Fatal("empty and failed are indistinguishable after projection")
	}
}

// awsLikeError implements smithy.APIError structurally, which is all
// SanitizeCloudFailure needs.
type awsLikeError struct {
	code string
	msg  string
}

func (e awsLikeError) Error() string                 { return e.code + ": " + e.msg }
func (e awsLikeError) ErrorCode() string             { return e.code }
func (e awsLikeError) ErrorMessage() string          { return e.msg }
func (e awsLikeError) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

// A stored message that somehow carries a secret-shaped run is redacted again
// on the way out. Belt and braces: the writer already sanitizes, but this
// endpoint is the one that reaches a browser.
func TestBuildJobResults_ReSanitizesStoredFailureMessages(t *testing.T) {
	stored := `{"success":false,"metadata":{"outcome":"failed","resource_types":[
	  {"resource_type":"kms","status":"failed","found":0,"scopes_succeeded":0,"scopes_attempted":1,
	   "failures":[{"scope":"us-east-1","reason":"credentials","code":"InvalidClientTokenId",
	                "message":"token AKIAIOSFODNN7EXAMPLE rejected"}]}]}}`

	out := buildJobResults("job-2", "completed", stored)
	if len(out.ResourceTypes) != 1 || len(out.ResourceTypes[0].Failures) != 1 {
		t.Fatalf("projection lost the failure: %+v", out.ResourceTypes)
	}
	msg := out.ResourceTypes[0].Failures[0].Message
	if strings.Contains(msg, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("a key-shaped run reached the client: %q", msg)
	}
	if !strings.Contains(msg, "rejected") {
		t.Errorf("the actionable part of the message was destroyed: %q", msg)
	}
}

// enumeration_skipped was stored from the day enumeration landed and served
// nowhere. "Enumeration was switched off" is a different statement from
// "enumeration found nothing", and only one of them is visible today.
func TestBuildJobResults_SurfacesEnumerationSkipped(t *testing.T) {
	stored := `{"success":true,"metadata":{"enumeration_skipped":"enumerate_compute is off for this integration"}}`
	out := buildJobResults("job-3", "completed", stored)
	if out.EnumerationSkipped != "enumerate_compute is off for this integration" {
		t.Errorf("enumeration_skipped = %q", out.EnumerationSkipped)
	}
}

// A job with no cloud metadata (every non-cloud interrogation) is unchanged:
// no resource types, no verdict. Absent means "not reported", and the UI must
// not be able to read it as "everything succeeded".
func TestBuildJobResults_NonCloudJobCarriesNoOutcome(t *testing.T) {
	stored := `{"success":true,"assets":[{"hostname":"switch.example.com","cipher_suite":"TLS_AES_128_GCM_SHA256"}]}`
	out := buildJobResults("job-4", "completed", stored)
	if len(out.ResourceTypes) != 0 {
		t.Errorf("resource types invented for a non-cloud job: %+v", out.ResourceTypes)
	}
	if out.Outcome != "" {
		t.Errorf("outcome = %q, want empty", out.Outcome)
	}
	if out.Summary.TotalAssets != 1 {
		t.Errorf("the existing projection regressed: %d assets", out.Summary.TotalAssets)
	}
}
