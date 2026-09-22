package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/smithy-go"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
)

// slice E. The bug these pin: a cloud discovery stored
// {"success": true, "metadata": {...}} for a run where the KMS collector had
// been denied, so "the account has no KMS keys" and "we were not allowed to
// look" were byte-identical results.
//
// Every test here is about a DISTINCTION. If a change makes two different
// situations produce the same output, something below goes red.

// apiErr is a stand-in for an AWS SDK error: smithy.APIError is the interface
// every aws-sdk-go-v2 service error implements, and errors.As against it is
// how the projection gets the provider's own code.
type apiErr struct {
	code    string
	message string
}

func (e apiErr) Error() string                 { return e.code + ": " + e.message }
func (e apiErr) ErrorCode() string             { return e.code }
func (e apiErr) ErrorMessage() string          { return e.message }
func (e apiErr) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

func fakeDevices(n int) []models.Device {
	out := make([]models.Device, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, models.Device{ID: uuid.New()})
	}
	return out
}

func outcomeFor(t *testing.T, outcomes []CloudResourceTypeOutcome, resourceType string) CloudResourceTypeOutcome {
	t.Helper()
	for _, o := range outcomes {
		if o.ResourceType == resourceType {
			return o
		}
	}
	t.Fatalf("no outcome recorded for %q; got %+v", resourceType, outcomes)
	return CloudResourceTypeOutcome{}
}

// ---------------------------------------------------------------------------
// The headline distinction: empty is not failed.
// ---------------------------------------------------------------------------

// TestRunCloudCollectors_EmptyIsNotFailed drives the REAL dispatch — the
// function DiscoverAWSResources calls — with one collector that finds nothing
// and one that is denied, and asserts the two are distinguishable.
//
// Mutation: delete the `outcomes.Attempt(...)` line in runCloudCollectors and
// this fails (no outcome recorded at all). Swap it for a version that ignores
// err and this fails too (both types read "succeeded, 0 found"), which is
// exactly the pre- behaviour.
func TestRunCloudCollectors_EmptyIsNotFailed(t *testing.T) {
	rec := NewCloudOutcomeRecorder([]string{"s3", "kms"})
	ctx := WithCloudOutcomes(context.Background(), rec)

	devices := runCloudCollectors(ctx, []string{"s3", "kms"}, []string{"us-east-1"}, map[string]cloudCollector{
		// Looked, and the account genuinely has none.
		"s3": {collect: func(context.Context, string) ([]models.Device, error) { return nil, nil }},
		// Could not look.
		"kms": {regional: true, collect: func(context.Context, string) ([]models.Device, error) {
			return nil, apiErr{code: "AccessDeniedException", message: "User is not authorized to perform: kms:ListKeys"}
		}},
	})

	if len(devices) != 0 {
		t.Fatalf("expected no devices, got %d", len(devices))
	}

	s3 := outcomeFor(t, rec.Outcomes(), "s3")
	kms := outcomeFor(t, rec.Outcomes(), "kms")

	if s3.Status != CloudTypeSucceeded || s3.Found != 0 {
		t.Errorf("empty s3 should be succeeded/0, got %s/%d", s3.Status, s3.Found)
	}
	if kms.Status != CloudTypeFailed {
		t.Errorf("denied kms should be failed, got %s", kms.Status)
	}
	if s3.Status == kms.Status {
		t.Fatal("an empty resource type and a denied one are indistinguishable — this is the #1924 bug")
	}
	if len(kms.Failures) != 1 {
		t.Fatalf("expected one recorded failure, got %d", len(kms.Failures))
	}
	if kms.Failures[0].Code != "AccessDeniedException" {
		t.Errorf("provider error code lost: %q", kms.Failures[0].Code)
	}
	if kms.Failures[0].Reason != CloudFailureAccessDenied {
		t.Errorf("reason = %q, want %q", kms.Failures[0].Reason, CloudFailureAccessDenied)
	}
	if kms.Failures[0].Scope != "us-east-1" {
		t.Errorf("scope = %q, want the failing region", kms.Failures[0].Scope)
	}
	if rec.Succeeded() {
		t.Error("a run whose KMS collection was denied must not report success")
	}
	// s3 succeeded, kms failed — the run saw some of what it was asked to.
	if got := rec.Verdict(); got != CloudRunPartial {
		t.Errorf("verdict = %q, want partial", got)
	}
}

// TestRunCloudCollectors_OneFailureDoesNotAbortTheRest pins the other half of
// the old bug: alb/elb/nlb, api_gateway and cloudfront used to `return nil,
// err`, so one failing type discarded every type that had already worked.
//
// Mutation: make runCloudCollectors return early on the first error and this
// fails — cloudfront's device disappears.
func TestRunCloudCollectors_OneFailureDoesNotAbortTheRest(t *testing.T) {
	rec := NewCloudOutcomeRecorder([]string{"alb", "cloudfront"})
	ctx := WithCloudOutcomes(context.Background(), rec)

	devices := runCloudCollectors(ctx, []string{"alb", "cloudfront"}, []string{"us-east-1"}, map[string]cloudCollector{
		"alb": {regional: true, collect: func(context.Context, string) ([]models.Device, error) {
			return nil, apiErr{code: "ThrottlingException", message: "Rate exceeded"}
		}},
		"cloudfront": {collect: func(context.Context, string) ([]models.Device, error) { return fakeDevices(1), nil }},
	})

	if len(devices) != 1 {
		t.Fatalf("a failing type discarded a working one's results: got %d devices, want 1", len(devices))
	}
	if got := outcomeFor(t, rec.Outcomes(), "alb"); got.Status != CloudTypeFailed {
		t.Errorf("alb status = %q, want failed", got.Status)
	}
	if got := outcomeFor(t, rec.Outcomes(), "alb").Failures[0].Reason; got != CloudFailureThrottled {
		t.Errorf("a throttle must not read as a permission problem: reason = %q", got)
	}
	cf := outcomeFor(t, rec.Outcomes(), "cloudfront")
	if cf.Status != CloudTypeSucceeded || cf.Found != 1 {
		t.Errorf("cloudfront = %s/%d, want succeeded/1", cf.Status, cf.Found)
	}
	if len(cf.Failures) != 0 {
		t.Errorf("a working type must carry no failures, got %+v", cf.Failures)
	}
	// A non-regional collector runs once, under "global" — not once per region.
	if cf.ScopesAttempted != 1 {
		t.Errorf("cloudfront scopes attempted = %d, want 1 (global)", cf.ScopesAttempted)
	}
}

// TestRunCloudCollectors_PartialAcrossRegions — a type that worked in one
// region and was denied in another is neither "succeeded" nor "failed".
//
// Mutation: make the dispatch pass all regions to the collector in one call
// (the pre- shape) and the per-region distinction is unrecoverable.
func TestRunCloudCollectors_PartialAcrossRegions(t *testing.T) {
	rec := NewCloudOutcomeRecorder([]string{"rds"})
	ctx := WithCloudOutcomes(context.Background(), rec)

	devices := runCloudCollectors(ctx, []string{"rds"}, []string{"us-east-1", "eu-west-1"}, map[string]cloudCollector{
		"rds": {regional: true, collect: func(_ context.Context, region string) ([]models.Device, error) {
			if region == "eu-west-1" {
				return nil, apiErr{code: "AccessDenied", message: "not authorized to perform: rds:DescribeDBInstances"}
			}
			return fakeDevices(2), nil
		}},
	})

	if len(devices) != 2 {
		t.Fatalf("the working region's results were discarded: %d devices", len(devices))
	}
	rds := outcomeFor(t, rec.Outcomes(), "rds")
	if rds.Status != CloudTypePartial {
		t.Errorf("status = %q, want partial", rds.Status)
	}
	if rds.ScopesAttempted != 2 || rds.ScopesSucceeded != 1 {
		t.Errorf("scopes = %d/%d, want 1 of 2", rds.ScopesSucceeded, rds.ScopesAttempted)
	}
	if rds.Found != 2 {
		t.Errorf("found = %d, want the two the working region returned", rds.Found)
	}
	if rec.Verdict() != CloudRunPartial || rec.Succeeded() {
		t.Errorf("verdict = %q / success = %v; a partial run is not a success", rec.Verdict(), rec.Succeeded())
	}
}

// TestRunCloudCollectors_CollectorReturningBothIsNotRounded — the shape
// DiscoverRDSEncryption and DiscoverAWSKMSKeys now return: devices AND an
// error. Neither half may be dropped.
func TestRunCloudCollectors_CollectorReturningBothIsNotRounded(t *testing.T) {
	rec := NewCloudOutcomeRecorder([]string{"rds"})
	ctx := WithCloudOutcomes(context.Background(), rec)

	devices := runCloudCollectors(ctx, []string{"rds"}, []string{"us-east-1"}, map[string]cloudCollector{
		"rds": {regional: true, collect: func(context.Context, string) ([]models.Device, error) {
			return fakeDevices(3), errors.New("us-east-1: page 2 failed")
		}},
	})

	if len(devices) != 3 {
		t.Errorf("devices returned alongside an error were discarded: %d", len(devices))
	}
	if got := outcomeFor(t, rec.Outcomes(), "rds"); got.Status != CloudTypeFailed || got.Found != 3 {
		t.Errorf("got %s/%d; the error must be recorded AND the partial results kept", got.Status, got.Found)
	}
}

// TestRunCloudCollectors_RequestedButUncollected — a type nobody collects is
// not_attempted, never "succeeded with zero". The old switch fell through
// silently and the job reported nothing about it at all.
func TestRunCloudCollectors_RequestedButUncollected(t *testing.T) {
	rec := NewCloudOutcomeRecorder([]string{"s3", "efs"})
	ctx := WithCloudOutcomes(context.Background(), rec)

	runCloudCollectors(ctx, []string{"s3", "efs"}, []string{"us-east-1"}, map[string]cloudCollector{
		"s3": {collect: func(context.Context, string) ([]models.Device, error) { return fakeDevices(4), nil }},
	})

	efs := outcomeFor(t, rec.Outcomes(), "efs")
	if efs.Status != CloudTypeNotAttempted {
		t.Errorf("efs status = %q, want not_attempted", efs.Status)
	}
	if efs.ScopesAttempted != 0 {
		t.Errorf("nothing looked, so no scope was attempted; got %d", efs.ScopesAttempted)
	}
	// Nothing FAILED, so the run is still complete — but the user can see that
	// efs was never collected rather than reading it as an empty account.
	if !rec.Succeeded() || rec.Verdict() != CloudRunComplete {
		t.Errorf("an uncollected type is not a failure: verdict = %q", rec.Verdict())
	}
}

// TestRunCloudCollectors_NilRecorderIsANoOp — a caller that does not opt in
// (Azure/GCP today) must behave exactly as before rather than reporting a
// verdict it did not measure.
func TestRunCloudCollectors_NilRecorderIsANoOp(t *testing.T) {
	devices := runCloudCollectors(context.Background(), []string{"s3"}, nil, map[string]cloudCollector{
		"s3": {collect: func(context.Context, string) ([]models.Device, error) { return fakeDevices(2), nil }},
	})
	if len(devices) != 2 {
		t.Fatalf("devices = %d, want 2", len(devices))
	}
	var nilRec *CloudOutcomeRecorder
	if nilRec.Outcomes() != nil {
		t.Error("a nil recorder must report nothing, not an empty verdict")
	}
	if !nilRec.Succeeded() || nilRec.Verdict() != CloudRunComplete {
		t.Error("a nil recorder must not change the caller's behaviour")
	}
}

// ---------------------------------------------------------------------------
// Verdict table
// ---------------------------------------------------------------------------

func TestCloudOutcomeRecorder_Verdict(t *testing.T) {
	denied := apiErr{code: "AccessDenied", message: "nope"}

	cases := []struct {
		name    string
		build   func(*CloudOutcomeRecorder)
		verdict string
		success bool
	}{
		{
			name: "all succeeded",
			build: func(r *CloudOutcomeRecorder) {
				r.Attempt("s3", "global", 3, nil)
				r.Attempt("kms", "us-east-1", 0, nil)
			},
			verdict: CloudRunComplete, success: true,
		},
		{
			name: "every attempted type failed",
			build: func(r *CloudOutcomeRecorder) {
				r.Attempt("s3", "global", 0, denied)
				r.Attempt("kms", "us-east-1", 0, denied)
			},
			verdict: CloudRunFailed, success: false,
		},
		{
			name: "one of two failed",
			build: func(r *CloudOutcomeRecorder) {
				r.Attempt("s3", "global", 3, nil)
				r.Attempt("kms", "us-east-1", 0, denied)
			},
			verdict: CloudRunPartial, success: false,
		},
		{
			name: "single type partial across regions",
			build: func(r *CloudOutcomeRecorder) {
				r.Attempt("kms", "us-east-1", 1, nil)
				r.Attempt("kms", "eu-west-1", 0, denied)
			},
			verdict: CloudRunPartial, success: false,
		},
		{
			name:    "nothing attempted",
			build:   func(r *CloudOutcomeRecorder) {},
			verdict: CloudRunComplete, success: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewCloudOutcomeRecorder([]string{"s3", "kms"})
			tc.build(r)
			if got := r.Verdict(); got != tc.verdict {
				t.Errorf("verdict = %q, want %q", got, tc.verdict)
			}
			if got := r.Succeeded(); got != tc.success {
				t.Errorf("success = %v, want %v", got, tc.success)
			}
		})
	}
}

// ApplyToJobResult is the one definition of what a cloud job's stored result
// says, shared by the interactive handler and the scheduled worker so the two
// cannot disagree about what success means.
func TestApplyToJobResult(t *testing.T) {
	t.Run("partial run writes the outcomes and reports failure", func(t *testing.T) {
		r := NewCloudOutcomeRecorder([]string{"s3", "kms"})
		r.Attempt("s3", "global", 4, nil)
		r.Attempt("kms", "us-east-1", 0, apiErr{code: "AccessDeniedException", message: "denied"})

		md := map[string]interface{}{"devices_count": 4}
		if success := r.ApplyToJobResult(md); success {
			t.Error("success must be false when a requested type could not be collected")
		}
		if md["outcome"] != CloudRunPartial {
			t.Errorf("outcome = %v, want partial", md["outcome"])
		}
		types, ok := md["resource_types"].([]CloudResourceTypeOutcome)
		if !ok || len(types) != 2 {
			t.Fatalf("resource_types = %#v", md["resource_types"])
		}
	})

	t.Run("a nil recorder asserts nothing", func(t *testing.T) {
		var r *CloudOutcomeRecorder
		md := map[string]interface{}{}
		if !r.ApplyToJobResult(md) {
			t.Error("a provider that does not record outcomes must keep its prior behaviour")
		}
		if _, present := md["outcome"]; present {
			t.Error("a nil recorder invented a verdict it did not measure")
		}
		if _, present := md["resource_types"]; present {
			t.Error("a nil recorder invented resource types")
		}
	})
}

// Requested order is the display order; a map would shuffle it per run.
func TestCloudOutcomeRecorder_PreservesRequestOrder(t *testing.T) {
	r := NewCloudOutcomeRecorder([]string{"alb", "elb", "nlb", "api_gateway", "cloudfront", "kms", "s3", "rds"})
	got := make([]string, 0, 8)
	for _, o := range r.Outcomes() {
		got = append(got, o.ResourceType)
	}
	want := "alb,elb,nlb,api_gateway,cloudfront,kms,s3,rds"
	if strings.Join(got, ",") != want {
		t.Errorf("order = %s, want %s", strings.Join(got, ","), want)
	}
}

// ---------------------------------------------------------------------------
// Provider error projection: keep the code, redact the payload.
// ---------------------------------------------------------------------------

func TestSanitizeCloudFailure_KeepsCodeClassifiesReason(t *testing.T) {
	cases := []struct {
		code   string
		msg    string
		reason string
	}{
		{"AccessDeniedException", "User: arn:aws:iam::123456789012:user/bot is not authorized to perform: kms:ListKeys", CloudFailureAccessDenied},
		{"UnauthorizedOperation", "You are not authorized to perform this operation", CloudFailureAccessDenied},
		{"ThrottlingException", "Rate exceeded", CloudFailureThrottled},
		{"RequestLimitExceeded", "Request limit exceeded", CloudFailureThrottled},
		{"ExpiredToken", "The security token included in the request is expired", CloudFailureCredentials},
		{"InvalidClientTokenId", "The security token included in the request is invalid", CloudFailureCredentials},
		{"OptInRequired", "The subscription to this region is not enabled", CloudFailureRegion},
		{"InternalFailure", "we broke", CloudFailureUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			f := SanitizeCloudFailure("us-east-1", apiErr{code: tc.code, message: tc.msg})
			if f.Code != tc.code {
				t.Errorf("code = %q, want %q verbatim — an AccessDenied is a different user action from a throttle", f.Code, tc.code)
			}
			if f.Reason != tc.reason {
				t.Errorf("reason = %q, want %q", f.Reason, tc.reason)
			}
			if f.Scope != "us-east-1" {
				t.Errorf("scope = %q", f.Scope)
			}
		})
	}
}

// A non-SDK error still gets recorded rather than dropped.
func TestSanitizeCloudFailure_PlainError(t *testing.T) {
	f := SanitizeCloudFailure("global", fmt.Errorf("dial tcp 192.0.2.10:443: connection refused"))
	if f.Reason != CloudFailureNetwork {
		t.Errorf("reason = %q, want network", f.Reason)
	}
	if f.Message == "" {
		t.Error("a plain error's message must survive")
	}
}

func TestSanitizeCloudFailure_NilError(t *testing.T) {
	if f := SanitizeCloudFailure("global", nil); f.Reason != "" || f.Message != "" {
		t.Errorf("a nil error must not synthesise a failure: %+v", f)
	}
}

// The redaction. Every case here is a shape an AWS error message has been
// observed to carry, and every one of them would otherwise be persisted into
// device_jobs.results — which CLAUDE.md forbids outright.
func TestSanitizeCloudErrorMessage_Redacts(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		absent  string
		present string
	}{
		{
			name:    "aws access key id",
			in:      "The AWS Access Key Id AKIAIOSFODNN7EXAMPLE does not exist in our records",
			absent:  "AKIAIOSFODNN7EXAMPLE",
			present: "does not exist",
		},
		{
			name:   "session token blob",
			in:     "signature mismatch for FQoGZXIvYXdzEBYaDHRlc3RzZXNzaW9udG9rZW5mb3J0ZXN0aW5ncHVycG9zZXNvbmx5",
			absent: "FQoGZXIvYXdzEBYaDHRlc3RzZXNzaW9udG9rZW5mb3J0ZXN0aW5ncHVycG9zZXNvbmx5",
		},
		{
			name:   "named secret",
			in:     "connection failed (password=hunter2seekrit)",
			absent: "hunter2seekrit",
		},
		{
			name:   "named token",
			in:     "x-amz-security-token: abc123def456",
			absent: "abc123def456",
		},
		{
			name:    "account id and arn survive — the tenant's own identifiers are the actionable part",
			in:      "User: arn:aws:iam::123456789012:user/discovery is not authorized",
			present: "arn:aws:iam::123456789012:user/discovery",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeCloudErrorMessage(tc.in)
			if tc.absent != "" && strings.Contains(got, tc.absent) {
				t.Errorf("secret-shaped run survived sanitization: %q", got)
			}
			if tc.present != "" && !strings.Contains(got, tc.present) {
				t.Errorf("actionable text was destroyed: %q does not contain %q", got, tc.present)
			}
		})
	}
}

func TestSanitizeCloudErrorMessage_BoundsAndFlattens(t *testing.T) {
	long := "denied " + strings.Repeat("why ", 400)
	got := SanitizeCloudErrorMessage(long)
	if len([]byte(got)) > cloudFailureMessageMax+4 {
		t.Errorf("message not bounded: %d bytes", len(got))
	}
	if flat := SanitizeCloudErrorMessage("line one\nline\ttwo\x00\x07"); strings.ContainsAny(flat, "\n\t\x00\x07") {
		t.Errorf("control characters survived: %q", flat)
	}
}
