package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/google/uuid"
	awsclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/aws"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
)

// slice E, the deepest half. The dispatch switch was not the only place
// a failure was swallowed: BOTH regional collectors under it logged their
// region error and carried on with a nil error, so a denied region produced
// "0 found" with no error for the dispatch to record. Fixing the switch alone
// would have shipped an honest-looking feature that could never report a KMS
// or RDS denial — the classic "check that cannot fail".
//
// These drive the real collectors against a stub AWS endpoint, which is the
// only seam that exists: the region loops build their service clients from
// awsClient.GetConfig().

// deniedAWS stands up an endpoint that answers every call with AccessDenied,
// in both wire shapes the two services use (KMS is JSON, RDS is query/XML).
func deniedAWS(t *testing.T) *awsclient.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("X-Amz-Target"), "TrentService") {
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"__type":"AccessDeniedException","message":"User: arn:aws:iam::123456789012:user/discovery is not authorized to perform: kms:ListKeys"}`))
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code>` +
			`<Message>User: arn:aws:iam::123456789012:user/discovery is not authorized to perform: rds:DescribeDBInstances</Message>` +
			`</Error></ErrorResponse>`))
	}))
	t.Cleanup(srv.Close)

	cfg := awssdk.Config{
		Region:           "us-east-1",
		Credentials:      credentials.NewStaticCredentialsProvider("AKIAEXAMPLEEXAMPLE00", "not-a-real-secret", ""),
		BaseEndpoint:     awssdk.String(srv.URL),
		RetryMaxAttempts: 1,
		HTTPClient:       srv.Client(),
	}
	return awsclient.NewClientFromConfig(cfg, "123456789012", "us-east-1")
}

// TestDiscoverAWSKMSKeys_ReturnsRegionFailure.
//
// Mutation performed: restore the original `log.Printf(...); continue` in
// DiscoverAWSKMSKeys's region loop (drop regionErrs / errors.Join) — this test
// fails with "a denied region reported success", which is precisely the
// production behaviour the spec's evidence item 8 recorded.
func TestDiscoverAWSKMSKeys_ReturnsRegionFailure(t *testing.T) {
	svc := NewKMSDiscoveryService(nil, nil, "")

	findings, err := svc.DiscoverAWSKMSKeys(context.Background(), uuid.New(), uuid.New(),
		[]string{"us-east-1"}, deniedAWS(t))

	if err == nil {
		t.Fatal("a denied region reported success — the caller cannot tell it apart from an account with no keys")
	}
	if len(findings) != 0 {
		t.Errorf("findings = %d, want 0", len(findings))
	}
	// And the failure still classifies as something the user can act on once
	// it reaches the job result.
	f := SanitizeCloudFailure("us-east-1", err)
	if f.Reason != CloudFailureAccessDenied {
		t.Errorf("reason = %q (%q), want access_denied", f.Reason, f.Message)
	}
}

// TestDiscoverRDSEncryption_ReturnsRegionFailure.
//
// Mutation performed: restore the original bare `break` (drop regionErrs) —
// this test fails the same way.
func TestDiscoverRDSEncryption_ReturnsRegionFailure(t *testing.T) {
	svc := NewStorageEncryptionService(nil, nil, "")

	devices, err := svc.DiscoverRDSEncryption(context.Background(), uuid.New(), deniedAWS(t), []string{"us-east-1"})

	if err == nil {
		t.Fatal("a denied region reported success — an IAM denial is indistinguishable from an account with no RDS instances")
	}
	if len(devices) != 0 {
		t.Errorf("devices = %d, want 0", len(devices))
	}
	if f := SanitizeCloudFailure("us-east-1", err); f.Reason != CloudFailureAccessDenied {
		t.Errorf("reason = %q (%q), want access_denied", f.Reason, f.Message)
	}
}

// The end-to-end shape the dispatch sees: a real collector that fails hands
// back an error, so the recorder can distinguish it from an empty account.
func TestDispatchRecordsRealCollectorDenial(t *testing.T) {
	client := deniedAWS(t)
	rec := NewCloudOutcomeRecorder([]string{"rds"})
	ctx := WithCloudOutcomes(context.Background(), rec)
	storage := NewStorageEncryptionService(nil, nil, "")
	tenantID := uuid.New()

	runCloudCollectors(ctx, []string{"rds"}, []string{"us-east-1"}, map[string]cloudCollector{
		"rds": {regional: true, collect: func(ctx context.Context, region string) ([]models.Device, error) {
			return storage.DiscoverRDSEncryption(ctx, tenantID, client, []string{region})
		}},
	})

	got := outcomeFor(t, rec.Outcomes(), "rds")
	if got.Status != CloudTypeFailed {
		t.Fatalf("status = %q, want failed", got.Status)
	}
	if len(got.Failures) != 1 || got.Failures[0].Reason != CloudFailureAccessDenied {
		t.Fatalf("failure not recorded with an actionable reason: %+v", got.Failures)
	}
	if rec.Succeeded() {
		t.Error("the run must not report success")
	}
}
