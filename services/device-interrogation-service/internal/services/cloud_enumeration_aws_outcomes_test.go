package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awsclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/aws"
)

// A credential without ec2:DescribeInstances in a region used to be logged and
// skipped, so the job read exactly like an account with no instances there.
// The enumeration calls are now recorded as per-type, per-region outcomes the
// job shows. The REAL enumerateAWS runs the REAL SDK paginators against a
// local EC2 query-API fake.
//
// MUTATION-VERIFIED: drop the outcomes.Attempt call after
// ListInstancesWithTerminated and the refusal is invisible again (no
// compute_instances outcome, no eu-west-1 row in the grid).
func TestEnumerateAWS_MissingDescribePermissionIsRecorded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		action := r.Form.Get("Action")
		// The SigV4 credential scope names the region the call was signed for.
		region := "us-east-1"
		if strings.Contains(r.Header.Get("Authorization"), "/eu-west-1/") {
			region = "eu-west-1"
		}
		w.Header().Set("Content-Type", "text/xml")
		if action == "DescribeInstances" && region == "eu-west-1" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<Response><Errors><Error><Code>UnauthorizedOperation</Code><Message>You are not authorized to perform this operation.</Message></Error></Errors><RequestID>req-1</RequestID></Response>`))
			return
		}
		ns := `xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"`
		switch action {
		case "DescribeVpcs":
			_, _ = w.Write([]byte(`<DescribeVpcsResponse ` + ns + `><requestId>r</requestId><vpcSet/></DescribeVpcsResponse>`))
		case "DescribeSubnets":
			_, _ = w.Write([]byte(`<DescribeSubnetsResponse ` + ns + `><requestId>r</requestId><subnetSet/></DescribeSubnetsResponse>`))
		case "DescribeSecurityGroups":
			_, _ = w.Write([]byte(`<DescribeSecurityGroupsResponse ` + ns + `><requestId>r</requestId><securityGroupInfo/></DescribeSecurityGroupsResponse>`))
		case "DescribeRegions":
			_, _ = w.Write([]byte(`<DescribeRegionsResponse ` + ns + `><requestId>r</requestId><regionInfo>` +
				`<item><regionName>us-east-1</regionName><optInStatus>opt-in-not-required</optInStatus></item>` +
				`<item><regionName>eu-west-1</regionName><optInStatus>opt-in-not-required</optInStatus></item>` +
				`<item><regionName>af-south-1</regionName><optInStatus>not-opted-in</optInStatus></item>` +
				`</regionInfo></DescribeRegionsResponse>`))
		case "DescribeInstances":
			_, _ = w.Write([]byte(`<DescribeInstancesResponse ` + ns + `><requestId>r</requestId><reservationSet/></DescribeInstancesResponse>`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	cfg := aws.Config{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("AKIDEXAMPLETESTONLY", "example-secret-test-only", ""),
		BaseEndpoint: aws.String(srv.URL),
		HTTPClient:   srv.Client(),
	}
	client := awsclient.NewClientFromConfig(cfg, "123456789012", "us-east-1")

	rec := NewCloudOutcomeRecorder([]string{"kms", CloudTypeComputeInstances})
	ctx := WithCloudOutcomes(context.Background(), rec)
	// The regions come from the account, not from the request (ADR-0009 D3):
	// the opted-out region is not read.
	regions := discoverRegionsWith(ctx, client.EC2ClientForRegion("us-east-1"), "us-east-1")
	if strings.Join(regions, ",") != "eu-west-1,us-east-1" {
		t.Fatalf("discovered regions = %v, want the two enabled ones", regions)
	}
	if _, err := (&CloudDiscoveryService{}).enumerateAWS(ctx, client, regions, selectEnumeration([]string{CloudTypeComputeInstances})); err != nil {
		t.Fatalf("enumerateAWS: %v", err)
	}

	var instances *CloudResourceTypeOutcome
	for _, o := range rec.Outcomes() {
		if o.ResourceType == CloudTypeComputeInstances {
			o := o
			instances = &o
		}
	}
	if instances == nil {
		t.Fatal("a refused DescribeInstances left no outcome — the job would read as 'no instances'")
	}
	if instances.Status != CloudTypePartial || instances.ScopesSucceeded != 1 || instances.ScopesAttempted != 2 {
		t.Errorf("compute_instances = %+v, want partial, 1 of 2 regions", *instances)
	}
	// The grid: one row per region, the refused one failed with the
	// provider's code, the other succeeded with its (zero) count.
	rows := map[string]CloudRegionOutcome{}
	for _, row := range instances.Regions {
		rows[row.Region] = row
	}
	if r := rows["eu-west-1"]; r.Status != CloudTypeFailed || r.Failure == nil || r.Failure.Code != "UnauthorizedOperation" {
		t.Errorf("eu-west-1 row = %+v, want failed / UnauthorizedOperation", r)
	}
	if r := rows["us-east-1"]; r.Status != CloudTypeSucceeded || r.Found != 0 {
		t.Errorf("us-east-1 row = %+v, want succeeded with 0", r)
	}
	// Coverage: only the region that answered completely may later be read
	// as proof that a resource is gone.
	if got := strings.Join(rec.Covered(), ","); !strings.Contains(got, "compute_instances@us-east-1") || strings.Contains(got, "compute_instances@eu-west-1") {
		t.Errorf("covered = %q, want us-east-1 and not eu-west-1", got)
	}
	if len(instances.Failures) != 1 || instances.Failures[0].Scope != "eu-west-1" ||
		instances.Failures[0].Code != "UnauthorizedOperation" || instances.Failures[0].Reason != CloudFailureAccessDenied {
		t.Errorf("failures = %+v, want eu-west-1 / UnauthorizedOperation / access_denied", instances.Failures)
	}
	if rec.Verdict() != CloudRunPartial {
		t.Errorf("verdict = %s, want partial", rec.Verdict())
	}
}
