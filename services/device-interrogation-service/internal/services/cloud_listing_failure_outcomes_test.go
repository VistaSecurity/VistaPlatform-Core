package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/google/uuid"
	awsclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/aws"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
)

// Observed on a live deployment (v4.4.0-rc.3): the cloud_discovery job logged
//
//	failed to list API Gateways in us-east-1: ... context deadline exceeded (skipping region)
//
// and stored `{"resource_type":"api_gateway","status":"succeeded","found":0,
// "scopes_attempted":1,"scopes_succeeded":1}` under outcome "complete". Two
// faults stacked: the GetApis loop never advanced its NextToken, so a region
// that answered spun on page one until the 30-second deadline; and the
// resulting error was logged and `break`-ed past, so the collector returned
// a nil error and the dispatch recorded success.
//
// These drive the REAL collectors against a stub AWS endpoint (the seam the
// KMS/RDS tests in cloud_collector_errors_test.go use) and assert on what the
// recorder — and so device_jobs.results — says.

// stubAWS answers API Gateway v2 (REST-JSON) and ELBv2 (query/XML) calls with
// handler, and returns a client whose every service is pointed at it.
func stubAWS(t *testing.T, handler http.HandlerFunc) *awsclient.Client {
	t.Helper()
	srv := httptest.NewServer(handler)
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

// signedRegion is the region in a SigV4 credential scope, which is how one stub
// endpoint can answer two regions differently.
func signedRegion(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	i := strings.Index(auth, "Credential=")
	if i < 0 {
		return ""
	}
	parts := strings.Split(auth[i+len("Credential="):], "/")
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

func apiGatewayDenied(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Amzn-ErrorType", "AccessDeniedException")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"message":"User: arn:aws:iam::123456789012:user/discovery is not authorized to perform: apigateway:GET"}`))
}

func apiGatewayJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

// runAPIGateway dispatches api_gateway over regions exactly as
// DiscoverAWSResources wires it, and returns the recorder.
func runAPIGateway(t *testing.T, client *awsclient.Client, regions []string) *CloudOutcomeRecorder {
	t.Helper()
	svc := NewCloudDiscoveryService(nil, nil, "")
	tenantID := uuid.New()
	rec := NewCloudOutcomeRecorder([]string{"api_gateway"})
	ctx := WithCloudOutcomes(context.Background(), rec)
	runCloudCollectors(ctx, []string{"api_gateway"}, regions, map[string]cloudCollector{
		"api_gateway": {regional: true, collect: func(ctx context.Context, region string) ([]models.Device, error) {
			return svc.discoverAPIGateways(ctx, tenantID, client, []string{region})
		}},
	})
	return rec
}

// An account with no APIs is a success with zero found — reached on the FIRST
// page, not after spinning until the deadline. Mutation performed: drop the
// NextToken termination in listAPIGatewaysWithCustomDomains (the original
// `for { GetApis(input{}) }`) — GetApis is called until the deadline and the
// type records a timeout failure instead of an honest zero.
func TestDiscoverAPIGateways_EmptyRegionIsOnePageAndSucceeds(t *testing.T) {
	old := apiGatewayListTimeout
	apiGatewayListTimeout = 2 * time.Second
	t.Cleanup(func() { apiGatewayListTimeout = old })

	var calls atomic.Int32
	client := stubAWS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/apis" {
			calls.Add(1)
		}
		apiGatewayJSON(w, `{"items":[]}`)
	})

	rec := runAPIGateway(t, client, []string{"us-east-1"})

	got := outcomeFor(t, rec.Outcomes(), "api_gateway")
	if got.Status != CloudTypeSucceeded || got.Found != 0 || got.ScopesSucceeded != 1 {
		t.Fatalf("empty account: %+v, want succeeded/0", got)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("GetApis called %d times for one empty page, want 1", n)
	}
}

// A region whose listing is denied is a FAILED scope, not a successful empty
// one, and the run is not "complete". Mutation performed: restore
// `log.Printf(...); break` in the GetApis error path — status reads
// "succeeded" and the run "complete", the reported case.
func TestDiscoverAPIGateways_DeniedListingIsRecordedFailed(t *testing.T) {
	client := stubAWS(t, func(w http.ResponseWriter, r *http.Request) { apiGatewayDenied(w) })

	rec := runAPIGateway(t, client, []string{"us-east-1"})

	got := outcomeFor(t, rec.Outcomes(), "api_gateway")
	if got.Status != CloudTypeFailed || got.ScopesSucceeded != 0 || got.ScopesAttempted != 1 {
		t.Fatalf("denied listing: %+v, want failed 0/1", got)
	}
	if len(got.Failures) != 1 || got.Failures[0].Reason != CloudFailureAccessDenied || got.Failures[0].Scope != "us-east-1" {
		t.Fatalf("failure not recorded with scope and actionable reason: %+v", got.Failures)
	}
	metadata := map[string]interface{}{}
	if rec.ApplyToJobResult(metadata) {
		t.Error("job result reports success for a resource type nothing could list")
	}
	if metadata["outcome"] != CloudRunFailed {
		t.Errorf("outcome = %v, want %q", metadata["outcome"], CloudRunFailed)
	}
}

// The live symptom: the listing exceeds its deadline. It must classify as a
// timeout on the region it happened in.
func TestDiscoverAPIGateways_DeadlineIsRecordedAsTimeout(t *testing.T) {
	old := apiGatewayListTimeout
	apiGatewayListTimeout = 150 * time.Millisecond
	t.Cleanup(func() { apiGatewayListTimeout = old })

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	client := stubAWS(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})

	rec := runAPIGateway(t, client, []string{"us-east-1"})

	got := outcomeFor(t, rec.Outcomes(), "api_gateway")
	if got.Status != CloudTypeFailed {
		t.Fatalf("deadline: %+v, want failed", got)
	}
	if len(got.Failures) != 1 || got.Failures[0].Reason != CloudFailureTimeout {
		t.Fatalf("deadline not classified as timeout: %+v", got.Failures)
	}
}

// One region answers, one is denied: partial, with the found count of the
// region that answered kept.
func TestDiscoverAPIGateways_OneRegionDeniedIsPartial(t *testing.T) {
	client := stubAWS(t, func(w http.ResponseWriter, r *http.Request) {
		if signedRegion(r) == "eu-west-1" {
			apiGatewayDenied(w)
			return
		}
		apiGatewayJSON(w, `{"items":[]}`)
	})

	rec := runAPIGateway(t, client, []string{"us-east-1", "eu-west-1"})

	got := outcomeFor(t, rec.Outcomes(), "api_gateway")
	if got.Status != CloudTypePartial || got.ScopesSucceeded != 1 || got.ScopesAttempted != 2 {
		t.Fatalf("one denied region: %+v, want partial 1/2", got)
	}
	if len(got.Failures) != 1 || got.Failures[0].Scope != "eu-west-1" {
		t.Fatalf("failure scope: %+v", got.Failures)
	}
	if rec.Verdict() != CloudRunPartial {
		t.Errorf("verdict = %q, want partial", rec.Verdict())
	}
}

// APIs exist but the custom-domain listing is denied. We cannot say which
// APIs carry TLS, so this is a failure — it used to `continue` past every API,
// i.e. "found 0, succeeded". Mutation performed: restore `continue` on the
// GetDomainNames error — the type reads succeeded.
func TestDiscoverAPIGateways_DeniedDomainListingIsRecordedFailed(t *testing.T) {
	client := stubAWS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/apis" {
			apiGatewayJSON(w, `{"items":[{"apiId":"abc123","name":"orders","protocolType":"HTTP","apiEndpoint":"https://abc123.execute-api.us-east-1.amazonaws.com"}]}`)
			return
		}
		apiGatewayDenied(w)
	})

	rec := runAPIGateway(t, client, []string{"us-east-1"})

	got := outcomeFor(t, rec.Outcomes(), "api_gateway")
	if got.Status != CloudTypeFailed {
		t.Fatalf("denied domain listing: %+v, want failed", got)
	}
}

// The same shape for load balancers: a listener listing that is denied must
// not read as "this load balancer has no TLS". Mutation performed: restore
// the bare `continue` on the DescribeListeners error — the collector returns
// a nil error and the type reads succeeded.
func TestDiscoverLoadBalancers_DeniedListenerListingIsAnError(t *testing.T) {
	client := stubAWS(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "text/xml")
		switch r.Form.Get("Action") {
		case "DescribeLoadBalancers":
			_, _ = w.Write([]byte(`<DescribeLoadBalancersResponse xmlns="http://elasticloadbalancing.amazonaws.com/doc/2015-12-01/"><DescribeLoadBalancersResult><LoadBalancers><member>` +
				`<LoadBalancerArn>arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web/abc</LoadBalancerArn>` +
				`<DNSName>web-1.us-east-1.elb.amazonaws.com</DNSName><Type>application</Type><Scheme>internet-facing</Scheme><State><Code>active</Code></State>` +
				`</member></LoadBalancers></DescribeLoadBalancersResult></DescribeLoadBalancersResponse>`))
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code>` +
				`<Message>User: arn:aws:iam::123456789012:user/discovery is not authorized to perform: elasticloadbalancing:DescribeListeners</Message>` +
				`</Error></ErrorResponse>`))
		}
	})
	svc := NewCloudDiscoveryService(nil, nil, "")
	tenantID := uuid.New()
	rec := NewCloudOutcomeRecorder([]string{"alb"})
	ctx := WithCloudOutcomes(context.Background(), rec)
	runCloudCollectors(ctx, []string{"alb"}, []string{"us-east-1"}, map[string]cloudCollector{
		"alb": {regional: true, collect: func(ctx context.Context, region string) ([]models.Device, error) {
			return svc.discoverLoadBalancers(ctx, tenantID, client, "alb", []string{region})
		}},
	})

	got := outcomeFor(t, rec.Outcomes(), "alb")
	if got.Status != CloudTypeFailed || len(got.Failures) != 1 || got.Failures[0].Reason != CloudFailureAccessDenied {
		t.Fatalf("denied listeners: %+v, want failed/access_denied", got)
	}
}
