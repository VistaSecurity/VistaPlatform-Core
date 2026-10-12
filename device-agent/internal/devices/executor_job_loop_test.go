package devices

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/models"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
)

// stubInterrogator lets a test decide what a "device" does.
type stubInterrogator struct {
	run func(ctx context.Context) (*di.InterrogateResult, error)
}

func (s stubInterrogator) Interrogate(ctx context.Context, _ di.DeviceInfo, _ di.Credentials) (*di.InterrogateResult, error) {
	return s.run(ctx)
}
func (stubInterrogator) SupportedDeviceTypes() []string { return []string{"stub_device"} }

func stubExecutor(run func(ctx context.Context) (*di.InterrogateResult, error)) (*JobExecutor, *recordingClient) {
	rec := &recordingClient{}
	reg := di.NewRegistry()
	reg.Register(stubInterrogator{run: run})
	return &JobExecutor{submitter: rec, config: &config.Config{}, registry: reg}, rec
}

func stubJob(params map[string]interface{}) *models.Job {
	return &models.Job{
		ID:          uuid.New(),
		Type:        "device_interrogation",
		DeviceType:  "stub_device",
		Credentials: map[string]interface{}{"username": "u", "password": "p"},
		Parameters:  params,
	}
}

// A device that never answers must not hold the poll loop. The stub ignores its
// context entirely (an SSH stall inside a library call), so this also proves
// the bound does not depend on the interrogator's cooperation.
//
// Mutation: replace `interrogateBounded(ctx, ...)` with a direct
// `interrogator.Interrogate(context.Background(), ...)` and this blocks until
// the test's own deadline.
func TestExecute_HungInterrogationTimesOutAsAFailure(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	exec, rec := stubExecutor(func(context.Context) (*di.InterrogateResult, error) {
		<-release
		return &di.InterrogateResult{}, nil
	})
	exec.jobTimeout = 50 * time.Millisecond

	done := make(chan error, 1)
	go func() { done <- exec.Execute(context.Background(), stubJob(nil)) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Execute: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Execute did not return: a hung device wedged the job loop")
	}

	got := rec.last()
	if got == nil || got.Success {
		t.Fatalf("want a failed result, got %+v", got)
	}
	if !strings.Contains(got.Error, "timed out after") {
		t.Fatalf("Error = %q; want a clear timeout reason", got.Error)
	}
}

// The job's own timeout_seconds wins over the executor default, and is capped.
func TestTimeoutFor(t *testing.T) {
	exec := &JobExecutor{}
	cases := []struct {
		name   string
		params map[string]interface{}
		want   time.Duration
	}{
		{"default", nil, DefaultJobTimeout},
		{"payload", map[string]interface{}{"timeout_seconds": float64(90)}, 90 * time.Second},
		{"zero ignored", map[string]interface{}{"timeout_seconds": float64(0)}, DefaultJobTimeout},
		{"negative ignored", map[string]interface{}{"timeout_seconds": float64(-5)}, DefaultJobTimeout},
		{"capped", map[string]interface{}{"timeout_seconds": float64(86400)}, maxJobTimeout},
		{"wrong type ignored", map[string]interface{}{"timeout_seconds": "90"}, DefaultJobTimeout},
	}
	for _, c := range cases {
		if got := exec.timeoutFor(&models.Job{Parameters: c.params}); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	exec.jobTimeout = time.Minute
	if got := exec.timeoutFor(&models.Job{}); got != time.Minute {
		t.Errorf("configured default: got %v", got)
	}
}

// A panic in one interrogator becomes a failed job, not a dead agent, and the
// message that goes out is redacted.
//
// Mutation: delete the `defer func() { if r := recover() ... }()` block in
// Execute and the panic escapes this test.
func TestExecute_PanicBecomesRedactedFailure(t *testing.T) {
	const secret = "hunter2-LIVE"
	exec, rec := stubExecutor(func(context.Context) (*di.InterrogateResult, error) {
		panic("boom while calling https://dev.example/api?password=" + secret)
	})

	if err := exec.Execute(context.Background(), stubJob(nil)); err != nil {
		t.Fatalf("Execute returned %v; the panic should have been reported as a result", err)
	}
	got := rec.last()
	if got == nil || got.Success {
		t.Fatalf("want a failed result, got %+v", got)
	}
	if !strings.Contains(got.Error, "panicked") || !strings.Contains(got.Error, "boom") {
		t.Fatalf("Error = %q; want the panic message", got.Error)
	}
	if strings.Contains(got.Error, secret) {
		t.Fatalf("the panic text leaked a credential: %q", got.Error)
	}

	// And the executor is still usable afterwards.
	exec2, rec2 := stubExecutor(func(context.Context) (*di.InterrogateResult, error) { return &di.InterrogateResult{}, nil })
	if err := exec2.Execute(context.Background(), stubJob(nil)); err != nil || rec2.last() == nil || !rec2.last().Success {
		t.Fatalf("a normal job after a panic failed: %v %+v", err, rec2.last())
	}
}

// ReportError redacts like submitFailure does.
func TestReportError_IsRedacted(t *testing.T) {
	exec, rec := newTestExecutor()
	leaky := (&url.Error{Op: "Get", URL: "https://x.example/?password=s3cr3t-LIVE", Err: http.ErrHandlerTimeout}).Error()
	if err := exec.ReportError(uuid.New(), leaky); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rec.last().Error, "s3cr3t-LIVE") {
		t.Fatalf("leaked: %q", rec.last().Error)
	}
}
