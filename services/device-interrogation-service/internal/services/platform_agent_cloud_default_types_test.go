package services

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
)

// A scheduled cloud run used to collect nothing but compute enumeration.
//
// The Scheduled Scans modal creates a schedule with no `parameters`,
// TriggerSchedule copies that empty map onto the job, and executeCloudDiscovery
// read the absent `resource_types` literally: runCloudCollectors looped over
// nothing, and the run still reported success. These tests drive the REAL
// executeCloudDiscovery with a discoverer that dispatches through the REAL
// runCloudCollectors, and watch which collectors actually run.

// recordingDiscoverer stands in for CloudDiscoveryService. DiscoverResources
// dispatches through runCloudCollectors with one recording collector per AWS
// resource type, so a collector that is never dispatched is never recorded.
type recordingDiscoverer struct {
	provider string

	mu             sync.Mutex
	ran            []string
	resourceCalls  [][]string
	evidenceCalls  [][]string
	discoverCalled bool
}

func (d *recordingDiscoverer) GetIntegrationCloudProvider(context.Context, uuid.UUID, uuid.UUID) (string, error) {
	return d.provider, nil
}

func (d *recordingDiscoverer) collectors() map[string]cloudCollector {
	out := map[string]cloudCollector{}
	for _, rt := range DefaultCloudResourceTypes("aws") {
		rt := rt
		out[rt] = cloudCollector{collect: func(context.Context, string) ([]models.Device, error) {
			d.mu.Lock()
			d.ran = append(d.ran, rt)
			d.mu.Unlock()
			return nil, nil
		}}
	}
	return out
}

func (d *recordingDiscoverer) DiscoverResources(ctx context.Context, _, _ uuid.UUID, _ string, resourceTypes, regions, _ []string) (*CloudDiscoveryResult, error) {
	d.discoverCalled = true
	d.resourceCalls = append(d.resourceCalls, append([]string(nil), resourceTypes...))
	runCloudCollectors(ctx, resourceTypes, regions, d.collectors())
	return &CloudDiscoveryResult{}, nil
}

func (d *recordingDiscoverer) DiscoverResourceEvidence(ctx context.Context, _, _ uuid.UUID, _ string, resourceTypes, regions, _ []string) (*CloudDiscoveryResult, error) {
	d.evidenceCalls = append(d.evidenceCalls, append([]string(nil), resourceTypes...))
	runCloudCollectors(ctx, resourceTypes, regions, d.collectors())
	return &CloudDiscoveryResult{}, nil
}

// recordingCloudSink stands in for platformCloudRunSink: it records what the
// worker asked it to write and answers with a fixed discovery job.
type recordingCloudSink struct {
	calls   int
	devices []models.Device
	jobID   uuid.UUID
	err     error
}

func (s *recordingCloudSink) MaterializeCloudRun(_ context.Context, _ *models.DeviceJob, _ string, _ uuid.UUID, devices []models.Device) (uuid.UUID, int, error) {
	s.calls++
	s.devices = append(s.devices, devices...)
	if s.err != nil {
		return uuid.Nil, 0, s.err
	}
	if s.jobID == uuid.Nil {
		s.jobID = uuid.New()
	}
	return s.jobID, len(devices), nil
}

func runScheduledCloudJob(t *testing.T, provider string, params map[string]interface{}) (*recordingDiscoverer, *models.JobResult) {
	t.Helper()
	t.Setenv("ENCRYPTION_MASTER_KEY", "unit-test-master-key-0123456789abcdef")
	d := &recordingDiscoverer{provider: provider}
	w := &PlatformAgentWorker{cloudService: d, cloudSink: &recordingCloudSink{}}
	integrationID := uuid.New()
	job := &models.DeviceJob{
		ID:            uuid.New(),
		TenantID:      uuid.New(),
		JobType:       models.JobTypeCloudDiscovery,
		IntegrationID: &integrationID,
		Parameters:    params,
	}
	res, err := w.executeCloudDiscovery(context.Background(), job)
	if err != nil {
		t.Fatalf("executeCloudDiscovery: %v", err)
	}
	return d, res
}

// MUTATION-VERIFIED: remove the DefaultCloudResourceTypes fallback in
// executeCloudDiscovery and no collector runs (ran == []).
func TestScheduledCloudJob_NoParametersRunsTheManualRunCollectors(t *testing.T) {
	// Both shapes a schedule with no parameters can hand the worker.
	for name, params := range map[string]map[string]interface{}{
		"nil parameters":   nil,
		"empty parameters": {},
	} {
		t.Run(name, func(t *testing.T) {
			d, res := runScheduledCloudJob(t, "aws", params)

			want := DefaultCloudResourceTypes("aws")
			got := append([]string(nil), d.ran...)
			sort.Strings(got)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("collectors run = %v, want every manual-run type %v", got, want)
			}

			// And the stored result reports each of them, rather than an empty
			// outcome list next to success=true.
			outs, _ := res.Metadata["resource_types"].([]CloudResourceTypeOutcome)
			if len(outs) != len(want) {
				t.Errorf("result reports %d resource-type outcomes, want %d", len(outs), len(want))
			}
		})
	}
}

// An explicit selection is honoured exactly — the default fills a gap, it
// never widens a request.
func TestScheduledCloudJob_ExplicitResourceTypesAreHonoured(t *testing.T) {
	for name, params := range map[string]map[string]interface{}{
		"jsonb-decoded list": {"resource_types": []interface{}{"kms"}},
		"in-memory list":     {"resource_types": []string{"kms"}},
	} {
		t.Run(name, func(t *testing.T) {
			d, _ := runScheduledCloudJob(t, "aws", params)
			if !reflect.DeepEqual(d.ran, []string{"kms"}) {
				t.Errorf("collectors run = %v, want [kms]", d.ran)
			}
		})
	}
}

// A source refresh names the one collector it refreshes. With none named it
// must not be widened into an account-wide collection.
func TestScheduledCloudJob_SourceRefreshIsNeverWidened(t *testing.T) {
	d, _ := runScheduledCloudJob(t, "aws", map[string]interface{}{"source_refresh_only": true})
	if d.discoverCalled {
		t.Fatal("a source refresh reached DiscoverResources")
	}
	if len(d.evidenceCalls) != 1 || len(d.evidenceCalls[0]) != 0 || len(d.ran) != 0 {
		t.Errorf("source refresh was widened: evidence calls %v, collectors run %v", d.evidenceCalls, d.ran)
	}
}

// Azure and GCP get their own manual-run set, not AWS's.
func TestScheduledCloudJob_DefaultIsPerProvider(t *testing.T) {
	for _, provider := range []string{"azure", "gcp"} {
		d, _ := runScheduledCloudJob(t, provider, nil)
		if len(d.resourceCalls) != 1 || !reflect.DeepEqual(d.resourceCalls[0], DefaultCloudResourceTypes(provider)) {
			t.Errorf("%s: DiscoverResources got %v, want %v", provider, d.resourceCalls, DefaultCloudResourceTypes(provider))
		}
	}
}

// The default is defined as "what a manual run sends". The Discover modal
// pre-selects every type in its RESOURCE_TYPES table, so the two tables must be
// the same list or a scheduled run and a clicked run collect different things.
//
// MUTATION-VERIFIED: drop "rds" from defaultCloudResourceTypes["aws"] (or add a
// type to the modal) and this fails.
func TestDefaultCloudResourceTypes_MatchDiscoverModal(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "frontend-v2", "src", "sections", "discovery", "cloud-modals.tsx")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block := regexp.MustCompile(`(?s)export const RESOURCE_TYPES[^=]*=\s*\{(.*?)\n\};`).FindSubmatch(src)
	if block == nil {
		t.Fatal("RESOURCE_TYPES table not found in cloud-modals.tsx — update this parser if it moved")
	}
	providerRe := regexp.MustCompile(`(?s)\n  (\w+): \[(.*?)\n  \],`)
	valueRe := regexp.MustCompile(`value:\s*'([^']+)'`)

	modal := map[string][]string{}
	for _, m := range providerRe.FindAllSubmatch(block[1], -1) {
		var values []string
		for _, v := range valueRe.FindAllSubmatch(m[2], -1) {
			values = append(values, string(v[1]))
		}
		modal[string(m[1])] = values
	}
	if len(modal) == 0 {
		t.Fatal("parsed no providers out of RESOURCE_TYPES")
	}

	if len(modal) != len(defaultCloudResourceTypes) {
		t.Errorf("modal offers providers %v, backend defaults cover %v", keys(modal), keys(defaultCloudResourceTypes))
	}
	for provider, want := range modal {
		got := append([]string(nil), defaultCloudResourceTypes[provider]...)
		w := append([]string(nil), want...)
		sort.Strings(got)
		sort.Strings(w)
		if !reflect.DeepEqual(got, w) {
			t.Errorf("%s: backend default %v != Discover modal pre-selection %v", provider, got, w)
		}
	}
}

// Every type the modal offers (and so every default a scheduled run collects)
// has a collector in its provider's dispatch table — an offered type with no
// collector would only ever report not_attempted.
//
// MUTATION-VERIFIED: offer a type the dispatch table does not have and this
// goes red.
func TestDefaultCloudResourceTypes_EveryTypeHasACollector(t *testing.T) {
	s := &CloudDiscoveryService{}
	tables := map[string]map[string]cloudCollector{
		"azure": azureCloudCollectors(s, uuid.Nil, uuid.Nil, nil, nil),
		"gcp":   gcpCloudCollectors(s, uuid.Nil, uuid.Nil, nil, nil),
	}
	for provider, table := range tables {
		for _, rt := range DefaultCloudResourceTypes(provider) {
			if _, ok := table[rt]; !ok {
				t.Errorf("%s offers %q but its dispatch table has no collector for it", provider, rt)
			}
		}
	}
}

func keys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
