package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
)

// Scheduled cloud runs used to deliver no at-rest resource at all (W14 / B6
// second half). The worker built DiscoveredAssets from each device's crypto
// configs, and a bucket, a database or a key store has none — so it produced
// nothing. These drive the REAL executeCloudDiscovery with collectors that
// return exactly those shapes and check every resource reaches the writer the
// interactive run uses. The DB-integration twin
// (TestIntegration_ScheduledCloudJob_WritesThroughTheInteractiveWriter) checks
// the rows themselves.

// fixedCloudDiscoverer answers a run with fixed devices, dispatched through the
// REAL runCloudCollectors so the outcome recorder sees what it would in
// production. failTypes names collectors that fail in every scope; failScope
// makes a collector regional and adds one more region, where it is denied —
// the shape of a partial run.
type fixedCloudDiscoverer struct {
	provider  string
	byType    map[string][]models.Device
	failTypes map[string]error
	failScope map[string]string
}

func (d *fixedCloudDiscoverer) GetIntegrationCloudProvider(context.Context, uuid.UUID, uuid.UUID) (string, error) {
	return d.provider, nil
}

func (d *fixedCloudDiscoverer) run(ctx context.Context, resourceTypes, regions []string) *CloudDiscoveryResult {
	collectors := map[string]cloudCollector{}
	for rt := range d.byType {
		rt := rt
		denied := d.failScope[rt]
		collectors[rt] = cloudCollector{regional: denied != "", collect: func(_ context.Context, scope string) ([]models.Device, error) {
			if denied != "" && scope == denied {
				return nil, errors.New("AccessDenied: not authorized in " + scope)
			}
			return d.byType[rt], nil
		}}
	}
	for _, scope := range d.failScope {
		regions = append(append([]string(nil), regions...), scope)
	}
	for rt, err := range d.failTypes {
		err := err
		collectors[rt] = cloudCollector{collect: func(context.Context, string) ([]models.Device, error) {
			return nil, err
		}}
	}
	return &CloudDiscoveryResult{Devices: runCloudCollectors(ctx, resourceTypes, regions, collectors)}
}

func (d *fixedCloudDiscoverer) DiscoverResources(ctx context.Context, _, _ uuid.UUID, _ string, resourceTypes, regions, _ []string) (*CloudDiscoveryResult, error) {
	return d.run(ctx, resourceTypes, regions), nil
}

func (d *fixedCloudDiscoverer) DiscoverResourceEvidence(ctx context.Context, _, _ uuid.UUID, _ string, resourceTypes, regions, _ []string) (*CloudDiscoveryResult, error) {
	return d.run(ctx, resourceTypes, regions), nil
}

var errAccessDenied = errors.New("AccessDenied: not authorized to perform s3:ListAllMyBuckets")

// atRestDevice builds a device the way storage_encryption_service.go builds an
// S3 bucket / RDS instance: no crypto_configs, the ARN in metadata.
func atRestDevice(deviceType, name, arn, resourceType string) models.Device {
	vendor, host := "AWS", name
	return models.Device{
		ID:              uuid.New(),
		DeviceType:      deviceType,
		Vendor:          &vendor,
		Hostname:        &host,
		DiscoveryMethod: "cloud_api",
		Metadata: models.JSONB{
			"arn":              arn,
			"region":           "us-east-1",
			"encrypted":        true,
			"encryption_type":  "aws-kms",
			"algorithm":        "AES-256",
			"resource_type":    resourceType,
			"discovery_method": "cloud_api",
		},
	}
}

func s3Bucket(name string) models.Device {
	return atRestDevice("aws_s3_bucket", name, "arn:aws:s3:::"+name, "s3_bucket")
}

func rdsInstance(name string) models.Device {
	return atRestDevice("aws_rds_instance", name, "arn:aws:rds:us-east-1:123456789012:db:"+name, "rds_instance")
}

// MUTATION-VERIFIED: restore the old crypto-config → DiscoveredAsset loop in
// place of MaterializeCloudRun and the sink receives nothing (and Assets holds
// no bucket or database).
func TestScheduledCloudJob_AtRestResourcesReachTheWriter(t *testing.T) {
	t.Setenv("ENCRYPTION_MASTER_KEY", "unit-test-master-key-0123456789abcdef")
	d := &fixedCloudDiscoverer{provider: "aws", byType: map[string][]models.Device{
		"s3":  {s3Bucket("example-audit-logs")},
		"rds": {rdsInstance("orders-db")},
	}}
	sink := &recordingCloudSink{}
	w := &PlatformAgentWorker{cloudService: d, cloudSink: sink}
	integrationID := uuid.New()
	job := &models.DeviceJob{ID: uuid.New(), TenantID: uuid.New(), JobType: models.JobTypeCloudDiscovery, IntegrationID: &integrationID,
		Parameters: map[string]interface{}{"resource_types": []interface{}{"s3", "rds"}, "regions": []interface{}{"us-east-1"}}}

	res, err := w.executeCloudDiscovery(context.Background(), job)
	if err != nil {
		t.Fatalf("executeCloudDiscovery: %v", err)
	}
	if sink.calls != 1 || len(sink.devices) != 2 {
		t.Fatalf("writer got %d call(s) with %d device(s), want 1 call with the bucket and the database", sink.calls, len(sink.devices))
	}
	// Nothing for ProcessJobResults to write a second time.
	if len(res.Assets) != 0 {
		t.Errorf("result carries %d asset(s); the rows are already written, so it must carry none", len(res.Assets))
	}
	if !materializedByExecutor(res) {
		t.Error("result is not marked as materialized by the executor")
	}
	if got := res.Metadata["discovery_job_id"]; got != sink.jobID.String() {
		t.Errorf("discovery_job_id = %v, want the writer's %s", got, sink.jobID)
	}
	if got := res.Metadata[metaCloudDiscoveriesWritten]; got != 2 {
		t.Errorf("%s = %v, want 2", metaCloudDiscoveriesWritten, got)
	}
}

// A partial run still delivers what it collected, and still gets a
// processing block (the refresh state machine reads it).
func TestScheduledCloudJob_PartialRunDeliversWhatItCollected(t *testing.T) {
	t.Setenv("ENCRYPTION_MASTER_KEY", "unit-test-master-key-0123456789abcdef")
	d := &fixedCloudDiscoverer{provider: "aws",
		byType:    map[string][]models.Device{"s3": {s3Bucket("example-audit-logs")}},
		failTypes: map[string]error{"kms": errors.New("AccessDeniedException: not authorized to perform kms:ListKeys")},
	}
	sink := &recordingCloudSink{}
	w := &PlatformAgentWorker{cloudService: d, cloudSink: sink}
	integrationID := uuid.New()
	job := &models.DeviceJob{ID: uuid.New(), TenantID: uuid.New(), JobType: models.JobTypeCloudDiscovery, IntegrationID: &integrationID,
		Parameters: map[string]interface{}{"resource_types": []interface{}{"s3", "kms"}, "regions": []interface{}{"us-east-1"}}}

	res, err := w.executeCloudDiscovery(context.Background(), job)
	if err != nil {
		t.Fatalf("executeCloudDiscovery: %v", err)
	}
	if res.Success {
		t.Error("a run with a denied collector reported success")
	}
	if res.Metadata["outcome"] != CloudRunPartial {
		t.Errorf("outcome = %v, want partial", res.Metadata["outcome"])
	}
	if len(sink.devices) != 1 {
		t.Errorf("writer got %d device(s), want the bucket", len(sink.devices))
	}
	if !shouldProcessResults(res) {
		t.Error("a partial run that wrote rows would get no processing block")
	}
}

// Azure and GCP runs report per-type outcomes too (M7). The recorder used to
// be AWS-only, so an Azure run whose Key Vault listing was refused reported
// success.
//
// MUTATION-VERIFIED: gate the recorder back to `cloudProvider == "aws"` and
// both providers read success with no outcomes.
func TestScheduledCloudJob_AzureAndGCPReportOutcomes(t *testing.T) {
	t.Setenv("ENCRYPTION_MASTER_KEY", "unit-test-master-key-0123456789abcdef")
	for provider, denied := range map[string]string{"azure": "key_vault", "gcp": "kms"} {
		d := &fixedCloudDiscoverer{provider: provider, byType: map[string][]models.Device{}, failTypes: map[string]error{denied: errAccessDenied}}
		w := &PlatformAgentWorker{cloudService: d, cloudSink: &recordingCloudSink{}}
		integrationID := uuid.New()
		job := &models.DeviceJob{ID: uuid.New(), TenantID: uuid.New(), JobType: models.JobTypeCloudDiscovery, IntegrationID: &integrationID,
			Parameters: map[string]interface{}{"resource_types": []interface{}{denied}}}
		res, err := w.executeCloudDiscovery(context.Background(), job)
		if err != nil {
			t.Fatalf("%s: %v", provider, err)
		}
		if res.Success || res.Metadata["outcome"] != CloudRunFailed {
			t.Errorf("%s: a run whose only collector was refused reads success=%v outcome=%v", provider, res.Success, res.Metadata["outcome"])
		}
	}
}

// Rows that could not be written fail the run, rather than completing it with
// nothing delivered.
func TestScheduledCloudJob_PersistFailureFailsTheRun(t *testing.T) {
	t.Setenv("ENCRYPTION_MASTER_KEY", "unit-test-master-key-0123456789abcdef")
	d := &fixedCloudDiscoverer{provider: "aws", byType: map[string][]models.Device{"s3": {s3Bucket("example-audit-logs")}}}
	w := &PlatformAgentWorker{cloudService: d, cloudSink: &recordingCloudSink{err: errors.New(cloudPersistFailure)}}
	integrationID := uuid.New()
	job := &models.DeviceJob{ID: uuid.New(), TenantID: uuid.New(), JobType: models.JobTypeCloudDiscovery, IntegrationID: &integrationID,
		Parameters: map[string]interface{}{"resource_types": []interface{}{"s3"}}}
	if _, err := w.executeCloudDiscovery(context.Background(), job); err == nil {
		t.Fatal("a run whose rows could not be written completed")
	}
}

// The processing block of a run whose executor wrote its own rows counts
// those rows, and a shortfall against what the executor said it wrote is not
// a clean run.
//
// MUTATION-VERIFIED: drop `+ executorRows` from "materialized" and the first
// case reads 0; drop the ExecutorDiscoveriesExpected check in
// fullyMaterialized and the shortfall case reads fully_materialized=true.
func TestProcessingLog_ExecutorWrittenRows(t *testing.T) {
	full := (&ProcessingLog{ExecutorDiscoveries: 3, ExecutorDiscoveriesExpected: 3}).Summary()
	if full["materialized"] != 3 || full["discoveries_written"] != 3 || full["fully_materialized"] != true {
		t.Errorf("clean run: materialized=%v written=%v fully=%v, want 3/3/true", full["materialized"], full["discoveries_written"], full["fully_materialized"])
	}
	short := (&ProcessingLog{ExecutorDiscoveries: 1, ExecutorDiscoveriesExpected: 3}).Summary()
	if short["fully_materialized"] != false {
		t.Error("fewer rows present than the executor wrote still reads fully_materialized")
	}
	unknown := (&ProcessingLog{ExecutorDiscoveries: -1, ExecutorDiscoveriesExpected: 3}).Summary()
	if unknown["fully_materialized"] != false || unknown["materialized"] != 0 {
		t.Errorf("an uncountable batch: materialized=%v fully=%v, want 0/false", unknown["materialized"], unknown["fully_materialized"])
	}
	// Every other job is untouched.
	plain := (&ProcessingLog{}).Summary()
	if plain["materialized"] != 0 || plain["fully_materialized"] != true {
		t.Errorf("empty non-cloud run changed: %v / %v", plain["materialized"], plain["fully_materialized"])
	}
}
