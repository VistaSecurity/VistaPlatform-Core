package services

// Discovery data that arrived over NATS reaches inventory-service as the
// discovery pipeline's import (discovery-processor consumes the queue and
// posts the findings): the identity engine files each address under an
// interface, recorded as `intake:identity`. The import ran its writes under
// context.Background(), so the change notifier's collector never saw them and
// a rule that includes intake was never told. Driven through the notifier's
// middleware and the real IngestPipelineFindingsReport. Skipped unless
// TEST_DATABASE_URL is set.
//
// Mutation: in resolveDiscoveryObservation, set ctxBG back to
// context.Background() (or ingestFindings' ctx) → red.

import (
	"context"
	"net/http"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changenotify"
)

func TestIntegration_ChangeNotify_DiscoveryPipelineImportRaisesIntakeChanges(t *testing.T) {
	f := newLeafLinkFixture(t)
	changeRule(t, f.db.DB.DB, f.tenant, `{"include_intake": true}`)
	pub := &raised{}
	n := changenotify.New(f.db.DB.DB)
	n.Synchronous = true
	n.SetPublisher(pub)

	finding := leafCertFinding("pipeline-notify.example.test", "198.51.100.161", 443, hexFingerprint("pipeline-notify"))
	var assetID string
	r := notifyRouter(n, func(ctx context.Context) error {
		report, err := f.svc.IngestPipelineFindingsReport(ctx, f.tenant, []IngestFinding{finding})
		if err == nil && len(report.Results) == 1 {
			assetID = report.Results[0].AssetID
		}
		return err
	})
	if code := hit(t, r); code != http.StatusNoContent {
		t.Fatalf("ingest: %d", code)
	}
	if assetID == "" {
		t.Fatal("setup: the finding resolved to no asset")
	}
	evs := pub.take()
	var ifaces, addrs int
	for _, ev := range evs {
		if ev.TenantID != f.tenant || ev.Metadata["source"] != "intake:identity" || ev.Metadata["actor"] != nil {
			t.Fatalf("unexpected event %+v", ev)
		}
		switch ev.SubjectType {
		case string(dcim.ObjectKindInterface):
			ifaces++
		case string(dcim.ObjectKindIpAddress):
			addrs++
			if ev.Metadata["object_label"] == nil {
				t.Errorf("the address event names no address: %+v", ev.Metadata)
			}
		}
	}
	if ifaces == 0 || addrs == 0 {
		t.Fatalf("the import raised %d interface and %d address events (want both): %+v", ifaces, addrs, evs)
	}
}
