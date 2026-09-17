package processor

import (
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/models"
)

// Marking discoveries processed used to be one transaction and one
// `WHERE id = $1` UPDATE per discovery, against an 8-way hash-partitioned table
// that had no index on id — so every row cost a full scan of all 8 partitions.
// markProcessed instead groups by the outcome each row is stamped with and
// issues one `id = ANY(...)` UPDATE per distinct outcome. This pins the
// grouping: same outcome collapses, different outcome does not, and insertion
// order of the groups is stable.
func TestProcessedMarks_GroupsByOutcome(t *testing.T) {
	ruleA := uuid.New()
	ruleB := uuid.New()

	m := newProcessedMarks()
	if !m.empty() {
		t.Fatal("fresh marks should be empty")
	}

	autoIDs := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	for _, id := range autoIDs {
		m.add(id, "auto_approved", nil)
	}
	pendingID := uuid.New()
	m.add(pendingID, "pending", nil)
	ruleAIDs := []uuid.UUID{uuid.New(), uuid.New()}
	for _, id := range ruleAIDs {
		m.add(id, "auto_approved", &ruleA)
	}
	m.add(uuid.New(), "auto_approved", &ruleB)

	if got, want := len(m.order), 4; got != want {
		t.Fatalf("group count = %d, want %d (auto/nil, pending/nil, auto/ruleA, auto/ruleB)", got, want)
	}

	wantOrder := []processedMark{
		{approvalStatus: "auto_approved"},
		{approvalStatus: "pending"},
		{approvalStatus: "auto_approved", ruleID: ruleA.String()},
		{approvalStatus: "auto_approved", ruleID: ruleB.String()},
	}
	for i, want := range wantOrder {
		if m.order[i] != want {
			t.Fatalf("group %d = %+v, want %+v", i, m.order[i], want)
		}
	}

	if got := len(m.ids[wantOrder[0]]); got != len(autoIDs) {
		t.Fatalf("auto_approved/no-rule group holds %d ids, want %d", got, len(autoIDs))
	}
	if got := len(m.ids[wantOrder[2]]); got != len(ruleAIDs) {
		t.Fatalf("auto_approved/ruleA group holds %d ids, want %d", got, len(ruleAIDs))
	}
	if got, want := m.ids[wantOrder[1]][0], pendingID.String(); got != want {
		t.Fatalf("pending group id = %s, want %s", got, want)
	}
}

func TestShouldKeepCloudPlaceholderManaged(t *testing.T) {
	sourceIP := "10.0.0.5"
	cases := []struct {
		name           string
		discovery      *models.SensorDiscovery
		classification *models.NetworkClassification
		want           bool
	}{
		{
			name: "cloud api placeholder without source stays managed",
			discovery: &models.SensorDiscovery{
				DestIP:   "0.0.0.0",
				Metadata: []byte(`{"discovery_method":"cloud_api","device_type":"gcp_storage_bucket"}`),
			},
			classification: &models.NetworkClassification{Ownership: "third_party", Type: "public"},
			want:           true,
		},
		{
			name: "real public cloud connection still routes externally",
			discovery: &models.SensorDiscovery{
				DestIP:   "203.0.113.10",
				Metadata: []byte(`{"discovery_method":"cloud_api","device_type":"aws_cloudfront"}`),
			},
			classification: &models.NetworkClassification{Ownership: "third_party", Type: "public"},
			want:           false,
		},
		{
			name: "source ip means observed connection remains external",
			discovery: &models.SensorDiscovery{
				DestIP:   "0.0.0.0",
				SourceIP: &sourceIP,
				Metadata: []byte(`{"discovery_method":"cloud_api","device_type":"gcp_storage_bucket"}`),
			},
			classification: &models.NetworkClassification{Ownership: "third_party", Type: "public"},
			want:           false,
		},
		{
			name: "sensor discovery placeholder is not special cased",
			discovery: &models.SensorDiscovery{
				DestIP:   "0.0.0.0",
				Metadata: []byte(`{"discovery_method":"active_enrichment"}`),
			},
			classification: &models.NetworkClassification{Ownership: "third_party", Type: "public"},
			want:           false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldKeepCloudPlaceholderManaged(tc.discovery, tc.classification); got != tc.want {
				t.Fatalf("shouldKeepCloudPlaceholderManaged() = %v, want %v", got, tc.want)
			}
		})
	}
}

// reverseDNSLookup runs from inside a cluster pod, whose resolver (CoreDNS)
// synthesises a PTR answer for any address it considers in-cluster rather
// than forwarding to the customer's real resolver. A customer host at
// 192.0.2.124 therefore does not fail the lookup — it gets a confidently
// wrong answer, "192-0-2-124.kubernetes.default.svc.cluster.local", that
// nothing on the customer's network ever answers to. isClusterInternalPTRName
// is the guard that keeps that fabricated name out of reverseDNSLookup's
// return value; this pins it directly since the resolver itself can't be
// exercised in a unit test.
func TestIsClusterInternalPTRName(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{
			name: "kubernetes-synthesized dash-IP name for a customer host",
			in:   "192-0-2-124.kubernetes.default.svc.cluster.local",
			want: true,
		},
		{
			name: "svc.cluster.local name for an in-cluster service",
			in:   "my-service.default.svc.cluster.local",
			want: true,
		},
		{
			name: "synthesized dash-IP shape under a non-default cluster domain",
			in:   "192-0-2-124.ec2.internal",
			want: true,
		},
		{
			name: "pod-scoped synthesized name under a custom cluster domain",
			in:   "192-0-2-124.default.pod.example-cluster.local",
			want: true,
		},
		{
			name: "legitimate customer FQDN with a trailing dot must still pass",
			in:   "host.corp.example.",
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isClusterInternalPTRName(tc.in); got != tc.want {
				t.Errorf("isClusterInternalPTRName(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
