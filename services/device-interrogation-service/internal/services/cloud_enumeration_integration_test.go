package services

// What only a real database can say about cloud enumeration (BUILD_PLAN 2.4).
//
// The builder tests next door pin what each provider PRODUCES. These pin what
// the recording actually WRITES: assets in the right class and the right
// approval state, the provider's resource id as an identifier, the `cloud.*`
// facts under the cloud-collector producer, the `contains` edges, the network
// segment an instance's address scopes to — and, on a second run, exactly the
// same rows rather than a second set.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/relationships"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// awsEnumerationPlanForTest builds the AWS plan from the shared fixture, with
// ids made unique per run so two tests in one database cannot collide on a
// tenant-global identifier.
func awsEnumerationPlanForTest(t *testing.T) cloudEnumerationPlan {
	t.Helper()
	suffix := uuid.New().String()[:8]
	instances, vpcs, subnets, groups := awsFixture()

	rewrite := func(s string) string { return s + "-" + suffix }
	vpcs[0].VPCID = rewrite(vpcs[0].VPCID)
	vpcs[0].ARN = rewrite(vpcs[0].ARN)
	subnets[0].SubnetID = rewrite(subnets[0].SubnetID)
	subnets[0].ARN = rewrite(subnets[0].ARN)
	subnets[0].VPCID = vpcs[0].VPCID
	// A per-run CIDR: network_segments is unique on (tenant, value), and a
	// shared one would make the second test's segment a match rather than an
	// insert.
	subnets[0].CIDRBlock = "10.0." + itoaByte(suffix) + ".0/24"
	instances[0].InstanceID = rewrite(instances[0].InstanceID)
	instances[0].ARN = rewrite(instances[0].ARN)
	instances[0].VPCID = vpcs[0].VPCID
	instances[0].SubnetID = subnets[0].SubnetID
	instances[0].PrivateIPs = []string{"10.0." + itoaByte(suffix) + ".20"}
	// The RESOURCE-NAME form, which encodes the instance id and is globally
	// unique, so it is a real hostname. The ip-name form EC2 also offers is
	// refused as one (awsclient.IsIPDerivedPrivateDNSName): it is an alias of
	// the private address and would become an unscoped `fqdn` identifier that
	// two instances can share.
	instances[0].PrivateDNSName = instances[0].InstanceID + ".ec2.internal"
	instances[0].Interfaces[0].Addresses = instances[0].PrivateIPs
	groups[0].GroupID = rewrite(groups[0].GroupID)
	instances[0].SecurityGroups[0].ID = groups[0].GroupID

	return buildAWSEnumerationPlan(instances, vpcs, subnets, groups)
}

// itoaByte turns a hex suffix into a stable 1..254 octet, so each test run gets
// its own /24 without coordinating.
func itoaByte(suffix string) string {
	sum := 0
	for _, r := range suffix {
		sum += int(r)
	}
	return itoa(sum%200 + 10)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

func TestIntegration_CloudEnumeration_WritesAssetsFactsAndContainment(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	integrationID := seedCloudIntegration(t, owner, tenantID)

	svc := NewCloudDiscoveryService(appDB, owner, testMasterKey)
	plan := awsEnumerationPlanForTest(t)

	devices, counts, err := svc.recordEnumeration(ctx, tenantID, integrationID, "production", plan)
	if err != nil {
		t.Fatalf("recordEnumeration: %v", err)
	}
	if counts != (CloudEnumerationCounts{Instances: 1, Networks: 1, Subnets: 1, SecurityGroups: 1}) {
		t.Fatalf("counts = %+v", counts)
	}
	if len(devices) != 3 {
		t.Fatalf("recorded %d devices, want 3 (vpc, subnet, instance)", len(devices))
	}

	vpcRes := plan.Networks[0]
	subnetRes := plan.Subnets[0]
	instRes := plan.Instances[0]

	vpcID := assetIDForCloudResource(t, owner, tenantID, vpcRes.ResourceID)
	subnetID := assetIDForCloudResource(t, owner, tenantID, subnetRes.ResourceID)
	instID := assetIDForCloudResource(t, owner, tenantID, instRes.ResourceID)

	// --- classes and approval state -----------------------------------------
	for _, tc := range []struct {
		id        uuid.UUID
		wantClass string
		label     string
	}{
		{vpcID, "virtual_network", "vpc"},
		{subnetID, "subnet", "subnet"},
		{instID, "compute_instance", "instance"},
	} {
		var classKey, status string
		if err := owner.QueryRow(
			`SELECT class_key, asset_status FROM assets WHERE tenant_id = $1 AND id = $2`,
			tenantID, tc.id).Scan(&classKey, &status); err != nil {
			t.Fatalf("%s asset row: %v", tc.label, err)
		}
		if classKey != tc.wantClass {
			t.Errorf("%s class_key = %q, want %q", tc.label, classKey, tc.wantClass)
		}
		// New cloud assets land pending_approval, exactly like every other
		// discovered asset. The engine only ever writes this status.
		if status != identity.StatusPendingApproval {
			t.Errorf("%s asset_status = %q, want %q", tc.label, status, identity.StatusPendingApproval)
		}
	}

	// --- the instance's address and hostname --------------------------------
	var hostname sql.NullString
	var primary sql.NullString
	if err := owner.QueryRow(
		`SELECT hostname, host(primary_address) FROM assets WHERE tenant_id = $1 AND id = $2`,
		tenantID, instID).Scan(&hostname, &primary); err != nil {
		t.Fatalf("instance address row: %v", err)
	}
	if hostname.String != instRes.Hostname {
		t.Errorf("hostname = %q, want the private DNS name %q", hostname.String, instRes.Hostname)
	}
	if primary.String != instRes.IPAddress {
		t.Errorf("primary_address = %q, want %q", primary.String, instRes.IPAddress)
	}

	// --- facts, under the cloud-collector producer --------------------------
	instFacts := factMap(t, owner, tenantID, instID)
	for key, want := range map[string]string{
		facts.KeyCloudProvider:   `"aws"`,
		facts.KeyCloudAccountID:  `"123456789012"`,
		facts.KeyCloudRegion:     `"us-east-1"`,
		facts.KeyCloudResourceID: `"` + instRes.ResourceID + `"`,
		facts.KeyCloudVPCID:      `"` + instRes.Metadata["vpc_id"].(string) + `"`,
	} {
		if got := instFacts[key]; got != want {
			t.Errorf("fact %s = %s, want %s", key, got, want)
		}
	}
	if instFacts[facts.KeyCloudSecurityGroups] == "" {
		t.Error("cloud.security_groups is missing — membership is the whole security-group answer")
	}
	if instFacts[facts.KeyNetInterfaces] == "" {
		t.Error("net.interfaces is missing")
	}
	// A fact written under the wrong producer would have been refused by
	// UpsertFacts, so reaching here at all proves the producer; the source_ref
	// is what ADR-0003 D3 names.
	var sourceKind, sourceRef string
	if err := owner.QueryRow(`
		SELECT source_kind, source_ref FROM asset_facts
		WHERE tenant_id = $1 AND asset_id = $2 AND key = $3`,
		tenantID, instID, facts.KeyCloudProvider).Scan(&sourceKind, &sourceRef); err != nil {
		t.Fatalf("fact provenance: %v", err)
	}
	if sourceKind != string(identity.SourceMeasured) || sourceRef != "cloud:aws" {
		t.Errorf("fact provenance = %s/%s, want measured/cloud:aws", sourceKind, sourceRef)
	}

	// --- class attributes ---------------------------------------------------
	attrs := attributeMap(t, owner, tenantID, instID)
	if attrs["instance_type"] != "m6i.large" || attrs["provider"] != "aws" {
		t.Errorf("instance attributes = %v", attrs)
	}
	if _, present := attrs["operating_system"]; present {
		t.Error("operating_system attribute was written; EC2 states no guest OS")
	}

	// --- containment --------------------------------------------------------
	assertEdge(t, owner, tenantID, vpcID, subnetID, relationships.Contains)
	assertEdge(t, owner, tenantID, subnetID, instID, relationships.Contains)
	// The reverse of a type is a LABEL, never a second edge.
	if edgeExists(t, owner, tenantID, instID, subnetID, relationships.MemberOf) {
		t.Error("a member_of edge was written alongside contains; one fact, two spellings")
	}

	// --- the network segment the address scopes to --------------------------
	var segType, segValue, segNetworkType string
	var segMeta []byte
	if err := owner.QueryRow(`
		SELECT segment_type, value, network_type, metadata
		FROM network_segments WHERE tenant_id = $1 AND value = $2`,
		tenantID, subnetRes.SegmentCIDR).Scan(&segType, &segValue, &segNetworkType, &segMeta); err != nil {
		t.Fatalf("network segment for %s: %v", subnetRes.SegmentCIDR, err)
	}
	if segType != "cidr" {
		t.Errorf("segment_type = %q, want cidr — ScopeForAddress consults only cidr and ip_range", segType)
	}
	if segNetworkType != "cloud" {
		t.Errorf("network_type = %q, want cloud", segNetworkType)
	}
	var meta map[string]any
	if err := json.Unmarshal(segMeta, &meta); err != nil {
		t.Fatalf("segment metadata: %v", err)
	}
	if meta["dynamic"] != false {
		t.Errorf("segment metadata dynamic = %#v, want an explicit false — a dynamic scope stops an address deciding identity", meta["dynamic"])
	}
	if meta["source"] != "cloud_discovery" {
		t.Errorf("segment provenance = %#v, want cloud_discovery", meta["source"])
	}

	// The instance's ip_address identifier must be scoped to that segment, not
	// to the tenant default — that scoping is what lets an agent inside the
	// instance, or the sensor on the wire, resolve to this same asset.
	var segID string
	if err := owner.QueryRow(
		`SELECT id::text FROM network_segments WHERE tenant_id = $1 AND value = $2`,
		tenantID, subnetRes.SegmentCIDR).Scan(&segID); err != nil {
		t.Fatalf("segment id: %v", err)
	}
	var idScope string
	if err := owner.QueryRow(`
		SELECT coalesce(scope, '') FROM asset_identifiers
		WHERE tenant_id = $1 AND asset_id = $2 AND kind = 'ip_address'`,
		tenantID, instID).Scan(&idScope); err != nil {
		t.Fatalf("ip_address identifier: %v", err)
	}
	if idScope != segID {
		t.Errorf("ip_address scope = %q, want the subnet's segment %q", idScope, segID)
	}

	// --- enumerated resources are NOT crypto findings -----------------------
	inserted, err := svc.WriteSensorDiscoveries(ctx, tenantID, uuid.New().String(), integrationID, "aws", devices)
	if err != nil {
		t.Fatalf("WriteSensorDiscoveries: %v", err)
	}
	if inserted != 0 {
		t.Errorf("WriteSensorDiscoveries wrote %d rows for enumerated resources; each one is a fabricated TLS:443 endpoint", inserted)
	}
}

// Two runs, one asset. A re-run matches on cloud_resource_id and updates.
func TestIntegration_CloudEnumeration_IsIdempotent(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	integrationID := seedCloudIntegration(t, owner, tenantID)

	svc := NewCloudDiscoveryService(appDB, owner, testMasterKey)
	plan := awsEnumerationPlanForTest(t)

	first, _, err := svc.recordEnumeration(ctx, tenantID, integrationID, "production", plan)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	second, _, err := svc.recordEnumeration(ctx, tenantID, integrationID, "production", plan)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}

	if len(first) != len(second) {
		t.Fatalf("runs produced %d and %d devices", len(first), len(second))
	}
	for i := range first {
		if first[i].ID != second[i].ID {
			t.Errorf("%s resolved to %s then %s — a re-run minted a second asset",
				first[i].DeviceType, first[i].ID, second[i].ID)
		}
	}

	// And the database agrees: one asset per resource id, one edge per pair.
	for _, res := range append(append([]cloudEnumResource{}, plan.Networks...), append(plan.Subnets, plan.Instances...)...) {
		var n int
		if err := owner.QueryRow(`
			SELECT count(*) FROM asset_identifiers
			WHERE tenant_id = $1 AND kind = 'cloud_resource_id' AND value = $2`,
			tenantID, res.ResourceID).Scan(&n); err != nil {
			t.Fatalf("identifier count: %v", err)
		}
		if n != 1 {
			t.Errorf("%s has %d cloud_resource_id rows, want 1", res.ResourceID, n)
		}
	}

	var edges int
	if err := owner.QueryRow(
		`SELECT count(*) FROM asset_relationships WHERE tenant_id = $1 AND type = 'contains'`,
		tenantID).Scan(&edges); err != nil {
		t.Fatalf("edge count: %v", err)
	}
	if edges != 2 {
		t.Errorf("%d contains edges after two runs, want 2 (vpc→subnet, subnet→instance)", edges)
	}
	var observations int
	if err := owner.QueryRow(`
		SELECT observation_count FROM asset_relationships
		WHERE tenant_id = $1 AND type = 'contains' LIMIT 1`, tenantID).Scan(&observations); err != nil {
		t.Fatalf("observation count: %v", err)
	}
	if observations != 2 {
		t.Errorf("observation_count = %d, want 2 — a re-observation bumps rather than appends", observations)
	}

	// One segment, not two: the second run matched the existing row.
	var segments int
	if err := owner.QueryRow(
		`SELECT count(*) FROM network_segments WHERE tenant_id = $1 AND value = $2`,
		tenantID, plan.Subnets[0].SegmentCIDR).Scan(&segments); err != nil {
		t.Fatalf("segment count: %v", err)
	}
	if segments != 1 {
		t.Errorf("%d segments for %s, want 1", segments, plan.Subnets[0].SegmentCIDR)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func assetIDForCloudResource(t *testing.T, db *sql.DB, tenantID uuid.UUID, resourceID string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.QueryRow(`
		SELECT asset_id FROM asset_identifiers
		WHERE tenant_id = $1 AND kind = 'cloud_resource_id' AND value = $2`,
		tenantID, resourceID).Scan(&id); err != nil {
		t.Fatalf("no asset carries cloud_resource_id %q: %v", resourceID, err)
	}
	return id
}

func factMap(t *testing.T, db *sql.DB, tenantID, assetID uuid.UUID) map[string]string {
	t.Helper()
	rows, err := db.Query(
		`SELECT key, value::text FROM asset_facts WHERE tenant_id = $1 AND asset_id = $2`,
		tenantID, assetID)
	if err != nil {
		t.Fatalf("read facts: %v", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			t.Fatalf("scan fact: %v", err)
		}
		out[k] = v
	}
	return out
}

func attributeMap(t *testing.T, db *sql.DB, tenantID, assetID uuid.UUID) map[string]any {
	t.Helper()
	var raw []byte
	if err := db.QueryRow(
		`SELECT coalesce(attributes, '{}'::jsonb) FROM assets WHERE tenant_id = $1 AND id = $2`,
		tenantID, assetID).Scan(&raw); err != nil {
		t.Fatalf("read attributes: %v", err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("attributes are not JSON: %v", err)
	}
	return out
}

func edgeExists(t *testing.T, db *sql.DB, tenantID, from, to uuid.UUID, typ relationships.Type) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`
		SELECT count(*) FROM asset_relationships
		WHERE tenant_id = $1 AND from_asset_id = $2 AND to_asset_id = $3 AND type = $4`,
		tenantID, from, to, string(typ)).Scan(&n); err != nil {
		t.Fatalf("edge lookup: %v", err)
	}
	return n > 0
}

// assertEdge asserts the edge exists AND says where it came from.
//
// The provenance half was added for gate 2. Without it the containment edges
// were the only rows this suite wrote whose source was never checked, and
// source_kind is the field a reviewer uses to decide whether to believe an edge
// at all — "the provider's own API stated this containment" (measured) is a
// different claim from "something proposed it" (inferred, ADR-0008 D4.2). An
// edge that lost its source_ref also cannot be swept when the resource goes
// away, because nothing identifies the pass that drew it.
func assertEdge(t *testing.T, db *sql.DB, tenantID, from, to uuid.UUID, typ relationships.Type) {
	t.Helper()
	var kind, ref string
	if err := db.QueryRow(`
		SELECT source_kind, coalesce(source_ref, '') FROM asset_relationships
		WHERE tenant_id = $1 AND from_asset_id = $2 AND to_asset_id = $3 AND type = $4`,
		tenantID, from, to, string(typ)).Scan(&kind, &ref); err != nil {
		t.Errorf("no %s edge from %s to %s: %v", typ, from, to, err)
		return
	}
	if kind != string(identity.SourceMeasured) {
		t.Errorf("%s edge %s -> %s source_kind = %q, want measured — the provider's API stated this containment", typ, from, to, kind)
	}
	if !strings.HasPrefix(ref, "cloud:") {
		t.Errorf("%s edge %s -> %s source_ref = %q, want a cloud:<provider> reference", typ, from, to, ref)
	}
}

// ---------------------------------------------------------------------------
// The two ways one private address can name two machines
// ---------------------------------------------------------------------------

// oneVPCPlan builds one VPC + subnet + instance, with the subnet's CIDR and the
// instance's private address FIXED by the caller and everything else varying by
// `tag`. Two calls with the same cidr/addr therefore describe two different
// instances that share an address — which is the whole point.
func oneVPCPlan(tag, cidr, addr string) cloudEnumerationPlan {
	instances, vpcs, subnets, groups := awsFixture()
	vpcs[0].VPCID = "vpc-" + tag
	vpcs[0].ARN = "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-" + tag
	subnets[0].SubnetID = "subnet-" + tag
	subnets[0].ARN = "arn:aws:ec2:us-east-1:123456789012:subnet/subnet-" + tag
	subnets[0].VPCID = vpcs[0].VPCID
	subnets[0].CIDRBlock = cidr
	instances[0].InstanceID = "i-" + tag
	instances[0].ARN = "arn:aws:ec2:us-east-1:123456789012:instance/i-" + tag
	instances[0].VPCID = vpcs[0].VPCID
	instances[0].SubnetID = subnets[0].SubnetID
	instances[0].PrivateIPs = []string{addr}
	// The ip-name private DNS form is refused as a hostname anyway; blanking it
	// keeps this test about the ADDRESS and nothing else.
	instances[0].PrivateDNSName = ""
	instances[0].Interfaces[0].Addresses = instances[0].PrivateIPs
	groups[0].GroupID = "sg-" + tag
	instances[0].SecurityGroups[0].ID = groups[0].GroupID
	return buildAWSEnumerationPlan(instances, vpcs, subnets, groups)
}

func instanceAssetID(t *testing.T, devices []models.Device) uuid.UUID {
	t.Helper()
	for _, d := range devices {
		if d.DeviceType == DeviceTypeAWSEC2Instance {
			return d.ID
		}
	}
	t.Fatal("the plan recorded no EC2 instance")
	return uuid.UUID{}
}

func cloudResourceIDsOf(t *testing.T, db *sql.DB, tenantID, assetID uuid.UUID) []string {
	t.Helper()
	rows, err := db.Query(`
		SELECT value FROM asset_identifiers
		WHERE tenant_id = $1 AND asset_id = $2 AND kind = 'cloud_resource_id'
		ORDER BY value`, tenantID, assetID)
	if err != nil {
		t.Fatalf("read cloud_resource_id identifiers: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("scan identifier: %v", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("identifier rows: %v", err)
	}
	return out
}

// Two VPCs, the same subnet CIDR, the same private address: TWO assets.
//
// This is the reproduction that failed before this workstream's identity fixes.
// `network_segments` was unique on (tenant, value), so both subnets shared one
// segment; both instances' ip_address identifiers landed in one scope; and
// because a `cloud_resource_id` the engine has never seen owns nothing and so
// cannot decide, `ip_address` decided instead and the second instance was
// ABSORBED — one asset carrying two `cloud_resource_id` identifiers, with the
// first instance's approval state, and no merge proposal.
//
// Mutation checks: drop `cloud_network_ref` from ensureCIDRSegment's INSERT, or
// take the network filter out of ScopeForAddress, and this fails.
func TestIntegration_CloudEnumeration_TwoVPCsSharingACIDRAreTwoAssets(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	integrationID := seedCloudIntegration(t, owner, tenantID)
	svc := NewCloudDiscoveryService(appDB, owner, testMasterKey)

	const cidr, addr = "10.0.1.0/24", "10.0.1.20"
	planA := oneVPCPlan("aaaa", cidr, addr)
	planB := oneVPCPlan("bbbb", cidr, addr)

	devA, _, err := svc.recordEnumeration(ctx, tenantID, integrationID, "production", planA)
	if err != nil {
		t.Fatalf("recordEnumeration(vpc-a): %v", err)
	}
	devB, _, err := svc.recordEnumeration(ctx, tenantID, integrationID, "production", planB)
	if err != nil {
		t.Fatalf("recordEnumeration(vpc-b): %v", err)
	}

	instA, instB := instanceAssetID(t, devA), instanceAssetID(t, devB)
	if instA == instB {
		t.Fatalf("two EC2 instances in two VPCs became ONE asset (%s); a shared CIDR is not a shared "+
			"address space, and merging them silently is the auto-merge ADR-0002 D5 forbids", instA)
	}

	// Each asset carries exactly its own ARN, and only its own.
	for _, tc := range []struct {
		label string
		asset uuid.UUID
		arn   string
	}{
		{"vpc-a", instA, "arn:aws:ec2:us-east-1:123456789012:instance/i-aaaa"},
		{"vpc-b", instB, "arn:aws:ec2:us-east-1:123456789012:instance/i-bbbb"},
	} {
		got := cloudResourceIDsOf(t, owner, tenantID, tc.asset)
		if len(got) != 1 || got[0] != tc.arn {
			t.Errorf("%s asset carries %v, want exactly [%s]", tc.label, got, tc.arn)
		}
	}

	// Two segments for the one CIDR, told apart by their VPC.
	var segs int
	if err := owner.QueryRow(`
		SELECT count(*) FROM network_segments WHERE tenant_id = $1 AND value = $2`,
		tenantID, cidr).Scan(&segs); err != nil {
		t.Fatalf("segment count: %v", err)
	}
	if segs != 2 {
		t.Errorf("%d segments for %s, want 2 — one per VPC", segs, cidr)
	}
	var refs int
	if err := owner.QueryRow(`
		SELECT count(DISTINCT cloud_network_ref) FROM network_segments
		WHERE tenant_id = $1 AND value = $2 AND cloud_network_ref IS NOT NULL`,
		tenantID, cidr).Scan(&refs); err != nil {
		t.Fatalf("network ref count: %v", err)
	}
	if refs != 2 {
		t.Errorf("%d distinct cloud_network_ref values, want 2 — the ref is what tells the segments apart", refs)
	}

	// And the two addresses are scoped to DIFFERENT segments, which is the
	// mechanism: without it they are one identifier and one asset.
	scopeOf := func(asset uuid.UUID) string {
		var scope string
		if err := owner.QueryRow(`
			SELECT coalesce(scope, '') FROM asset_identifiers
			WHERE tenant_id = $1 AND asset_id = $2 AND kind = 'ip_address'`,
			tenantID, asset).Scan(&scope); err != nil {
			t.Fatalf("ip_address scope for %s: %v", asset, err)
		}
		return scope
	}
	if a, b := scopeOf(instA), scopeOf(instB); a == b {
		t.Errorf("both instances' addresses are scoped to %q; one address in two VPCs is two places", a)
	}
}

// The residual, and the reason it is not silent: an address REUSED inside ONE
// subnet.
//
// EC2 hands a freed private address to the next instance launched, so this is
// genuinely one segment and the VPC-scoping fix does not — and should not —
// separate them. What stops the silent merge is the engine's singleton guard:
// the new instance's `cloud_resource_id` disagrees with the one the matched
// asset carries, so the observation becomes its own pending asset and a merge
// proposal asks a human. The OLD asset is left exactly as it was.
//
// Mutation check: remove the singleton guard from Engine.Resolve and this fails
// — the replacement is absorbed and no proposal is written.
func TestIntegration_CloudEnumeration_ReusedAddressOpensAProposal(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	integrationID := seedCloudIntegration(t, owner, tenantID)
	svc := NewCloudDiscoveryService(appDB, owner, testMasterKey)

	// ONE VPC and ONE subnet: the second run is the same placement with a new
	// instance in it, which is what terminate-then-launch looks like from here.
	const cidr, addr = "10.7.1.0/24", "10.7.1.20"
	const newARN = "arn:aws:ec2:us-east-1:123456789012:instance/i-new2"
	first := oneVPCPlan("old1", cidr, addr)
	second := oneVPCPlan("old1", cidr, addr)
	second.Instances[0].ResourceID = newARN
	second.Instances[0].Metadata["instance_id"] = "i-new2"
	second.Instances[0].Facts[facts.KeyCloudResourceID] = newARN

	devFirst, _, err := svc.recordEnumeration(ctx, tenantID, integrationID, "production", first)
	if err != nil {
		t.Fatalf("recordEnumeration(first): %v", err)
	}
	oldAsset := instanceAssetID(t, devFirst)

	devSecond, _, err := svc.recordEnumeration(ctx, tenantID, integrationID, "production", second)
	if err != nil {
		t.Fatalf("recordEnumeration(second): %v", err)
	}
	newAsset := instanceAssetID(t, devSecond)

	if newAsset == oldAsset {
		t.Fatalf("the replacement instance was absorbed into %s; from the outside an address that changed "+
			"hands and a machine that was rebuilt look identical, and guessing is not the engine's job", oldAsset)
	}

	// The old asset is untouched: still one ARN, still its own.
	if got := cloudResourceIDsOf(t, owner, tenantID, oldAsset); len(got) != 1 ||
		got[0] != "arn:aws:ec2:us-east-1:123456789012:instance/i-old1" {
		t.Errorf("the old asset carries %v, want exactly its own ARN — it must not acquire the replacement's", got)
	}
	if got := cloudResourceIDsOf(t, owner, tenantID, newAsset); len(got) != 1 || got[0] != newARN {
		t.Errorf("the new asset carries %v, want exactly [%s]", got, newARN)
	}

	// A human is asked. Without the proposal the split is invisible: two assets
	// and nothing saying they might be one thing.
	//
	// A merge proposal is an `asset_history` row with action `merge_proposed`
	// (shared/identity/postgres's OpenMergeProposal); there is no separate table.
	var proposals int
	if err := owner.QueryRow(`
		SELECT count(*) FROM asset_history
		WHERE tenant_id = $1 AND action = 'merge_proposed'`,
		tenantID).Scan(&proposals); err != nil {
		t.Fatalf("proposal count: %v", err)
	}
	if proposals == 0 {
		t.Error("no merge proposal was opened; a contested identity nobody is asked about is a silent decision")
	}
}
