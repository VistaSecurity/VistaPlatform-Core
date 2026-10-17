package services

// What only a real database can say about cloud enumeration (BUILD_PLAN 2.4).
//
// The builder tests next door pin what each provider PRODUCES. These pin what
// the recording actually WRITES: the instance in the right class and the right
// approval state, the provider's resource id as an identifier, the `cloud.*`
// facts under the cloud-collector producer, its ENI as an interface with its
// address, the VPC and subnet as prefixes (and as NO asset and NO `contains`
// edge — DCIM row 1.5f), the prefix the instance's address scopes to — and, on
// a second run, exactly the same rows rather than a second set.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/identifiersql"
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
	// A per-run CIDR: a shared one would make the second test's prefix a
	// match rather than an insert.
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
	instances[0].Interfaces[0].SubnetID = subnets[0].SubnetID
	instances[0].Interfaces[0].VPCID = vpcs[0].VPCID
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

func TestIntegration_CloudEnumeration_WritesInstanceInterfacesAndPrefixes(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	svc := NewCloudDiscoveryService(appDB, owner, testMasterKey)
	ctx, integrationID := accountRunContext(ctx, t, svc, owner, tenantID)
	plan := awsEnumerationPlanForTest(t)

	devices, counts, err := svc.recordEnumeration(ctx, tenantID, integrationID, "production", plan)
	if err != nil {
		t.Fatalf("recordEnumeration: %v", err)
	}
	if counts != (CloudEnumerationCounts{Instances: 1, Networks: 1, Subnets: 1, SecurityGroups: 1}) {
		t.Fatalf("counts = %+v", counts)
	}
	if len(devices) != 1 {
		t.Fatalf("recorded %d devices, want 1: the instance (the VPC and subnet are prefixes)", len(devices))
	}

	vpcRes := plan.Networks[0]
	subnetRes := plan.Subnets[0]
	instRes := plan.Instances[0]
	instID := assetIDForCloudResource(t, owner, tenantID, instRes.ResourceID)

	// --- no network asset (row 1.5f) ----------------------------------------
	assertNoCloudNetworkAssets(t, owner, tenantID, vpcRes.ResourceID, subnetRes.ResourceID)

	// --- class and approval state -------------------------------------------
	var classKey, status string
	if err := owner.QueryRow(
		`SELECT class_key, asset_status FROM assets WHERE tenant_id = $1 AND id = $2`,
		tenantID, instID).Scan(&classKey, &status); err != nil {
		t.Fatalf("instance asset row: %v", err)
	}
	if classKey != "compute_instance" {
		t.Errorf("class_key = %q, want compute_instance", classKey)
	}
	// New cloud assets land pending_approval, exactly like every other
	// discovered asset. The engine only ever writes this status.
	if status != identity.StatusPendingApproval {
		t.Errorf("asset_status = %q, want %q", status, identity.StatusPendingApproval)
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
	} {
		if got := instFacts[key]; got != want {
			t.Errorf("fact %s = %s, want %s", key, got, want)
		}
	}
	if instFacts[facts.KeyCloudSecurityGroups] == "" {
		t.Error("cloud.security_groups is missing — membership is the whole security-group answer")
	}
	// Retired by row 1.5f: the ENIs are interfaces and the network is prefix
	// containment.
	for _, gone := range []string{facts.KeyNetInterfaces, facts.KeyCloudVPCID, facts.KeyCloudSubnetID} {
		if v, present := instFacts[gone]; present {
			t.Errorf("fact %s = %s is still written", gone, v)
		}
	}
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

	// --- the ENI is an interface carrying the address -----------------------
	var ifaceName, ifaceType, ifaceSource, addr string
	if err := owner.QueryRow(`
		SELECT i.name, i.type, i.source_kind, host(ip.address) || '/' || masklen(ip.address)
		  FROM interfaces i JOIN ip_addresses ip
		    ON ip.tenant_id = i.tenant_id AND ip.assigned_kind = 'interface' AND ip.assigned_id = i.id
		 WHERE i.tenant_id = $1 AND i.asset_id = $2`, tenantID, instID).Scan(&ifaceName, &ifaceType, &ifaceSource, &addr); err != nil {
		t.Fatalf("ENI interface: %v", err)
	}
	if ifaceName != "eni-01" || ifaceType != "virtual" || ifaceSource != "measured" {
		t.Errorf("interface = %s/%s/%s, want eni-01/virtual/measured", ifaceName, ifaceType, ifaceSource)
	}
	if want := instRes.IPAddress + "/24"; addr != want {
		t.Errorf("ENI address = %s, want %s (the subnet's length)", addr, want)
	}

	// --- the VPC and the subnet are prefixes in the VPC's address space -----
	for _, cidr := range []string{vpcRes.CIDRs[0], subnetRes.CIDRs[0]} {
		var ref, networkType string
		var dhcp sql.NullBool
		if err := owner.QueryRow(`
			SELECT coalesce(cloud_network_ref, ''), coalesce(network_type, ''), dhcp_managed
			  FROM prefixes WHERE tenant_id = $1 AND prefix = $2::cidr`,
			tenantID, cidr).Scan(&ref, &networkType, &dhcp); err != nil {
			t.Fatalf("prefix %s: %v", cidr, err)
		}
		if ref != vpcRes.ResourceID || networkType != "cloud" || !dhcp.Valid || dhcp.Bool {
			t.Errorf("prefix %s: cloud_network_ref=%q network_type=%q dhcp_managed=%v, want %q / cloud / false",
				cidr, ref, networkType, dhcp, vpcRes.ResourceID)
		}
	}

	// The instance's address is scoped to the SUBNET's prefix, not the tenant
	// default and not the VPC's: that is the scope an agent inside the
	// instance, or the sensor on the wire, reaches for the same address — so
	// all three resolve to this one asset. (A subnet prefix carrying its own
	// subnet id rather than the VPC's would be skipped for a sighting that
	// names its VPC, and this assertion would fail.)
	var subnetPrefix string
	if err := owner.QueryRow(`SELECT id::text FROM prefixes WHERE tenant_id = $1 AND prefix = $2::cidr`,
		tenantID, subnetRes.CIDRs[0]).Scan(&subnetPrefix); err != nil {
		t.Fatalf("subnet prefix id: %v", err)
	}
	var idScope string
	if err := owner.QueryRow(`
		SELECT coalesce(scope, '') FROM (`+identifiersql.All+`) ident_rows
		WHERE tenant_id = $1 AND asset_id = $2 AND kind = 'ip_address'`,
		tenantID, instID).Scan(&idScope); err != nil {
		t.Fatalf("ip_address identifier: %v", err)
	}
	if idScope != subnetPrefix {
		t.Errorf("ip_address scope = %q, want the subnet's prefix %q", idScope, subnetPrefix)
	}

	// The account's network listing matched the declared account asset and
	// changed nothing about it but its last sighting.
	account := assetIDForCloudResource(t, owner, tenantID, "aws:123456789012")
	var acctClass, acctStatus, acctName string
	if err := owner.QueryRow(`SELECT class_key, asset_status, coalesce(display_name, '') FROM assets WHERE tenant_id = $1 AND id = $2`,
		tenantID, account).Scan(&acctClass, &acctStatus, &acctName); err != nil {
		t.Fatal(err)
	}
	if acctClass != "cloud_account" || acctStatus != identity.StatusMonitoring || acctName != "aws-"+integrationID.String()[:8] {
		t.Errorf("account asset = %s/%s/%q after the network listing, want cloud_account/monitoring/its integration's name",
			acctClass, acctStatus, acctName)
	}
	var acctInterfaces int
	if err := owner.QueryRow(`SELECT count(*) FROM interfaces WHERE tenant_id = $1 AND asset_id = $2`, tenantID, account).Scan(&acctInterfaces); err != nil || acctInterfaces != 0 {
		t.Errorf("the account grew %d interfaces (%v); its sighting carries prefixes only", acctInterfaces, err)
	}

	// --- no containment edge ------------------------------------------------
	var edges int
	if err := owner.QueryRow(`SELECT count(*) FROM asset_relationships WHERE tenant_id = $1 AND type = 'contains'`,
		tenantID).Scan(&edges); err != nil {
		t.Fatal(err)
	}
	if edges != 0 {
		t.Errorf("%d contains edges written; a VPC / subnet is a prefix, containment is by address", edges)
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

// assertNoCloudNetworkAssets fails if any asset carries a retired class or one
// of the networks' resource ids (row 1.5f).
func assertNoCloudNetworkAssets(t *testing.T, db *sql.DB, tenantID uuid.UUID, resourceIDs ...string) {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id = $1 AND class_key IN ('subnet', 'virtual_network')`,
		tenantID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d assets of class subnet / virtual_network; they are prefixes since row 1.5f", n)
	}
	for _, rid := range resourceIDs {
		if err := db.QueryRow(`SELECT count(*) FROM (`+identifiersql.All+`) ident_rows
			WHERE tenant_id = $1 AND kind = 'cloud_resource_id' AND value = $2`, tenantID, rid).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("an asset carries the network's resource id %s", rid)
		}
	}
}

// Two runs, one asset, one prefix each. A re-run matches on cloud_resource_id
// and updates.
func TestIntegration_CloudEnumeration_IsIdempotent(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	svc := NewCloudDiscoveryService(appDB, owner, testMasterKey)
	ctx, integrationID := accountRunContext(ctx, t, svc, owner, tenantID)
	plan := awsEnumerationPlanForTest(t)

	first, _, err := svc.recordEnumeration(ctx, tenantID, integrationID, "production", plan)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	rows := func() map[string]int {
		out := map[string]int{}
		for _, table := range []string{"assets", "interfaces", "ip_addresses", "prefixes", "asset_relationships", "clusters"} {
			var n int
			if err := owner.QueryRow(`SELECT count(*) FROM `+table+` WHERE tenant_id = $1`, tenantID).Scan(&n); err != nil {
				t.Fatal(err)
			}
			out[table] = n
		}
		return out
	}
	before := rows()
	// DCIM row 4.2: the account + region is mirrored as ONE aws cluster with
	// the instance as its VM (mutation: drop the MirrorCloudCluster call from
	// recordCloudResource → red).
	var mirrored int
	if err := owner.QueryRow(`SELECT count(*) FROM assets a JOIN clusters c ON c.id = a.cluster_id JOIN cluster_types ct ON ct.id = c.type_id
		WHERE a.tenant_id = $1 AND a.class_key = 'compute_instance' AND ct.slug = 'aws' AND c.external_ids ? 'cloud'`, tenantID).Scan(&mirrored); err != nil {
		t.Fatal(err)
	}
	if mirrored != len(plan.Instances) || before["clusters"] != 1 {
		t.Errorf("mirrored instances = %d of %d in %d clusters, want every instance in one account+region cluster", mirrored, len(plan.Instances), before["clusters"])
	}
	prefixObservations := func() int {
		var n int
		if err := owner.QueryRow(`SELECT observation_count FROM prefixes WHERE tenant_id = $1 AND prefix = $2::cidr`,
			tenantID, plan.Subnets[0].CIDRs[0]).Scan(&n); err != nil {
			t.Fatalf("prefix observation count: %v", err)
		}
		return n
	}
	firstObservations := prefixObservations()
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
	if after := rows(); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Errorf("rows after the second run %v, want unchanged %v", after, before)
	}
	var n int
	if err := owner.QueryRow(`
		SELECT count(*) FROM (`+identifiersql.All+`) ident_rows
		WHERE tenant_id = $1 AND kind = 'cloud_resource_id' AND value = $2`,
		tenantID, plan.Instances[0].ResourceID).Scan(&n); err != nil {
		t.Fatalf("identifier count: %v", err)
	}
	if n != 1 {
		t.Errorf("%s has %d cloud_resource_id rows, want 1", plan.Instances[0].ResourceID, n)
	}
	// The prefix was observed again rather than written again: once by the
	// account's network listing and once by the instance sitting in it, per run.
	if firstObservations != 2 {
		t.Errorf("subnet prefix observation_count after one run = %d, want 2 (the account's listing and the instance)", firstObservations)
	}
	if got := prefixObservations(); got != 2*firstObservations {
		t.Errorf("subnet prefix observation_count = %d after two runs, want %d — a re-observation bumps rather than appends", got, 2*firstObservations)
	}
}

// accountRunContext seeds an integration that names the fixtures' AWS account
// and begins a cloud run for it, as a real run does: the account asset exists
// (declared by the integration), so the account's network listing records the
// prefixes BEFORE any instance resolves (recordNetworkPrefixes).
func accountRunContext(ctx context.Context, t *testing.T, svc *CloudDiscoveryService, owner *sql.DB, tenantID uuid.UUID) (context.Context, uuid.UUID) {
	t.Helper()
	integrationID := seedAccountIntegration(t, owner, tenantID, "123456789012", false)
	return svc.beginCloudRun(ctx, tenantID, integrationID, "aws"), integrationID
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func assetIDForCloudResource(t *testing.T, db *sql.DB, tenantID uuid.UUID, resourceID string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.QueryRow(`
		SELECT asset_id FROM (`+identifiersql.All+`) ident_rows
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
	instances[0].Interfaces[0].SubnetID = subnets[0].SubnetID
	instances[0].Interfaces[0].VPCID = vpcs[0].VPCID
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
		SELECT value FROM (`+identifiersql.All+`) ident_rows
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
// The network container was unique on (tenant, value), so both subnets shared
// one scope; both instances' ip_address identifiers landed in it; and
// because a `cloud_resource_id` the engine has never seen owns nothing and so
// cannot decide, `ip_address` decided instead and the second instance was
// ABSORBED — one asset carrying two `cloud_resource_id` identifiers, with the
// first instance's approval state, and no merge proposal.
//
// The subnets are prefixes (rows 1.5f, 1.6), and a prefix's identity includes
// its cloud network (prefixes_identity_uniq keys on `cloud_network_ref`), so
// the two subnets are two prefix rows and the two addresses sit in two scopes.
// Mutation checks: drop the cloud_network_ref predicate from the observed
// prefix writer's lookup, or take the network filter out of ScopeForAddress,
// and this fails.
func TestIntegration_CloudEnumeration_TwoVPCsSharingACIDRAreTwoAssets(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	svc := NewCloudDiscoveryService(appDB, owner, testMasterKey)
	ctx, integrationID := accountRunContext(ctx, t, svc, owner, tenantID)

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

	// Two prefixes for the one CIDR, told apart by their VPC.
	var prefixes, refs int
	if err := owner.QueryRow(`
		SELECT count(*), count(DISTINCT cloud_network_ref) FROM prefixes WHERE tenant_id = $1 AND prefix = $2::cidr`,
		tenantID, cidr).Scan(&prefixes, &refs); err != nil {
		t.Fatalf("prefix count: %v", err)
	}
	if prefixes != 2 || refs != 2 {
		t.Errorf("%d prefixes (%d distinct cloud_network_ref) for %s, want 2 and 2 — one per VPC", prefixes, refs, cidr)
	}

	// And the two addresses are scoped to DIFFERENT prefixes, which is the
	// mechanism: without it they are one identifier and one asset.
	scopeOf := func(asset uuid.UUID) string {
		var scope string
		if err := owner.QueryRow(`
			SELECT coalesce(scope, '') FROM (`+identifiersql.All+`) ident_rows
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
// genuinely one prefix and the VPC-scoping fix does not — and should not —
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
	svc := NewCloudDiscoveryService(appDB, owner, testMasterKey)
	ctx, integrationID := accountRunContext(ctx, t, svc, owner, tenantID)

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
