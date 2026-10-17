package services

// Cloud placement and the topology's cloud hierarchy against a real Postgres
// (asset-inventory ADR-0009 D7, DCIM row 4.6): the breadcrumb's steps come from
// the stored attributes, the prefix and its network container, and the
// hosted_on / member_of edges; the topology groups the same resources by
// account → region → prefix → class.
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestIntegration_CloudPlacement_AndTopologyClouds(t *testing.T) {
	svc, db, tenant := newTopologyFixture(t)
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	ref := "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-" + uuid.New().String()[:8]
	vpc := seedPrefix(t, db, tenant, "vpc", "10.77.0.0/16")
	sub := seedPrefix(t, db, tenant, "child", "10.77.1.0/24")
	exec(`UPDATE prefixes SET cloud_network_ref = $2 WHERE id = ANY(ARRAY[$1::uuid, $3::uuid])`, vpc, ref, sub)

	asset := func(class, name string, prefix *uuid.UUID, attrs string) uuid.UUID {
		id := seedTopologyAsset(t, db, tenant, name, class, "cloud_resource."+class, nil, prefix)
		exec(`UPDATE assets SET attributes = $2::jsonb WHERE id = $1`, id, attrs)
		return id
	}
	account := asset("cloud_account", "prod-account", nil, `{"provider":"aws","account_id":"123456789012"}`)
	inst := asset("compute_instance", "web-01", &sub, `{"provider":"aws","account_id":"123456789012","region":"us-east-1","provider_type":"AWS::EC2::Instance"}`)
	sg := asset("security_group", "web-sg", nil, `{"provider":"aws","account_id":"123456789012","region":"us-east-1"}`)
	asset("object_storage", "bucket-1", nil, `{"provider":"aws","account_id":"123456789012","region":"global"}`)
	exec(`INSERT INTO asset_identifiers (tenant_id, asset_id, kind, value) VALUES ($1, $2, 'cloud_resource_id', 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-01')`, tenant, sg)
	exec(`INSERT INTO asset_relationships (tenant_id, from_asset_id, to_asset_id, type, status) VALUES ($1,$2,$3,'hosted_on','active'), ($1,$2,$4,'member_of','active')`, tenant, inst, account, sg)
	exec(`INSERT INTO asset_facts (tenant_id, asset_id, key, value, source_kind, source_ref) VALUES ($1,$2,'cloud.security_groups',
		'[{"id":"sg-01","name":"web"},{"id":"sg-02","name":"db"}]'::jsonb,'measured','cloud:aws')`, tenant, inst)

	p, err := svc.GetCloudPlacement(ctx, tenant, inst)
	if err != nil {
		t.Fatalf("GetCloudPlacement: %v", err)
	}
	if p.AccountAssetID == nil || *p.AccountAssetID != account || p.Region != "us-east-1" || p.ProviderType != "AWS::EC2::Instance" {
		t.Errorf("placement = %+v", p)
	}
	if p.Prefix == nil || p.Prefix.Prefix != "10.77.1.0/24" || p.Network == nil || p.Network.Prefix != "10.77.0.0/16" {
		t.Errorf("prefix steps = %+v / %+v", p.Network, p.Prefix)
	}
	// sg-01 is the asset (by its resource id's last segment); sg-02 is known
	// only from the fact. Two groups, not three.
	if len(p.SecurityGroups) != 2 {
		t.Fatalf("groups = %+v", p.SecurityGroups)
	}
	var asAsset, factOnly int
	for _, g := range p.SecurityGroups {
		if g.AssetID != nil && *g.AssetID == sg {
			asAsset++
		} else if g.AssetID == nil && g.ID == "sg-02" {
			factOnly++
		}
	}
	if asAsset != 1 || factOnly != 1 {
		t.Errorf("groups = %+v", p.SecurityGroups)
	}
	if _, err := svc.GetCloudPlacement(ctx, tenant, uuid.New()); err != ErrNotFound {
		t.Errorf("unknown asset: %v, want ErrNotFound", err)
	}

	tp, err := svc.GetTopology(ctx, tenant)
	if err != nil {
		t.Fatalf("GetTopology: %v", err)
	}
	if len(tp.Clouds) != 1 || tp.Clouds[0].AccountID != "123456789012" || tp.Clouds[0].AccountAssetID == nil || tp.Clouds[0].AssetCount != 3 {
		t.Fatalf("clouds = %+v", tp.Clouds)
	}
	regions := map[string]int{}
	for _, r := range tp.Clouds[0].Regions {
		regions[r.Region] = r.AssetCount
	}
	if regions["us-east-1"] != 2 || regions["global"] != 1 {
		t.Errorf("regions = %v", regions)
	}
}
