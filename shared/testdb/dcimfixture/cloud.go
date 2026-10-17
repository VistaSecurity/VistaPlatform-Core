package dcimfixture

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// The cloud populator (DCIM BUILD_PLAN row 4.6, asset-inventory ADR-0009):
// one AWS account asset and, per site, a region holding CloudInstancesPerSite
// compute instances, a security group they are all members of, a Lambda
// function, a bucket and (once) a DNS zone — the rows the Cloud lens, the
// Placement breadcrumb, the topology's cloud hierarchy and the cloud
// disappearance sweep read: the `cloud_resource` attributes, `hosted_on` and
// `member_of` edges, and the lifecycle facts (`cloud.listing`,
// `cloud.last_enumerated_at`, the account's `cloud.enumeration_coverage`).
const CloudInstancesPerSite = 3

// CloudAccountID is the fixture account's id.
const CloudAccountID = "210987654321"

// CloudResources is how many cloud assets (account included) the populator
// writes for a scale with `sites` sites.
func CloudResources(sites int) int {
	if sites == 0 {
		return 0
	}
	return 1 + sites*(CloudInstancesPerSite+3) + 1
}

// CloudRelationships is how many edges it writes: every resource's
// `hosted_on`, plus each instance's `member_of` its region's security group.
// The populator's count (its registry name is the table it owns rows in).
func CloudRelationships(sites int) int {
	if sites == 0 {
		return 0
	}
	return CloudResources(sites) - 1 + sites*CloudInstancesPerSite
}

func populateCloud(ctx context.Context, tx *sql.Tx, e *Env) (int, error) {
	if e.Scale.Sites == 0 {
		return -1, nil
	}
	now := time.Now().UTC()
	at := now.Format(time.RFC3339Nano)
	edges := 0
	insert := func(class, name string, attrs map[string]any) (uuid.UUID, error) {
		e.Witness(name)
		raw, _ := json.Marshal(attrs)
		var id uuid.UUID
		err := tx.QueryRowContext(ctx, `INSERT INTO assets (tenant_id, class_key, class_path, display_name, hostname, asset_status,
			attributes, last_seen_at, first_discovered_at, created_at, updated_at)
			VALUES ($1, $2, 'cloud_resource.' || $2, $3, $3, 'monitoring', $4::jsonb, $5, $5, $5, $5) RETURNING id`,
			e.Tenant, class, name, string(raw), now).Scan(&id)
		return id, err
	}
	edge := func(from, to uuid.UUID, typ string) error {
		edges++
		_, err := tx.ExecContext(ctx, `INSERT INTO asset_relationships (tenant_id, from_asset_id, to_asset_id, type, status) VALUES ($1, $2, $3, $4, 'active')`,
			e.Tenant, from, to, typ)
		return err
	}
	fact := func(asset uuid.UUID, key string, value any) error {
		raw, _ := json.Marshal(value)
		_, err := tx.ExecContext(ctx, `INSERT INTO asset_facts (tenant_id, asset_id, key, value, source_kind, source_ref, observed_at)
			VALUES ($1, $2, $3, $4::jsonb, 'measured', 'cloud:aws', $5)`, e.Tenant, asset, key, string(raw), now)
		return err
	}
	base := func(region, providerType string) map[string]any {
		return map[string]any{"provider": "aws", "account_id": CloudAccountID, "region": region, "provider_type": providerType}
	}

	account, err := insert("cloud_account", "fixture-cloud-account", map[string]any{"provider": "aws", "account_id": CloudAccountID})
	if err != nil {
		return 0, err
	}
	coverage := map[string]string{}
	record := func(id uuid.UUID, listing string) error {
		coverage[listing] = at
		if err := edge(id, account, "hosted_on"); err != nil {
			return err
		}
		if err := fact(id, "cloud.listing", listing); err != nil {
			return err
		}
		return fact(id, "cloud.last_enumerated_at", at)
	}
	for site := 0; site < e.Scale.Sites; site++ {
		region := fmt.Sprintf("fx-region-%d", site+1)
		sg, err := insert("security_group", fmt.Sprintf("fixture-sg-%02d", site+1), base(region, "AWS::EC2::SecurityGroup"))
		if err != nil {
			return edges, err
		}
		if err := record(sg, "security_groups@"+region); err != nil {
			return edges, err
		}
		for i := 0; i < CloudInstancesPerSite; i++ {
			inst, err := insert("compute_instance", fmt.Sprintf("fixture-instance-%02d-%02d", site+1, i+1), base(region, "AWS::EC2::Instance"))
			if err != nil {
				return edges, err
			}
			if err := record(inst, "compute_instances@"+region); err != nil {
				return edges, err
			}
			if err := edge(inst, sg, "member_of"); err != nil {
				return edges, err
			}
		}
		fn, err := insert("serverless_function", fmt.Sprintf("fixture-function-%02d", site+1),
			map[string]any{"provider": "aws", "account_id": CloudAccountID, "region": region, "provider_type": "AWS::Lambda::Function",
				"runtime": "python3.12", "environment_variable_names": []string{"STAGE"}})
		if err != nil {
			return edges, err
		}
		if err := record(fn, "serverless_functions@"+region); err != nil {
			return edges, err
		}
		bucket, err := insert("object_storage", fmt.Sprintf("fixture-bucket-%02d", site+1), base(region, "AWS::S3::Bucket"))
		if err != nil {
			return edges, err
		}
		if err := record(bucket, "s3@global"); err != nil {
			return edges, err
		}
	}
	zone, err := insert("dns_zone", "fixture.example.test", map[string]any{"provider": "aws", "account_id": CloudAccountID, "region": "global",
		"provider_type": "AWS::Route53::HostedZone", "zone_name": "fixture.example.test", "visibility": "public"})
	if err != nil {
		return edges, err
	}
	if err := record(zone, "dns_zones@global"); err != nil {
		return edges, err
	}
	return edges, fact(account, "cloud.enumeration_coverage", coverage)
}
