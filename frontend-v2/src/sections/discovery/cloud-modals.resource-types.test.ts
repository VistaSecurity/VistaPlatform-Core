import { describe, it, expect } from 'vitest';
import { RESOURCE_TYPES, REGION_SCOPE_NOTE } from './cloud-modals';

// The AWS discovery backend dispatches EIGHT resource types
// (cloud_discovery_service.go DiscoverAWSResources); the modal used to offer
// five, so KMS keys, S3 bucket encryption and RDS encryption — two of the
// capability's three pillars — had no UI path at all. These pin the parity and
// the global-vs-regional split the request body depends on.

describe('RESOURCE_TYPES.aws', () => {
  it('offers every resource type the backend dispatches', () => {
    expect(RESOURCE_TYPES.aws.map((r) => r.value).sort()).toEqual(
      ['alb', 'api_gateway', 'cloudfront', 'compute_instances', 'container_clusters', 'dns_zones', 'elb', 'kms', 'networks', 'nlb', 'rds', 's3', 'secret_stores', 'security_groups', 'serverless_functions'],
    );
  });

  it('marks exactly the account-wide types global', () => {
    // S3 ListBuckets and CloudFront ListDistributions are called without a
    // region argument; everything else iterates the account's regions.
    expect(RESOURCE_TYPES.aws.filter((r) => r.global).map((r) => r.value).sort()).toEqual(['cloudfront', 'dns_zones', 's3']);
  });

  it('gives every type a label and a description', () => {
    for (const rt of RESOURCE_TYPES.aws) {
      expect(rt.label.trim()).not.toBe('');
      expect(rt.description.trim()).not.toBe('');
    }
  });
});

// Azure and GCP had the same gap (integrations review M5): Key Vault, storage
// and SQL on Azure, and Cloud KMS, Cloud Storage and Cloud SQL on GCP, all had
// collectors (cloud_discovery_service.go azureCloudCollectors /
// gcpCloudCollectors) and no way to ask for them. The backend's scheduled-run
// default is pinned to this table by TestDefaultCloudResourceTypes_MatchDiscoverModal.
describe('RESOURCE_TYPES for Azure and GCP', () => {
  it('offers every Azure collector', () => {
    expect(RESOURCE_TYPES.azure.map((r) => r.value).sort()).toEqual(
      ['application_gateway', 'compute_instances', 'container_clusters', 'dns_zones', 'key_vault', 'load_balancer', 'networks', 'secret_stores', 'security_groups', 'serverless_functions', 'sql_database', 'storage_account'],
    );
  });

  it('offers every GCP collector', () => {
    expect(RESOURCE_TYPES.gcp.map((r) => r.value).sort()).toEqual(
      ['cloudsql', 'compute_instances', 'container_clusters', 'dns_zones', 'kms', 'load_balancer', 'networks', 'secret_stores', 'security_groups', 'serverless_functions', 'ssl_proxy', 'storage'],
    );
  });

  it('gives every type a label and a description', () => {
    for (const rt of [...RESOURCE_TYPES.azure, ...RESOURCE_TYPES.gcp]) {
      expect(rt.label.trim()).not.toBe('');
      expect(rt.description.trim()).not.toBe('');
    }
  });
});

// The KMS collector collects AWS-managed keys and labels their custody; the
// copy said they were skipped.
describe('RESOURCE_TYPES.aws KMS copy', () => {
  it('does not claim AWS-managed keys are skipped', () => {
    const kms = RESOURCE_TYPES.aws.find((r) => r.value === 'kms');
    expect(kms?.description).not.toMatch(/skipped/i);
    expect(kms?.description).toMatch(/AWS-managed/);
  });
});

// ADR-0009 D3: the account is the scope. The modal offers no region field —
// AWS regions are listed from the account, Azure and GCP listings are
// account-wide — and says so per provider.
describe('region scope', () => {
  it('states where each provider reads, and offers no region list', () => {
    for (const p of ['aws', 'azure', 'gcp'] as const) {
      expect(REGION_SCOPE_NOTE[p].trim()).not.toBe('');
    }
    expect(REGION_SCOPE_NOTE.aws).toMatch(/DescribeRegions/);
  });

  // The account inventory listings lead the list on every provider: the
  // frame the rest hangs on, selected like any other type.
  it('leads every provider with the three enumeration listings', () => {
    for (const p of ['aws', 'azure', 'gcp'] as const) {
      expect(RESOURCE_TYPES[p].slice(0, 3).map((r) => r.value)).toEqual(['compute_instances', 'networks', 'security_groups']);
    }
  });
});
