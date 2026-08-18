import { describe, it, expect } from 'vitest';
import { RESOURCE_TYPES, AWS_REGIONS, selectionNeedsRegions, selectionHasGlobal } from './cloud-modals';

// The AWS discovery backend dispatches EIGHT resource types
// (cloud_discovery_service.go DiscoverAWSResources); the modal used to offer
// five, so KMS keys, S3 bucket encryption and RDS encryption — two of the
// capability's three pillars — had no UI path at all. These pin the parity and
// the global-vs-regional split the request body depends on.

describe('RESOURCE_TYPES.aws', () => {
  it('offers every resource type the backend dispatches', () => {
    expect(RESOURCE_TYPES.aws.map((r) => r.value).sort()).toEqual(
      ['alb', 'api_gateway', 'cloudfront', 'elb', 'kms', 'nlb', 'rds', 's3'],
    );
  });

  it('marks exactly the account-wide types global', () => {
    // S3 ListBuckets and CloudFront ListDistributions are called without a
    // region argument; everything else iterates the selected regions.
    expect(RESOURCE_TYPES.aws.filter((r) => r.global).map((r) => r.value).sort()).toEqual(['cloudfront', 's3']);
  });

  it('gives every type a label and a description', () => {
    for (const rt of RESOURCE_TYPES.aws) {
      expect(rt.label.trim()).not.toBe('');
      expect(rt.description.trim()).not.toBe('');
    }
  });
});

describe('AWS_REGIONS', () => {
  it('covers the commercial-partition regions the old 15-entry list missed', () => {
    for (const r of ['eu-north-1', 'af-south-1', 'me-central-1', 'me-south-1', 'ap-east-1', 'ca-west-1', 'il-central-1']) {
      expect(AWS_REGIONS).toContain(r);
    }
  });

  it('holds no duplicates and no other partition', () => {
    expect(new Set(AWS_REGIONS).size).toBe(AWS_REGIONS.length);
    // GovCloud / China are separate partitions with separate credentials.
    expect(AWS_REGIONS.some((r) => r.startsWith('us-gov-') || r.startsWith('cn-'))).toBe(false);
  });
});

describe('selectionNeedsRegions', () => {
  it('is true when any regional type is selected', () => {
    expect(selectionNeedsRegions('aws', ['alb'])).toBe(true);
    expect(selectionNeedsRegions('aws', ['kms'])).toBe(true);
    expect(selectionNeedsRegions('aws', ['rds'])).toBe(true);
    expect(selectionNeedsRegions('aws', ['s3', 'rds'])).toBe(true);
  });

  it('is false for a global-only selection — regions would filter nothing', () => {
    expect(selectionNeedsRegions('aws', ['s3'])).toBe(false);
    expect(selectionNeedsRegions('aws', ['cloudfront'])).toBe(false);
    expect(selectionNeedsRegions('aws', ['s3', 'cloudfront'])).toBe(false);
  });

  it('is false with nothing selected, and for non-AWS providers', () => {
    expect(selectionNeedsRegions('aws', [])).toBe(false);
    expect(selectionNeedsRegions('azure', ['load_balancer'])).toBe(false);
    expect(selectionNeedsRegions('gcp', ['ssl_proxy'])).toBe(false);
  });
});

describe('selectionHasGlobal', () => {
  it('detects a global type in a mixed selection', () => {
    expect(selectionHasGlobal('aws', ['rds', 's3'])).toBe(true);
    expect(selectionHasGlobal('aws', ['alb', 'kms', 'rds'])).toBe(false);
    expect(selectionHasGlobal('azure', ['load_balancer'])).toBe(false);
  });
});
