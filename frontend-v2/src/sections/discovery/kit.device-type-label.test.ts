import { describe, it, expect } from 'vitest';
import { deviceTypeLabel } from './kit';

// The Devices table and the job drawer rendered `device_type` raw, so a
// discovered S3 bucket read as `aws_s3_bucket`. The cloud resource types have
// no other label anywhere in the UI, so this map is the only place they are
// named for the user.

describe('deviceTypeLabel', () => {
  it('names the AWS cloud resource types', () => {
    expect(deviceTypeLabel('aws_kms')).toBe('AWS KMS key');
    expect(deviceTypeLabel('aws_s3_bucket')).toBe('AWS S3 bucket');
    expect(deviceTypeLabel('aws_rds_instance')).toBe('AWS RDS instance');
    expect(deviceTypeLabel('aws_alb')).toBe('AWS Application Load Balancer');
    expect(deviceTypeLabel('aws_cloudfront')).toBe('AWS CloudFront');
  });

  it('names the Azure and GCP resource types', () => {
    expect(deviceTypeLabel('azure_keyvault_key')).toBe('Azure Key Vault key');
    expect(deviceTypeLabel('gcp_kms_crypto_key')).toBe('GCP Cloud KMS key');
  });

  it('keeps the appliance vendors readable', () => {
    expect(deviceTypeLabel('f5')).toBe('F5 BIG-IP');
    expect(deviceTypeLabel('palo_alto')).toBe('Palo Alto');
  });

  it('is case-insensitive and tolerates surrounding space', () => {
    expect(deviceTypeLabel('AWS_S3_Bucket')).toBe('AWS S3 bucket');
    expect(deviceTypeLabel('  f5 ')).toBe('F5 BIG-IP');
  });

  it('prettifies an unknown type rather than shouting snake_case', () => {
    expect(deviceTypeLabel('aws_efs_filesystem')).toBe('AWS Efs Filesystem');
    expect(deviceTypeLabel('juniper')).toBe('Juniper');
  });

  it('returns undefined for nothing, so callers fall back to their own dash', () => {
    expect(deviceTypeLabel(undefined)).toBeUndefined();
    expect(deviceTypeLabel(null)).toBeUndefined();
    expect(deviceTypeLabel('   ')).toBeUndefined();
  });
});
