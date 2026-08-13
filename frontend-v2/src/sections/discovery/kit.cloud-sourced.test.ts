import { describe, it, expect } from 'vitest';
import { isCloudSourced } from './kit';

// L-7: cloud-sourced devices (AWS/Azure/GCP resources such as a CloudFront
// distribution) carry no SSH/HTTPS management credentials, so Interrogate and
// Test connection fail with "Device has no credentials configured" if
// clicked. isCloudSourced is what the Devices page uses to disable those
// buttons and show a "Cloud" origin chip instead of letting them look
// clickable.

describe('isCloudSourced', () => {
  it('flags a device discovered via cloud API', () => {
    expect(isCloudSourced({ discovery_method: 'cloud_api' })).toBe(true);
  });

  it('is case-insensitive', () => {
    expect(isCloudSourced({ discovery_method: 'Cloud_API' })).toBe(true);
  });

  it('leaves network-discovered devices interrogable', () => {
    expect(isCloudSourced({ discovery_method: 'manual' })).toBe(false);
    expect(isCloudSourced({ discovery_method: 'network_scan' })).toBe(false);
  });

  it('treats an absent discovery_method as not cloud-sourced', () => {
    expect(isCloudSourced({ discovery_method: undefined })).toBe(false);
    expect(isCloudSourced({ discovery_method: '' })).toBe(false);
    expect(isCloudSourced({})).toBe(false);
  });
});
