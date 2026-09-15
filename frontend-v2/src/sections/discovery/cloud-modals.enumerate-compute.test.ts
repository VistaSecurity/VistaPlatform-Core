import { describe, it, expect } from 'vitest';
import { readEnumerateCompute, ENUMERATE_COMPUTE_KEY } from './cloud-modals';
import { enumerationSummary } from './logs-page';

// The per-integration compute/network enumeration switch (BUILD_PLAN 2.4).
//
// ABSENT means ON. Every integration written before the setting existed carries
// no value at all and the backend reads a missing key as `true`
// (cloud_integration_auth.go loadCloudIntegrationSettings). Reading it as off
// here would show a switch in the opposite position to the behaviour, which is
// worse than not showing one.
describe('readEnumerateCompute', () => {
  it('defaults ON for an integration that predates the setting', () => {
    expect(readEnumerateCompute(undefined)).toBe(true);
    expect(readEnumerateCompute(null)).toBe(true);
    expect(readEnumerateCompute({})).toBe(true);
    expect(readEnumerateCompute({ auth_mode: 'access_key' })).toBe(true);
  });

  it('reads an explicit boolean', () => {
    expect(readEnumerateCompute({ [ENUMERATE_COMPUTE_KEY]: true })).toBe(true);
    expect(readEnumerateCompute({ [ENUMERATE_COMPUTE_KEY]: false })).toBe(false);
  });

  // The AWS credential decrypt path stringifies every non-string config value
  // it passes through, so a stored `false` can come back as the STRING "false".
  // Reading only the boolean would treat that as "not set" and silently show
  // the switch on while the backend had it off.
  it('reads the stringified forms the decrypt path produces', () => {
    expect(readEnumerateCompute({ [ENUMERATE_COMPUTE_KEY]: 'false' })).toBe(false);
    expect(readEnumerateCompute({ [ENUMERATE_COMPUTE_KEY]: 'FALSE' })).toBe(false);
    expect(readEnumerateCompute({ [ENUMERATE_COMPUTE_KEY]: '0' })).toBe(false);
    expect(readEnumerateCompute({ [ENUMERATE_COMPUTE_KEY]: 'true' })).toBe(true);
    expect(readEnumerateCompute({ [ENUMERATE_COMPUTE_KEY]: '1' })).toBe(true);
  });

  it('falls back to ON for a value it cannot read', () => {
    expect(readEnumerateCompute({ [ENUMERATE_COMPUTE_KEY]: 'maybe' })).toBe(true);
    expect(readEnumerateCompute({ [ENUMERATE_COMPUTE_KEY]: 42 })).toBe(true);
  });
});

describe('enumerationSummary', () => {
  it('omits the fragment when the run did not enumerate', () => {
    expect(enumerationSummary(undefined)).toBeNull();
  });

  // Absent and all-zero are different answers: "we did not look" versus "there
  // was nothing there".
  it('says so when the run enumerated and found nothing', () => {
    expect(enumerationSummary({ instances: 0, networks: 0, subnets: 0, security_groups: 0 }))
      .toBe('no compute found');
  });

  it('lists only the non-zero counts', () => {
    expect(enumerationSummary({ instances: 12, networks: 3, subnets: 9, security_groups: 14 }))
      .toBe('12 instances, 3 networks, 9 subnets, 14 security groups');
    expect(enumerationSummary({ instances: 0, networks: 1, subnets: 4, security_groups: 0 }))
      .toBe('1 network, 4 subnets');
  });

  it('says "1 instance", not "1 instances"', () => {
    expect(enumerationSummary({ instances: 1, networks: 0, subnets: 1, security_groups: 1 }))
      .toBe('1 instance, 1 subnet, 1 security group');
  });
});
