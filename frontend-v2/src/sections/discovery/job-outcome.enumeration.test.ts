import { describe, it, expect } from 'vitest';
import { enumerationSummary } from './job-outcome';

// The enumeration half of a cloud run, as one log-line fragment. The switch
// that used to decide whether a run enumerated (`enumerate_compute`) is gone —
// compute, network and security-group listings are resource types selected per
// run since DCIM row 4.6 (asset-inventory ADR-0009 D3).
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
      .toBe('12 instances, 3 networks, 9 network prefixes, 14 security groups');
    expect(enumerationSummary({ instances: 0, networks: 1, subnets: 4, security_groups: 0 }))
      .toBe('1 network, 4 network prefixes');
  });

  it('says "1 instance", not "1 instances"', () => {
    expect(enumerationSummary({ instances: 1, networks: 0, subnets: 1, security_groups: 1 }))
      .toBe('1 instance, 1 network prefix, 1 security group');
  });
});
