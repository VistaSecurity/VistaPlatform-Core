import { describe, it, expect } from 'vitest';
import { hostInventorySummary } from './logs-page';

// The Job Logs line for a host-inventory run (asset-inventory 2.11b).
//
// Through 2.11a these runs appeared in the stream with an honest but useless
// headline: the result was HELD, so the line said 0 assets and carried a `fatal`
// explaining why. Now that they materialise, the line has to report what landed
// — and has to keep saying something when nothing did, because a feature that
// silently does nothing is the failure this whole workstream exists to avoid.

describe('hostInventorySummary', () => {
  it('omits the fragment entirely for a job that is not a host inventory', () => {
    // Absent and zeroed are different answers: absent means this is a device
    // interrogation or a cloud discovery, and the cloud fragment beside it
    // draws exactly the same distinction.
    expect(hostInventorySummary(undefined)).toBeNull();
  });

  it('reports what a normal collection landed', () => {
    expect(hostInventorySummary({
      asset_id: '11111111-1111-1111-1111-111111111111',
      facts: 14, endpoints: 18, packages: 412,
      installs_created: 412, installs_removed: 0,
    })).toBe('412 packages, 18 listeners, 14 facts');
  });

  it('names removals, because an upgrade is visible there and nowhere else', () => {
    // A version change is a different catalogue row, so moving openssl 3.0.13 →
    // 3.0.14 shows as one removal and one creation. Without the removals in the
    // line, an upgrade and a no-op run look identical.
    expect(hostInventorySummary({
      facts: 14, endpoints: 18, packages: 412,
      installs_created: 2, installs_removed: 2,
    })).toBe('412 packages, 18 listeners, 14 facts, 2 removed');
  });

  it('omits the package count when the package step failed, rather than saying zero', () => {
    expect(hostInventorySummary({
      facts: 12, endpoints: 18,
      installs_created: 0, installs_removed: 0,
    })).toBe('18 listeners, 12 facts');
  });

  it('leads with a contested identity, because it changes what the rest means', () => {
    // The numbers describe a PENDING asset the engine created beside a merge
    // proposal, not a settled host. Reading them without that is reading them
    // as a successful collection of a machine nobody has agreed exists.
    expect(hostInventorySummary({
      facts: 14, endpoints: 18, packages: 412,
      installs_created: 412, installs_removed: 0, contested: true,
    })).toBe('identity contested — merge proposal waiting, 412 packages, 18 listeners, 14 facts');
  });

  it('still says something for a run that landed nothing', () => {
    // The all-zero case is exactly the one a silent feature hides in.
    expect(hostInventorySummary({
      facts: 0, endpoints: 0, installs_created: 0, installs_removed: 0,
    })).toBe('collected nothing');
  });

  it('singularises', () => {
    expect(hostInventorySummary({
      facts: 1, endpoints: 1, packages: 1, installs_created: 1, installs_removed: 0,
    })).toBe('1 package, 1 listener, 1 fact');
  });
});
