import { describe, expect, it } from 'vitest';
import {
  type AutoScanDraft, type AutoScanLimits, type AutoScanPolicy,
  describePolicy, draftFromPolicy, draftToPayload, formatPorts, isDirty, parsePorts, validateDraft,
} from './auto-scan-form';

const limits: AutoScanLimits = {
  min_rescan_interval_hours: 1,
  max_rescan_interval_hours: 720,
  max_ports: 64,
  supported_protocols: ['SSH', 'TLS'],
  default_ports: [22, 443, 8443],
};

const policy: AutoScanPolicy = {
  enabled: true,
  scan_on_first_observation: true,
  rescan_interval_hours: 24,
  protocols: ['SSH', 'TLS'],
  ports: [22, 443, 8443],
};

const draft = (over: Partial<AutoScanDraft> = {}): AutoScanDraft => ({ ...draftFromPolicy(policy), ...over });

describe('parsePorts', () => {
  it('accepts commas, spaces and newlines, because all three get pasted', () => {
    expect(parsePorts('443, 8443').ports).toEqual([443, 8443]);
    expect(parsePorts('443 8443').ports).toEqual([443, 8443]);
    expect(parsePorts('443\n8443\n22').ports).toEqual([22, 443, 8443]);
    expect(parsePorts('  443 ,,  22  ').ports).toEqual([22, 443]);
  });

  it('dedupes and sorts', () => {
    expect(parsePorts('8443,443,443,22').ports).toEqual([22, 443, 8443]);
  });

  it('is empty for an empty box, with no error', () => {
    expect(parsePorts('')).toEqual({ ports: [] });
    expect(parsePorts('   ')).toEqual({ ports: [] });
  });

  // A list that quietly drops "84 43" (a typo for 8443) would leave the tenant
  // believing a port is scanned that is not.
  it('REFUSES an unparseable entry rather than dropping it', () => {
    expect(parsePorts('443, https').error).toBeTruthy();
    expect(parsePorts('443, https').ports).toEqual([]);
    expect(parsePorts('443-8443').error).toBeTruthy();
    expect(parsePorts('4.43').error).toBeTruthy();
  });

  it('refuses ports outside 1–65535', () => {
    expect(parsePorts('0').error).toBeTruthy();
    expect(parsePorts('65536').error).toBeTruthy();
    expect(parsePorts('65535').ports).toEqual([65535]);
    expect(parsePorts('1').ports).toEqual([1]);
  });
});

// "Prefer the observing sensor": both polarities survive the draft,
// an older server's policy that omits it reads as ON (the server's default),
// and flipping it alone makes the form dirty and reaches the PUT body.
describe('prefer_observing_sensor', () => {
  it('reads absent as ON', () => {
    expect(draftFromPolicy(policy).preferObservingSensor).toBe(true);
    expect(draftFromPolicy({ ...policy, prefer_observing_sensor: false }).preferObservingSensor).toBe(false);
    expect(draftFromPolicy({ ...policy, prefer_observing_sensor: true }).preferObservingSensor).toBe(true);
  });

  it('is part of the payload', () => {
    expect(draftToPayload(draft({ preferObservingSensor: false })).prefer_observing_sensor).toBe(false);
    expect(draftToPayload(draft()).prefer_observing_sensor).toBe(true);
  });

  it('flipping it alone is a change', () => {
    expect(isDirty(draft({ preferObservingSensor: false }), policy)).toBe(true);
    expect(isDirty(draft({ preferObservingSensor: true }), policy)).toBe(false);
    expect(isDirty(draft({ preferObservingSensor: false }), { ...policy, prefer_observing_sensor: false })).toBe(false);
  });

  it('does not affect validation', () => {
    expect(validateDraft(draft({ preferObservingSensor: false }), limits)).toBeNull();
  });
});

describe('validateDraft', () => {
  it('accepts the default policy', () => {
    expect(validateDraft(draft(), limits)).toBeNull();
  });

  // The bounds come from the SERVER's limits block. A page carrying its own
  // copy of 1 and 720 accepts numbers the server refuses the moment either
  // changes.
  it('enforces the server bounds, at both ends', () => {
    expect(validateDraft(draft({ intervalHours: '0' }), limits)).toMatch(/between 1 and 720/);
    expect(validateDraft(draft({ intervalHours: '721' }), limits)).toMatch(/between 1 and 720/);
    expect(validateDraft(draft({ intervalHours: '1' }), limits)).toBeNull();
    expect(validateDraft(draft({ intervalHours: '720' }), limits)).toBeNull();
  });

  it('reads the bounds from the limits it is given, not from constants', () => {
    const tighter = { ...limits, min_rescan_interval_hours: 6, max_rescan_interval_hours: 48 };
    expect(validateDraft(draft({ intervalHours: '1' }), tighter)).toMatch(/between 6 and 48/);
    expect(validateDraft(draft({ intervalHours: '24' }), tighter)).toBeNull();
  });

  it('rejects a non-integer interval', () => {
    for (const v of ['', ' ', 'daily', '12.5', '-3']) {
      expect(validateDraft(draft({ intervalHours: v }), limits)).toBeTruthy();
    }
  });

  it('requires at least one protocol and one port', () => {
    expect(validateDraft(draft({ protocols: [] }), limits)).toMatch(/at least one protocol/i);
    expect(validateDraft(draft({ portsText: '' }), limits)).toMatch(/at least one port/i);
  });

  it('surfaces the port parse error rather than a generic one', () => {
    expect(validateDraft(draft({ portsText: '443, https' }), limits)).toMatch(/https/);
  });

  it('enforces the port cap', () => {
    const many = Array.from({ length: limits.max_ports + 1 }, (_, i) => i + 1).join(',');
    expect(validateDraft(draft({ portsText: many }), limits)).toMatch(/At most 64 ports/);
  });
});

describe('isDirty', () => {
  it('is false for the stored policy', () => {
    expect(isDirty(draft(), policy)).toBe(false);
  });

  // Re-typing "443,8443" as "443, 8443" is not a change, and a Save button that
  // lights up for whitespace teaches people to ignore it.
  it('ignores formatting and ordering in the ports box', () => {
    expect(isDirty(draft({ portsText: ' 8443,443 ,22 ' }), policy)).toBe(false);
    expect(isDirty(draft({ portsText: '8443\n443\n22' }), policy)).toBe(false);
  });

  it('notices every real change', () => {
    expect(isDirty(draft({ enabled: false }), policy)).toBe(true);
    expect(isDirty(draft({ scanOnFirstObservation: false }), policy)).toBe(true);
    expect(isDirty(draft({ intervalHours: '48' }), policy)).toBe(true);
    expect(isDirty(draft({ protocols: ['TLS'] }), policy)).toBe(true);
    expect(isDirty(draft({ portsText: '443' }), policy)).toBe(true);
  });

  // Turning the feature OFF is the change most worth noticing: a dirty check
  // that treated `false` as "nothing entered" would disable the Save button on
  // the one edit a tenant most wants to make.
  it('notices being turned off', () => {
    expect(isDirty(draft({ enabled: false, scanOnFirstObservation: false }), policy)).toBe(true);
  });
});

describe('draftToPayload', () => {
  it('sends numbers, not the typed text', () => {
    const payload = draftToPayload(draft({ intervalHours: '72', portsText: '8443, 443' }));
    expect(payload.rescan_interval_hours).toBe(72);
    expect(payload.ports).toEqual([443, 8443]);
    expect(payload.protocols).toEqual(['SSH', 'TLS']);
  });

  it('carries an explicit false rather than omitting it', () => {
    const payload = draftToPayload(draft({ enabled: false, scanOnFirstObservation: false }));
    expect(payload.enabled).toBe(false);
    expect(payload.scan_on_first_observation).toBe(false);
  });
});

describe('describePolicy', () => {
  it('says plainly when nothing is scanned', () => {
    const text = describePolicy(draft({ enabled: false }), 57);
    expect(text).toMatch(/off/i);
    expect(text).not.toMatch(/57/);
  });

  it('names the cadence and the scope', () => {
    const text = describePolicy(draft(), 57);
    expect(text).toMatch(/every 24 hours/);
    expect(text).toMatch(/first seen/);
    expect(text).toMatch(/57 assets are in scope/);
  });

  it('reads a multiple of a day as days', () => {
    expect(describePolicy(draft({ intervalHours: '72' }), 2)).toMatch(/every 3 days/);
    expect(describePolicy(draft({ intervalHours: '6' }), 2)).toMatch(/every 6 hours/);
    expect(describePolicy(draft({ intervalHours: '1' }), 2)).toMatch(/every 1 hour\b/);
  });

  it('drops the first-observation clause when that half is off', () => {
    const text = describePolicy(draft({ scanOnFirstObservation: false }), 3);
    expect(text).not.toMatch(/first seen/);
    expect(text).toMatch(/every 24 hours/);
  });

  it('reads a single asset as singular', () => {
    expect(describePolicy(draft(), 1)).toMatch(/1 asset is in scope/);
  });
});

describe('formatPorts', () => {
  it('sorts numerically, not lexically', () => {
    expect(formatPorts([8443, 22, 443, 10443])).toBe('22, 443, 8443, 10443');
  });
});
