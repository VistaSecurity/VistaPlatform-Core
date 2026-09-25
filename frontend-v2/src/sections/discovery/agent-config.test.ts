import { describe, it, expect } from 'vitest';
import {
  settingLabel,
  settingName,
  settingUnit,
  originNote,
  stateNote,
  overridesToSend,
  changedKeys,
  confirmationsNeeded,
  hasDeviceOverrides,
  versionNote,
  type Setting,
} from './agent-config';
import { saveResultFrom } from './agent-config-queries';

const setting = (over: Partial<Setting> & Pick<Setting, 'key' | 'value'>): Setting => ({
  origin: 'built_in',
  kind: typeof over.value === 'boolean' ? 'bool' : typeof over.value === 'number' ? 'int' : 'enum',
  apply: 'immediate',
  description: '',
  ...over,
});

describe('labels', () => {
  it('derives a label and strips the unit suffix', () => {
    expect(settingLabel('host_inventory_enabled')).toBe('Host inventory enabled');
    expect(settingLabel('poll_interval_seconds')).toBe('Poll interval');
    // The one thing derivation gets wrong that a reader notices. This setting
    // is the reason: the console said "Host observation dns", which is not how
    // anyone writes DNS and not a phrase a user could search the docs for.
    expect(settingLabel('host_observation_dns')).toBe('Host observation DNS');
    expect(settingLabel('dedup_ttl_minutes')).toBe('Dedup TTL');
    // An unknown word must still be title-cased, never mangled — adding a
    // setting can't produce something worse than today.
    expect(settingLabel('some_future_knob')).toBe('Some future knob');
    expect(settingUnit('poll_interval_seconds')).toBe('seconds');
    expect(settingUnit('dedup_ttl_minutes')).toBe('minutes');
    expect(settingUnit('host_observation')).toBeNull();
  });

  it('prefers the label the platform sends', () => {
    expect(settingName({ key: 'third_party_tls_enrichment', label: 'Actively enrich third-party TLS connections' }))
      .toBe('Actively enrich third-party TLS connections');
    // Absent or blank falls back to the derived name, never to nothing.
    expect(settingName({ key: 'third_party_tls_enrichment' })).toBe('Third party TLS enrichment');
    expect(settingName({ key: 'host_observation_dns', label: '  ' })).toBe('Host observation DNS');
  });

  it('names where a value came from', () => {
    expect(originNote('device')).toMatch(/this device/i);
    expect(originNote('fleet')).toMatch(/fleet/i);
    expect(originNote('built_in')).toMatch(/built-in/i);
  });
});

describe('stateNote', () => {
  it('never renders not_reporting as a kind of success or as pending', () => {
    const note = stateNote({ state: 'not_reporting', desired_revision: 'r' });
    expect(note.tone).toBe('danger');
    expect(note.label).not.toMatch(/applied|up to date|pending/i);
    // An operator has to learn the action is "upgrade", not "wait".
    expect(note.detail).toMatch(/upgrade/i);
  });

  it('distinguishes never-checked-in from checked-in-but-silent', () => {
    const never = stateNote({ state: 'never_reported', desired_revision: 'r' });
    const silent = stateNote({ state: 'not_reporting', desired_revision: 'r' });
    expect(never.label).not.toBe(silent.label);
    expect(never.detail).not.toBe(silent.detail);
  });

  it('treats an absent status as never reported rather than applied', () => {
    expect(stateNote(undefined).label).toBe('Never reported');
  });

  it('flags a failure as a failure', () => {
    expect(stateNote({ state: 'failed', desired_revision: 'r' }).tone).toBe('danger');
  });
});

describe('overridesToSend', () => {
  const settings = [
    setting({ key: 'host_inventory_enabled', value: false }),
    setting({ key: 'poll_interval_seconds', value: 30, origin: 'fleet' }),
    setting({ key: 'heartbeat_interval_seconds', value: 90, origin: 'device' }),
  ];

  it('sends only what the form actually changed, plus existing device overrides', () => {
    const out = overridesToSend(settings, { host_inventory_enabled: true }, 'device');
    expect(out).toEqual({ host_inventory_enabled: true, heartbeat_interval_seconds: 90 });
  });

  it('does NOT pin a device to a value it merely inherits', () => {
    // Re-selecting the same value the fleet default already gives must not
    // create an override — that would silently detach this device from future
    // fleet changes, which is invisible in a form and permanent in a database.
    const out = overridesToSend(settings, { poll_interval_seconds: 30 }, 'device');
    expect(out.poll_interval_seconds).toBeUndefined();
  });

  it('keeps an explicit false as a value rather than dropping it', () => {
    const withFleetOn = [setting({ key: 'host_inventory_enabled', value: true, origin: 'fleet' })];
    const out = overridesToSend(withFleetOn, { host_inventory_enabled: false }, 'device');
    expect(out).toEqual({ host_inventory_enabled: false });
  });

  it('clears an override when the form matches the inherited value and the override was the device', () => {
    const out = overridesToSend(settings, { heartbeat_interval_seconds: 90 }, 'device');
    // Still sent: the device owns this key, and dropping it here would clear
    // the override as a side effect of not touching the field.
    expect(out.heartbeat_interval_seconds).toBe(90);
  });
});

describe('overridesToSend at fleet scope', () => {
  // A write replaces the whole set at the layer it targets, so an untouched
  // fleet default must be sent back. Written device-first this kept only
  // `origin === 'device'` values — never true in the fleet form — so changing
  // one fleet setting reset every other one to built-in AND moved every agent
  // inheriting them. Data loss from a save the operator thought was narrow.
  const fleetSettings = [
    setting({ key: 'host_inventory_enabled', value: true, origin: 'fleet' }),
    setting({ key: 'host_inventory_interval_seconds', value: 21600, origin: 'fleet' }),
    setting({ key: 'poll_interval_seconds', value: 30, origin: 'built_in' }),
  ];

  it('sends back untouched fleet defaults alongside the change', () => {
    const out = overridesToSend(fleetSettings, { host_inventory_enabled: false }, 'fleet');
    expect(out).toEqual({
      host_inventory_enabled: false,
      host_inventory_interval_seconds: 21600,
    });
  });

  it('does not promote a built-in default into a fleet default', () => {
    // Sending it would pin the tenant to today's built-in and detach the fleet
    // from a future change to the binary's default.
    const out = overridesToSend(fleetSettings, { host_inventory_enabled: false }, 'fleet');
    expect(out.poll_interval_seconds).toBeUndefined();
  });

  it('does promote a built-in default the operator actually changed', () => {
    const out = overridesToSend(fleetSettings, { poll_interval_seconds: 45 }, 'fleet');
    expect(out.poll_interval_seconds).toBe(45);
  });

  it('keeps device-scope behaviour unchanged', () => {
    const deviceSettings = [setting({ key: 'a', value: 1, origin: 'device' })];
    expect(overridesToSend(deviceSettings, {}, 'device')).toEqual({ a: 1 });
    // And a fleet-origin value is NOT sent at device scope: it is inherited,
    // and echoing it back would pin this device to today's fleet default.
    const inherited = [setting({ key: 'b', value: 2, origin: 'fleet' })];
    expect(overridesToSend(inherited, {}, 'device')).toEqual({});
  });
});

describe('changedKeys', () => {
  it('lists only genuinely changed settings', () => {
    const settings = [setting({ key: 'a', value: 1 }), setting({ key: 'b', value: 2 })];
    expect(changedKeys(settings, { a: 1, b: 5 })).toEqual(['b']);
  });
});

describe('confirmationsNeeded', () => {
  const dns = setting({
    key: 'host_observation_dns',
    value: false,
    confirm: 'Turning this on records which names this network resolved.',
  });

  it('asks when the setting is being turned on', () => {
    expect(confirmationsNeeded([dns], { host_observation_dns: true })).toHaveLength(1);
  });

  it('does not ask when it is being turned off', () => {
    expect(confirmationsNeeded([dns], { host_observation_dns: false })).toHaveLength(0);
  });

  it('does not re-ask for a setting that is already on', () => {
    const already = { ...dns, value: true };
    expect(confirmationsNeeded([already], { host_observation_dns: true })).toHaveLength(0);
  });

  it('ignores settings that carry no confirmation', () => {
    const plain = setting({ key: 'host_inventory_enabled', value: false });
    expect(confirmationsNeeded([plain], { host_inventory_enabled: true })).toHaveLength(0);
  });
});

describe('hasDeviceOverrides', () => {
  it('is true only when something is set on the device itself', () => {
    expect(hasDeviceOverrides([setting({ key: 'a', value: 1, origin: 'fleet' })])).toBe(false);
    expect(hasDeviceOverrides([setting({ key: 'a', value: 1, origin: 'device' })])).toBe(true);
  });
});

describe('versionNote', () => {
  it('says nothing when there is nothing to say', () => {
    expect(versionNote(undefined)).toBeNull();
  });

  it('never renders unknown as a kind of up-to-date', () => {
    const note = versionNote({ device: '', expected: '1.0.0', state: 'unknown' })!;
    expect(note.tone).toBe('muted');
    expect(note.label).not.toMatch(/up to date|current/i);
  });

  it('distinguishes "the device said nothing" from "the platform knows nothing"', () => {
    const noDevice = versionNote({ device: '', expected: '1.0.0', state: 'unknown' })!;
    const noPlatform = versionNote({ device: '1.0.0', expected: '', state: 'unknown' })!;
    expect(noDevice.detail).not.toBe(noPlatform.detail);
    expect(noDevice.detail).toMatch(/has not reported/i);
    expect(noPlatform.detail).toMatch(/does not know/i);
  });

  it('says plainly that upgrading is manual', () => {
    // The platform deliberately does not replace binaries; a badge saying
    // "update available" must not imply a button that does it.
    const note = versionNote({ device: '1.0.0', expected: '1.2.0', state: 'behind' })!;
    expect(note.detail).toMatch(/manual|does not replace/i);
  });

  it('treats ahead as noteworthy rather than broken', () => {
    const note = versionNote({ device: '1.2.0', expected: '1.0.0', state: 'ahead' })!;
    expect(note.tone).toBe('warn');
    expect(note.detail).toMatch(/mid-upgrade|newer/i);
  });
});

describe('saveResultFrom', () => {
  it('turns JSON-null slices into empty arrays', () => {
    // The write handler used to emit `"adjusted": null` when nothing was
    // raised. The panel maps that field after every successful save.
    const got = saveResultFrom({
      changed: ['host_observation_dns: false → true'],
      adjusted: null,
      needs_restart: null,
    });
    expect(got.adjusted).toEqual([]);
    expect(got.needs_restart).toEqual([]);
    expect(got.changed).toEqual(['host_observation_dns: false → true']);
  });
});
