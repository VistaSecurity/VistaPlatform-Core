// Presentation logic for control-plane-managed sensor and agent settings
//. Pure, so the meanings below are testable without a browser.
//
// The settings themselves are NOT listed here. The API returns each one with
// its kind, bounds, allowed values, description and whether it needs
// confirming, precisely so the console does not keep a second copy of the
// registry that can drift from the platform's.

export type SettingKind = 'bool' | 'int' | 'enum';
export type SettingOrigin = 'built_in' | 'fleet' | 'device';
export type ConfigState =
  | 'never_reported'
  | 'not_reporting'
  | 'pending'
  | 'awaiting_restart'
  | 'applied'
  | 'failed';

export type SettingValue = boolean | number | string;

export interface Setting {
  key: string;
  value: SettingValue;
  origin: SettingOrigin;
  kind: SettingKind;
  apply: 'immediate' | 'restart';
  /** The platform's own name for a setting whose key reads badly as words.
   *  Absent for most; the name is then derived from the key. */
  label?: string;
  description: string;
  confirm?: string;
  min?: number;
  max?: number;
  allowed?: string[];
}

export interface ConfigStatus {
  state: ConfigState;
  desired_revision: string;
  reported_at?: string;
  failures?: Record<string, string>;
  pending_restart?: string[];
}

/** A human label for a setting key, derived rather than tabulated: a table
 *  here is a second registry, and it would silently show a raw key the day the
 *  platform adds one. Seconds-suffixed keys lose the suffix because the unit is
 *  shown next to the field.
 *
 *  Acronyms are the one thing derivation gets wrong that a reader notices:
 *  `host_observation_dns` rendered as "Host observation dns", which is not how
 *  anyone writes DNS and not a phrase a user could search the docs for. The set
 *  is deliberately small and covers the words in this product's vocabulary; an
 *  unknown word is still title-cased rather than mangled, so adding a setting
 *  never produces something worse than today. */
const ACRONYMS = new Set(['dns', 'ttl', 'ip', 'os', 'url', 'tls', 'ssh']);

export function settingLabel(key: string): string {
  const words = key
    .replace(/_seconds$/, '')
    .replace(/_minutes$/, '')
    .split('_')
    .map((w) => (ACRONYMS.has(w) ? w.toUpperCase() : w));
  const label = words.join(' ');
  return label.charAt(0).toUpperCase() + label.slice(1);
}

/** The name to show for a setting: the platform's label when it sends one,
 *  otherwise the key turned into words. */
export function settingName(s: Pick<Setting, 'key' | 'label'>): string {
  return s.label?.trim() ? s.label : settingLabel(s.key);
}

/** The unit an int setting is measured in, taken from its key so the input can
 *  show minutes where the platform stores minutes. */
export function settingUnit(key: string): 'seconds' | 'minutes' | null {
  if (key.endsWith('_seconds')) return 'seconds';
  if (key.endsWith('_minutes')) return 'minutes';
  return null;
}

/** Where the effective value came from, in words an operator can act on. */
export function originNote(origin: SettingOrigin): string {
  switch (origin) {
    case 'device':
      return 'Set on this device';
    case 'fleet':
      return 'From fleet defaults';
    case 'built_in':
      return 'Built-in default';
  }
}

export interface StateNote {
  label: string;
  tone: 'ok' | 'warn' | 'danger' | 'muted';
  detail: string;
}

/** How a convergence state reads to an operator.
 *
 *  The six states exist because they need six different actions, and this is
 *  where that has to survive contact with the UI. In particular `not_reporting`
 *  must never be rendered as a variant of "up to date" or as "pending": that
 *  device is running a build too old to be managed, and waiting will not fix
 *  it. */
export function stateNote(status: ConfigStatus | undefined): StateNote {
  switch (status?.state) {
    case 'applied':
      return { label: 'Applied', tone: 'ok', detail: 'This device is running these settings.' };
    case 'pending':
      return { label: 'Pending', tone: 'warn', detail: 'Saved. The device picks these up on its next check-in.' };
    case 'awaiting_restart':
      return {
        label: 'Awaiting restart',
        tone: 'warn',
        detail: 'The device accepted the change but adopts it when it restarts.',
      };
    case 'failed':
      return { label: 'Failed', tone: 'danger', detail: 'The device could not apply one or more settings.' };
    case 'not_reporting':
      return {
        label: 'Not reporting',
        tone: 'danger',
        detail: 'This device checked in but does not report its configuration — it is running a build older than remote management. Upgrade it.',
      };
    case 'never_reported':
    default:
      return {
        label: 'Never reported',
        tone: 'muted',
        detail: 'This device has not checked in yet, so nothing is known about what it is running.',
      };
  }
}

/** Whether a setting should be shown as the source of a failure. */
export function failureFor(status: ConfigStatus | undefined, key: string): string | undefined {
  return status?.failures?.[key];
}

/** Whether the device has accepted a setting but not yet adopted it. */
export function awaitingRestart(status: ConfigStatus | undefined, key: string): boolean {
  return (status?.pending_restart ?? []).includes(key);
}

/** The values to SEND, given what the form holds, what each setting's effective
 *  value and origin were when it loaded, and WHICH LAYER is being written.
 *
 *  A write replaces the whole set at the layer it targets — a partial write
 *  cannot express "remove this one" — so anything already set at that layer and
 *  not touched by the form has to be sent back, or saving one setting silently
 *  clears the rest.
 *
 *  The scope is a parameter because the answer differs by layer, and getting it
 *  from the origin alone is what made this wrong: written device-first, it kept
 *  only `origin === 'device'` values, which in the fleet-defaults form is never
 *  true — every tenant-set default came back as `origin: 'fleet'`, was dropped
 *  from the body, and changing one setting reset all the others to built-in AND
 *  moved every agent inheriting them.
 *
 *  A value equal to what the layer already INHERITS is still not sent: that
 *  would pin the layer to today's inherited value and silently detach it from
 *  future changes — the difference between "this device wants 30 minutes" and
 *  "this device is happy with whatever the fleet says", invisible in a form and
 *  permanent in a database. */
export function overridesToSend(
  settings: Setting[],
  edited: Record<string, SettingValue>,
  // REQUIRED, deliberately. It defaulted to 'device' for one commit, and
  // deleting `, scope` from the single call site then left every test passing
  // — a one-token deletion that silently restored tenant-wide data loss, legal
  // because the default made it legal. A required parameter makes that deletion
  // a compile error, which is the only guard no test can be inert about.
  scope: 'device' | 'fleet',
): Record<string, SettingValue> {
  // The origin a value has when THIS layer is the one that set it.
  const ownOrigin: SettingOrigin = scope === 'fleet' ? 'fleet' : 'device';
  const out: Record<string, SettingValue> = {};
  for (const s of settings) {
    const next = edited[s.key];
    if (next === undefined) {
      // Untouched: keep what this layer already holds, so a save of one
      // setting does not erase the others.
      if (s.origin === ownOrigin) out[s.key] = s.value;
      continue;
    }
    if (next === s.value && s.origin !== ownOrigin) continue;
    out[s.key] = next;
  }
  return out;
}

/** Settings whose value the form has actually changed. */
export function changedKeys(settings: Setting[], edited: Record<string, SettingValue>): string[] {
  return settings.filter((s) => edited[s.key] !== undefined && edited[s.key] !== s.value).map((s) => s.key);
}

/** The confirmations a save needs: a setting that carries one AND is being
 *  turned on. Turning it off needs no acknowledgement — the acknowledgement is
 *  about what starts being collected. */
export function confirmationsNeeded(settings: Setting[], edited: Record<string, SettingValue>): Setting[] {
  return settings.filter((s) => Boolean(s.confirm) && s.value !== true && edited[s.key] === true);
}

/** Whether clearing this device's overrides would change anything. */
export function hasDeviceOverrides(settings: Setting[]): boolean {
  return settings.some((s) => s.origin === 'device');
}

export type VersionState = 'unknown' | 'current' | 'behind' | 'ahead';

export interface VersionInfo {
  device: string;
  expected: string;
  state: VersionState;
}

export interface VersionNote {
  label: string;
  tone: 'ok' | 'warn' | 'muted';
  detail: string;
}

/** How a device's version reads to an operator.
 *
 *  `unknown` must never be rendered as a variant of "up to date". A comparison
 *  that could not be made is not a comparison, and an operator who reads
 *  "current" against an unknown baseline believes a fleet is patched when
 *  nobody has checked. */
export function versionNote(v: VersionInfo | undefined): VersionNote | null {
  if (!v) return null;
  switch (v.state) {
    case 'current':
      return {
        label: 'Up to date',
        tone: 'ok',
        detail: `Running ${v.device}, which is the version that ships with this release.`,
      };
    case 'behind':
      return {
        label: 'Update available',
        tone: 'warn',
        detail: `Running ${v.device}; this release ships ${v.expected}. Upgrading is a manual step — the platform does not replace binaries.`,
      };
    case 'ahead':
      return {
        label: 'Newer than the platform',
        tone: 'warn',
        detail: `Running ${v.device}, which is newer than this platform release (${v.expected}). Expected mid-upgrade; otherwise check which binary was installed.`,
      };
    case 'unknown':
    default:
      return {
        label: 'Version unknown',
        tone: 'muted',
        detail: v.device
          ? `Running ${v.device}. This platform does not know which version it ships, so there is nothing to compare against.`
          : 'This device has not reported a version, so there is nothing to compare against.',
      };
  }
}
