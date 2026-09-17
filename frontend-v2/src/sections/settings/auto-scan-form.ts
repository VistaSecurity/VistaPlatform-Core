// The Active Scanning form's decisions, out of the component so they can be
// tested without rendering: what the operator typed in the ports box, whether
// the draft is savable, and whether it differs from what is stored.
//
// Validation here is the SERVER's rule, read out of the response's `limits`
// block rather than hard-coded — a page carrying its own copy of 1 and 720
// accepts numbers the server refuses the moment either changes.
import type { inventoryComponents } from '@vistasecurity/api-contract';

export type AutoScanPolicy = inventoryComponents['schemas']['AutoScanPolicy'];
export type AutoScanLimits = inventoryComponents['schemas']['AutoScanLimits'];
export type AutoScanSummary = inventoryComponents['schemas']['AutoScanSummary'];

/** The form's editable state. Ports stay TEXT until save, so a half-typed list isn't reformatted under the cursor. */
export interface AutoScanDraft {
  enabled: boolean;
  scanOnFirstObservation: boolean;
  intervalHours: string;
  protocols: string[];
  portsText: string;
  /** "Prefer the observing sensor". Absent from an older server's policy reads as ON, which is the server's default too. */
  preferObservingSensor: boolean;
}

export function draftFromPolicy(policy: AutoScanPolicy): AutoScanDraft {
  return {
    enabled: policy.enabled,
    scanOnFirstObservation: policy.scan_on_first_observation,
    intervalHours: String(policy.rescan_interval_hours),
    protocols: [...policy.protocols],
    portsText: formatPorts(policy.ports),
    preferObservingSensor: policy.prefer_observing_sensor ?? true,
  };
}

export function formatPorts(ports: number[]): string {
  return [...ports].sort((a, b) => a - b).join(', ');
}

/**
 * Reads the ports box. Commas, spaces and newlines all separate, because all
 * three are what people paste.
 *
 * An unparseable entry is an ERROR, never a silently dropped one: a port list
 * that quietly loses `84 43` (a typo for 8443) would leave the tenant believing
 * a port is scanned that is not.
 */
export function parsePorts(text: string): { ports: number[]; error?: string } {
  const tokens = text.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean);
  const ports: number[] = [];
  const seen = new Set<number>();
  for (const token of tokens) {
    if (!/^\d+$/.test(token)) return { ports: [], error: `“${token}” is not a port number.` };
    const n = Number(token);
    if (n < 1 || n > 65535) return { ports: [], error: `Port ${n} is outside 1–65535.` };
    if (seen.has(n)) continue;
    seen.add(n);
    ports.push(n);
  }
  return { ports: ports.sort((a, b) => a - b) };
}

/** The message to show, or null when the draft is savable. */
export function validateDraft(draft: AutoScanDraft, limits: AutoScanLimits): string | null {
  const hours = Number(draft.intervalHours);
  if (!/^\d+$/.test(draft.intervalHours.trim()) || !Number.isInteger(hours)) {
    return 'The rescan interval must be a whole number of hours.';
  }
  if (hours < limits.min_rescan_interval_hours || hours > limits.max_rescan_interval_hours) {
    return `The rescan interval must be between ${limits.min_rescan_interval_hours} and ${limits.max_rescan_interval_hours} hours.`;
  }
  if (draft.protocols.length === 0) return 'Choose at least one protocol.';
  const { ports, error } = parsePorts(draft.portsText);
  if (error) return error;
  if (ports.length === 0) return 'List at least one port.';
  if (ports.length > limits.max_ports) {
    return `At most ${limits.max_ports} ports can be scanned automatically; you listed ${ports.length}.`;
  }
  return null;
}

/** The draft as the PUT body. Call only when validateDraft returned null. */
export function draftToPayload(draft: AutoScanDraft): AutoScanPolicy {
  return {
    enabled: draft.enabled,
    scan_on_first_observation: draft.scanOnFirstObservation,
    rescan_interval_hours: Number(draft.intervalHours),
    protocols: [...draft.protocols].sort(),
    ports: parsePorts(draft.portsText).ports,
    prefer_observing_sensor: draft.preferObservingSensor,
  };
}

/**
 * Whether the draft differs from what is stored.
 *
 * Compared on VALUES, not on the typed text: re-typing `443,8443` as
 * `443, 8443` is not a change, and a Save button that lights up for whitespace
 * teaches people to ignore it.
 */
export function isDirty(draft: AutoScanDraft, saved: AutoScanPolicy): boolean {
  if (draft.enabled !== saved.enabled) return true;
  if (draft.scanOnFirstObservation !== saved.scan_on_first_observation) return true;
  if (draft.preferObservingSensor !== (saved.prefer_observing_sensor ?? true)) return true;
  if (Number(draft.intervalHours) !== saved.rescan_interval_hours) return true;
  if ([...draft.protocols].sort().join(',') !== [...saved.protocols].sort().join(',')) return true;
  return parsePorts(draft.portsText).ports.join(',') !== [...saved.ports].sort((a, b) => a - b).join(',');
}

/**
 * The one-line summary under the toggles — what the platform will actually do,
 * in the tenant's own numbers.
 *
 * It exists because "enabled" plus four other controls does not tell anyone
 * what happens. It is the sentence a tenant admin reads before deciding
 * whether to leave this on.
 */
export function describePolicy(draft: AutoScanDraft, assetsInScope: number): string {
  if (!draft.enabled) {
    return 'Automatic scanning is off. Nothing is scanned unless you start a scan yourself from Discovery.';
  }
  const hours = Number(draft.intervalHours);
  const cadence = !Number.isFinite(hours) || hours <= 0
    ? 'on a schedule'
    : hours === 24
      ? 'every 24 hours'
      : hours % 24 === 0
        ? `every ${hours / 24} days`
        : `every ${hours} hour${hours === 1 ? '' : 's'}`;
  const first = draft.scanOnFirstObservation
    ? 'New internal hosts are scanned as soon as they are first seen, and every'
    : 'Every';
  const scope = assetsInScope === 1 ? '1 asset is' : `${assetsInScope} assets are`;
  return `${first} internal host is scanned ${cadence}. ${scope} in scope today.`;
}
