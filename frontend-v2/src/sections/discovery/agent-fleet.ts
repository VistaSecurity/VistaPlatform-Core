import { relTime } from './kit';

// Display logic for the Discovery agents table (Discovery → Sensors & Agents).
//
// Kept out of sensors-page.tsx so it can be unit-tested directly: frontend-v2's
// vitest runs in the node environment with no jsdom, so a pure module is
// testable where a component is not.
//
// A discovery agent is not a sensor and these are the fields that show it —
// what it may interrogate, which addresses its host actually holds, and what
// work it has done. None of them had anywhere to render while agents were
// squeezed into the sensor-shaped table.

/** The subset of an agent row this module needs. Structural, so it accepts the
 *  generated API type without importing it. */
export interface AgentFleetRow {
  ip_address?: string | null;
  addresses?: AgentFleetAddress[] | null;
  profile?: string | null;
  job_count: number;
  last_job_at?: string | null;
}

export interface AgentFleetAddress {
  address: string;
  is_primary: boolean;
  interface_name?: string;
  prefix_length?: number | null;
}

/**
 * An agent's profile is what it is ALLOWED to interrogate. Today the bootstrap
 * endpoint accepts exactly one, so render it in the operator's words rather than
 * leaking the enum — but pass anything unrecognized through verbatim, so a
 * profile added later shows up instead of silently blanking the column.
 */
export function profileLabel(profile?: string | null): string {
  if (!profile) return '—';
  if (profile === 'device_interrogation') return 'Network devices';
  return profile;
}

/**
 * "2h ago" + "47 jobs" — when the agent last did work, and how much it has ever
 * done. Either number alone is ambiguous: a count without a time cannot show an
 * agent has gone quiet, and a time without a count cannot distinguish
 * never-used from long-idle. `count` is empty for an agent that has run nothing,
 * so the row reads "Never run" rather than "Never run · 0 jobs".
 */
export function jobsSummary(a: AgentFleetRow): { last: string; count: string } {
  return {
    last: a.last_job_at ? relTime(a.last_job_at) : 'Never run',
    count: a.job_count > 0 ? `${a.job_count} job${a.job_count === 1 ? '' : 's'}` : '',
  };
}

/**
 * The host's primary address plus a count of the others it holds.
 *
 * A discovery agent is routinely multi-homed, and which segments it can reach is
 * the operator's real question; `ip_address` alone answers only "where does it
 * call home from". Prefers the agent's self-reported primary, then the address
 * flagged primary in its inventory, then any address at all — so a row is only
 * blank when the agent has genuinely reported nothing.
 */
/**
 * The full address inventory as one line, for the host cell's tooltip:
 * "Ethernet 192.0.2.173/24 · Ethernet 2 198.51.100.20/24".
 *
 * The cell itself can only show the primary and a count, but the whole point of
 * recording every address is that an operator can find out which segments the
 * agent actually sits on — so the detail has to be reachable somewhere, and the
 * prefix is what makes it a segment rather than a bare address.
 *
 * Empty string when there is nothing to show, so the caller can omit the
 * attribute entirely rather than render an empty tooltip.
 */
export function addressTooltip(a: AgentFleetRow): string {
  return (a.addresses ?? [])
    .map((x) => {
      const cidr = x.prefix_length != null ? `${x.address}/${x.prefix_length}` : x.address;
      return x.interface_name ? `${x.interface_name} ${cidr}` : cidr;
    })
    .join(' · ');
}

/**
 * Platform-managed rows are the tenant's per-workspace HANDLE to an in-cluster
 * service every tenant shares — not something they deployed, and not theirs to
 * remove. Deleting one does not stop the service: it severs this workspace's
 * attribution target, after which their interrogation and scheduled-scan results
 * stop reaching inventory with no error anywhere.
 *
 * The predicate mirrors the server guard exactly (sensor-manager's
 * models.Sensor.IsPlatformManaged): `platform === 'platform'` — the sentinel the
 * provisioning trigger and cluster-sensor auto-registration both stamp, and
 * already how the admin Fleet view and billing identify these rows — OR the
 * `system` tag, which is what the interrogation pipeline's own sensor lookup
 * selects on. Either marker alone is enough, so a row missing one is still
 * recognised. `profile` is deliberately not consulted: `discovery` and
 * `device_interrogation` are legitimate values for a customer-deployed sensor,
 * and blocking those would be the same bug pointed the other way.
 *
 * Hiding the button is a courtesy, not the control — the server refuses the
 * request with 403 regardless of what the client offers.
 */
export function isPlatformManaged(row: { platform?: string | null; tags?: string[] | null }): boolean {
  if (row.platform === 'platform') return true;
  return (row.tags ?? []).includes('system');
}

export function hostSummary(a: AgentFleetRow): { primary: string; extra: string } {
  const addrs = a.addresses ?? [];
  const primary = a.ip_address ?? addrs.find((x) => x.is_primary)?.address ?? addrs[0]?.address ?? null;
  const others = primary ? addrs.filter((x) => x.address !== primary).length : addrs.length;
  return {
    primary: primary ?? '—',
    extra: others > 0 ? `+${others} more address${others === 1 ? '' : 'es'}` : '',
  };
}
