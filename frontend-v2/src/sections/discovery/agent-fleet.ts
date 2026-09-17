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
  last_host_inventory_at?: string | null;
  host_inventory_packages?: number | null;
  host_inventory_listeners?: number | null;
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

/** The subset of a `sensors` row this module's partition needs. */
export interface SensorFleetRow {
  platform?: string | null;
  tags?: string[] | null;
  profile?: string | null;
}

/**
 * Is this `sensors` row actually the in-cluster DEVICE INTERROGATION agent?
 *
 * It is a row in `sensors` for a plumbing reason, not because it is a sensor.
 * `create_system_sensors_for_tenant` gives every tenant two platform rows, and
 * device-interrogation-service's result processor resolves the
 * `device_interrogation` one (ResultProcessor.lookupSystemSensor) to use as the
 * `sensor_discoveries.sensor_id` every interrogated and cloud-discovered asset
 * is attributed to. The row is load-bearing and must not be removed — but it
 * describes a command-driven interrogation agent, not a passive libpcap
 * capture, so the Sensors table is the wrong place to show it: it renders "—"
 * for Segment and carries `sensor_type = 'api'` under a column headed Type.
 *
 * BOTH markers are required, and that is the whole point of the predicate:
 *
 *   - platform-managed, so a customer-deployed sensor that happens to carry the
 *     `device_interrogation` profile stays in the sensor table where its owner
 *     put it (the same care `isPlatformManaged` takes not to key on profile).
 *   - profile `device_interrogation`, so the platform DISCOVERY sensor — which
 *     genuinely is a sensor — is not swept along with it.
 */
export function isPlatformInterrogationAgent(row: SensorFleetRow): boolean {
  return isPlatformManaged(row) && (row.profile ?? '').toLowerCase() === 'device_interrogation';
}

/**
 * Split the `sensors` fleet into the rows the Sensors table owns and the rows
 * the Discovery agents table owns.
 *
 * Returned as a partition rather than two filters so the two lists cannot drift
 * apart: every row lands in exactly one of them, and a row can never be
 * dropped from the page by falling through both predicates.
 */
export function partitionSensorFleet<T extends SensorFleetRow>(rows: T[]): {
  sensors: T[];
  interrogationAgents: T[];
} {
  const sensors: T[] = [];
  const interrogationAgents: T[] = [];
  for (const r of rows) {
    (isPlatformInterrogationAgent(r) ? interrogationAgents : sensors).push(r);
  }
  return { sensors, interrogationAgents };
}

/**
 * "Last host inventory: 2h ago — 412 packages, 18 listeners".
 *
 * A host-inventory collection is the agent describing the machine it is
 * INSTALLED ON, on its own timer — not work anybody queued — so the jobs column
 * cannot express it: an agent busy interrogating firewalls that has never
 * reported its own host reads as healthy on "47 jobs · 2h ago". Turning local
 * collection on is a single env var (HOST_INVENTORY_ENABLED), and leaving it off
 * is the kind of silence this product keeps having to learn to make visible.
 *
 * `null` when the agent has never reported one, so the caller omits the line
 * rather than rendering "Last host inventory: never" on every agent that was
 * never meant to run one.
 *
 * The two counts are independently optional and for the usual reason. A
 * collection whose package step FAILED carries no package count at all — a host
 * whose dpkg could not be read and a host with no packages are different
 * answers — so "18 listeners" alone is the honest line, and "0 packages, 18
 * listeners" would not be.
 */
export function hostInventorySummary(a: AgentFleetRow): string | null {
  if (!a.last_host_inventory_at) return null;
  const parts = [
    a.host_inventory_packages != null
      ? `${a.host_inventory_packages} package${a.host_inventory_packages === 1 ? '' : 's'}`
      : null,
    a.host_inventory_listeners != null
      ? `${a.host_inventory_listeners} listener${a.host_inventory_listeners === 1 ? '' : 's'}`
      : null,
  ].filter(Boolean);
  const when = `Last host inventory: ${relTime(a.last_host_inventory_at)}`;
  return parts.length ? `${when} — ${parts.join(', ')}` : when;
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
