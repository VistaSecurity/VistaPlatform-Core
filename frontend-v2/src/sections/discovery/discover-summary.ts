// What the Discover wizard says happened, derived from the job's results.
//
// Kept pure and separate from the modal so the honesty of the wording is
// testable: "found" counts what the job SAW (discovery_findings) and the split
// counts what reached inventory (the ingestion queue). They legitimately differ
// — a third-party endpoint is recorded as a connection rather than an asset, a
// finding with no resolved IP cannot be anchored, and ingestion is asynchronous
// — so a shortfall is stated rather than quietly absorbed, and an unknown is
// never rendered as a zero.

import type { inventoryComponents } from '@vistasecurity/api-contract';

export type Materialization = NonNullable<
  inventoryComponents['schemas']['DiscoveryJobResults']['materialization']
>;

export interface SummaryPart {
  text: string;
  tone: 'neutral' | 'ok' | 'warn' | 'muted';
}

export interface DiscoverySummary {
  parts: SummaryPart[];
  note: string;
  /** True while the pipeline still has rows to disposition — the caller polls. */
  settling: boolean;
}

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;

/**
 * What a finding count is, in the job's own terms: "15 open ports on 10
 * hosts" — every finding is a port that answered on a host — so it is never
 * read as 15 new assets. Without the host count (an older server, or
 * unknown) it stays "15 findings".
 */
export function findingsLabel(count: number, hosts?: number | null): string {
  if (typeof hosts !== 'number') return plural(count, 'finding');
  return `${plural(count, 'open port')} on ${plural(hosts, 'host')}`;
}

export function describeMaterialization(count: number, m?: Materialization): DiscoverySummary {
  const parts: SummaryPart[] = [{ text: `Found ${findingsLabel(count, m?.finding_hosts)}`, tone: 'neutral' }];

  if (!m) {
    return {
      parts,
      note: 'Inventory status for this job is unavailable right now — check Inventory and Discovery → Approvals.',
      settling: false,
    };
  }

  const auto = m.auto_approved ?? 0;
  const pending = m.pending_approval ?? 0;
  const awaiting = m.awaiting_processing ?? 0;
  const queued = m.queued ?? 0;
  const suppressed = m.suppressed ?? 0;
  const observed = m.observed ?? 0;

  if (auto > 0) parts.push({ text: `${auto} auto-approved`, tone: 'ok' });
  if (pending > 0) parts.push({ text: `${pending} awaiting approval`, tone: 'warn' });
  if (awaiting > 0) parts.push({ text: `${awaiting} still processing`, tone: 'muted' });
  // Suppressed rows matched an asset the tenant already archived or denied —
  // nothing was added and nothing is awaiting a decision, so this is neither
  // "added to inventory" nor "awaiting approval". Stated explicitly rather
  // than silently absorbed into the shortfall note below, so a job that
  // mostly re-observed denied devices does not read as findings that simply
  // vanished.
  if (suppressed > 0) {
    parts.push({ text: `${plural(suppressed, 'finding')} on denied or archived assets — not shown in Approvals`, tone: 'muted' });
  }
  // Kept as evidence with no asset and no approval to come — see
  // observationsNotice for where they went. "0 added to inventory" still
  // follows when nothing else landed: that is exactly what happened.
  if (observed > 0) parts.push({ text: `${observed} kept as observations`, tone: 'muted' });
  if (auto === 0 && pending === 0 && awaiting === 0 && suppressed === 0) {
    parts.push({ text: '0 added to inventory', tone: 'muted' });
  }

  const rule =
    'Assets are auto-approved only on network segments with auto-approve enabled; the rest wait in Discovery → Approvals.';
  const shortfall = count - queued;
  const note =
    shortfall > 0
      ? `${plural(shortfall, 'finding')} did not become an inventory asset (external endpoints are recorded under Inventory → Connections). ${rule}`
      : rule;

  return { parts, note, settling: awaiting > 0 };
}

export interface ObservationsNotice {
  text: string;
  /** "Review it in" / "Review them in", before the link. */
  review: string;
  /** Where the person reviews them: Discovery → Observations. */
  href: string;
}

/**
 * Where findings that could not become assets went. A row the
 * pipeline kept as an observation was not added and is not awaiting approval,
 * so without this the job read "0 pending approval" with no explanation.
 *
 * `observed` also covers benign rows — a host observation, a third-party
 * endpoint recorded as a connection — so the wording claims only what is true
 * of all of them: kept as observations, not tied to an asset yet. DHCP is an
 * example, never the stated reason. Undefined when the count is unknown or
 * zero: an unknown is not a zero, and a zero needs no notice.
 */
export function observationsNotice(m?: Materialization): ObservationsNotice | undefined {
  const n = m?.observed;
  if (typeof n !== 'number' || n <= 0) return undefined;
  const hosts = m?.observed_hosts;
  const what = typeof hosts === 'number' && hosts > 0 ? `${plural(n, 'finding')} on ${plural(hosts, 'host')}` : plural(n, 'finding');
  return {
    text:
      `${what} ${n === 1 ? 'was' : 'were'} kept as observations — ${n === 1 ? 'it' : 'they'} could not be tied to an asset yet ` +
      '(for example, on a network that uses DHCP an address alone does not identify a device).',
    review: n === 1 ? 'Review it in' : 'Review them in',
    href: '/discovery/observations',
  };
}
