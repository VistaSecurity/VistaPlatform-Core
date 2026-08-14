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

export function describeMaterialization(count: number, m?: Materialization): DiscoverySummary {
  const parts: SummaryPart[] = [{ text: `Found ${plural(count, 'finding')}`, tone: 'neutral' }];

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

  if (auto > 0) parts.push({ text: `${auto} auto-approved`, tone: 'ok' });
  if (pending > 0) parts.push({ text: `${pending} awaiting approval`, tone: 'warn' });
  if (awaiting > 0) parts.push({ text: `${awaiting} still processing`, tone: 'muted' });
  if (auto === 0 && pending === 0 && awaiting === 0) {
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
