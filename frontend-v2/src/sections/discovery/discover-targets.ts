// What the Discover wizard makes of POST /discovery/jobs's target verdicts
// ( W5.13b). Pure, so every state is unit-testable without a DOM.
//
// A person may scan public addresses, blocks and hostnames outside their
// registered networks — owner decision Q10: "we don't judge, we enable" — but
// only after confirming, and never a reserved range. The API says which, with a
// code the wizard branches on (never the message text):
//
//   422 external_targets_unconfirmed → ask: "N targets are outside…" / Scan anyway
//   403 external_targets_disabled    → the operator switched it off; explain
//   400 targets_refused              → list each target and why it can never be scanned
// 422 scan_target_too_large → the scanner cannot fully expand a target; show the
//                                      server's sentence, which names the target, its count and the limit
//   422 scan_budget_exceeded         → the plan's addresses × ports is over the installation's budget
//the server's sentence plus the biggest target
//   422 scan_plan_unavailable        → this deployment does not run depth-based scans (switched off,
//                                      or an older platform); a calm notice, not the person's mistake
//   409 sensor_scan_plan_unsupported → the chosen tenant sensor's software cannot run a scan by depth
// ( WP2b); the server's sentence, and the platform as the way out
import type { inventoryComponents } from '@vistasecurity/api-contract';

export type ExternalTarget = inventoryComponents['schemas']['DiscoveryExternalTarget'];
export type RefusedTarget = inventoryComponents['schemas']['DiscoveryRefusedTarget'];
export type OversizeTarget = inventoryComponents['schemas']['DiscoveryOversizeTarget'];
export type BudgetLargestTarget = inventoryComponents['schemas']['DiscoveryBudgetLargestTarget'];
// Loosely typed on purpose: a failed response may be any 4xx/5xx body, not
// only a DiscoveryTargetVerdictError.
type VerdictBody = {
  error?: unknown;
  details?: unknown;
  external_targets?: ExternalTarget[];
  pending_asset_ids?: unknown;
  refused_targets?: RefusedTarget[];
  oversize_targets?: OversizeTarget[];
  largest_target?: BudgetLargestTarget;
};

export type TargetVerdict =
  // `pending` is an Active Scan's answer to "what must the confirmation
  // resend": every asset of the request still to be done (see ActiveScanExternalTargetsError).
  // Absent for a discovery job, which is refused whole, and from an older server.
  | { kind: 'unconfirmed'; targets: ExternalTarget[]; message: string; pending?: string[] }
  | { kind: 'disabled'; targets: ExternalTarget[]; message: string }
  | { kind: 'refused'; refused: RefusedTarget[]; message: string }
  // `oversize` is empty when only the job's total is over the limit.
  | { kind: 'too_large'; oversize: OversizeTarget[]; message: string }
  // `largest` is absent when the server did not name one.
  | { kind: 'budget'; largest?: BudgetLargestTarget; message: string }
  | { kind: 'plan_unavailable'; message: string }
  | { kind: 'sensor_unsupported'; message: string }
  | { kind: 'error'; message: string };

/** Classify a failed create-job response. */
export function targetVerdict(status: number, body: unknown): TargetVerdict {
  const b = (body ?? {}) as VerdictBody;
  const details = typeof b.details === 'string' ? b.details : '';
  if (b.error === 'external_targets_unconfirmed' && Array.isArray(b.external_targets)) {
    const pending = Array.isArray(b.pending_asset_ids) ? b.pending_asset_ids.filter((id): id is string => typeof id === 'string') : undefined;
    return { kind: 'unconfirmed', targets: b.external_targets, message: details, ...(pending ? { pending } : {}) };
  }
  if (b.error === 'external_targets_disabled') {
    return { kind: 'disabled', targets: Array.isArray(b.external_targets) ? b.external_targets : [], message: details };
  }
  if (b.error === 'targets_refused' && Array.isArray(b.refused_targets)) {
    return { kind: 'refused', refused: b.refused_targets, message: details };
  }
  if (b.error === 'scan_target_too_large') {
    return {
      kind: 'too_large',
      oversize: Array.isArray(b.oversize_targets) ? b.oversize_targets : [],
      message: details || 'A scan target names more addresses than one scan can cover. Split it into smaller blocks.',
    };
  }
  if (b.error === 'scan_budget_exceeded') {
    return {
      kind: 'budget',
      largest: b.largest_target && typeof b.largest_target.target === 'string' ? b.largest_target : undefined,
      message: details || 'This scan is larger than one scan may be. Choose a lower depth or split the targets across scans.',
    };
  }
  // Not the person's input: the deployment cannot run a depth-based scan yet.
  // The server's own sentence names the old fields, which nobody in the
  // dialog can act on, so the dialog says it in its own words.
  if (b.error === 'scan_plan_unavailable') {
    return { kind: 'plan_unavailable', message: PLAN_UNAVAILABLE_EXPLANATION };
  }
  if (b.error === 'sensor_scan_plan_unsupported') {
    return {
      kind: 'sensor_unsupported',
      message: details || "This sensor's software does not support scan depth — upgrade it, or run the scan from the platform; nothing was scanned.",
    };
  }
  const fallback = typeof b.error === 'string' && b.error !== 'validation_error' ? b.error : '';
  return { kind: 'error', message: details || fallback || `Failed to start discovery (${status})` };
}

/** The confirmation's headline — the sentence the owner asked for. */
export function externalConfirmTitle(count: number): string {
  return `${count} target${count === 1 ? ' is' : 's are'} outside your registered networks. Only scan systems you are authorized to test.`;
}

/** One line per external target: what was entered, and where it points. */
export function describeExternal(t: ExternalTarget): string {
  const addrs = (t.addresses ?? []).filter((a) => a && a !== t.target);
  return addrs.length ? `${t.target} → ${addrs.join(', ')}` : t.target;
}

export const PLAN_UNAVAILABLE_EXPLANATION =
  'Scans by depth are not available on this installation right now, so nothing was started. ' +
  'You can still scan known assets from Inventory → All assets, and your platform operator can tell you more.';

export const DISABLED_EXPLANATION =
  'Your platform operator has turned off scanning targets outside your registered networks. ' +
  'Register the range under Settings → Infrastructure → Network Segments if it is yours, or ask your operator.';

/** An external target on the per-asset Active Scan: which asset it is. */
export type ExternalAssetTarget = ExternalTarget & { asset_id?: string; asset_name?: string };

/** One line per asset: its name, and the address(es) it would be scanned at. */
export function describeExternalAsset(t: ExternalAssetTarget): string {
  const where = (t.addresses ?? []).length ? t.addresses.join(', ') : t.target;
  return t.asset_name && t.asset_name !== where ? `${t.asset_name} (${where})` : where;
}

/** Carried by a mutation's rejection so the page can branch on it; `ids` are
 *  the assets to resend when the person confirms. */
export class TargetVerdictError extends Error {
  constructor(readonly verdict: TargetVerdict, readonly ids?: string[]) {
    super(verdict.message);
    this.name = 'TargetVerdictError';
  }
}
