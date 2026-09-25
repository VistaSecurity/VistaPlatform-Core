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
import type { inventoryComponents } from '@vistasecurity/api-contract';

export type ExternalTarget = inventoryComponents['schemas']['DiscoveryExternalTarget'];
export type RefusedTarget = inventoryComponents['schemas']['DiscoveryRefusedTarget'];
// Loosely typed on purpose: a failed response may be any 4xx/5xx body, not
// only a DiscoveryTargetVerdictError.
type VerdictBody = { error?: unknown; details?: unknown; external_targets?: ExternalTarget[]; refused_targets?: RefusedTarget[] };

export type TargetVerdict =
  | { kind: 'unconfirmed'; targets: ExternalTarget[]; message: string }
  | { kind: 'disabled'; targets: ExternalTarget[]; message: string }
  | { kind: 'refused'; refused: RefusedTarget[]; message: string }
  | { kind: 'error'; message: string };

/** Classify a failed create-job response. */
export function targetVerdict(status: number, body: unknown): TargetVerdict {
  const b = (body ?? {}) as VerdictBody;
  const details = typeof b.details === 'string' ? b.details : '';
  if (b.error === 'external_targets_unconfirmed' && Array.isArray(b.external_targets)) {
    return { kind: 'unconfirmed', targets: b.external_targets, message: details };
  }
  if (b.error === 'external_targets_disabled') {
    return { kind: 'disabled', targets: Array.isArray(b.external_targets) ? b.external_targets : [], message: details };
  }
  if (b.error === 'targets_refused' && Array.isArray(b.refused_targets)) {
    return { kind: 'refused', refused: b.refused_targets, message: details };
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
