// What a person-initiated scan of an asset looks like on screen — Discovery →
// Active Scan's rows and the asset drawer's Active Scan button read the same
// `active_scan` record the API projects (AssetActiveScan).
//
// The record says `scanning` from dispatch until every job the request created
// has ended and the platform has settled it (within about a minute of the last
// job ending). While it does, the row must not invite another click: before
// this existed, a scanned row sat there unchanged and one host was scanned
// twelve times in a row from the page.
import type { inventoryComponents } from '@vistasecurity/api-contract';

export type AssetActiveScan = inventoryComponents['schemas']['AssetActiveScan'];

export type ActiveScanView =
  | { kind: 'none' }
  | { kind: 'scanning'; since?: string }
  | { kind: 'completed'; at?: string }
  | { kind: 'failed'; at?: string };

/** The asset's scan state, from its `active_scan` record. */
export function activeScanView(asset: { active_scan?: AssetActiveScan | null } | null | undefined): ActiveScanView {
  const rec = asset?.active_scan;
  switch (rec?.status) {
    case 'scanning':
      return { kind: 'scanning', since: rec.started_at };
    case 'completed':
      return { kind: 'completed', at: rec.finished_at };
    case 'failed':
      return { kind: 'failed', at: rec.finished_at };
    default:
      return { kind: 'none' };
  }
}

/** True while the asset's scan is in flight: its Scan button is disabled. */
export function isScanning(asset: { active_scan?: AssetActiveScan | null } | null | undefined): boolean {
  return activeScanView(asset).kind === 'scanning';
}

/** True when any row is mid-scan — the list keeps polling until none is. */
export function anyScanning(assets: ReadonlyArray<{ active_scan?: AssetActiveScan | null }>): boolean {
  return assets.some(isScanning);
}

/** How often an asset list is re-read while a row is mid-scan. */
export const SCANNING_POLL_MS = 10_000;
