// The asset page's tab registry (ADR-0006 D3).
//
// "A configuration item with children, edges, software, findings and history
// does not fit a drawer." The drawer keeps its job — the peek from a list — and
// the page is where the whole thing lives, at a URL that can be shared.
//
// The registry is a plain list so the routing rules are testable without
// mounting React: which tab a URL selects, what an unknown tab falls back to,
// and which tabs are placeholders for a later phase.

export interface AssetTab {
  key: string;
  label: string;
  /** kebab-case lucide icon name. */
  icon: string;
  /**
   * Tabs that arrive later. They are SHOWN — the shape of the asset record is
   * part of what the page communicates, and a tab that appears in a later
   * release without warning is a worse surprise than one that says when it is
   * coming — but their body says which phase brings them and why, rather than
   * rendering an empty table that reads as "this asset has none".
   */
  placeholder?: { phase: string; message: string };
}

export const ASSET_TABS: AssetTab[] = [
  { key: 'overview', label: 'Overview', icon: 'circle-user' },
  { key: 'endpoints', label: 'Services & Endpoints', icon: 'ethernet-port' },
  // Live since workstream 2.8. The inline neighbourhood MAP is still to come
  // (2.9); the tab shows the edges, their provenance and the impact closure,
  // which is the substance — a tab that lists what an asset is attached to is
  // not a placeholder just because it does not yet draw it.
  { key: 'relationships', label: 'Relationships', icon: 'waypoints' },
  { key: 'cryptography', label: 'Cryptography', icon: 'key-round' },
  { key: 'findings', label: 'Findings', icon: 'triangle-alert' },
  // LIVE since workstream 2.6b. It was a phase-3 placeholder waiting on the
  // host agent; SBOM ingestion is a second source for the same rows and arrived
  // first, so the tab reads real `software_installs` now. End-of-life state is
  // still to come (workstream 3.4's vulnerability + EOL catalogue).
  { key: 'software', label: 'Software', icon: 'package' },
  { key: 'history', label: 'History', icon: 'history' },
];

export const DEFAULT_ASSET_TAB = 'overview';

/** Resolves a URL segment to a tab. An unknown or absent segment lands on
 *  Overview rather than on a blank page — a stale deep link should still show
 *  the asset. */
export function findAssetTab(key: string | undefined | null): AssetTab {
  return ASSET_TABS.find((t) => t.key === key) ?? ASSET_TABS[0];
}

/** The canonical path for one tab of one asset. Overview is the bare path, so
 *  the URL a user copies off the first tab is the short one. */
export function assetTabPath(id: string, tab: string): string {
  return tab === DEFAULT_ASSET_TAB ? `/inventory/assets/${id}` : `/inventory/assets/${id}/${tab}`;
}

/** Whether a tab is live in this phase. */
export function isTabLive(tab: AssetTab): boolean {
  return !tab.placeholder;
}
