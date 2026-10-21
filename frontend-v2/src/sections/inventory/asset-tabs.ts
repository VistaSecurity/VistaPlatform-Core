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
  // An asset's interfaces, physical and virtual (DCIM BUILD_PLAN row 1.2,
  // asset-inventory ADR-0010 D3). Declared here today; discovery fills it once
  // intake (row 1.5) maps the agent, SNMP and UniFi interface data onto it.
  { key: 'interfaces', label: 'Interfaces', icon: 'network' },
  // Every address the asset holds in one table, with its primary and
  // out-of-band flags (DCIM gap 2): through its interfaces, or named in its
  // primary IPv4 / IPv6 / OOB columns. Reads ipam.read; the row actions ipam.manage.
  { key: 'ip-addresses', label: 'IP Addresses', icon: 'route' },
  // The asset's other port components (DCIM BUILD_PLAN row 3.1, ADR-0010 D3):
  // console ports, console server ports, front and rear ports, device bays.
  { key: 'ports', label: 'Ports', icon: 'cable' },
  // What the asset is physically made of (DCIM BUILD_PLAN row 2.4,
  // asset-inventory ADR-0010 D4): its device type, module bays and modules,
  // inventory items, virtual chassis and device bays.
  { key: 'hardware', label: 'Hardware', icon: 'cpu' },
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
  // The DCIM change record and journal (asset-inventory ADR-0010 D5, DCIM
  // BUILD_PLAN row 0.3). Live but young: the asset writers move onto
  // object_changes in phase 1, so until then it lists what the substrate
  // itself records (tags, journal) and says so when empty. History stays the
  // asset_history reader until those writers move.
  { key: 'changes', label: 'Changes', icon: 'git-compare' },
  // The weight-merged JSON of every config context that matches this asset
  // (DCIM BUILD_PLAN row 5.3, DATA_MODEL §8).
  { key: 'config-context', label: 'Config Context', icon: 'braces' },
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
