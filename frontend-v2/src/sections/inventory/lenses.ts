// Inventory lens catalogue — shared by the sidebar (renders the lens sub-nav)
// and the Inventory page (renders the data per lens). The active lens lives in
// the URL (`/inventory?lens=<key>`) so both stay in sync.
//
// ADR-0006 D1 restructured this: the lens MECHANISM is kept and extended, not
// replaced. What changed is that the class-faceted "All assets" lens (D2) takes
// over as the default from `infrastructure`, and the list is grouped in the nav
// registry (Assets / Cryptography / Lifecycle) rather than split into "primary"
// and "by protocol". `group` is what the sidebar reads.
export interface InventoryLens {
  key: string;
  label: string;
  icon: string; // kebab-case lucide name
  // What kind of record the lens is anchored on. `data` is the at-rest
  // protection anchor (crypto applications: buckets, databases) — it is none of
  // asset/config/cert/key, and the page switches on it to pick its dataset, so
  // it gets its own member rather than being folded into the closest neighbour.
  anchor: 'asset' | 'config' | 'cert' | 'key' | 'data';
  live: boolean;
  primary: boolean;
  /** Which nav group the lens sits in (ADR-0006 D1). */
  group: 'assets' | 'cryptography' | 'lifecycle';
  protocol?: string; // config lenses: filter to this protocol
  /** A lens whose page is a phase-2/3 placeholder. It is shown in the nav —
   *  the shape of the product is part of what the nav communicates — but its
   *  body says when it arrives instead of pretending to be empty data. */
  placeholder?: { phase: string; message: string };
}

export const INVENTORY_LENSES: InventoryLens[] = [
  // --- Assets ---
  { key: 'assets', label: 'All assets', icon: 'database', anchor: 'asset', live: true, primary: true, group: 'assets' },
  // LIVE since workstream 2.9. The neighbourhood half of ADR-0006 D4: a graph
  // around one focus asset, up to three hops, with the impact overlay and the
  // GraphML/Cytoscape export. The tenant-wide TOPOLOGY half (site → segment →
  // class, a tree with counts and no graph library) is still to come, and is
  // deliberately not faked here — a hierarchy drawn as a force graph is the
  // unreadable thing D4 rejected.
  { key: 'map', label: 'Map', icon: 'waypoints', anchor: 'asset', live: true, primary: true, group: 'assets' },
  // LIVE since workstream 2.6b. The lens anchors on the PRODUCT, not on the
  // asset: the question it answers is "who runs log4j 2.14?", and a list of
  // assets with a software column answers that only by being read sideways.
  // `anchor: 'asset'` is kept because the lens still drills THROUGH to assets —
  // the page switches on it to pick a dataset, and 'product' would be a fifth
  // anchor with one member.
  { key: 'software', label: 'Software', icon: 'package', anchor: 'asset', live: true, primary: true, group: 'assets' },
  // --- Cryptography ---
  { key: 'certificate', label: 'Certificates', icon: 'file-badge', anchor: 'cert', live: true, primary: true, group: 'cryptography' },
  { key: 'keys', label: 'Keys', icon: 'key-round', anchor: 'key', live: true, primary: true, group: 'cryptography' },
  { key: 'configuration', label: 'Configuration', icon: 'sliders-horizontal', anchor: 'config', live: true, primary: true, group: 'cryptography' },
  { key: 'tls', label: 'TLS', icon: 'lock', anchor: 'config', live: true, primary: false, group: 'cryptography', protocol: 'TLS' },
  { key: 'ssh', label: 'SSH', icon: 'terminal', anchor: 'config', live: true, primary: false, group: 'cryptography', protocol: 'SSH' },
  // Data Protection is a PROPERTY lens, not a resource family: at-rest
  // (keyed-and-durable) posture across every resource that stores data.
  { key: 'data-protection', label: 'Data Protection', icon: 'vault', anchor: 'data', live: true, primary: true, group: 'cryptography' },
  { key: 'connections', label: '3rd Party', icon: 'link', anchor: 'asset', live: true, primary: true, group: 'cryptography' },
  // --- Lifecycle ---
  { key: 'stale', label: 'Stale', icon: 'clock-alert', anchor: 'asset', live: true, primary: true, group: 'lifecycle' },
];

/**
 * The class-faceted list is the default (ADR-0006 D2). `infrastructure` and
 * `network` are ALIASES of it rather than lenses: their questions — "what is out
 * there" and "what is in this segment" — are `class:` and `segment_id:` facets
 * on the one list now, and keeping them as separate lenses would have been the
 * lens-per-class shape the ADR rejected. A bookmark to either still lands
 * somewhere sensible.
 */
export const DEFAULT_LENS = 'assets';

/** Retired lens keys → the lens (and optional query) that answers the same
 *  question now. Read by the Inventory page, which rewrites the URL so a
 *  bookmark repairs itself instead of silently showing something else. */
export const LENS_ALIASES: Readonly<Record<string, { lens: string; query?: string }>> = {
  infrastructure: { lens: 'assets' },
  network: { lens: 'assets' },
};

export const findLens = (key: string | null): InventoryLens =>
  INVENTORY_LENSES.find((l) => l.key === key) ?? INVENTORY_LENSES[0];

/** Resolves an alias to its target, or null when the key is a real lens (or
 *  unknown, which `findLens` already handles by falling back to the default). */
export const resolveLensAlias = (key: string | null): { lens: string; query?: string } | null => {
  if (!key) return null;
  if (INVENTORY_LENSES.some((l) => l.key === key)) return null;
  return LENS_ALIASES[key] ?? null;
};

export const lensesInGroup = (group: InventoryLens['group']): InventoryLens[] =>
  INVENTORY_LENSES.filter((l) => l.group === group);
