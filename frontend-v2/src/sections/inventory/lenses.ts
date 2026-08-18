// Inventory lens catalogue — shared by the sidebar (renders the lens sub-nav)
// and the Inventory page (renders the data per lens). The active lens lives in
// the URL (`/inventory?lens=<key>`) so both stay in sync. Ported from the mock's
// Lenses.jsx: primary lenses + a "By Protocol" group.
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
  protocol?: string; // config lenses: filter to this protocol
}

export const INVENTORY_LENSES: InventoryLens[] = [
  { key: 'infrastructure', label: 'Infrastructure', icon: 'server', anchor: 'asset', live: true, primary: true },
  { key: 'certificate', label: 'Certificates', icon: 'file-badge', anchor: 'cert', live: true, primary: true },
  { key: 'keys', label: 'Cryptographic Keys', icon: 'key-round', anchor: 'key', live: true, primary: true },
  { key: 'configuration', label: 'Configuration', icon: 'sliders-horizontal', anchor: 'config', live: true, primary: true },
  { key: 'network', label: 'Network', icon: 'network', anchor: 'asset', live: true, primary: true },
  // Data Protection is a PROPERTY lens, not a resource family: at-rest
  // (keyed-and-durable) posture across every resource that stores data. It sits
  // beside the in-transit lenses rather than adding a resource-family nav.
  { key: 'data-protection', label: 'Data Protection', icon: 'vault', anchor: 'data', live: true, primary: true },
  { key: 'connections', label: '3rd Party', icon: 'link', anchor: 'asset', live: true, primary: true },
  { key: 'stale', label: 'Stale Assets', icon: 'clock-alert', anchor: 'asset', live: true, primary: true },
  { key: 'tls', label: 'TLS', icon: 'lock', anchor: 'config', live: true, primary: false, protocol: 'TLS' },
  { key: 'ssh', label: 'SSH', icon: 'terminal', anchor: 'config', live: true, primary: false, protocol: 'SSH' },
];

export const DEFAULT_LENS = 'infrastructure';

export const findLens = (key: string | null): InventoryLens =>
  INVENTORY_LENSES.find((l) => l.key === key) ?? INVENTORY_LENSES[0];
