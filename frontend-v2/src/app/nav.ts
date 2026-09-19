// Vista Console primary navigation — the 5-section lifecycle IA, ported from the
// design mock's Shell.jsx (the LOCKED structure in REDESIGN_RISK_COMPLIANCE_AND_REMEDIATION.md).
// Settings and My Profile live in the profile dropdown, not the top rail.

export interface NavSubItem {
  path: string;
  label: string;
  /**
   * Inventory only: the lens this item selects. The Inventory section's items
   * all live at `/inventory` and differ by `?lens=`, so active state cannot be
   * decided from the pathname alone — the shell compares this against the URL's
   * lens instead of doing a string match on the query part of `path`.
   */
  lens?: string;
  /** A cross-link OUT of this section (Inventory → Discovery → Approvals). It
   *  renders with an arrow so it is visibly a departure, not a sub-page, and it
   *  never takes the active state from the section it points at. */
  crossLink?: boolean;
}
export interface NavGroup {
  label?: string;
  items: NavSubItem[];
}
export interface NavSection {
  id: string;
  label: string;
  /** lucide-react icon name */
  icon: string;
  /** where the section row navigates */
  path: string;
  /** sub-navigation shown when the section is active */
  groups?: NavGroup[];
}

export const SECTIONS: NavSection[] = [
  { id: 'dashboard', label: 'Dashboard', icon: 'LayoutDashboard', path: '/dashboard' },
  {
    id: 'discovery',
    label: 'Discovery',
    icon: 'Radar',
    path: '/discovery',
    groups: [
      { items: [{ path: '/discovery', label: 'Command Center' }] },
      {
        label: 'Sensors & Scanning',
        items: [
          { path: '/discovery/sensors', label: 'Sensors & Agents' },
          { path: '/discovery/jobs', label: 'Discovery Jobs' },
          { path: '/discovery/devices', label: 'Devices' },
          { path: '/discovery/active-scan', label: 'Active Scan' },
          { path: '/discovery/scans', label: 'Scheduled Scans' },
        ],
      },
      { label: 'Review', items: [{ path: '/discovery/observations', label: 'Observations' }, { path: '/discovery/approvals', label: 'Approvals' }] },
      { label: 'Logs', items: [{ path: '/discovery/logs', label: 'Job Logs' }] },
      {
        label: 'Sources',
        items: [
          { path: '/discovery/cloud', label: 'Cloud' },
          { path: '/discovery/pcap', label: 'PCAP Upload' },
          // Sources is a GROUP, not a page, so SBOM upload is a sibling of PCAP
          // Upload rather than a card on a "Sources page" that does not exist.
          // Both are the same shape of intake: bring us a file, we turn it into
          // inventory.
          { path: '/discovery/sbom', label: 'SBOM Upload' },
        ],
      },
    ],
  },
  {
    // ADR-0006 D1: Inventory becomes the general inventory's home and gains
    // sub-groups, mirroring how Discovery is grouped. Crypto keeps every lens it
    // had, grouped under one label so it reads as a module of the inventory
    // rather than as the whole of it.
    id: 'inventory',
    label: 'Inventory',
    icon: 'Database',
    path: '/inventory',
    groups: [
      {
        label: 'Assets',
        items: [
          { path: '/inventory?lens=assets', label: 'All assets', lens: 'assets' },
          { path: '/inventory?lens=map', label: 'Map', lens: 'map' },
          { path: '/inventory?lens=software', label: 'Software', lens: 'software' },
        ],
      },
      {
        label: 'Cryptography',
        items: [
          { path: '/inventory?lens=certificate', label: 'Certificates', lens: 'certificate' },
          { path: '/inventory?lens=keys', label: 'Keys', lens: 'keys' },
          { path: '/inventory?lens=configuration', label: 'Configuration', lens: 'configuration' },
          { path: '/inventory?lens=tls', label: 'TLS', lens: 'tls' },
          { path: '/inventory?lens=ssh', label: 'SSH', lens: 'ssh' },
          { path: '/inventory?lens=data-protection', label: 'Data Protection', lens: 'data-protection' },
          { path: '/inventory?lens=connections', label: '3rd Party', lens: 'connections' },
        ],
      },
      {
        label: 'Lifecycle',
        items: [
          { path: '/inventory?lens=stale', label: 'Stale', lens: 'stale' },
          // Pending is a CROSS-LINK, not a second queue (ADR-0006 D1). Pending
          // assets are reviewed in one place; listing them here as well would
          // be the second inbox the ADR rules out.
          { path: '/discovery/approvals', label: 'Pending', crossLink: true },
        ],
      },
    ],
  },
  {
    id: 'rc',
    label: 'Risk & Compliance',
    icon: 'ShieldCheck',
    path: '/risk-compliance/posture',
    groups: [
      {
        items: [
          { path: '/risk-compliance/posture', label: 'Posture' },
          { path: '/risk-compliance/findings', label: 'Findings' },
          // "CBOM" until the artifact pipeline gained kinds (ADR-0005 D6). It
          // now lists software, hardware and full-inventory snapshots too, and
          // a user wanting an SBOM would never have looked under "CBOM" — an
          // unreachable feature, which is the failure the reachability check
          // exists to catch. The ROUTE stays /cbom: it is a URL people have
          // bookmarked, and renaming it would buy nothing.
          { path: '/risk-compliance/cbom', label: 'Bills of Materials' },
        ],
      },
    ],
  },
  {
    id: 'rem',
    label: 'Remediation',
    icon: 'Wrench',
    path: '/remediation/alerts',
    groups: [
      {
        items: [
          { path: '/remediation/alerts', label: 'Alerts' },
          { path: '/remediation/queue', label: 'Queue' },
          { path: '/remediation/plans', label: 'Plans' },
        ],
      },
    ],
  },
];
