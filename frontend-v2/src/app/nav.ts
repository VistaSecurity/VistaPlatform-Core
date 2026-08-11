// Vista Console primary navigation — the 5-section lifecycle IA, ported from the
// design mock's Shell.jsx (the LOCKED structure in REDESIGN_RISK_COMPLIANCE_AND_REMEDIATION.md).
// Settings and My Profile live in the profile dropdown, not the top rail.

export interface NavSubItem {
  path: string;
  label: string;
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
      { label: 'Review', items: [{ path: '/discovery/approvals', label: 'Approvals' }] },
      { label: 'Logs', items: [{ path: '/discovery/logs', label: 'Job Logs' }] },
      {
        label: 'Sources',
        items: [
          { path: '/discovery/cloud', label: 'Cloud' },
          { path: '/discovery/pcap', label: 'PCAP Upload' },
        ],
      },
    ],
  },
  { id: 'inventory', label: 'Inventory', icon: 'Database', path: '/inventory' },
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
          { path: '/risk-compliance/cbom', label: 'CBOM' },
        ],
      },
    ],
  },
  {
    id: 'rem',
    label: 'Remediation',
    icon: 'Wrench',
    path: '/remediation/triage',
    groups: [
      {
        items: [
          { path: '/remediation/alerts', label: 'Alerts' },
          { path: '/remediation/triage', label: 'Triage' },
          { path: '/remediation/queue', label: 'Queue' },
          { path: '/remediation/plans', label: 'Plans' },
        ],
      },
    ],
  },
];
