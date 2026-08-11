// Posture "views" — the sub-nav tabs shown under Posture in the rail, driven by
// `?tab=` on /risk-compliance/posture (same pattern as the Findings/Inventory
// lenses). Single source of truth for the rail (app-shell) and the page.
export interface PostureTab {
  key: string;
  label: string;
  icon: string; // components/ui/icon.tsx name
}

export const POSTURE_TABS: PostureTab[] = [
  { key: 'overview', label: 'Overview', icon: 'gauge' },
  { key: 'frameworks', label: 'Frameworks', icon: 'shield-check' },
  { key: 'algorithms', label: 'Algorithm Reference', icon: 'binary' },
];

export const DEFAULT_POSTURE_TAB = 'overview';
