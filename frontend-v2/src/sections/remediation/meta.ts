import type { complianceEngineComponents } from '@vistasecurity/api-contract';

export type Ticket = complianceEngineComponents['schemas']['Ticket'];

export const PRIORITY_COLOR: Record<string, string> = {
  critical: 'var(--danger)', high: 'var(--warn-strong)', medium: 'var(--warn)', low: 'var(--ok)',
};
export const STATUS_COLOR: Record<string, string> = {
  open: 'var(--info)', in_progress: 'var(--warn)', resolved: 'var(--ok)', closed: 'var(--neutral)',
};
export const CATEGORY_ICON: Record<string, string> = {
  compliance: 'shield-check', certificate: 'file-badge', remediation: 'wrench',
  vulnerability: 'circle-alert', operational: 'settings', general: 'file-text',
};

export type SlaState = 'overdue' | 'due_soon' | 'on_track' | 'none';
export const SLA_META: Record<Exclude<SlaState, 'none'>, { color: string; label: string }> = {
  overdue: { color: 'var(--danger)', label: 'Overdue' },
  due_soon: { color: 'var(--warn-strong)', label: 'Due soon' },
  on_track: { color: 'var(--ok)', label: 'On track' },
};

export function dueDays(t: Ticket): number | null {
  if (!t.due_date) return null;
  return Math.floor((new Date(t.due_date).getTime() - Date.now()) / 86400000);
}

/** Same window the backend's overdue/due-soon checker uses (3 days). */
export function slaState(t: Ticket): SlaState {
  if (t.status === 'resolved' || t.status === 'closed') return 'none';
  const d = dueDays(t);
  if (d == null) return 'none';
  if (d < 0) return 'overdue';
  if (d <= 3) return 'due_soon';
  return 'on_track';
}

/** Map a ticket/alert severity-ish string onto the risk-level vocabulary. */
export function severityLevel(s?: string | null): string {
  const v = (s || '').toLowerCase();
  if (v === 'critical') return 'Critical';
  if (v === 'high') return 'High';
  if (v === 'medium') return 'Medium';
  if (v === 'low') return 'Low';
  return 'Informational';
}
