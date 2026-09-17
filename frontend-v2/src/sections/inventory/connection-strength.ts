import { STRENGTHS } from '@vistasecurity/primitives/ratings';
import type { inventoryComponents, inventoryOperations } from '@vistasecurity/api-contract';

export type ConnectionStrength = inventoryComponents['schemas']['ExternalConnection']['strength'];
export type ConnectionStrengthFilter = NonNullable<inventoryOperations['listExternalConnections']['parameters']['query']>['strength'];

export function connectionStrengthLabel(strength: ConnectionStrength, weakReasons?: readonly string[]): string {
  return strength == null ? (weakReasons?.length ? 'Reassessment required' : 'Not assessed') : (STRENGTHS.find(row => row.value === strength)?.label ?? 'Not assessed');
}
export function connectionStrengthTone(strength: ConnectionStrength): string {
  switch (strength) {
    case 'weak': return 'var(--danger)';
    case 'acceptable': return 'var(--warn)';
    case 'strong':
    case 'recommended': return 'var(--ok)';
    default: return 'var(--app-t3)';
  }
}
export const CONNECTION_STRENGTH_OPTIONS = ['All', ...STRENGTHS.map(row => row.label), 'Not assessed'];
export function connectionStrengthFilter(label: string): ConnectionStrengthFilter {
  if (label === 'Not assessed') return 'unassessed';
  return STRENGTHS.find(row => row.label === label)?.value;
}
