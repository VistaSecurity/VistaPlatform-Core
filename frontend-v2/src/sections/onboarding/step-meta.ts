// Maps onboarding step IDs (from the seeded default workflow) to their UI:
// the page that owns the action (deep-link target), an icon, and the permission
// a user needs to actually perform that step. Keeping this here means the
// backend workflow stays presentation-agnostic. Step IDs match
// scripts/database/seed.sql.
import { TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';

export interface StepMeta {
  route: string;
  icon: string;
  /** Permission required to perform the step; undefined = no gate. */
  permission?: string;
}

const STEP_META: Record<string, StepMeta> = {
  define_networks: { route: '/settings/segments', icon: 'link-2', permission: TENANT_PERMISSIONS.settings.read },
  add_locations: { route: '/settings/locations', icon: 'map-pin', permission: TENANT_PERMISSIONS.settings.read },
  // sensors.create — matches the gate on the Register button this step links to,
  // which matches POST /sensors/pending.
  deploy_agent: { route: '/discovery/sensors', icon: 'monitor-smartphone', permission: TENANT_PERMISSIONS.sensors.create },
};

// A user "can onboard" (sees the checklist + the dropdown entry) if they can act
// on at least one step. Read-only viewers are never nagged. See Section 1 of the
// feature spec.
export const ONBOARDING_PERMISSIONS = [TENANT_PERMISSIONS.settings.read, TENANT_PERMISSIONS.sensors.manage];

export function stepMeta(id: string): StepMeta {
  return STEP_META[id] ?? { route: '/dashboard', icon: 'circle-dot' };
}
