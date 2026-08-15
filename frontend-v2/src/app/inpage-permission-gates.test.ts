// In-page RBAC gates must name the permission their route enforces.
//
// The settings-rail gates are pinned in sections/settings/nav.test.ts. This file
// covers the layer one click deeper: the buttons, toggles and drawers INSIDE a
// page. A gate that is weaker than its route hands the user an enabled control
// and a 403; a gate that is stricter hides a control the server would have
// allowed. Both are bugs, and neither is visible from the nav registry.
//
// Each case below asserts BOTH sides from source:
//   1. the Go route still requires the permission we think it does, and
//   2. the TSX gate names the matching TENANT_PERMISSIONS path.
// Asserting only (2) would pass forever after a route's requirement changed,
// which is the failure mode this whole sweep exists to close. Both anchors are
// asserted non-empty so a file restructure fails loudly instead of vacuously
// passing.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../../../', import.meta.url));
const read = (rel: string) => readFileSync(repoRoot + rel, 'utf8');

/** Assert a Go route registration line exists carrying `permConst`. */
function routeRequires(goFile: string, routeFragment: string, permConst: string) {
  const src = read(goFile);
  const line = src
    .split('\n')
    .find((l) => l.includes(routeFragment) && l.includes(permConst));
  expect(
    line,
    `${goFile}: no route line matching "${routeFragment}" gated on ${permConst} — has the route's permission changed?`,
  ).toBeTruthy();
}

/** Assert a TSX source names a TENANT_PERMISSIONS path, and does not name a forbidden one. */
function gateUses(tsxFile: string, permPath: string, mustNotUse?: string[]) {
  const src = read(tsxFile);
  expect(
    src.includes(`TENANT_PERMISSIONS.${permPath}`),
    `${tsxFile}: expected a gate on TENANT_PERMISSIONS.${permPath}`,
  ).toBe(true);
  for (const bad of mustNotUse ?? []) {
    expect(
      src.includes(`TENANT_PERMISSIONS.${bad}`),
      `${tsxFile}: must not gate on TENANT_PERMISSIONS.${bad} — the route asks for ${permPath}`,
    ).toBe(false);
  }
}

/**
 * The permission named by the nearest `TENANT_PERMISSIONS.x.y` at or above the
 * line holding `anchor` — i.e. the gate the anchored element sits inside.
 * Line-scanning rather than one regex because a gate's `fallback` attribute
 * contains `>` and JSX, which no reasonable single pattern survives.
 */
function gateEnclosing(src: string, anchor: string): string {
  const lines = src.split('\n');
  const at = lines.findIndex((l) => l.includes(anchor));
  expect(at, `could not locate "${anchor}"`).toBeGreaterThan(-1);
  for (let i = at; i >= 0 && i > at - 12; i--) {
    const m = /TENANT_PERMISSIONS\.(\w+\.\w+)/.exec(lines[i]);
    if (m) return m[1];
  }
  throw new Error(`no enclosing PermissionGate found within 12 lines above "${anchor}"`);
}

const FE = 'frontend-v2/src/';

describe('Scopes (Settings → Policies → Scopes)', () => {
  it('gates scope writes on compliance.update, which is what cbom-service enforces', () => {
    routeRequires('services/cbom-service/cmd/main.go', 'scopeHandler.RegisterRoutes', 'PermissionComplianceUpdate');
    // Whole file: ScopesPage and FrameworksPage are both compliance-owned, and
    // neither may fall back to settings.update. RetentionPage in the same file
    // is audit.manage, so settings.update must not appear at all.
    gateUses(`${FE}sections/settings/pages-policies.tsx`, 'compliance.update', ['settings.update']);
  });
});

describe('Compliance frameworks (activate / deactivate / set default)', () => {
  it('gates on compliance.update, not compliance.manage', () => {
    const go = 'services/compliance-engine/cmd/main.go';
    routeRequires(go, '/frameworks/subscribe"', 'PermissionComplianceUpdate');
    routeRequires(go, '/frameworks/default"', 'PermissionComplianceUpdate');
    gateUses(`${FE}sections/settings/pages-policies.tsx`, 'compliance.update', ['compliance.manage']);
  });
});

describe('Custom policies (Enterprise policy authoring)', () => {
  it('gates on compliance.update — the permission the ee authoring routes require', () => {
    routeRequires(
      'services/compliance-engine/ee/policyauthoring/handlers.go',
      'requireUpdate :=',
      'PermissionComplianceUpdate',
    );
    gateUses(`${FE}sections/settings/pages-custom-policies.tsx`, 'compliance.update', ['compliance.manage']);
  });
});

describe('Retention policies (regression guard for #1375)', () => {
  it('still gates writes on audit.manage', () => {
    routeRequires('services/audit-service/cmd/main.go', '/audit-service/retention-policies"', 'PermissionAuditManage');
    gateUses(`${FE}sections/settings/pages-policies.tsx`, 'audit.manage');
  });
});

describe('Alert-rule enable/disable toggle (Settings → Alert Rules)', () => {
  it('gates on audit.manage — the toggle PUTs an audit-service route', () => {
    routeRequires('services/audit-service/cmd/main.go', '/audit-service/alert-rules/:id"', 'PermissionAuditManage');
    const src = read(`${FE}sections/settings/pages-integrations.tsx`);
    expect(src).toContain('TENANT_PERMISSIONS.audit.manage');
    // The toggle and its fallback must sit under audit.manage, not settings.update.
    expect(gateEnclosing(src, '<AlertRuleToggle')).toBe('audit.manage');
  });
});

describe('CMDB sync / pull (Settings → Integrations)', () => {
  it('gates the inventory-moving actions on assets.manage, not settings.update', () => {
    const go = 'services/inventory-service/ee/cmdbsync/routes.go';
    routeRequires(go, '/cmdb/profiles/:id/sync"', 'PermissionAssetsManage');
    routeRequires(go, '/cmdb/profiles/:id/pull"', 'PermissionAssetsManage');
    // Profile CRUD stays settings.update in the same file.
    routeRequires(go, '/cmdb/profiles"', 'PermissionSettingsUpdate');
    const src = read(`${FE}sections/settings/pages-integrations.tsx`);
    expect(gateEnclosing(src, '<CmdbPullButton')).toBe('assets.manage');
    expect(gateEnclosing(src, '<CmdbSyncButton')).toBe('assets.manage');
    expect(gateEnclosing(src, '<CmdbTestButton')).toBe('settings.update');
  });
});

describe('Sensor detail drawer (config, interfaces, commands)', () => {
  it('gates on sensors.update — sensors.manage guards only certificate operations', () => {
    const go = 'services/sensor-manager/cmd/main.go';
    routeRequires(go, '/sensors/:sensor_id/config"', 'PermissionSensorsUpdate');
    routeRequires(go, '/sensors/:sensor_id/commands"', 'PermissionSensorsUpdate');
    routeRequires(go, '/sensors/:sensor_id/certificates/revoke"', 'PermissionSensorsManage');
    const src = read(`${FE}sections/discovery/sensor-detail-drawer.tsx`);
    expect(src).toContain('TENANT_PERMISSIONS.sensors.update');
    // Exactly one sensors.manage gate survives: the certificate revoke button.
    expect(src.match(/TENANT_PERMISSIONS\.sensors\.manage/g)?.length).toBe(1);
  });
});

describe('Register sensor or agent (Discovery → Sensors & Agents)', () => {
  it('gates on sensors.create — POST /sensors/pending', () => {
    routeRequires('services/sensor-manager/cmd/main.go', '/sensors/pending"', 'PermissionSensorsCreate');
    gateUses(`${FE}sections/discovery/sensors-page.tsx`, 'sensors.create', ['sensors.manage']);
    // The onboarding checklist deep-links this button; its gate must agree.
    expect(read(`${FE}sections/onboarding/step-meta.ts`)).toContain(
      'deploy_agent: { route: \'/discovery/sensors\', icon: \'monitor-smartphone\', permission: TENANT_PERMISSIONS.sensors.create }',
    );
  });
});

describe('Discovery job retry / cancel (Discovery → Job Logs)', () => {
  it('gates on discovery.update, not discovery.manage', () => {
    const go = 'services/device-interrogation-service/internal/api/router.go';
    routeRequires(go, 'jobs.POST("/:id/retry"', 'PermissionDiscoveryUpdate');
    routeRequires(go, 'jobs.POST("/:id/cancel"', 'PermissionDiscoveryUpdate');
    gateUses(`${FE}sections/discovery/jobs-page.tsx`, 'discovery.update', ['discovery.manage']);
  });
});

describe('Scheduled scans (Discovery → Scheduled Scans)', () => {
  it('gates create / enable-disable / trigger on their own three permissions', () => {
    const go = 'services/device-interrogation-service/internal/api/router.go';
    routeRequires(go, 'schedules.POST(""', 'PermissionDiscoveryCreate');
    routeRequires(go, 'schedules.POST("/:id/enable"', 'PermissionDiscoveryUpdate');
    routeRequires(go, 'schedules.POST("/:id/trigger"', 'PermissionDiscoveryManage');
    const src = read(`${FE}sections/discovery/scans-page.tsx`);
    expect(src).toContain('TENANT_PERMISSIONS.discovery.create');
    expect(src).toContain('TENANT_PERMISSIONS.discovery.update');
    expect(src).toContain('TENANT_PERMISSIONS.discovery.manage');
  });
});

describe('Devices (Discovery → Devices)', () => {
  it('gates add / edit / interrogate on create / update / manage respectively', () => {
    const go = 'services/device-interrogation-service/internal/api/router.go';
    routeRequires(go, 'devices.POST(""', 'PermissionDiscoveryCreate');
    routeRequires(go, 'devices.PUT("/:id"', 'PermissionDiscoveryUpdate');
    routeRequires(go, 'devices.POST("/:id/interrogate"', 'PermissionDiscoveryManage');
    const src = read(`${FE}sections/discovery/devices-page.tsx`);
    expect(src).toContain('TENANT_PERMISSIONS.discovery.create');
    expect(src).toContain('TENANT_PERMISSIONS.discovery.update');
    expect(src).toContain('TENANT_PERMISSIONS.discovery.manage');
  });
});

describe('Spreadsheet import', () => {
  it('gates the launcher and the submit on the target resource, not on discovery', () => {
    const go = 'services/inventory-service/cmd/main.go';
    routeRequires(go, '/inventory-service/infrastructure-assets/bulk"', 'PermissionAssetsCreate');
    routeRequires(go, '/inventory-service/network-segments/bulk"', 'PermissionSettingsUpdate');
    // Launcher on the command center is assets.create; "Discover assets" beside
    // it keeps discovery.create.
    const cc = read(`${FE}sections/discovery/command-center.tsx`);
    expect(cc).toContain('TENANT_PERMISSIONS.assets.create');
    expect(cc).toContain('TENANT_PERMISSIONS.discovery.create');
    // The modal picks its submit gate from the chosen target.
    const modal = read(`${FE}sections/discovery/import-modal.tsx`);
    expect(modal).toContain(
      "target === 'assets' ? TENANT_PERMISSIONS.assets.create : TENANT_PERMISSIONS.settings.update",
    );
  });
});

describe('SSO group → role mapping', () => {
  it('does not offer a dropdown it cannot populate', () => {
    // GET /tenant/:tenantId/roles is behind users.manage; the modal itself opens
    // at settings.update. Without users.manage the fetch 403s, so the editor
    // must not render an empty select whose save would blank existing mappings.
    routeRequires('services/auth-service/internal/api/router.go', 'tenantRoles.Use', '"users.manage"');
    const src = read(`${FE}sections/settings/sso-modals.tsx`);
    expect(src).toContain('TENANT_PERMISSIONS.users.manage');
    expect(src).toContain('rolesReadable');
    // The query must not fire at all without the permission.
    expect(src).toMatch(/enabled:[^\n]*rolesReadable/);
  });
});
