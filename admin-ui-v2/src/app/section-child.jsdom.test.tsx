// @vitest-environment jsdom
//
// Sub-view route guards, MOUNTED (RC-3, admin-ui data review).
//
// The rail hides a sub-view the operator's role cannot use (nav.ts child
// `permission`); these pin that the ROUTE refuses it too — a deep link to
// /security/policy without platform.settings gets the no-access notice, not a
// page whose every call 403s — and that a section's index lands on the first
// sub-view the operator may open.
//
// Mounts the real SupportPage / SecurityPage layouts inside a MemoryRouter
// with the leaf pages and the permission context stubbed.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter, Route, Routes } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const state = vi.hoisted(() => ({ perms: new Set<string>() }));

vi.mock('@vistasecurity/primitives/platform-auth', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    usePlatformPermissions: () => ({
      isLoading: false,
      hasPermission: (p: string) => state.perms.has(p),
      hasAnyPermission: (ps: string[]) => ps.some((p) => state.perms.has(p)),
    }),
  };
});

vi.mock('../sections/support/tenant-health-page', () => ({ TenantHealthPage: () => <p>page:health</p> }));
vi.mock('../sections/support/job-repair-page', () => ({ JobRepairPage: () => <p>page:repair</p> }));
vi.mock('../sections/security/dashboard-page', () => ({ SecurityDashboardPage: () => <p>page:dashboard</p> }));
vi.mock('../sections/security/policy-page', () => ({ SecurityPolicyPage: () => <p>page:policy</p> }));
vi.mock('../sections/security/activity-page', () => ({ ActivityPage: () => <p>page:activity</p> }));
vi.mock('../sections/security/retention-page', () => ({ RetentionPage: () => <p>page:retention</p> }));
vi.mock('../sections/security/siem-page', () => ({ SiemPage: () => <p>page:siem</p> }));

import { SupportPage } from '../sections/support/support-page';
import { SecurityPage } from '../sections/security/security-page';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  state.perms = new Set();
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

function mount(path: string) {
  act(() => {
    root.render(
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/support/*" element={<SupportPage />} />
          <Route path="/security/*" element={<SecurityPage />} />
        </Routes>
      </MemoryRouter>,
    );
  });
  return container.textContent ?? '';
}

const NO_ACCESS = "You don't have access to this section";

describe('sub-view route guard', () => {
  it('refuses a deep link to a sub-view the role lacks', () => {
    state.perms = new Set(['platform.audit']);
    const text = mount('/security/dashboard');
    expect(text).toContain(NO_ACCESS);
    expect(text).not.toContain('page:dashboard');
  });

  it('opens it for a role holding the sub-view permission', () => {
    state.perms = new Set(['platform.security']);
    expect(mount('/security/dashboard')).toContain('page:dashboard');
  });

  // Owner decision 10 (RC-21): Support ▸ Impersonation is removed. An old
  // bookmark falls through to the section catch-all and lands on Tenant
  // Health; platform.impersonate alone opens nothing in Support.
  it('/support/impersonation no longer routes to a page', () => {
    state.perms = new Set(['platform.health', 'platform.impersonate']);
    const text = mount('/support/impersonation');
    expect(text).toContain('page:health');
    expect(text).not.toContain('impersonation');
    state.perms = new Set(['platform.impersonate']);
    expect(mount('/support')).not.toContain('page:');
  });

  it('guards Security ▸ Policy on platform.settings', () => {
    state.perms = new Set(['platform.audit']);
    expect(mount('/security/policy')).toContain(NO_ACCESS);
    state.perms = new Set(['platform.settings']);
    expect(mount('/security/policy')).toContain('page:policy');
  });
});

describe('section index', () => {
  it('lands on the first sub-view the role may open', () => {
    state.perms = new Set(['platform.settings']);
    expect(mount('/security')).toContain('page:policy');
  });

  it('keeps the first sub-view when the role holds it', () => {
    state.perms = new Set(['platform.health']);
    expect(mount('/support')).toContain('page:health');
  });

  // The seeded support_agent holds platform.audit but not platform.security:
  // it used to land on a Security Dashboard that 403'd.
  it('skips a Security Dashboard the role cannot read', () => {
    state.perms = new Set(['platform.audit']);
    expect(mount('/security')).toContain('page:activity');
  });
});
