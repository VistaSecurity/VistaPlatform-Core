// Tenants ▸ Settings tab.
//
// The property worth pinning hardest is that "Platform default" OMITS its key
// from the request body. The backend merges what it is sent into a jsonb
// document several other features share, and reads an absent key as "leave
// this alone" — so a form that helpfully sent `false` for "no override" would
// turn every unset setting into a silent override and stop the tenant tracking
// the platform default, without any error anywhere.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { TenantSettingsPanel, toOverride, toSettings } from './tenant-settings-tab';
import type { TenantSettingsSnapshot } from './queries';

const state = vi.hoisted(() => ({
  settings: {
    data: undefined as TenantSettingsSnapshot | undefined,
    isLoading: false,
    isError: false,
    refetch: vi.fn(),
  },
  platform: { data: undefined as { email_verification_required?: boolean } | undefined },
  save: { mutateAsync: vi.fn(), isPending: false },
  canManage: true,
}));

vi.mock('./queries', () => ({
  useTenantSettings: () => state.settings,
  useUpdateTenantSettings: () => state.save,
}));
vi.mock('../security/queries', () => ({
  usePlatformSettings: () => state.platform,
}));
vi.mock('@vistasecurity/primitives/platform-auth', () => ({
  PLATFORM_PERMISSIONS: { tenants: { manage: 'tenants.manage' } },
  usePlatformPermissions: () => ({ hasPermission: () => state.canManage }),
}));

const tenantId = '11111111-1111-4111-8111-111111111111';

const render = () => renderToStaticMarkup(createElement(TenantSettingsPanel, { tenantId }));

beforeEach(() => {
  state.settings = { data: { settings: {}, version: 0 }, isLoading: false, isError: false, refetch: vi.fn() };
  state.platform = { data: undefined };
  state.save = { mutateAsync: vi.fn(), isPending: false };
  state.canManage = true;
});

describe('toSettings — what actually reaches the wire', () => {
  it('omits a key left on the platform default rather than sending false', () => {
    const body = toSettings({ email_verification_required: 'inherit', onboarding_required: 'inherit' });
    expect(body).toEqual({});
    // Explicit: the key must be ABSENT, not present-and-false. `toEqual({})`
    // alone would also pass for `{k: undefined}`, which serialises away, but
    // being present with `false` is the failure mode this test exists for.
    expect('email_verification_required' in body).toBe(false);
    expect('onboarding_required' in body).toBe(false);
    expect(JSON.stringify(body)).toBe('{}');
  });

  it('sends an explicit false when the operator chose "Not required"', () => {
    const body = toSettings({ email_verification_required: 'off', onboarding_required: 'on' });
    expect(body).toEqual({ email_verification_required: false, onboarding_required: true });
    expect(JSON.stringify(body)).toContain('"email_verification_required":false');
  });

  it('sends only the overridden key when the other is inherited', () => {
    expect(toSettings({ email_verification_required: 'on', onboarding_required: 'inherit' }))
      .toEqual({ email_verification_required: true });
  });
});

describe('toOverride — stored value to control state', () => {
  it('maps undefined to inherit, and keeps false distinct from it', () => {
    expect(toOverride(undefined)).toBe('inherit');
    expect(toOverride(false)).toBe('off');
    expect(toOverride(true)).toBe('on');
  });
});

describe('TenantSettingsPanel', () => {
  it('offers all three states, with the platform default selected when unset', () => {
    const html = render();
    expect(html).toContain('Platform default');
    expect(html).toContain('Required');
    expect(html).toContain('Not required');
    // Both rows start on the inherit chip.
    expect(html.match(/aria-pressed="true"/g)).toHaveLength(2);
  });

  it('names what the platform default currently resolves to', () => {
    state.platform = { data: { email_verification_required: false } };
    expect(render()).toContain('Platform default (not required)');
    state.platform = { data: { email_verification_required: true } };
    expect(render()).toContain('Platform default (required)');
  });

  it('falls back to a bare label when the platform setting has not loaded', () => {
    state.platform = { data: undefined };
    const html = render();
    expect(html).toContain('Platform default</button>');
    expect(html).not.toContain('Platform default (undefined)');
  });

  it('shows a stored override as selected rather than as the default', () => {
    state.settings.data = { settings: { email_verification_required: false }, version: 3 };
    const html = render();
    // email verification is overridden to off; onboarding is still inherited.
    expect(html).toContain('>Not required</button>');
    expect(html.match(/aria-pressed="true"/g)).toHaveLength(2);
    // The overridden row must NOT have its inherit chip pressed.
    const emailRow = html.slice(0, html.indexOf('Onboarding walkthrough'));
    expect(emailRow).toContain('aria-pressed="true"');
    expect(emailRow).not.toContain('aria-pressed="true">Platform default');
  });

  it('renders read-only and disables every control without tenants.manage', () => {
    state.canManage = false;
    const html = render();
    expect(html).toContain('Read-only');
    // 2 rows x 3 chips, all disabled.
    expect(html.match(/disabled=""/g)).toHaveLength(6);
  });

  it('surfaces load failure with a retry instead of an empty form', () => {
    state.settings = { data: undefined, isLoading: false, isError: true, refetch: vi.fn() };
    const html = render();
    expect(html).toContain('Retry');
    expect(html).not.toContain('Platform default');
  });

  it('shows a loading state rather than a form seeded with defaults', () => {
    state.settings = { data: undefined, isLoading: true, isError: false, refetch: vi.fn() };
    const html = render();
    expect(html).toContain('Loading settings');
    expect(html).not.toContain('aria-pressed');
  });
});

// The reachability chain, asserted on the drawer's own source.
//
// Every test above drives the panel directly, so every one of them stays green
// if the drawer never renders it — which is the exact shape of the bug this
// whole change exists to fix (a working layer nothing reaches). There is no
// jsdom/React harness in this app to click the tab strip with, so the wiring is
// pinned by reading the drawer source, the same way draft-controls-modal.test.ts
// pins its modal. Delete either line in tenant-drawer.tsx and this fails.
describe('reachability — the drawer actually mounts the panel', () => {
  it('lists Settings in the tab strip and renders the panel for it', async () => {
    const src = (await import('./tenant-drawer.tsx?raw')).default;
    expect(src).toContain("import { TenantSettingsPanel } from './tenant-settings-tab'");
    expect(src).toMatch(/const TABS = \[[^\]]*'Settings'[^\]]*\]/);
    expect(src).toMatch(/tab === 'Settings' && <TenantSettingsPanel tenantId={t\.id} \/>/);
  });
});
