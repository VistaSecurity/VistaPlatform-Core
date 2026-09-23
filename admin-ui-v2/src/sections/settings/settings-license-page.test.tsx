// Settings → License & Usage: every screen state of the licence card and the
// Enterprise data-retention section (edition-licensing spec §1 screen table),
// and that the MSP usage panel mounts on MSP licences only — rendered with the
// real components (the real LicenseUsagePanel included) over mocked query hooks.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { LicenseInfo, RetentionSetting } from './license-queries';
import type { LicenseState } from '../../lib/edition';

type Q<T> = { data?: T; isLoading: boolean; isError: boolean; refetch: () => void };

const state: { license: Q<LicenseInfo>; retention: Q<RetentionSetting>; canEdit: boolean; edition: LicenseState } = vi.hoisted(() => ({
  license: { isLoading: false, isError: false, refetch: () => {} },
  retention: { isLoading: false, isError: false, refetch: () => {} },
  canEdit: true,
  edition: 'enterprise',
}));

vi.mock('./license-queries', async (orig) => {
  const real = await orig<typeof import('./license-queries')>();
  return {
    ...real,
    useLicense: () => state.license,
    useRetention: () => state.retention,
    useSaveRetention: () => ({ mutateAsync: vi.fn(), isPending: false }),
  };
});
// The licence edition as the console knows it (GET /admin/platform/edition).
// isMsp mirrors the real hook: it fails OPEN on 'unknown'.
vi.mock('../../lib/edition', () => ({
  usePlatformEdition: () => ({ license: state.edition, isMsp: state.edition === 'msp' || state.edition === 'unknown' }),
}));
// The usage panel's own data: loading, so the real panel renders its chrome.
vi.mock('./license-usage-queries', async (orig) => {
  const real = await orig<typeof import('./license-usage-queries')>();
  const loading = { data: undefined, isLoading: true, isError: false, error: null, refetch: () => {} };
  return {
    ...real,
    useLicenseUsage: () => loading,
    useLicenseUsageReports: () => loading,
    useGenerateLicenseUsageReport: () => ({ isPending: false, mutate: vi.fn() }),
  };
});
vi.mock('@vistasecurity/primitives/platform-auth', () => ({
  PLATFORM_PERMISSIONS: { platform: { settings: 'platform.settings' } },
  usePlatformPermissions: () => ({ hasPermission: () => state.canEdit }),
}));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));

const { SettingsLicensePage, submitRetention } = await import('./settings-license-page');
const { expiryWarning, retentionDays, retentionForm, retentionLabel } = await import('./license-queries');

const render = () => renderToStaticMarkup(createElement(SettingsLicensePage));

const base: LicenseInfo = {
  edition: 'enterprise', display_name: 'Vista Platform Enterprise', status: 'active', licensed_edition: 'enterprise',
  licensee: 'Acme Corp', subject: 'acme-2026', issued_at: '2026-01-01T00:00:00Z', expires_at: '2027-01-15T12:00:00Z',
  days_left: 200, max_tenants: null, grace_days: null, verified_at: '2026-09-23T00:00:00Z',
  install_id: '6b0f2a55-6a8e-4b7e-9d3c-111111111111', bound_install_id: null,
};
const ok = <T,>(data: T): Q<T> => ({ data, isLoading: false, isError: false, refetch: () => {} });

beforeEach(() => {
  state.license = ok(base);
  state.retention = ok({ max_days: null, applies: true });
  state.canEdit = true;
  state.edition = 'enterprise';
});

describe('licence card', () => {
  it('loading: a skeleton, no conclusions', () => {
    state.license = { isLoading: true, isError: false, refetch: () => {} };
    const html = render();
    expect(html).toContain('data-testid="license-loading"');
    expect(html).not.toContain('Vista Platform');
  });

  it('error: says it could not read the status and offers a retry', () => {
    state.license = { isLoading: false, isError: true, refetch: () => {} };
    const html = render();
    expect(html).toContain('Could not read licence status');
    expect(html).toContain('Retry');
  });

  it('empty (no licence): Core, and how to install one', () => {
    state.license = ok({ ...base, edition: 'core', display_name: 'Vista Platform Core', status: 'none', licensed_edition: null, licensee: null, subject: null, expires_at: null, days_left: null, issued_at: null, verified_at: null });
    const html = render();
    expect(html).toContain('Vista Platform Core — no licence installed');
    expect(html).toContain('vistaplatform-license');
    expect(html).toContain(base.install_id!);
    expect(html).not.toContain('Data retention');
  });

  it('default (Enterprise): edition, licensee, expiry, days left — and no warning far from expiry', () => {
    const html = render();
    expect(html).toContain('Vista Platform Enterprise');
    expect(html).toContain('Licensed to Acme Corp');
    expect(html).toContain('Jan 15, 2027');
    expect(html).toContain('Days left');
    expect(html).not.toContain('role="alert"');
  });

  it.each([[30, 30], [20, 30], [14, 14], [9, 14], [7, 7], [1, 7]])('warns at %i days left (threshold %i)', (days, threshold) => {
    state.license = ok({ ...base, days_left: days });
    const html = render();
    expect(html).toContain(`data-warning="${threshold}"`);
    expect(html).toContain(`expires in ${days} day`);
  });

  it('expired: says so and that tenants dropped to Core', () => {
    state.license = ok({ ...base, edition: 'core', display_name: 'Vista Platform Core', status: 'expired', days_left: 0 });
    const html = render();
    expect(html).toContain('Licence expired');
    expect(html).toContain('dropped to Vista Platform Core');
    expect(html).not.toContain('Data retention');
  });

  it('never says "community" or "trial"', () => {
    const html = render().toLowerCase();
    expect(html).not.toContain('community');
    expect(html).not.toContain('trial');
  });
});

describe('data retention (Enterprise only)', () => {
  it('is absent on MSP', () => {
    state.license = ok({ ...base, edition: 'msp', display_name: 'Vista Platform MSP', licensed_edition: 'msp' });
    state.edition = 'msp';
    expect(render()).not.toContain('Data retention');
  });

  it('loading', () => {
    state.retention = { isLoading: true, isError: false, refetch: () => {} };
    expect(render()).toContain('data-testid="retention-loading"');
  });

  it('error', () => {
    state.retention = { isLoading: false, isError: true, refetch: () => {} };
    expect(render()).toContain('Could not read the retention setting');
  });

  it('default: unlimited', () => {
    const html = render();
    expect(html).toContain('Data retention');
    expect(html).toContain('Currently: <strong style="color:var(--op-t1)">Unlimited</strong>');
  });

  it('a cap reads in years when it divides evenly', () => {
    state.retention = ok({ max_days: 2555, applies: true });
    expect(render()).toContain('7 years');
  });

  it('read-only without platform.settings', () => {
    state.canEdit = false;
    const html = render();
    expect(html).toContain('needs the platform.settings permission');
    expect(html).not.toContain('>Save<');
  });
});

describe('MSP usage panel (MSP licences only)', () => {
  const hasUsagePanel = (html: string) =>
    html.includes('Licence usage') || html.includes('Usage reports') || html.includes('Generate report');

  it('renders on an MSP licence, after the licence card', () => {
    state.license = ok({ ...base, edition: 'msp', display_name: 'Vista Platform MSP', licensed_edition: 'msp', max_tenants: 50 });
    state.edition = 'msp';
    const html = render();
    expect(html).toContain('Licence usage');
    expect(html).toContain('Usage reports');
    expect(html).toContain('Generate report');
    expect(html.indexOf('Licence usage')).toBeGreaterThan(html.indexOf('Licensed tenants'));
  });

  it('is absent on Enterprise', () => {
    state.edition = 'enterprise';
    const html = render();
    expect(html).toContain('Vista Platform Enterprise');
    expect(hasUsagePanel(html)).toBe(false);
  });

  it('is absent on Core (no licence)', () => {
    state.license = ok({ ...base, edition: 'core', display_name: 'Vista Platform Core', status: 'none', licensed_edition: null, licensee: null, subject: null, expires_at: null, days_left: null, issued_at: null, verified_at: null });
    state.edition = 'core';
    const html = render();
    expect(html).toContain('Vista Platform Core');
    expect(hasUsagePanel(html)).toBe(false);
  });

  it.each<LicenseState>(['pending', 'unknown'])('is absent while the edition is %s (does not fail open)', (edition) => {
    state.edition = edition;
    expect(hasUsagePanel(render())).toBe(false);
  });
});

describe('retention form helpers', () => {
  it('expiryWarning picks the tightest threshold', () => {
    expect(expiryWarning(null)).toBeNull();
    expect(expiryWarning(31)).toBeNull();
    expect(expiryWarning(30)).toBe(30);
    expect(expiryWarning(14)).toBe(14);
    expect(expiryWarning(7)).toBe(7);
    expect(expiryWarning(0)).toBe(7);
  });
  it('retentionDays validates and converts', () => {
    expect(retentionDays('7', 'years')).toBe(2555);
    expect(retentionDays('400', 'days')).toBe(400);
    expect(retentionDays('0', 'days')).toBeNull();
    expect(retentionDays('101', 'years')).toBeNull();
    expect(retentionDays('1.5', 'years')).toBeNull();
    expect(retentionDays('', 'days')).toBeNull();
  });
  it('retentionForm / retentionLabel round-trip', () => {
    expect(retentionForm(null)).toEqual({ mode: 'unlimited', amount: '', unit: 'years' });
    expect(retentionForm(730)).toEqual({ mode: 'cap', amount: '2', unit: 'years' });
    expect(retentionForm(400)).toEqual({ mode: 'cap', amount: '400', unit: 'days' });
    expect(retentionLabel(365)).toBe('1 year');
    expect(retentionLabel(1)).toBe('1 day');
  });
});

describe('saving the cap', () => {
  it('success: says what retention now is', async () => {
    const save = vi.fn(async (d: number | null) => ({ max_days: d }));
    expect(await submitRetention(save, 2555)).toEqual({ ok: true, message: 'Saved — data retention is now 7 years. Recorded in the audit log.' });
    expect(save).toHaveBeenCalledWith(2555);
    expect((await submitRetention(save, null)).message).toContain('now unlimited');
  });
  it('error: surfaces the server message inline', async () => {
    const save = vi.fn(async () => { throw new Error('retention cap must be a whole number of days'); });
    expect(await submitRetention(save, 5)).toEqual({ ok: false, message: 'retention cap must be a whole number of days' });
  });
});
