// Tenants ▸ (a tenant) ▸ Edit — billing and trial fields are MSP-only.
//
// On an Enterprise (or Core) licence there is no billing and no trial, so the
// modal must not offer a Payment status select (with its 'trial' option), must
// not demand a billing email (which used to block renaming a tenant that had
// none), must not send either field, and must not point at Plans & Pricing,
// which is hidden there. admin-service 409s a payment_status write off MSP as
// the backstop (ee/msp tenants.go).
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { Tenant } from './queries';

const state = vi.hoisted(() => ({ license: 'enterprise' }));

vi.mock('../../lib/edition', () => ({
  usePlatformEdition: () => ({ license: state.license, isMsp: state.license === 'msp', has: () => true }),
}));
vi.mock('./queries', async (orig) => {
  const real = await orig<typeof import('./queries')>();
  return { ...real, useUpdateTenant: () => ({ mutate: vi.fn(), isPending: false }) };
});
vi.mock('react-hot-toast', () => ({ default: Object.assign(vi.fn(), { success: vi.fn(), error: vi.fn() }) }));

const { TenantFormModal, tenantFormError, tenantUpdateBody } = await import('./tenant-form-modal');

const tenant = {
  id: '11111111-1111-4111-8111-111111111111', name: 'Acme', slug: 'acme', domain: null,
  subscription_tier_id: null, billing_email: '', payment_status: 'active', stripe_customer_id: null,
  sso_enabled: false, is_active: true, custom_branding: null, ui_config: null, settings: null,
  created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', deleted_at: null,
} as unknown as Tenant;

const render = () => renderToStaticMarkup(createElement(TenantFormModal, { tenant, onClose: () => {} }));

beforeEach(() => { state.license = 'enterprise'; });

describe('TenantFormModal — render by licence', () => {
  it('Enterprise: name and domain only; no payment status, no trial, no billing email, no Plans & Pricing', () => {
    const html = render();
    expect(html).toContain('Name');
    expect(html).toContain('Domain');
    expect(html).not.toContain('Payment status');
    expect(html.toLowerCase()).not.toContain('trial');
    expect(html).not.toContain('Billing email');
    expect(html).not.toContain('Plans &amp; Pricing');
    expect(html).toContain('Entitlements tab');
  });

  it('Core licence on the ee build: same as Enterprise', () => {
    state.license = 'core';
    const html = render();
    expect(html).not.toContain('Payment status');
    expect(html).not.toContain('Billing email');
  });

  it('MSP: billing email and payment status (with trial) are offered', () => {
    state.license = 'msp';
    const html = render();
    expect(html).toContain('Billing email');
    expect(html).toContain('Payment status');
    expect(html).toContain('<option value="trial">');
    expect(html).toContain('Plans &amp; Pricing');
  });
});

describe('tenantFormError', () => {
  const v = { name: 'Acme', domain: '', billingEmail: '', paymentStatus: 'active' };
  it('does not require a billing email off MSP (a tenant without one can be renamed)', () => {
    expect(tenantFormError(v, false)).toBeNull();
  });
  it('still requires one on MSP', () => {
    expect(tenantFormError(v, true)).toBe('A valid billing email is required');
    expect(tenantFormError({ ...v, billingEmail: 'billing@acme.test' }, true)).toBeNull();
  });
  it('requires a name everywhere', () => {
    expect(tenantFormError({ ...v, name: ' ' }, false)).toBe('Name is required');
  });
});

describe('tenantUpdateBody', () => {
  const changed = { name: 'Acme Two', domain: '', billingEmail: 'b@acme.test', paymentStatus: 'trial' };
  it('off MSP sends neither billing_email nor payment_status, even when edited', () => {
    expect(tenantUpdateBody(tenant, changed, false)).toEqual({ name: 'Acme Two' });
  });
  it('on MSP sends the changed billing fields', () => {
    expect(tenantUpdateBody(tenant, changed, true)).toEqual({ name: 'Acme Two', billing_email: 'b@acme.test', payment_status: 'trial' });
  });
  it('sends nothing unchanged', () => {
    expect(tenantUpdateBody(tenant, { name: 'Acme', domain: '', billingEmail: '', paymentStatus: 'active' }, true)).toEqual({});
  });
});
