// Licence-edition gating of the operator navigation (edition-licensing spec §6).
//
// The build cannot tell Enterprise from MSP — one ee binary serves both — so a
// third gate reads the LICENCE: Plans & Pricing is hidden on Enterprise (no
// plans there; Core keeps tier authoring), Billing & Revenue only shows on MSP.
// Both directions are pinned, over the REAL SECTIONS registry, plus the
// pending/unknown rules and the resolver that turns the API answer into them.
//
// Mutations run against this file (each turns a case red):
//   - drop `license: 'not-enterprise'` from Plans            → Enterprise keeps Plans
//   - drop `license: 'msp'` from Billing                     → Enterprise keeps Billing
//   - licenseAllows treats 'unknown' as closed               → fail-open case
//   - visibleSections ignores the licence argument           → every Enterprise case
import { describe, expect, it } from 'vitest';
import { SECTIONS, licenseAllows, visibleSections, type NavItem } from './nav';
import { resolveEditionState, type EditionCapabilities, type LicenseState } from '../lib/edition';

const EE_BUILD: EditionCapabilities = { msp: true, billing: true };
const CORE_BUILD: EditionCapabilities = { msp: false, billing: false };
const all = () => true;
const ids = (sections: NavItem[]) => sections.map((s) => s.id);
const nav = (license: LicenseState, caps: EditionCapabilities = EE_BUILD) => ids(visibleSections(all, caps, SECTIONS, license));

describe('Enterprise licence', () => {
  it('hides Plans & Pricing and Billing & Revenue', () => {
    const got = nav('enterprise');
    expect(got).not.toContain('plans');
    expect(got).not.toContain('billing');
  });
  it('keeps the tenant directory and every other section', () => {
    const got = nav('enterprise');
    for (const id of ['overview', 'tenants', 'support', 'settings', 'security']) expect(got).toContain(id);
  });
});

describe('MSP licence', () => {
  it('offers Plans & Pricing and Billing & Revenue', () => {
    const got = nav('msp');
    expect(got).toContain('plans');
    expect(got).toContain('billing');
  });
});

describe('Core (no licence)', () => {
  it('keeps tier authoring but has no billing', () => {
    expect(nav('core', CORE_BUILD)).toContain('plans');
    expect(nav('core', CORE_BUILD)).not.toContain('billing');
    // An ee build with no licence installed: the billing CODE is present, but
    // nobody is licensed to bill.
    expect(nav('core', EE_BUILD)).not.toContain('billing');
    expect(nav('core', EE_BUILD)).toContain('plans');
  });
});

describe('pending and unknown', () => {
  it('hides licence-gated entries until the read-out lands', () => {
    const got = nav('pending');
    expect(got).not.toContain('plans');
    expect(got).not.toContain('billing');
  });
  it('fails open when the licence could not be read', () => {
    const got = nav('unknown');
    expect(got).toContain('plans');
    expect(got).toContain('billing');
  });
  it('never gates an unmarked entry', () => {
    for (const l of ['pending', 'unknown', 'core', 'enterprise', 'msp'] as LicenseState[]) {
      expect(licenseAllows({}, l)).toBe(true);
    }
  });
});

describe('Settings → License & Usage', () => {
  it('is offered on every edition', () => {
    for (const l of ['core', 'enterprise', 'msp'] as LicenseState[]) {
      const settings = visibleSections(all, EE_BUILD, SECTIONS, l).find((s) => s.id === 'settings');
      expect(settings?.children?.map((c) => c.id)).toContain('license');
    }
  });
});

describe('resolveEditionState — the licence half', () => {
  const caps = { msp: true, billing: true };
  it('reads license_edition', () => {
    expect(resolveEditionState({ edition: 'enterprise', capabilities: caps, license_edition: 'enterprise' }, false).license).toBe('enterprise');
    const msp = resolveEditionState({ edition: 'enterprise', capabilities: caps, license_edition: 'msp' }, false);
    expect(msp.license).toBe('msp');
    expect(msp.isMsp).toBe(true);
  });
  it('is pending before the answer and unknown on failure or a null licence', () => {
    expect(resolveEditionState(undefined, false).license).toBe('pending');
    expect(resolveEditionState(undefined, false).isMsp).toBe(false);
    expect(resolveEditionState(undefined, true).license).toBe('unknown');
    expect(resolveEditionState({ edition: 'enterprise', capabilities: caps, license_edition: null }, false).license).toBe('unknown');
    // An older admin-service that does not send the field at all.
    expect(resolveEditionState({ edition: 'enterprise', capabilities: caps }, false).license).toBe('unknown');
  });
  it('isMsp is false on Enterprise and Core', () => {
    expect(resolveEditionState({ edition: 'enterprise', capabilities: caps, license_edition: 'enterprise' }, false).isMsp).toBe(false);
    expect(resolveEditionState({ edition: 'core', capabilities: caps, license_edition: 'core' }, false).isMsp).toBe(false);
  });
});
