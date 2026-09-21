import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { IdentityStatus } from './identity-status';

describe('identity is independent of approval and classification', () => {
  it('does not call a monitored legacy asset established', () => {
    const html = renderToStaticMarkup(<IdentityStatus asset={{ identity_status: 'legacy', asset_status: 'monitoring', class_key: 'server' }} />);
    expect(html).toContain('Identity not evaluated');
    expect(html).not.toContain('Identity established');
  });
  // D8 fixes this string. The journey test
  // (cross-vlan-provisional.jsdom.test.tsx) drives it through three pages; this
  // one pins the words themselves, because "unverified" is the half a
  // well-meaning tidy-up removes first.
  it('says a provisional item is unverified, not merely pending', () => {
    const html = renderToStaticMarkup(<IdentityStatus asset={{ identity_status: 'provisional', asset_status: 'pending_approval', class_key: 'printer' }} />);
    expect(html).toContain('Provisional identity — unverified');
    expect(html).toContain('data-identity="provisional"');
    expect(html).not.toContain('Identity established');
  });
  it('marks only provisional items, so the badge means something', () => {
    const html = renderToStaticMarkup(<IdentityStatus asset={{ identity_status: 'established' }} />);
    expect(html).not.toContain('data-identity');
    expect(html).not.toContain('Provisional');
  });
  it('can establish an unknown type and still show an open conflict', () => {
    const html = renderToStaticMarkup(<IdentityStatus asset={{ identity_status: 'established', class_key: 'unknown_host', has_identity_conflict: true }} />);
    expect(html).toContain('Identity established');
    expect(html).toContain('Identity conflict needs review');
  });
});
