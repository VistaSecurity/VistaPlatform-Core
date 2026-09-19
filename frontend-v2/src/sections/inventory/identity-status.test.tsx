import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { IdentityStatus } from './identity-status';

describe('identity is independent of approval and classification', () => {
  it('does not call a monitored legacy asset established', () => {
    const html = renderToStaticMarkup(<IdentityStatus asset={{ identity_status: 'legacy', asset_status: 'monitoring', class_key: 'server' }} />);
    expect(html).toContain('Legacy — identity not reevaluated');
    expect(html).not.toContain('Identity established');
  });
  it('can establish an unknown type and still show an open conflict', () => {
    const html = renderToStaticMarkup(<IdentityStatus asset={{ identity_status: 'established', class_key: 'unknown_host', has_identity_conflict: true }} />);
    expect(html).toContain('Identity established');
    expect(html).toContain('Identity conflict needs review');
  });
});
