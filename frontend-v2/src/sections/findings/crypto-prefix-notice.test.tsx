import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { CryptoLoadedPrefixNotice } from './bits';

describe('CryptoLoadedPrefixNotice', () => {
  it('states the loaded and total units and scopes every local operation', () => {
    const html = renderToStaticMarkup(<CryptoLoadedPrefixNotice loaded={500} total={2000} />);

    expect(html).toContain('data-testid="crypto-loaded-prefix-notice"');
    expect(html).toContain('first <strong>500</strong> of <strong>2000</strong> crypto configurations');
    expect(html).toContain('Filters, CSV export, and bulk actions apply to loaded rows');
  });

  it('renders nothing when the loaded rows are complete', () => {
    expect(renderToStaticMarkup(<CryptoLoadedPrefixNotice loaded={42} total={42} />)).toBe('');
  });
});
