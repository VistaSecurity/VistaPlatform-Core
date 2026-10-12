import { renderToStaticMarkup } from 'react-dom/server';
import { expect, it } from 'vitest';
import { ShownOfNotice } from './shown-of-notice';

it('says how many of how many are shown when the list is capped', () => {
  const html = renderToStaticMarkup(<ShownOfNotice shown={100} total={340} noun="configurations" />);
  expect(html).toContain('data-testid="shown-of-notice"');
  expect(html).toContain('Showing <strong>100</strong> of <strong>340</strong> configurations');
});

it('renders nothing when everything is shown', () => {
  expect(renderToStaticMarkup(<ShownOfNotice shown={5} total={5} noun="findings" />)).toBe('');
});
