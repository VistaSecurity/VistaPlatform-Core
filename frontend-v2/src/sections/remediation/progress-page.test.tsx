// The two pieces of real logic on the Progress page.
//
// `by_category` is the view the producer-aligned categories exist to make
// legible — before the split, four producers shared one bar — so how it is
// ordered and what it hides are product decisions worth pinning.
import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { CategoryBreakdown, formatHours } from './progress-page';

const render = (byCategory: Parameters<typeof CategoryBreakdown>[0]['byCategory']) =>
  renderToStaticMarkup(<CategoryBreakdown byCategory={byCategory} />);

describe('the per-category backlog', () => {
  it('orders by OPEN work, not by total', () => {
    // The page answers "what is left", so a category with 900 closed tickets
    // and 1 open one must not outrank one with 50 still open.
    const html = render({
      lifecycle: { closed: 900, open: 1 },
      crypto: { open: 50 },
    });
    expect(html.indexOf('Cryptography')).toBeLessThan(html.indexOf('End of life'));
  });

  it('hides a category with no tickets at all', () => {
    // The backend returns a row per category it has seen. Rendering an
    // all-zero bar for every one of eleven categories buries the two that
    // matter.
    const html = render({ crypto: { open: 3 }, drift: {} });
    expect(html).toContain('Cryptography');
    expect(html).not.toContain('Drift');
  });

  it('labels a retired category rather than leaving the cell blank', () => {
    // Pre-split rows carry `remediation`. An unlabelled row reads as broken
    // rather than as old.
    expect(render({ remediation: { open: 4 } })).toContain('Remediation');
  });

  it('shows an unrecognised category under its raw key', () => {
    // Better a key the reader can search for than a silently dropped row: a
    // server one release newer than this bundle is the likely cause.
    expect(render({ something_new: { open: 2 } })).toContain('something_new');
  });

  it('says so when there is nothing, rather than rendering an empty frame', () => {
    expect(render({})).toContain('No tickets');
    expect(render(null)).toContain('No tickets');
    expect(render(undefined)).toContain('No tickets');
  });
});

describe('resolution time', () => {
  it('uses the coarsest unit that stays readable', () => {
    expect(formatHours(0.5)).toBe('30m');
    expect(formatHours(3.25)).toBe('3.3h');
    expect(formatHours(47)).toBe('47.0h');
    expect(formatHours(72)).toBe('3.0d');
  });

  it('never renders a resolution time as a bare zero', () => {
    // "0h" reads as instantaneous resolution; minutes are the honest unit.
    expect(formatHours(0.01)).toBe('1m');
  });
});
