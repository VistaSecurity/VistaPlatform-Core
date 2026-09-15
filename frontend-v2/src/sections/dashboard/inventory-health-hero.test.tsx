// The Inventory health hero, RENDERED (ADR-0006 D5, workstream 3.8).
//
// `inventory-health.test.ts` pins the arithmetic; this pins the markup that
// consumes it, and the two are not the same guard. The arithmetic returning
// `null` for a facet level that failed is worth nothing if the JSX then prints
// `value ?? 0` — and until this file existed, that exact edit passed all 1264
// frontend tests. It is the "test the WIRING, not just the helper" rule: the
// honesty rules D5 turns on live in the component, so they are asserted against
// the component.
//
// No jsdom and no testing-library: `renderToStaticMarkup` is enough to read
// what a tile prints, the query cache is SEEDED rather than fetched (so no
// network and no act() dance), and nothing here needs an effect to have run.
import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router';
import { InventoryHealthHero } from './inventory-health-hero';
import { HYGIENE_FRAMEWORK_CODE } from './inventory-health';

/** The hero's two query keys, spelled as the hooks spell them. */
const FACET_KEY = ['inventory', 'assets', 'facets', '', 'class,status,stale_status'];
const HYGIENE_KEY = ['posture', 'available-frameworks'];

type Facets = { buckets: Record<string, { value: string; count: number; label?: string }[]>; failed: string[] };

function render(facets: Facets, frameworks: unknown[]): string {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(FACET_KEY, facets);
  qc.setQueryData(HYGIENE_KEY, frameworks);
  return renderToStaticMarkup(
    <QueryClientProvider client={qc}>
      <MemoryRouter><InventoryHealthHero /></MemoryRouter>
    </QueryClientProvider>,
  );
}

/** What the element carrying this testid printed, tags stripped. */
function textOf(html: string, testId: string): string {
  const open = html.indexOf(`data-testid="${testId}"`);
  if (open < 0) return '';
  const start = html.indexOf('>', open) + 1;
  return html.slice(start, html.indexOf('<', start));
}

const healthy: Facets = {
  buckets: {
    class: [
      { value: 'hardware', count: 40, label: 'Hardware' },
      { value: 'hardware.computer.server', count: 30, label: 'Server' },
      { value: 'service', count: 12, label: 'Service' },
    ],
    status: [{ value: 'monitoring', count: 48 }, { value: 'pending_approval', count: 4 }],
    stale_status: [{ value: 'active', count: 52 }],
  },
  failed: [],
};

const scored = [{
  platform_framework: { code: HYGIENE_FRAMEWORK_CODE },
  is_licensed: true, preview_score: 82,
  controls_passing: 9, controls_failing: 2, controls_not_assessed: 1,
}];

describe('a count whose facet level FAILED', () => {
  it('prints an em dash, never a zero', () => {
    // The whole reason `bucketCount` is three-valued. A hero tile reading
    // "0 stale" off a request that never answered is an assertion about the
    // tenant's data made on no evidence, and zero is the most reassuring thing
    // this tile can say.
    const html = render({ ...healthy, failed: ['stale_status'] }, scored);
    expect(textOf(html, 'hero-count-stale')).toBe('—');
    expect(textOf(html, 'hero-count-stale')).not.toBe('0');
    // …and it says so rather than leaving the dash to be interpreted.
    expect(html).toContain("Couldn&#x27;t load");
  });

  it('still prints the levels that DID answer', () => {
    // One facet failing must not blank the rail, or the hero.
    const html = render({ ...healthy, failed: ['stale_status'] }, scored);
    expect(textOf(html, 'hero-count-pending')).toBe('4');
  });
});

describe('a count whose facet level answered with nothing', () => {
  it('prints 0 — the other polarity', () => {
    // "We looked and there are none" is a real answer and must stay a number.
    // A component that dashed both would be honest about nothing and useless
    // about everything.
    expect(textOf(render(healthy, scored), 'hero-count-stale')).toBe('0');
  });
});

describe('the headline total', () => {
  it('is the sum of the ROOT classes, not of every bucket', () => {
    // 40 + 12 = 52. Summing all three buckets gives 82 for an estate of 52,
    // because `hardware.computer.server` is already inside `hardware`.
    expect(textOf(render(healthy, scored), 'hero-total')).toBe('52');
  });

  it('is an em dash when the class level failed', () => {
    expect(textOf(render({ ...healthy, failed: ['class'] }, scored), 'hero-total')).toBe('—');
  });
});

describe('the data-quality score', () => {
  it('reads "Not assessed" when the engine has produced none', () => {
    // Null both before the first evaluation and after one in which no control
    // could be assessed. Neither is 100% and neither is 0 — and the
    // gauge must not be on screen at all, because a gauge IS a number.
    const html = render(healthy, [{
      platform_framework: { code: HYGIENE_FRAMEWORK_CODE }, is_licensed: true, preview_score: null,
    }]);
    expect(html).toContain('data-testid="hygiene-not-assessed"');
    expect(html).not.toContain('data-testid="hygiene-score"');
    expect(html).toContain('Not assessed');
  });

  it('renders the gauge when there IS a score', () => {
    const html = render(healthy, scored);
    expect(html).toContain('data-testid="hygiene-score"');
    expect(html).not.toContain('data-testid="hygiene-not-assessed"');
    // The coverage split, including the third bucket at whatever it is: a
    // coverage line that omitted "not assessed" would read as "everything was
    // checked".
    expect(html).toContain('not assessed');
  });

  it('says the framework is ABSENT rather than scoring it', () => {
    const html = render(healthy, [{ platform_framework: { code: 'pqc-readiness' }, is_licensed: true, preview_score: 40 }]);
    expect(html).toContain('data-testid="hygiene-absent"');
    expect(html).not.toContain('data-testid="hygiene-score"');
  });
});

describe('the hero links out', () => {
  it('offers the topology at its deep-linkable URL', () => {
    expect(render(healthy, scored)).toContain('/inventory?lens=map&amp;view=topology');
  });

  it('sends a class bar to the list of exactly what it counted', () => {
    expect(render(healthy, scored)).toContain('query=class%3Ahardware');
  });
});
