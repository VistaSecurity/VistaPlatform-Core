// @vitest-environment jsdom
//
// Risk & Compliance → Posture → Frameworks: the framework cards, MOUNTED.
//
// The stored score behind each card's preview now honours every control's
// population, so "Not assessed" is far more common than it was: a tenant with no
// racks or warranty dates recorded sees most DCIM hygiene controls not assessed
// rather than passing. The card must carry that honestly — a null score is "—",
// never 0 and never 100, and whenever any control was skipped the score comes
// with "N of M controls assessed" beside it.
//
// The pure helpers (formatScore, coverageLine) are unit-tested in
// control-status.test.ts; this proves the CARD uses them. Five states: loading,
// error, empty, scored, and the not-assessed state in both its partial and its
// total form.
//
// jsdom + React's own `act`, no testing-library (as command-palette.jsdom.test.tsx).
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { MemoryRouter } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { AvailableFrameworkRow } from './queries';

type QueryState = { data?: AvailableFrameworkRow[]; isLoading: boolean; isError: boolean };
let state: QueryState = { isLoading: true, isError: false };

vi.mock('./queries', () => ({
  useAvailableFrameworks: () => state,
  useFrameworkDetail: () => ({ data: undefined, isLoading: false, isError: false }),
}));

import { FrameworkBrowser } from './framework-browser';

function row(over: Partial<AvailableFrameworkRow> & { name: string; controls: number }): AvailableFrameworkRow {
  const { name, controls, ...rest } = over;
  return {
    platform_framework: {
      id: `fw-${name.toLowerCase().replace(/\s+/g, '-')}`,
      code: name.toLowerCase().replace(/\s+/g, '-'),
      name,
      version: '1.0',
      description: '',
      organization: 'Vista Platform',
      controls_count: controls,
    },
    is_licensed: true,
    is_platform_default: false,
    ...rest,
  };
}

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

function render(next: QueryState) {
  state = next;
  act(() => {
    root.render(
      <MemoryRouter initialEntries={['/risk-compliance/posture?tab=frameworks']}>
        <FrameworkBrowser />
      </MemoryRouter>,
    );
  });
  return container.textContent ?? '';
}

describe('FrameworkBrowser framework cards', () => {
  it('loading: says so, and shows no card or score', () => {
    const text = render({ isLoading: true, isError: false });
    expect(text).toContain('Loading frameworks');
    expect(text).not.toContain('%');
  });

  it('error: says the catalogue could not be loaded, not that there are no frameworks', () => {
    const text = render({ isLoading: false, isError: true });
    expect(text).toContain("Couldn't load frameworks");
    expect(text).not.toContain('No frameworks activated yet');
  });

  it('empty: no activated frameworks is a first-run state, not a zero score', () => {
    const text = render({ isLoading: false, isError: false, data: [] });
    expect(text).toContain('No frameworks activated yet');
    expect(text).not.toContain('0%');
  });

  it('scored: every control assessed shows the score and no coverage line', () => {
    const text = render({
      isLoading: false, isError: false,
      data: [row({ name: 'Cert Hygiene', controls: 4, preview_score: 75, controls_passing: 3, controls_failing: 1, controls_not_assessed: 0 })],
    });
    expect(text).toContain('Cert Hygiene');
    expect(text).toContain('75%');
    expect(text).toContain('1 failing');
    expect(text).not.toContain('controls assessed');
  });

  it('not assessed, partly: the score comes with the size of the sample behind it', () => {
    // The Gate 3 shape: 15 controls, 7 assessed (2 pass, 5 fail), 8 outside
    // their populations.
    const text = render({
      isLoading: false, isError: false,
      data: [row({ name: 'Inventory Hygiene', controls: 15, preview_score: 25, controls_passing: 2, controls_failing: 5, controls_not_assessed: 8 })],
    });
    expect(text).toContain('25%');
    expect(text).toContain('7 of 15 controls assessed');
  });

  it('not assessed, wholly: a null score renders a dash, never 0% and never 100%', () => {
    const text = render({
      isLoading: false, isError: false,
      data: [row({ name: 'Lifecycle', controls: 4, preview_score: null, controls_passing: 0, controls_failing: 0, controls_not_assessed: 4 })],
    });
    expect(text).toContain('Lifecycle');
    expect(text).toContain('—');
    expect(text).toContain('0 of 4 controls assessed');
    expect(text).not.toContain('0%');
    expect(text).not.toContain('100%');
  });
});
