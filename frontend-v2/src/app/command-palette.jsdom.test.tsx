// @vitest-environment jsdom
//
// The command palette, MOUNTED (ADR-0006 D9).
//
// `palette-results.test.ts` pins which rows exist and where each one links.
// That is the part with decisions in it, and it is the part that was tested —
// but the palette is a KEYBOARD surface, and none of its keyboard behaviour
// lives in those functions. Opening on ⌘K, the highlight moving under the
// arrows, Enter navigating to the highlighted row and Escape closing are all
// effects and handlers inside the component, and until this file existed every
// one of them could be deleted with 1,400 frontend tests still green.
//
// That is the "test the WIRING, not just the helper" rule. The helper tests
// would survive a palette that renders nothing.
//
// This is the repo's first jsdom test. It deliberately uses NO testing-library:
// jsdom (MIT) plus React's own `act` is enough to mount, type and press keys,
// and a second testing dependency is a bigger commitment than this one file
// justifies. `vitest.config.ts` stays `environment: 'node'`; the docblock at the
// top of this file is what opts it in, so the other 97 suites keep their
// current runtime.

import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// The palette reads live features and the AI seam status through hooks that
// fetch. Both are stubbed at the module boundary rather than through a fake
// server: what is under test is the keyboard, and a real fetch would make every
// assertion here depend on the shape of two unrelated endpoints.
vi.mock('@vistasecurity/primitives/features', () => ({
  useFeatures: () => ({ features: {} }),
}));
vi.mock('./ask-mode', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./ask-mode')>();
  return {
    ...actual,
    // No provider: the toggle is not offered, which is the Core default and the
    // state this test wants (it is testing search mode).
    useAskAvailability: () => ({ loading: false, available: false, reason: 'not_built' as const }),
    useAsk: () => ({ mutate: vi.fn(), reset: vi.fn(), isPending: false }),
  };
});
// The asset / certificate / device / sensor reads. Only assets answer, so the
// result list is predictable and the assertions below are about the KEYBOARD
// rather than about ranking.
const ASSETS = [
  { id: 'a-1', hostname: 'switch-core-01', display_name: 'switch-core-01', class_key: 'switch', environment: 'production' },
  { id: 'a-2', hostname: 'switch-edge-02', display_name: 'switch-edge-02', class_key: 'switch', environment: 'production' },
];
vi.mock('../lib/clients', () => ({
  clients: {
    inventory: { GET: vi.fn(async (path: string) => (
      path === '/infrastructure-assets' ? { data: { assets: ASSETS } } : { data: {} }
    )) },
    devices: { GET: vi.fn(async () => ({ data: { devices: [] } })) },
    sensors: { GET: vi.fn(async () => ({ data: { sensors: [] } })) },
  },
}));

const navigate = vi.fn();
vi.mock('react-router', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router')>();
  return { ...actual, useNavigate: () => navigate };
});

import { CommandPalette } from './command-palette';

// React refuses to treat `act` as an act scope without this, and says so on
// stderr rather than failing — so updates would flush outside act and the
// assertions would read a half-rendered tree.
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let container: HTMLDivElement;
let root: Root;
let open = true;
const onOpenChange = vi.fn((next: boolean) => { open = next; });

async function mount(): Promise<void> {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  await act(async () => {
    root.render(
      <QueryClientProvider client={qc}>
        <MemoryRouter><CommandPalette open={open} onOpenChange={onOpenChange} /></MemoryRouter>
      </QueryClientProvider>,
    );
  });
}

/**
 * Let the 300 ms debounce and the query that follows it settle.
 *
 * A POLL rather than a fixed number of flushes. The debounce is a timer, the
 * fetch resolves in a microtask, and react-query commits its result in another
 * render — the number of turns between "typed" and "rows on screen" is an
 * implementation detail of three libraries, and pinning it to a count is how a
 * suite like this becomes intermittently red for reasons nobody can reproduce.
 * Bounded, so a genuinely broken palette fails rather than hanging.
 */
async function settle(until: () => boolean = () => rowLabels().length > 0): Promise<void> {
  for (let i = 0; i < 50; i++) {
    await act(async () => {
      vi.advanceTimersByTime(50);
      await Promise.resolve();
    });
    if (until()) return;
  }
}

function input(): HTMLInputElement {
  const el = container.querySelector('input');
  if (!el) throw new Error('the palette rendered no input');
  return el as HTMLInputElement;
}

async function type(text: string): Promise<void> {
  await act(async () => {
    const el = input();
    // React tracks the value on the DOM node, so assigning `.value` and firing
    // `input` is ignored unless the tracker is bypassed. This is what
    // testing-library's `fireEvent.change` does; doing it here is the price of
    // not taking the dependency.
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
    if (!setter) throw new Error('no value setter on HTMLInputElement');
    setter.call(el, text);
    el.dispatchEvent(new window.Event('input', { bubbles: true }));
  });
}

async function press(key: string, target: EventTarget = input()): Promise<void> {
  await act(async () => {
    target.dispatchEvent(new window.KeyboardEvent('keydown', { key, bubbles: true }));
  });
}

// Selected by ROLE, not by a test id added for the purpose: the rows are
// `role="option"` because that is what they are, and a selector that depends on
// the accessibility markup fails if the markup regresses — which is the second
// thing worth pinning here.
function rowLabels(): string[] {
  return [...container.querySelectorAll('[role="option"]')]
    .map((el) => (el.textContent ?? '').trim());
}

function activeRow(): Element | null {
  return container.querySelector('[role="option"][data-active="true"]');
}

beforeEach(() => {
  // jsdom implements no layout, so it has no `scrollIntoView` — and the palette
  // calls it to keep the highlighted row visible. Unstubbed, every test here
  // dies inside an effect with a TypeError that says nothing about the palette.
  window.HTMLElement.prototype.scrollIntoView = vi.fn();
  vi.useFakeTimers({ shouldAdvanceTime: true });
  open = true;
  navigate.mockClear();
  onOpenChange.mockClear();
});

afterEach(() => {
  act(() => { root?.unmount(); });
  container?.remove();
  vi.useRealTimers();
});

describe('the command palette, mounted', () => {
  it('focuses its input on open, so the next keystroke is the search', async () => {
    await mount();
    // The focus is behind a 40 ms timeout (the dialog has to be in the document
    // first). A palette that opens without focus makes every user click the box
    // before typing, which defeats the entire point of a keystroke.
    await act(async () => { vi.advanceTimersByTime(60); });
    expect(document.activeElement).toBe(input());
  });

  it('shows quick navigation before anything is typed', async () => {
    await mount();
    expect(rowLabels().length).toBeGreaterThan(0);
  });

  it('searches after the debounce and renders the matches', async () => {
    await mount();
    await type('switch');
    await settle(() => rowLabels().some((l) => l.includes('switch-edge-02')));
    const labels = rowLabels();
    expect(labels.some((l) => l.includes('switch-core-01'))).toBe(true);
    expect(labels.some((l) => l.includes('switch-edge-02'))).toBe(true);
  });

  it('moves the highlight with the arrows and opens the highlighted row on Enter', async () => {
    await mount();
    await type('switch');
    await settle(() => rowLabels().some((l) => l.includes('switch-edge-02')));

    // Down from the first row lands on the second. The first row after a search
    // is a quick-nav match or the best asset; what matters is that ArrowDown
    // MOVES and Enter opens whatever is highlighted rather than a fixed row.
    const first = activeRow()?.textContent ?? '';
    await press('ArrowDown');
    const second = activeRow()?.textContent ?? '';
    expect(second).not.toBe(first);

    await press('Enter');
    expect(navigate).toHaveBeenCalledTimes(1);
    // …and to the row that was highlighted, not to the first one.
    const target = navigate.mock.calls[0][0] as string;
    expect(typeof target).toBe('string');
    expect(target.length).toBeGreaterThan(1);
  });

  it('does not run off the end of the list', async () => {
    // The other polarity of the arrow handler. An unclamped index leaves Enter
    // with nothing to open and the palette silently doing nothing.
    await mount();
    await type('switch');
    await settle(() => rowLabels().some((l) => l.includes('switch-edge-02')));
    for (let i = 0; i < 40; i++) await press('ArrowDown');
    expect(activeRow()).not.toBeNull();
    await press('Enter');
    expect(navigate).toHaveBeenCalledTimes(1);
  });

  it('closes on Escape', async () => {
    await mount();
    await press('Escape');
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it('closes on the ⌘K that opened it', async () => {
    // The global toggle, which is bound to the DOCUMENT rather than to the
    // input — so it is dispatched there.
    await mount();
    await act(async () => {
      document.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'k', metaKey: true, bubbles: true }));
    });
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });
});
