// @vitest-environment jsdom
import { act, createElement } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useDebouncedValue } from './use-debounced-value';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let container: HTMLDivElement;
let root: Root;
const seenBox = { value: '' };

function Probe({ value, delay }: { value: string; delay?: number }) {
  seenBox.value = useDebouncedValue(value, delay ?? 250);
  return null;
}

beforeEach(() => {
  vi.useFakeTimers();
  container = document.createElement('div');
  root = createRoot(container);
});

afterEach(() => {
  act(() => root.unmount());
  vi.useRealTimers();
});

const render = (value: string) => act(() => { root.render(createElement(Probe, { value })); });

describe('useDebouncedValue', () => {
  it('returns the initial value immediately', () => {
    render('a');
    expect(seenBox.value).toBe('a');
  });

  it('only adopts a new value after the delay, and only the last of a burst', () => {
    render('');
    render('a');
    act(() => { vi.advanceTimersByTime(100); });
    render('ab');
    act(() => { vi.advanceTimersByTime(100); });
    render('abc');
    expect(seenBox.value).toBe('');
    act(() => { vi.advanceTimersByTime(249); });
    expect(seenBox.value).toBe('');
    act(() => { vi.advanceTimersByTime(1); });
    expect(seenBox.value).toBe('abc');
  });
});
