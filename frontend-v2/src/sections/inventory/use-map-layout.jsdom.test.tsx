// @vitest-environment jsdom
//
// Layout moves to a worker past WORKER_THRESHOLD, and never depends on it:
// no `Worker` (jsdom, old browsers) or a worker that errors falls back to the
// same inline `layoutGraph`, with identical positions.
import { act, useEffect } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { layoutGraph, type LayoutDirection, type LayoutInput, type LayoutResult } from './map-layout';
import { WORKER_THRESHOLD, shouldUseWorker, useMapLayout } from './use-map-layout';
import type { LayoutRequest, LayoutResponse } from './map-layout.worker';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const graphOf = (n: number): LayoutInput => ({
  nodes: Array.from({ length: n }, (_, i) => ({ id: `n${i}` })),
  edges: Array.from({ length: n - 1 }, (_, i) => ({ id: `e${i}`, source: `n${Math.floor(i / 2)}`, target: `n${i + 1}` })),
});

let mode: 'ok' | 'error' = 'ok';
const created: FakeWorker[] = [];
const queue: Array<() => void> = [];
class FakeWorker {
  onmessage: ((ev: { data: LayoutResponse }) => void) | null = null;
  onerror: (() => void) | null = null;
  terminated = false;
  constructor() { created.push(this); }
  postMessage(req: LayoutRequest): void {
    // Held until `flush()`, so "in flight" is observable without a timing race.
    queue.push(() => {
      if (mode === 'error') { this.onerror?.(); return; }
      this.onmessage?.({ data: { seq: req.seq, result: layoutGraph(req.graph, req.direction) } });
    });
  }
  terminate(): void { this.terminated = true; }
}

let host: HTMLDivElement;
let root: Root;
let last: { layout: LayoutResult; pending: boolean };

function Probe({ graph, direction }: { graph: LayoutInput; direction: LayoutDirection }) {
  const out = useMapLayout(graph, direction);
  useEffect(() => { last = out; });
  return null;
}
const flush = () => act(async () => { queue.splice(0).forEach((reply) => reply()); await Promise.resolve(); });

beforeEach(() => {
  mode = 'ok';
  created.length = 0;
  queue.length = 0;
  vi.stubGlobal('Worker', FakeWorker);
  host = document.createElement('div');
  root = createRoot(host);
});
afterEach(() => {
  act(() => root.unmount());
  vi.unstubAllGlobals();
});

it('stays inline below the threshold', async () => {
  const g = graphOf(10);
  await act(async () => { root.render(<Probe graph={g} direction="LR" />); });
  expect(created).toHaveLength(0);
  expect(last.pending).toBe(false);
  expect(last.layout).toEqual(layoutGraph(g, 'LR'));
});

it('lays a big graph out in the worker and returns the same positions', async () => {
  const g = graphOf(WORKER_THRESHOLD);
  expect(shouldUseWorker(g)).toBe(true);
  await act(async () => { root.render(<Probe graph={g} direction="LR" />); });
  expect(created).toHaveLength(1);
  expect(last.pending).toBe(true);
  await flush();
  expect(last.pending).toBe(false);
  expect(last.layout).toEqual(layoutGraph(g, 'LR'));

  // A direction flip keeps the last layout up while the new one is computed.
  await act(async () => { root.render(<Probe graph={g} direction="TB" />); });
  expect(last.pending).toBe(true);
  expect(Object.keys(last.layout.positions)).toHaveLength(g.nodes.length);
  await flush();
  expect(last.pending).toBe(false);
  expect(last.layout).toEqual(layoutGraph(g, 'TB'));
  expect(created).toHaveLength(1); // one worker, reused
});

it('falls back to inline layout when there is no Worker', async () => {
  vi.stubGlobal('Worker', undefined);
  const g = graphOf(WORKER_THRESHOLD);
  await act(async () => { root.render(<Probe graph={g} direction="LR" />); });
  expect(last.pending).toBe(false);
  expect(last.layout).toEqual(layoutGraph(g, 'LR'));
});

it('falls back to inline layout when the worker errors', async () => {
  mode = 'error';
  const g = graphOf(WORKER_THRESHOLD);
  await act(async () => { root.render(<Probe graph={g} direction="LR" />); });
  await flush();
  expect(last.pending).toBe(false);
  expect(last.layout).toEqual(layoutGraph(g, 'LR'));
});

it('terminates the worker on unmount', async () => {
  const g = graphOf(WORKER_THRESHOLD);
  await act(async () => { root.render(<Probe graph={g} direction="LR" />); });
  act(() => root.unmount());
  expect(created[0].terminated).toBe(true);
  root = createRoot(host); // afterEach unmounts again
});

it('the worker module answers a request with layoutGraph\'s result', async () => {
  const posted: LayoutResponse[] = [];
  const g = graphOf(8);
  vi.stubGlobal('self', Object.assign(Object.create(globalThis), { postMessage: (m: LayoutResponse) => posted.push(m) }));
  await import('./map-layout.worker');
  const handler = (self as unknown as { onmessage: (ev: { data: LayoutRequest }) => void }).onmessage;
  handler({ data: { seq: 7, graph: g, direction: 'TB' } });
  expect(posted).toEqual([{ seq: 7, result: layoutGraph(g, 'TB') }]);
});
