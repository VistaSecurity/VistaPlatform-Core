// The map's layout, off the main thread when it is big enough to matter.
//
// `layoutGraph` is a synchronous dagre run. On a small neighbourhood that is a
// few milliseconds and a `useMemo` is the right tool; near the server's cap
// (500 nodes / 2000 edges) it is SECONDS, during which the tab ignores input.
// Past `WORKER_THRESHOLD` the work moves to a module worker. Where there is no
// `Worker` (jsdom, tests) or the worker fails to start or throws, the same
// function runs inline, so behaviour never depends on the worker being there.
import { useEffect, useMemo, useRef, useState } from 'react';
import { FORCE_LAYOUT_THRESHOLD, layoutGraph, type LayoutDirection, type LayoutInput, type LayoutResult } from './map-layout';
import type { LayoutResponse } from './map-layout.worker';

/** Nodes + edges above which layout goes to the worker. A dagre run at this size
 *  is already tens of milliseconds; below it the postMessage round trip is the
 *  larger cost. */
export const WORKER_THRESHOLD = FORCE_LAYOUT_THRESHOLD;

const EMPTY: LayoutResult = { positions: {}, width: 0, height: 0 };

export const shouldUseWorker = (g: LayoutInput, workerAvailable = typeof Worker !== 'undefined'): boolean =>
  workerAvailable && g.nodes.length + g.edges.length > WORKER_THRESHOLD;

interface Settled { graph: LayoutInput; direction: LayoutDirection; result: LayoutResult }

export function useMapLayout(
  graph: LayoutInput,
  direction: LayoutDirection,
): { layout: LayoutResult; pending: boolean } {
  const [failed, setFailed] = useState(false);
  const offThread = !failed && shouldUseWorker(graph);

  const inline = useMemo(
    () => (offThread ? null : layoutGraph(graph, direction)),
    [offThread, graph, direction],
  );

  const [settled, setSettled] = useState<Settled | null>(null);
  const worker = useRef<Worker | null>(null);
  const seq = useRef(0);

  useEffect(() => {
    if (!offThread) return;
    let w = worker.current;
    if (!w) {
      try {
        w = new Worker(new URL('./map-layout.worker.ts', import.meta.url), { type: 'module' });
      } catch {
        // Not a synchronous setState in the effect body: report it next tick.
        queueMicrotask(() => setFailed(true));
        return;
      }
      worker.current = w;
    }
    const mine = ++seq.current;
    w.onmessage = ({ data }: MessageEvent<LayoutResponse>) => {
      // A newer request is in flight: this answer is for a graph or direction
      // the user has already moved on from.
      if (data.seq !== seq.current) return;
      if ('error' in data) { setFailed(true); return; }
      setSettled({ graph, direction, result: data.result });
    };
    w.onerror = () => setFailed(true);
    w.postMessage({
      seq: mine,
      direction,
      graph: {
        nodes: graph.nodes.map((n) => ({ id: n.id, depth: (n as { depth?: number }).depth })),
        edges: graph.edges.map((e) => ({ id: e.id, source: e.source, target: e.target })),
      },
    });
  }, [offThread, graph, direction]);

  useEffect(() => () => { worker.current?.terminate(); worker.current = null; }, []);

  if (inline) return { layout: inline, pending: false };
  const current = settled !== null && settled.graph === graph && settled.direction === direction;
  // While a run is in flight the last finished layout stays on screen, so a
  // direction flip does not blank the canvas.
  return { layout: settled?.result ?? EMPTY, pending: !current };
}
