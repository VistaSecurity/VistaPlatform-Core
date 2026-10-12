// Runs `layoutGraph` off the main thread (see `use-map-layout.ts`).
//
// Dagre on a graph near the server's 500-node / 2000-edge cap takes seconds, and
// done inline that is seconds of dead input on every depth or direction change.
// The module is pure (no React, no xyflow), which is what lets it run here
// unchanged.
import { layoutGraph, type LayoutDirection, type LayoutInput, type LayoutResult } from './map-layout';

export interface LayoutRequest {
  seq: number;
  graph: LayoutInput;
  direction: LayoutDirection;
}

export type LayoutResponse =
  | { seq: number; result: LayoutResult }
  | { seq: number; error: string };

const scope = self as unknown as {
  onmessage: ((ev: { data: LayoutRequest }) => void) | null;
  postMessage: (msg: LayoutResponse) => void;
};

scope.onmessage = ({ data }) => {
  try {
    scope.postMessage({ seq: data.seq, result: layoutGraph(data.graph, data.direction) });
  } catch (err) {
    scope.postMessage({ seq: data.seq, error: err instanceof Error ? err.message : String(err) });
  }
};
