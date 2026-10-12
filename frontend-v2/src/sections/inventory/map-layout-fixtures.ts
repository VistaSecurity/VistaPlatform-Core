// Seeded random graphs for the layout tests. Not shipped: only tests import it.
import type { LayoutInput } from './map-layout';

const lcg = (seed: number) => {
  let s = seed >>> 0;
  return () => ((s = (Math.imul(s, 1664525) + 1013904223) >>> 0) / 4294967296);
};

/** `n` nodes, `m` random edges. `cyclic` lets edges point either way; otherwise
 *  they only point to a higher index. Depth is the BFS hop from node 0 over the
 *  undirected edges, as the server's `depth` is. */
export function randomGraph(n: number, m: number, cyclic: boolean, seed = 7): LayoutInput {
  const r = lcg(seed);
  const ids = Array.from({ length: n }, (_, i) => `n${String(i).padStart(4, '0')}`);
  const edges: { id: string; source: string; target: string }[] = [];
  const adj: number[][] = ids.map(() => []);
  for (let i = 0; i < m; i++) {
    let a = Math.floor(r() * n);
    let b = Math.floor(r() * n);
    if (!cyclic && a > b) [a, b] = [b, a];
    if (a === b) b = (b + 1) % n;
    edges.push({ id: `e${i}`, source: ids[a], target: ids[b] });
    adj[a].push(b); adj[b].push(a);
  }
  const depth = new Array<number>(n).fill(-1);
  depth[0] = 0;
  const q = [0];
  for (let h = 0; h < q.length; h++) for (const j of adj[q[h]]) if (depth[j] < 0) { depth[j] = depth[q[h]] + 1; q.push(j); }
  return { rootId: ids[0], nodes: ids.map((id, i) => ({ id, depth: Math.max(0, depth[i]) })), edges };
}
