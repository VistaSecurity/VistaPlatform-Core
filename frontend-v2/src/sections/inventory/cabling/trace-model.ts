// The cable trace, as the view draws it (DCIM BUILD_PLAN row 3.4). Pure: the
// server's path (`steps`, one per cable crossed: near end, cable, far end) is
// turned into a left-to-right hop sequence — port, cable, port, then the hop
// INSIDE a device (a patch panel's front → rear, a circuit's A → Z) before the
// next cable — and into the "copy as text" form.
import type { CablePath, CablePathNode, CablePaths } from './cabling-queries';

export type Hop =
  | { type: 'ports'; nodes: CablePathNode[]; far: boolean }
  | { type: 'cable'; nodes: CablePathNode[] }
  | { type: 'through'; label: string };

const KIND_WORD: Record<string, string> = {
  interface: 'interface',
  front_port: 'front port',
  rear_port: 'rear port',
  console_port: 'console port',
  console_server_port: 'console server port',
  circuit_termination: 'circuit termination',
  provider_network: 'provider network',
  power_port: 'power port',
  power_outlet: 'power outlet',
  power_feed: 'power feed',
};

export const kindWord = (kind: string): string => KIND_WORD[kind] ?? kind.replace(/_/g, ' ');

/** "core-sw-1:Gi1/0/1", a circuit end by its own name, a cable by its label. */
export function nodeText(n: CablePathNode): string {
  if (n.kind === 'cable') return n.name;
  if (n.asset_name) return `${n.asset_name}:${n.name}`;
  if (n.power_panel_name) return `${n.power_panel_name}:${n.name}`;
  return n.name;
}

/** What happens inside a device between two cables. */
function throughLabel(prev: CablePathNode[], next: CablePathNode[]): string {
  const a = prev[0];
  const b = next[0];
  if (!a || !b) return 'through';
  if (a.kind === 'front_port' && b.kind === 'rear_port') return 'front → rear';
  if (a.kind === 'rear_port' && b.kind === 'front_port') return 'rear → front';
  if (a.kind === 'circuit_termination' && b.kind === 'circuit_termination') return 'circuit';
  if (b.kind === 'provider_network') return 'provider network';
  // Row 6.1: a PDU's outlet draws from the PDU's own inlet.
  if (a.kind === 'power_outlet' && b.kind === 'power_port') return 'outlet → inlet';
  return 'through';
}

/** The hop sequence of one path. The last port group is the far end. */
export function pathHops(p: CablePath): Hop[] {
  const out: Hop[] = [];
  p.steps.forEach((s, i) => {
    if (i === 0) out.push({ type: 'ports', nodes: s.near_end, far: false });
    else out.push({ type: 'through', label: throughLabel(p.steps[i - 1].far_end, s.near_end) }, { type: 'ports', nodes: s.near_end, far: false });
    if (s.cables.length > 0) out.push({ type: 'cable', nodes: s.cables });
    if (s.far_end.length > 0) out.push({ type: 'ports', nodes: s.far_end, far: false });
  });
  // Collapse a step that repeats the previous far end as its near end (a
  // dangling last step names the same port again).
  const dedup: Hop[] = [];
  for (const h of out) {
    const prev = dedup[dedup.length - 1];
    if (h.type === 'ports' && prev?.type === 'ports' && sameNodes(prev.nodes, h.nodes)) continue;
    if (h.type === 'ports' && prev?.type === 'through') {
      const before = dedup[dedup.length - 2];
      if (before?.type === 'ports' && sameNodes(before.nodes, h.nodes)) { dedup.pop(); continue; }
    }
    dedup.push(h);
  }
  for (let i = dedup.length - 1; i >= 0; i--) {
    const h = dedup[i];
    if (h.type === 'ports') {
      dedup[i] = { ...h, far: true };
      break;
    }
  }
  return dedup;
}

function sameNodes(a: CablePathNode[], b: CablePathNode[]): boolean {
  return a.length === b.length && a.every((n, i) => n.id === b[i].id);
}

/** Whether a node is the path's destination (drawn highlighted). */
export function isDestination(p: CablePath, n: CablePathNode): boolean {
  return !!p.destination && p.destination.id === n.id;
}

/** The path's one-line state. */
export function pathState(p: CablePath): string {
  const parts: string[] = [];
  parts.push(p.is_complete ? 'complete' : 'incomplete');
  if (!p.is_active) parts.push('not every cable is connected');
  if (p.is_split) parts.push('splits — cannot be followed as one');
  return parts.join(' · ');
}

/** "Copy as text": one line per hop, a blank line between paths. */
export function traceText(t: CablePaths): string {
  if (t.paths.length === 0) return `${nodeText(t.object)}: not cabled`;
  return t.paths.map((p, i) => {
    const lines = [`Path ${i + 1} from ${nodeText(p.origin)} (${pathState(p)})`];
    for (const h of pathHops(p)) {
      if (h.type === 'ports') lines.push(`  ${h.far ? '◉' : '○'} ${h.nodes.map(nodeText).join(', ')} [${kindWord(h.nodes[0]?.kind ?? '')}]`);
      else if (h.type === 'cable') {
        const c = h.nodes[0];
        const bits = [c?.type, c?.operational_status, c?.color ? `#${c.color}` : null].filter(Boolean).join(', ');
        lines.push(`  │ cable ${h.nodes.map(nodeText).join(', ')}${bits ? ` (${bits})` : ''}`);
      } else lines.push(`  ↓ ${h.label}`);
    }
    if (p.destination) lines.push(`  → far end: ${nodeText(p.destination)}`);
    return lines.join('\n');
  }).join('\n\n');
}
