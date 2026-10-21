// Physical cabling on the map (DCIM BUILD_PLAN row 3.6; asset-inventory
// ADR-0006 D4, ADR-0010 D6). Pure, like `map-model.ts`: which cable runs are
// drawn, how they read, and what "Show physical path" does for a relationship.
//
// A relationship is a LOGICAL claim (this switch talks to that server); a
// cable path is the PHYSICAL run row 3.2 computed (Gi1/0/1 → patch panel →
// patch panel → eth0). The map draws both, in different styles, and lets a
// person go from the first to the second.
import type { inventoryComponents } from '@vistasecurity/api-contract';
import type { Neighbourhood } from './relationships';
import { cableHref } from './object-pages/object-links';
import type { MapEdge } from './map-model';

export type NeighbourhoodCablePath = inventoryComponents['schemas']['NeighbourhoodCablePath'];

/** One cable run as the map draws it. */
export interface MapCablePath {
  /** `cable:<id>` — never a relationship uuid, so the two edge sets cannot collide. */
  id: string;
  source: string;
  target: string;
  cableId: string;
  cableLabel: string;
  /** A proposal nobody has approved (row 3.3): drawn dashed. */
  pending: boolean;
  /** Not every cable on the run is `connected` (planned, decommissioning). */
  notConnected: boolean;
  operationalStatus: string;
  fromInterfaceId: string;
  fromInterfaceName: string;
  toInterfaceId: string;
  toInterfaceName: string;
  cableCount: number;
  patchPanelCount: number;
  circuitCount: number;
  /** "Gi1/0/1 ↔ eth0". */
  label: string;
}

/** The cable colour: the accent, which no class group or relationship uses. */
export const CABLE_EDGE_COLOR = 'var(--accent)';
export const CABLE_EDGE_WIDTH = 3.2;
export const CABLE_EDGE_DASH = '7 5';

export const CABLE_EDGE_PREFIX = 'cable:';
export const isCableEdgeId = (id: string): boolean => id.startsWith(CABLE_EDGE_PREFIX);

/** The runs between nodes that are on the graph. A run to a node the cap
 *  removed would be a line into empty space. */
export function buildMapCablePaths(nbh: Neighbourhood | undefined, nodeIds: ReadonlySet<string>): MapCablePath[] {
  const out: MapCablePath[] = [];
  const seen = new Set<string>();
  for (const c of nbh?.cable_paths ?? []) {
    if (!c?.id || seen.has(c.id)) continue;
    if (!nodeIds.has(c.from_asset_id) || !nodeIds.has(c.to_asset_id)) continue;
    seen.add(c.id);
    out.push({
      id: `${CABLE_EDGE_PREFIX}${c.id}`,
      source: c.from_asset_id,
      target: c.to_asset_id,
      cableId: c.cable_id,
      cableLabel: c.cable_label ?? '',
      pending: c.status === 'pending',
      notConnected: c.operational_status !== 'connected',
      operationalStatus: c.operational_status,
      fromInterfaceId: c.from_interface_id,
      fromInterfaceName: c.from_interface_name,
      toInterfaceId: c.to_interface_id,
      toInterfaceName: c.to_interface_name,
      cableCount: c.cable_count,
      patchPanelCount: c.patch_panel_count,
      circuitCount: c.circuit_count,
      label: `${c.from_interface_name} ↔ ${c.to_interface_name}`,
    });
  }
  return out;
}

const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;

/** "3 cables through 2 patch panels", "1 cable, direct". */
export function cablePathSummary(c: Pick<MapCablePath, 'cableCount' | 'patchPanelCount' | 'circuitCount'>): string {
  const via: string[] = [];
  if (c.patchPanelCount > 0) via.push(plural(c.patchPanelCount, 'patch panel', 'patch panels'));
  if (c.circuitCount > 0) via.push(plural(c.circuitCount, 'circuit', 'circuits'));
  const cables = plural(c.cableCount, 'cable', 'cables');
  return via.length ? `${cables} through ${via.join(' and ')}` : `${cables}, direct`;
}

/** What a cable run's status line says. Proposed and not-connected both qualify it. */
export function cablePathState(c: Pick<MapCablePath, 'pending' | 'notConnected' | 'operationalStatus'>): string {
  const parts: string[] = [];
  if (c.pending) parts.push('Proposed — awaiting approval');
  if (c.notConnected) parts.push(`Not connected (${c.operationalStatus})`);
  return parts.length ? parts.join(' · ') : 'Connected';
}

/**
 * The cabling layer's state. `null` is "the person has not touched it", which
 * means ON when there is anything to draw — a map with cables on it shows them
 * — and off (and disabled) when there is nothing.
 */
export function cablingLayerOn(choice: boolean | null, count: number): boolean {
  if (count === 0) return false;
  return choice ?? true;
}

/** Where "Show physical path" goes for a relationship, or why it cannot. */
export type PhysicalPathTarget =
  | { enabled: true; interfaceId: string; interfaceName: string }
  | { enabled: false; reason: string };

/**
 * The trace starts at the FROM interface the observation named; when only the
 * far end's port is known the trace runs from there instead (a cable path reads
 * the same from either end). With neither there is no port to trace from, and
 * the action says so instead of guessing.
 */
export function physicalPathTarget(edge: Pick<MapEdge, 'synthetic' | 'fromInterfaceId' | 'fromInterfaceName' | 'toInterfaceId' | 'toInterfaceName'>): PhysicalPathTarget {
  if (edge.synthetic) {
    return { enabled: false, reason: 'This line is drawn from a recorded cloud region, not observed on a port.' };
  }
  if (edge.fromInterfaceId) return { enabled: true, interfaceId: edge.fromInterfaceId, interfaceName: edge.fromInterfaceName ?? 'interface' };
  if (edge.toInterfaceId) return { enabled: true, interfaceId: edge.toInterfaceId, interfaceName: edge.toInterfaceName ?? 'interface' };
  return { enabled: false, reason: 'No interface is known for this relationship, so there is no port to trace from.' };
}

/** This cable's own page (`/inventory/cables/:id`). */
export const cableLensHref = (cableId: string): string => cableHref(cableId);
