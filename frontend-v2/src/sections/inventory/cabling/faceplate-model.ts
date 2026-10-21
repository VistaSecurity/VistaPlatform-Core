// The faceplate, as data (DCIM BUILD_PLAN row 3.4). Pure: which ports are
// drawn, in what order, in which rows, and what colour their state is.
//
// Order: the device type's template order (2.2), else natural name order
// (Gi1/0/2 before Gi1/0/10), the order the interface list already uses. A port
// with no template (added by hand, or discovered) goes after the templated ones.
import { INTERFACE_TYPE_GROUP, type InterfaceType } from '@vistasecurity/primitives/dcim';
import type { CableTerminationKind, CableIndex } from '../dcim/cable-queries';
import type { Interface } from '../dcim/interface-queries';

/** The faceplate's port kinds, one row group each, in faceplate order. */
export const FACEPLATE_KINDS = ['interface', 'console_port', 'console_server_port', 'front_port', 'rear_port', 'power_port', 'power_outlet'] as const;
export type FaceplateKind = (typeof FACEPLATE_KINDS)[number];

export const FACEPLATE_KIND_LABEL: Record<FaceplateKind, string> = {
  interface: 'Interfaces',
  console_port: 'Console ports',
  console_server_port: 'Console server ports',
  front_port: 'Front ports',
  rear_port: 'Rear ports',
  power_port: 'Power ports',
  power_outlet: 'Power outlets',
};

/** The device type's template route per kind (row 2.2). */
export const TEMPLATE_ROUTE: Record<FaceplateKind, string> = {
  interface: 'interface-templates',
  console_port: 'console-port-templates',
  console_server_port: 'console-server-port-templates',
  front_port: 'front-port-templates',
  rear_port: 'rear-port-templates',
  power_port: 'power-port-templates',
  power_outlet: 'power-outlet-templates',
};

export type PortState = 'up' | 'down' | 'disabled' | 'unknown' | 'passive';

export const PORT_STATE_LABEL: Record<PortState, string> = {
  up: 'Up',
  down: 'Down',
  disabled: 'Disabled',
  unknown: 'State not reported',
  passive: 'Passive (no link state)',
};

/** Fill tone per state when the crypto overlay is off. */
export const PORT_STATE_COLOR: Record<PortState, string> = {
  up: 'var(--ok)',
  down: 'var(--danger-text)',
  disabled: 'var(--app-t3)',
  unknown: 'var(--app-panel2)',
  passive: 'var(--app-panel2)',
};

export interface FacePort {
  kind: FaceplateKind;
  id: string;
  name: string;
  label: string | null;
  type: string;
  state: PortState;
  cableId: string | null;
  markConnected: boolean;
}

/** An interface's drawn state: disabled (declared) wins over the measured one. */
export function interfaceState(i: Pick<Interface, 'enabled' | 'operational_status'>): PortState {
  if (!i.enabled) return 'disabled';
  if (i.operational_status === 'up') return 'up';
  if (i.operational_status === 'down') return 'down';
  return 'unknown';
}

/** Virtual, wireless and cellular interfaces are not sockets on a faceplate. */
export function isPhysicalInterface(type: string): boolean {
  const g = INTERFACE_TYPE_GROUP[type as InterfaceType];
  return g !== 'virtual' && g !== 'wireless' && g !== 'cellular';
}

const CHUNK = /(\d+)|(\D+)/g;

/** Natural order: digit runs compare as numbers. */
export function naturalCompare(a: string, b: string): number {
  const pa = a.match(CHUNK) ?? [];
  const pb = b.match(CHUNK) ?? [];
  for (let i = 0; i < Math.min(pa.length, pb.length); i++) {
    const x = pa[i];
    const y = pb[i];
    if (x === y) continue;
    const nx = /^\d+$/.test(x);
    const ny = /^\d+$/.test(y);
    if (nx && ny) {
      const d = Number(x) - Number(y);
      if (d !== 0) return d;
      continue;
    }
    return x < y ? -1 : 1;
  }
  return pa.length - pb.length;
}

/** Ports in template order (by template name), then the rest naturally. */
export function orderPorts<T extends { name: string }>(ports: readonly T[], templateNames: readonly string[] | null | undefined): T[] {
  const rank = new Map((templateNames ?? []).map((n, i) => [n, i]));
  return [...ports].sort((a, b) => {
    const ra = rank.get(a.name);
    const rb = rank.get(b.name);
    if (ra !== undefined && rb !== undefined) return ra - rb;
    if (ra !== undefined) return -1;
    if (rb !== undefined) return 1;
    return naturalCompare(a.name, b.name);
  });
}

/** Ports per faceplate row: a 48-port switch draws as two rows of 24. */
export const PORTS_PER_ROW = 24;

export function faceplateRows<T>(ports: readonly T[], perRow = PORTS_PER_ROW): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < ports.length; i += perRow) out.push(ports.slice(i, i + perRow));
  return out;
}

/** A port's short face label: the last number in its name ("Gi1/0/24" → "24"). */
export function shortLabel(name: string): string {
  const m = name.match(/(\d+)(?!.*\d)/);
  return m ? m[1] : name.slice(0, 3);
}

export type CableMark = 'none' | 'cabled' | 'pending' | 'planned' | 'marked';

/** How a port's cable is drawn: a solid dot, a dashed (proposed or planned)
 *  cable, "marked connected", or nothing. */
export function cableMark(p: Pick<FacePort, 'id' | 'cableId' | 'markConnected'>, cables: CableIndex | undefined): CableMark {
  const end = cables?.get(p.id);
  if (end) {
    if (end.cable.status === 'pending') return 'pending';
    if (end.cable.operational_status !== 'connected') return 'planned';
    return 'cabled';
  }
  if (p.cableId) return 'cabled';
  if (p.markConnected) return 'marked';
  return 'none';
}

export const toTerminationKind = (k: FaceplateKind): CableTerminationKind => k;
