// The object pages' routes (DCIM gap 7). One place builds every href, so a
// lens row, a trace hop, a drawer title and the route table cannot drift apart.
import type { Location } from 'react-router';

export type ObjectPageKind = 'prefix' | 'vlan' | 'circuit' | 'cable' | 'interface';

export const OBJECT_PAGE_BASE: Record<ObjectPageKind, string> = {
  prefix: '/inventory/prefixes',
  vlan: '/inventory/vlans',
  circuit: '/inventory/circuits',
  cable: '/inventory/cables',
  interface: '/inventory/interfaces',
};

/** The lens each page's breadcrumb returns to. */
export const OBJECT_PAGE_LENS: Record<ObjectPageKind, { label: string; href: string }> = {
  prefix: { label: 'Networks', href: '/inventory?lens=networks' },
  vlan: { label: 'VLANs', href: '/inventory?lens=vlans' },
  circuit: { label: 'Circuits', href: '/inventory?lens=circuits' },
  cable: { label: 'Cabling', href: '/inventory?lens=cabling' },
  interface: { label: 'Assets', href: '/inventory?lens=assets' },
};

export const objectPageHref = (kind: ObjectPageKind, id: string): string => `${OBJECT_PAGE_BASE[kind]}/${encodeURIComponent(id)}`;
export const prefixHref = (id: string): string => objectPageHref('prefix', id);
export const vlanHref = (id: string): string => objectPageHref('vlan', id);
export const circuitHref = (id: string): string => objectPageHref('circuit', id);
export const cableHref = (id: string): string => objectPageHref('cable', id);
export const interfaceHref = (id: string): string => objectPageHref('interface', id);

/** Router state a link to an object page carries, so Back returns to the lens
 *  with its query string rather than to the lens's defaults. */
export function fromState(loc: Pick<Location, 'pathname' | 'search'>): { from: string } {
  return { from: `${loc.pathname}${loc.search}` };
}

/** The return target: the state's `from` when it is an in-app inventory path,
 *  else the lens default. Anything else (an external URL) is ignored. */
export function backTarget(state: unknown, fallback: string): string {
  const from = (state as { from?: unknown } | null)?.from;
  return typeof from === 'string' && /^\/inventory(?:[/?#]|$)/.test(from) ? from : fallback;
}
