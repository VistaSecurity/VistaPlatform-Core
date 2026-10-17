// A prefix's gateway, and whether a sensor reaches it ( slice C; DCIM row
// 1.6: networks are IPAM prefixes).
//
// Interrogating a router records which prefixes it is the gateway of. Four
// surfaces read that record — the asset page's "Networks routed" card, the
// "via <gateway>" line on a host's Overview, the prefix panel on Inventory →
// Networks, and the network row on Inventory → Map — and every decision they
// share lives here, pure and unit-tested, so the four can never disagree about
// what "no gateway" or "no sensor" means.
//
// Three rules this file keeps:
//
//   - **A gateway is never guessed.** It is what a device reported about
//     itself. `null` from the API (nobody reported it, or that device has since
//     been deleted) is "gateway not recorded" — never the network's `.1`.
//   - **A null coverage is an answer.** Every prefix is a CIDR, so `coverage:
//     null` means no tenant sensor reaches it — a warning, not an error.
//   - **Absent is not empty.** `routed_prefixes: []` says the asset routes
//     nothing; an ABSENT `routed_prefixes` on the single-asset read says the
//     server could not work it out. The two must never render alike.
import type { Asset, inventoryComponents } from '@vistasecurity/api-contract';
import { relativeSeen, stripMask } from './asset-shape';
import { assetTabPath, DEFAULT_ASSET_TAB } from './asset-tabs';
import { prefixDrillThroughQuery, topologyAssetsHref } from './topology-model';

export type PrefixGateway = inventoryComponents['schemas']['PrefixGateway'];
export type PrefixCoverage = inventoryComponents['schemas']['PrefixCoverage'];
export type RoutedPrefix = inventoryComponents['schemas']['RoutedPrefix'];
export type FHRPGroupRef = inventoryComponents['schemas']['FHRPGroupRef'];

/** Where a gateway's name links: its asset page. */
export function gatewayHref(g: Pick<PrefixGateway, 'asset_id'>): string {
  return assetTabPath(g.asset_id, DEFAULT_ASSET_TAB);
}

/** A gateway's own address, without a host mask (`/32`, `/128`). */
export function gatewayAddress(g: Pick<PrefixGateway, 'address'>): string {
  return stripMask(g.address);
}

/** The name a gateway is shown by. The server already falls back from display
 *  name to hostname to address; this only covers a blank it might still send. */
export function gatewayName(g: Pick<PrefixGateway, 'display_name' | 'address'>): string {
  const name = (g.display_name ?? '').trim();
  return name || gatewayAddress(g) || 'Unnamed device';
}

/** When an interrogation last reported a gateway on a network, for a hover:
 *  "Reported by an interrogation 3d ago", or '' when the time is unreadable. */
export function reportedText(observedAt: string | null | undefined): string {
  const ago = relativeSeen(observedAt);
  return ago ? `Reported by an interrogation ${ago}` : '';
}

/** The words for a network with no recorded gateway, and the hover that says
 *  what they mean. Shared so the map and the settings table say the same thing. */
export const GATEWAY_NOT_RECORDED = 'gateway not recorded';
export const GATEWAY_NOT_RECORDED_TITLE =
  "No device has reported being this network's gateway. Interrogate the router that serves it and it is recorded here.";

// ------------------------------------------------------------- coverage ----

export type CoverageNote =
  | { kind: 'sensor'; text: string; sensorId: string }
  | { kind: 'none'; text: string; title: string };

export const NO_SENSOR_TEXT = 'No sensor on this network';
export const NO_SENSOR_TITLE =
  'No sensor can reach this network, so hosts here are known from the gateway and relayed traffic only. Deploy a sensor with an interface on it to observe it directly.';

/**
 * What a prefix's coverage note says. A null is a real answer: no sensor
 * reaches it. That is a warning, not an error: nothing failed, the network is
 * simply observed second-hand.
 */
export function coverageNote(coverage: PrefixCoverage | null | undefined): CoverageNote {
  if (coverage) {
    const name = (coverage.sensor_name ?? '').trim() || 'unnamed sensor';
    return { kind: 'sensor', text: `Sensor: ${name}`, sensorId: coverage.sensor_id };
  }
  return { kind: 'none', text: NO_SENSOR_TEXT, title: NO_SENSOR_TITLE };
}

// ------------------------------------------------------- routed networks ----

export type RoutedNetworks =
  | { state: 'error' }
  | { state: 'none' }
  | { state: 'rows'; rows: RoutedPrefix[] };

/**
 * The "Networks routed" card's state, from the single-asset read.
 *
 * `none` hides the card (spec §1: shown only when the asset is the gateway of
 * at least one network). `error` is an absent field — the server could not
 * read the asset's routed networks — and gets a visible note rather than an
 * empty card that would read as "routes nothing".
 */
export function routedNetworks(asset: Pick<Asset, 'routed_prefixes'>): RoutedNetworks {
  const rows = asset.routed_prefixes;
  if (!Array.isArray(rows)) return { state: 'error' };
  if (rows.length === 0) return { state: 'none' };
  return { state: 'rows', rows };
}

/** A routed network's VLAN cell. A prefix with no VLAN is untagged, so it says
 *  that rather than a dash. */
export function vlanText(vlanId: number | null | undefined): string {
  return typeof vlanId === 'number' ? String(vlanId) : 'Untagged';
}

/** A routed network's DHCP cell. Three-valued: null is "nobody has said". */
export function dhcpText(dynamic: boolean | null | undefined): string {
  if (dynamic === true) return 'DHCP';
  if (dynamic === false) return 'Static';
  return 'Unknown';
}

/** The Inventory query a routed network's host count links to — the topology
 *  tree's own `prefix_id:` drill-through, so the count and the list agree. */
export function routedHostsHref(row: Pick<RoutedPrefix, 'prefix_id'>): string {
  return topologyAssetsHref(prefixDrillThroughQuery({ prefix_id: row.prefix_id }));
}

// ------------------------------------------------------------------- via ----

/**
 * The gateway a host reaches its network through, or null.
 *
 * The server omits `prefix_gateway` when the prefix has no gateway, when it
 * could not be read, and when this asset IS that gateway. The id check repeats
 * the last rule on this side: a router whose Overview said "via <itself>" would
 * be the one place this feature told the user something untrue.
 */
export function viaGateway(asset: Pick<Asset, 'id' | 'prefix_gateway'>): PrefixGateway | null {
  const g = asset.prefix_gateway;
  if (!g || !g.asset_id) return null;
  if (g.asset_id === asset.id) return null;
  return g;
}

/**
 * The FHRP group (VRRP, HSRP, …) whose virtual address is in the host's own
 * prefix, or null — the address the host actually routes through when the
 * gateway is a redundant pair.
 */
export function viaFHRPGroup(asset: Pick<Asset, 'prefix_fhrp_group'>): FHRPGroupRef | null {
  const g = asset.prefix_fhrp_group;
  return g && g.virtual_address ? g : null;
}

/** An FHRP group as "VRRP 10 (192.0.2.254)". */
export function fhrpText(g: Pick<FHRPGroupRef, 'protocol' | 'group_id' | 'virtual_address'>): string {
  const proto = (g.protocol ?? '').replace(/\d+$/, '').toUpperCase() || 'FHRP';
  // The virtual address is stored with its prefix length (192.0.2.254/24);
  // the line names the address hosts route to, so the length is dropped.
  const host = (g.virtual_address ?? '').split('/')[0];
  return `${proto} ${g.group_id} (${host})`;
}
