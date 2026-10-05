// A network's gateway, and whether a sensor reaches it ( slice C).
//
// Interrogating a router records which networks it is the gateway of. Four
// surfaces read that record — the asset page's "Networks routed" card, the
// "via <gateway>" line on a host's Overview, the Gateway and Coverage columns on
// Settings → Network Segments, and the network row on Inventory → Map — and
// every decision they share lives here, pure and unit-tested, so the four can
// never disagree about what "no gateway" or "no sensor" means.
//
// Three rules this file keeps:
//
//   - **A gateway is never guessed.** It is what a device reported about
//     itself. `null` from the API (nobody reported it, or that device has since
//     been deleted) is "gateway not recorded" — never the network's `.1`.
//   - **Coverage only applies to a CIDR network.** The server always sends
//     `coverage: null` on a range, domain or cloud network, where "which sensor
//     reaches it" has no meaning; reading that null as "no sensor" would tell
//     the user to fix something that is not broken.
//   - **Absent is not empty.** `routed_segments: []` says the asset routes
//     nothing; an ABSENT `routed_segments` on the single-asset read says the
//     server could not work it out. The two must never render alike.
import type { Asset, inventoryComponents } from '@vistasecurity/api-contract';
import { relativeSeen, stripMask } from './asset-shape';
import { assetTabPath, DEFAULT_ASSET_TAB } from './asset-tabs';
import { segmentDrillThroughQuery, topologyAssetsHref } from './topology-model';

export type SegmentGateway = inventoryComponents['schemas']['SegmentGateway'];
export type SegmentCoverage = inventoryComponents['schemas']['SegmentCoverage'];
export type RoutedSegment = inventoryComponents['schemas']['RoutedSegment'];

/** Where a gateway's name links: its asset page. */
export function gatewayHref(g: Pick<SegmentGateway, 'asset_id'>): string {
  return assetTabPath(g.asset_id, DEFAULT_ASSET_TAB);
}

/** A gateway's own address, without a host mask (`/32`, `/128`). */
export function gatewayAddress(g: Pick<SegmentGateway, 'address'>): string {
  return stripMask(g.address);
}

/** The name a gateway is shown by. The server already falls back from display
 *  name to hostname to address; this only covers a blank it might still send. */
export function gatewayName(g: Pick<SegmentGateway, 'display_name' | 'address'>): string {
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
  | { kind: 'none'; text: string; title: string }
  | { kind: 'not-applicable' };

export const NO_SENSOR_TEXT = 'No sensor on this network';
export const NO_SENSOR_TITLE =
  'No sensor can reach this network, so hosts here are known from the gateway and relayed traffic only. Deploy a sensor with an interface on it to observe it directly.';

/**
 * What a network's coverage note says.
 *
 * `not-applicable` for anything but a CIDR network — the server sends null
 * there by contract, and that null is not a gap. On a CIDR network a null is a
 * real answer: no sensor reaches it. That is a warning, not an error: nothing
 * failed, the network is simply observed second-hand.
 */
export function coverageNote(segmentType: string, coverage: SegmentCoverage | null | undefined): CoverageNote {
  if (segmentType !== 'cidr') return { kind: 'not-applicable' };
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
  | { state: 'rows'; rows: RoutedSegment[] };

/**
 * The "Networks routed" card's state, from the single-asset read.
 *
 * `none` hides the card (spec §1: shown only when the asset is the gateway of
 * at least one network). `error` is an absent field — the server could not
 * read the asset's routed networks — and gets a visible note rather than an
 * empty card that would read as "routes nothing".
 */
export function routedNetworks(asset: Pick<Asset, 'routed_segments'>): RoutedNetworks {
  const rows = asset.routed_segments;
  if (!Array.isArray(rows)) return { state: 'error' };
  if (rows.length === 0) return { state: 'none' };
  return { state: 'rows', rows };
}

/** A routed network's VLAN cell. A null tag is what the device reported for an
 *  untagged network, so it says that rather than a dash. */
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
 *  tree's own `segment_id:` drill-through, so the count and the list agree. */
export function routedHostsHref(row: Pick<RoutedSegment, 'segment_id'>): string {
  return topologyAssetsHref(segmentDrillThroughQuery({ segment_id: row.segment_id }));
}

// ------------------------------------------------------------------- via ----

/**
 * The gateway a host reaches its network through, or null.
 *
 * The server omits `segment_gateway` when the segment has no gateway, when it
 * could not be read, and when this asset IS that gateway. The id check repeats
 * the last rule on this side: a router whose Overview said "via <itself>" would
 * be the one place this feature told the user something untrue.
 */
export function viaGateway(asset: Pick<Asset, 'id' | 'segment_gateway'>): SegmentGateway | null {
  const g = asset.segment_gateway;
  if (!g || !g.asset_id) return null;
  if (g.asset_id === asset.id) return null;
  return g;
}
