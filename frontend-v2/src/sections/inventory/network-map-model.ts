// The Network view's model (feature: network-crypto-map).
//
// The map lens's third view: every live asset placed by site and network, each
// device marked by the crypto it serves. Everything with a decision in it lives
// here, PURE and unit-tested — which site and tray an asset lands in, what
// colour its badge is, which crypto traits the By-crypto view groups on — and
// `network-map-view.tsx` is the markup.
//
// Two rules this file exists to keep:
//
//   - **No second opinion about crypto.** Strength and post-quantum status come
//     from the server, which reads the algorithm catalogue and the one PQC
//     classifier. Nothing here decides an algorithm is weak from its name.
//   - **Unknown is not zero.** A risk score of 0 that nothing assessed is "not
//     assessed", drawn neutral, never the green of a real low score.
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { ASSET_CLASSES, type AssetClassKey } from '@vistasecurity/primitives/assets';
import { riskLevelFromScore, strengthRank, type RiskLevel } from '@vistasecurity/primitives/ratings';
import { ICON_NAMES } from '../../components/ui/icon';
import { LEVEL_COLOR } from '../../components/ui/risk';
import { CLASS_GROUP_STYLES, classGroupOf, type ClassGroupKey } from './map-model';

export type NetworkMap = inventoryComponents['schemas']['NetworkMap'];
export type NetworkMapAsset = inventoryComponents['schemas']['NetworkMapAsset'];
export type NetworkMapSegment = inventoryComponents['schemas']['NetworkMapSegment'];
export type NetworkMapComponent = inventoryComponents['schemas']['NetworkMapComponent'];

// ------------------------------------------------------------ view state ---

export const NETWORK_VIEWS = ['funnel', 'circuit', 'radial', 'crypto'] as const;
export type NetworkView = (typeof NETWORK_VIEWS)[number];

export const NETWORK_VIEW_LABEL: Readonly<Record<NetworkView, string>> = {
  funnel: 'Funnel',
  circuit: 'Circuit',
  radial: 'Radial',
  crypto: 'By crypto',
};

/** Sites (summary cards) → Networks (counts) → Devices (every device). */
export type Zoom = 0 | 1 | 2;
export const ZOOM_LABEL: readonly string[] = ['Sites', 'Networks', 'Devices'];

export type ColourMode = 'risk' | 'pqc';

export interface NetworkMapPrefs {
  view: NetworkView;
  zoom: Zoom;
  colour: ColourMode;
  onlyCrypto: boolean;
}

/** Below this many assets the whole estate fits on screen, so the map opens on
 *  every device; at or above it, on the site summary (D1). */
export const DEVICES_ZOOM_BELOW = 100;

/** The opening state for an estate of `totalAssets`, before any saved choice. */
export function defaultPrefs(totalAssets: number): NetworkMapPrefs {
  return {
    view: 'funnel',
    zoom: totalAssets < DEVICES_ZOOM_BELOW ? 2 : 0,
    colour: 'risk',
    onlyCrypto: false,
  };
}

/**
 * Read saved prefs, keeping only fields that are still valid values.
 *
 * Saved state outlives releases: a view renamed or removed in a later build
 * must fall back to the default rather than render nothing, so each field is
 * checked on its own and the rest of a stale record is still honoured.
 */
export function parsePrefs(raw: unknown, fallback: NetworkMapPrefs): NetworkMapPrefs {
  if (!raw || typeof raw !== 'object') return fallback;
  const r = raw as Record<string, unknown>;
  return {
    view: (NETWORK_VIEWS as readonly unknown[]).includes(r.view) ? (r.view as NetworkView) : fallback.view,
    zoom: r.zoom === 0 || r.zoom === 1 || r.zoom === 2 ? r.zoom : fallback.zoom,
    colour: r.colour === 'risk' || r.colour === 'pqc' ? r.colour : fallback.colour,
    onlyCrypto: typeof r.onlyCrypto === 'boolean' ? r.onlyCrypto : fallback.onlyCrypto,
  };
}

// ------------------------------------------------------------- grouping ----

/** The server's label for an asset with no site — shared with the topology
 *  tree and the facet rail, which name it the same way. */
export const UNASSIGNED_SITE = 'Unassigned';

export type SiteKind = 'site' | 'cloud' | 'unassigned';

export interface Tray {
  key: string;
  name: string;
  /** The CIDR / range / cloud reference, or a line saying why there is none. */
  detail: string;
  segmentId: string | null;
  assets: NetworkMapAsset[];
}

export interface SiteGroup {
  key: string;
  name: string;
  kind: SiteKind;
  trays: Tray[];
  /** Every asset in every tray, in tray order. */
  assets: NetworkMapAsset[];
}

const UNSEGMENTED_TRAY = '~unsegmented~';

/**
 * Place every asset in a site and a tray (D2).
 *
 * - A physical site groups by the network segment each asset is assigned to.
 *   No subnet is inferred from an address: a device the data files in the
 *   wrong segment is drawn in the wrong segment, because a map that quietly
 *   corrected the data would hide the thing that needs fixing.
 * - An asset with no segment sits in an explicit **Unsegmented** tray.
 * - An asset with no site but a recorded cloud account is grouped under that
 *   account, one tray per region — a cloud account is where a cloud resource
 *   lives, and "Unassigned" would lump every account together.
 * - Everything else with no site is **Unassigned**, last.
 *
 * Sites are ordered biggest first with Unassigned last; trays likewise with
 * Unsegmented last. Ties break on the name, so the order is total and the map
 * does not reshuffle between renders.
 */
export function groupSites(map: NetworkMap | undefined, assets: readonly NetworkMapAsset[]): SiteGroup[] {
  const segments = new Map((map?.segments ?? []).map((s) => [s.segment_id, s]));
  const sites = new Map<string, { name: string; kind: SiteKind; trays: Map<string, Tray> }>();

  for (const a of assets) {
    const account = (a.cloud_account ?? '').trim();
    const site = (a.site ?? '').trim() || UNASSIGNED_SITE;
    let siteKey: string;
    let siteName: string;
    let kind: SiteKind;
    if (site === UNASSIGNED_SITE && account) {
      siteKey = `cloud:${account}`;
      siteName = `Cloud account ${account}`;
      kind = 'cloud';
    } else if (site === UNASSIGNED_SITE) {
      siteKey = `site:${UNASSIGNED_SITE}`;
      siteName = 'No site recorded';
      kind = 'unassigned';
    } else {
      siteKey = `site:${site}`;
      siteName = site;
      kind = 'site';
    }
    let group = sites.get(siteKey);
    if (!group) {
      group = { name: siteName, kind, trays: new Map() };
      sites.set(siteKey, group);
    }

    let trayKey: string;
    let tray: Omit<Tray, 'assets'>;
    const seg = a.segment_id ? segments.get(a.segment_id) : undefined;
    if (a.segment_id) {
      trayKey = a.segment_id;
      tray = {
        key: trayKey,
        // A segment id the segments list does not carry (deactivated since the
        // asset was placed) still gets its own tray rather than merging into
        // Unsegmented — the asset IS assigned, to a network this answer does
        // not describe.
        name: seg?.name ?? 'Inactive network',
        detail: seg?.value ?? 'Not an active segment',
        segmentId: a.segment_id,
      };
    } else if (kind === 'cloud') {
      const region = (a.cloud_region ?? '').trim();
      trayKey = `region:${region}`;
      tray = { key: trayKey, name: region || 'No region recorded', detail: region ? 'Cloud region' : '', segmentId: null };
    } else {
      trayKey = UNSEGMENTED_TRAY;
      tray = { key: trayKey, name: 'Unsegmented', detail: 'No network assigned', segmentId: null };
    }
    let t = group.trays.get(trayKey);
    if (!t) {
      t = { ...tray, assets: [] };
      group.trays.set(trayKey, t);
    }
    t.assets.push(a);
  }

  const byName = (x: string, y: string) => (x < y ? -1 : x > y ? 1 : 0);
  const out: SiteGroup[] = [...sites.entries()].map(([key, g]) => {
    const trays = [...g.trays.values()].sort((x, y) => {
      const xu = x.key === UNSEGMENTED_TRAY ? 1 : 0;
      const yu = y.key === UNSEGMENTED_TRAY ? 1 : 0;
      return xu - yu || y.assets.length - x.assets.length || byName(x.name, y.name);
    });
    return { key, name: g.name, kind: g.kind, trays, assets: trays.flatMap((t) => t.assets) };
  });
  return out.sort((x, y) => {
    const xu = x.kind === 'unassigned' ? 1 : 0;
    const yu = y.kind === 'unassigned' ? 1 : 0;
    return xu - yu || y.assets.length - x.assets.length || byName(x.name, y.name);
  });
}

/** Active segments no drawn asset sits in. Counted, not drawn: an empty tray
 *  per unused network is scaffolding with nothing to click. */
export function emptySegmentCount(map: NetworkMap | undefined): number {
  const used = new Set((map?.assets ?? []).map((a) => a.segment_id).filter(Boolean));
  return (map?.segments ?? []).filter((s) => !used.has(s.segment_id)).length;
}

export const hasCrypto = (a: NetworkMapAsset): boolean => a.crypto_service_count > 0;

/** The assets the view draws, after the crypto filter and the site focus. */
export function visibleAssets(map: NetworkMap | undefined, onlyCrypto: boolean): NetworkMapAsset[] {
  const all = map?.assets ?? [];
  return onlyCrypto ? all.filter(hasCrypto) : all;
}

// ---------------------------------------------------------------- tones ----

/**
 * What a device's badge says, as one of a closed set of tones.
 *
 * Risk mode: the canonical band of the asset's score, or `unassessed` when
 * nothing assessed it (D4). PQC mode: the server's classification of the
 * asset's configurations — `migrate` if ANY needs migration (a single
 * classical asymmetric component is enough), `unclassified` if any could not
 * be classified, else `ready`.
 *
 * Both modes return `services` for a device with open services but no crypto
 * observed on them, and null for a device with neither: there is nothing to
 * badge, and an empty badge would read as a zero.
 */
export type Tone =
  | 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unassessed'
  | 'migrate' | 'ready' | 'unclassified'
  | 'services';

const LEVEL_TONE: Readonly<Record<RiskLevel, Tone>> = {
  Critical: 'critical', High: 'high', Medium: 'medium', Low: 'low', Informational: 'info',
};

export function assetTone(a: NetworkMapAsset, mode: ColourMode): Tone | null {
  if (!hasCrypto(a)) return a.service_count > 0 ? 'services' : null;
  if (mode === 'risk') {
    if (!a.risk_assessed) return 'unassessed';
    return LEVEL_TONE[riskLevelFromScore(a.risk_score)];
  }
  const p = a.crypto.pqc;
  if (p.needs_migration > 0) return 'migrate';
  if (p.unclassified > 0 || p.pqc_ready + p.symmetric_safe === 0) return 'unclassified';
  return 'ready';
}

/** The number on a badge: crypto services, or open services when none carry
 *  crypto. */
export const badgeCount = (a: NetworkMapAsset): number =>
  hasCrypto(a) ? a.crypto_service_count : a.service_count;

export const TONE_COLOR: Readonly<Record<Tone, string>> = {
  critical: LEVEL_COLOR.Critical,
  high: LEVEL_COLOR.High,
  medium: LEVEL_COLOR.Medium,
  low: LEVEL_COLOR.Low,
  info: LEVEL_COLOR.Informational,
  unassessed: 'transparent',
  migrate: 'var(--warn)',
  ready: 'var(--ok)',
  unclassified: 'var(--neutral)',
  services: 'transparent',
};

/** Tones drawn hollow — an outline, not a fill — because they are the absence
 *  of an answer rather than an answer. */
export const HOLLOW_TONES: ReadonlySet<Tone> = new Set<Tone>(['unassessed', 'services']);

export const TONE_LABEL: Readonly<Record<Tone, string>> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Informational',
  unassessed: 'Not assessed',
  migrate: 'Needs PQC migration',
  ready: 'Quantum-safe',
  unclassified: 'Not classified',
  services: 'Services, no crypto seen',
};

/** The legend for a mode, in reading order (worst first). */
export function legendTones(mode: ColourMode): Tone[] {
  return mode === 'risk'
    ? ['critical', 'high', 'medium', 'low', 'info', 'unassessed', 'services']
    : ['migrate', 'unclassified', 'ready', 'services'];
}

/** How many of `assets` carry each tone — the risk breakdown on a site card
 *  and a network summary. Assets with nothing to badge are not counted. */
export function toneCounts(assets: readonly NetworkMapAsset[], mode: ColourMode): { tone: Tone; count: number }[] {
  const counts = new Map<Tone, number>();
  for (const a of assets) {
    const t = assetTone(a, mode);
    if (t) counts.set(t, (counts.get(t) ?? 0) + 1);
  }
  return legendTones(mode).filter((t) => counts.has(t)).map((tone) => ({ tone, count: counts.get(tone)! }));
}

// ---------------------------------------------------------------- icons ----

const kebab = (pascal: string): string => pascal.replace(/([a-z0-9])([A-Z])/g, '$1-$2').toLowerCase();
const KNOWN_ICONS = new Set(ICON_NAMES);

/**
 * The icon a device tile shows: its class's own icon from the generated
 * taxonomy (a router looks like a router), falling back to its class GROUP's
 * icon when this build's icon map lacks it or the class key is unknown.
 */
export function assetIcon(classKey: string): string {
  const cls = ASSET_CLASSES[classKey as AssetClassKey];
  const own = cls ? kebab(cls.icon) : '';
  if (own && KNOWN_ICONS.has(own)) return own;
  return CLASS_GROUP_STYLES[classGroupOf(classKey)].icon;
}

/** Per-class-group counts for a Networks-zoom summary, biggest first. */
export function groupCounts(assets: readonly NetworkMapAsset[]): { group: ClassGroupKey; count: number }[] {
  const counts = new Map<ClassGroupKey, number>();
  for (const a of assets) {
    const g = classGroupOf(a.class_key);
    counts.set(g, (counts.get(g) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([group, count]) => ({ group, count }))
    .sort((x, y) => y.count - x.count || (x.group < y.group ? -1 : 1));
}

// --------------------------------------------------------------- traits ----

export const ROLE_LABEL: Readonly<Record<NetworkMapComponent['algorithm_type'], string>> = {
  protocol_version: 'Protocol',
  cipher_suite: 'Cipher suite',
  key_exchange: 'Key exchange',
  signature: 'Signature',
  symmetric: 'Cipher',
  hash: 'MAC / hash',
};

export type TraitTone = 'bad' | 'warn' | 'good' | 'neutral';

export interface Trait {
  key: string;
  label: string;
  /** The row's tone, from the catalogue strength (or PQC status). */
  tone: TraitTone;
  /** True when no device on the map USES it — every holder only offers it. */
  offeredOnly: boolean;
  /** Worst-first sort rank; lower is worse. */
  rank: number;
  /** Rows hidden until "show all": strong, non-PQC components nobody needs
   *  to act on. */
  quiet: boolean;
  assetIds: string[];
}

const EXPIRING_TRAIT = 'cert:expiring-90d';

function componentTone(c: NetworkMapComponent): { tone: TraitTone; rank: number; quiet: boolean } {
  const r = strengthRank(c.strength);
  if (r === 0) return { tone: 'bad', rank: 0, quiet: false };
  if (r === 1) return { tone: 'warn', rank: 2, quiet: false };
  // A PQC component is worth seeing even though it is strong: it is the
  // answer to "who has started migrating".
  if (c.is_pqc) return { tone: 'good', rank: 5, quiet: false };
  // No strength recorded is NOT strong — it is unassessed, and it stays in
  // view for the same reason an unassessed risk score does.
  if (r === null) return { tone: 'neutral', rank: 3, quiet: false };
  return { tone: 'neutral', rank: r === 2 ? 4 : 6, quiet: true };
}

/**
 * The By-crypto rows: devices grouped by a catalogue component they share, and
 * by certificates expiring within 90 days. Worst first, then by how many
 * devices a fix would reach.
 */
export function cryptoTraits(assets: readonly NetworkMapAsset[]): Trait[] {
  const rows = new Map<string, Trait>();
  for (const a of assets) {
    for (const c of a.crypto.components ?? []) {
      const key = `${c.algorithm_type}|${c.name}`;
      let row = rows.get(key);
      if (!row) {
        const t = componentTone(c);
        row = {
          key,
          label: `${ROLE_LABEL[c.algorithm_type]} · ${c.name}`,
          tone: t.tone,
          rank: t.rank,
          quiet: t.quiet,
          offeredOnly: true,
          assetIds: [],
        };
        rows.set(key, row);
      }
      if (c.observed) row.offeredOnly = false;
      if (!row.assetIds.includes(a.asset_id)) row.assetIds.push(a.asset_id);
    }
    if (a.crypto.certs_expiring_90d > 0) {
      let row = rows.get(EXPIRING_TRAIT);
      if (!row) {
        row = {
          key: EXPIRING_TRAIT,
          label: 'Certificate expires within 90 days',
          tone: 'warn',
          rank: 1,
          quiet: false,
          offeredOnly: false,
          assetIds: [],
        };
        rows.set(EXPIRING_TRAIT, row);
      }
      row.assetIds.push(a.asset_id);
    }
  }
  return [...rows.values()].sort((x, y) =>
    x.rank - y.rank || y.assetIds.length - x.assetIds.length || (x.label < y.label ? -1 : 1));
}

// --------------------------------------------------------------- radial ----

export interface Arc {
  a0: number;
  a1: number;
}

/**
 * Split `[a0, a1)` into consecutive arcs proportional to `weights`.
 *
 * A weight below 1 is raised to 1, so an empty site or network still gets a
 * sliver it can be clicked on rather than vanishing from the ring.
 */
export function splitArc(a0: number, a1: number, weights: readonly number[]): Arc[] {
  const w = weights.map((x) => Math.max(1, x));
  const total = w.reduce((s, x) => s + x, 0);
  const out: Arc[] = [];
  let at = a0;
  for (const x of w) {
    const next = at + ((a1 - a0) * x) / total;
    out.push({ a0: at, a1: next });
    at = next;
  }
  return out;
}

/** An annular sector as an SVG path, angles clockwise from 12 o'clock. */
export function arcPath(cx: number, cy: number, r0: number, r1: number, a0: number, a1: number): string {
  const p = (r: number, a: number) => `${(cx + r * Math.sin(a)).toFixed(2)} ${(cy - r * Math.cos(a)).toFixed(2)}`;
  // A full ring is two half-arcs: an SVG arc whose start and end coincide
  // draws nothing at all.
  if (a1 - a0 >= Math.PI * 2 - 1e-6) {
    const m = a0 + Math.PI;
    return `M${p(r1, a0)} A${r1} ${r1} 0 1 1 ${p(r1, m)} A${r1} ${r1} 0 1 1 ${p(r1, a0)} `
      + `M${p(r0, a0)} A${r0} ${r0} 0 1 0 ${p(r0, m)} A${r0} ${r0} 0 1 0 ${p(r0, a0)} Z`;
  }
  const large = a1 - a0 > Math.PI ? 1 : 0;
  return `M${p(r1, a0)} A${r1} ${r1} 0 ${large} 1 ${p(r1, a1)} L${p(r0, a1)} A${r0} ${r0} 0 ${large} 0 ${p(r0, a0)} Z`;
}

// ----------------------------------------------------------- truncation ----

export function networkTruncationNotice(map: NetworkMap | undefined): string | null {
  if (!map?.truncated) return null;
  const shown = (map.assets ?? []).length;
  return `Showing ${shown.toLocaleString()} of ${map.total_assets.toLocaleString()} assets — the highest-risk first. `
    + 'Every count on this map describes the assets shown, not the whole estate.';
}
