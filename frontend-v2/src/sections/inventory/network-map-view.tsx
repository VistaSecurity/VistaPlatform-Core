// The Network view (feature: network-crypto-map).
//
// Inventory → Map → Network: every live asset placed by site and network, each
// device badged by the crypto it serves, in four interchangeable layouts and
// three zoom levels, with any device explodable into its services and their
// crypto. The decisions live in `network-map-model.ts` and are unit-tested;
// this file is layout, controls and state.
//
// State: the layout choices (view, zoom, colour, the crypto filter) are a
// per-viewer convenience kept in localStorage; the site focus and the selected
// device are in the URL (`site=`, `asset=`), so a map is a link somebody can
// paste into a ticket.
import { useCallback, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link, useSearchParams } from 'react-router';
import { Icon } from '../../components/ui';
import { useNetworkMap } from './relationship-queries';
import { CLASS_GROUP_STYLES } from './map-model';
import { classLabel } from './asset-shape';
import { ExplodedDevice } from './network-map-exploded';
import { SEGMENTS_SETTINGS_PATH } from '../settings/auto-scan-not-scanned';
import {
  HOLLOW_TONES, NETWORK_VIEWS, NETWORK_VIEW_LABEL, TONE_COLOR, TONE_LABEL, ZOOM_LABEL,
  arcPath, assetIcon, assetTone, badgeCount, cryptoTraits, defaultPrefs, emptySegmentCount,
  groupCounts, groupSites, hasCrypto, legendTones, networkTruncationNotice, parsePrefs, splitArc,
  toneCounts, visibleAssets,
  type ColourMode, type NetworkMapAsset, type NetworkMapPrefs, type SiteGroup, type Tone, type Tray,
  type TraitTone, type Zoom,
} from './network-map-model';

const PREFS_KEY = 'vista.inventory.networkMap.prefs';

function loadPrefs(fallback: NetworkMapPrefs): NetworkMapPrefs {
  try {
    const raw = window.localStorage.getItem(PREFS_KEY);
    return raw ? parsePrefs(JSON.parse(raw), fallback) : fallback;
  } catch {
    return fallback;
  }
}

function savePrefs(p: NetworkMapPrefs) {
  try {
    window.localStorage.setItem(PREFS_KEY, JSON.stringify(p));
  } catch {
    // Private windows and blocked storage: the map still works, it just
    // forgets the layout choice.
  }
}

// ------------------------------------------------------------ small parts --

function Segmented<T extends string | number>({ label, options, value, onChange, testId }: {
  label: string;
  options: readonly { value: T; label: string }[];
  value: T;
  onChange: (v: T) => void;
  testId: string;
}) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
      <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>{label}</span>
      <div role="radiogroup" aria-label={label} data-testid={testId}
        style={{ display: 'inline-flex', borderRadius: 9, border: '1px solid var(--app-border2)', overflow: 'hidden' }}>
        {options.map((o) => {
          const on = o.value === value;
          return (
            <button key={String(o.value)} role="radio" aria-checked={on} onClick={() => onChange(o.value)}
              style={{
                padding: '5px 11px', fontSize: 12, border: 'none', cursor: 'pointer',
                background: on ? 'var(--accent-soft, var(--app-panel2))' : 'transparent',
                color: on ? 'var(--app-t1)' : 'var(--app-t3)', fontWeight: on ? 650 : 400,
              }}>
              {o.label}
            </button>
          );
        })}
      </div>
    </div>
  );
}

function ToneDot({ tone, size = 10 }: { tone: Tone; size?: number }) {
  const hollow = HOLLOW_TONES.has(tone);
  return (
    <span aria-hidden style={{
      display: 'inline-block', width: size, height: size, borderRadius: size, flexShrink: 0,
      background: hollow ? 'transparent' : TONE_COLOR[tone],
      border: hollow ? '1px solid var(--app-border2)' : 'none',
    }} />
  );
}

function ToneBreakdown({ assets, mode }: { assets: readonly NetworkMapAsset[]; mode: ColourMode }) {
  const counts = toneCounts(assets, mode);
  if (!counts.length) return <span style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>No services observed</span>;
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
      {counts.map(({ tone, count }) => (
        <span key={tone} title={TONE_LABEL[tone]} style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 11.5, color: 'var(--app-t2)' }}>
          <ToneDot tone={tone} />{count}
        </span>
      ))}
    </div>
  );
}

/** One device. A button, so every tile is a tab stop that opens the exploded
 *  view on Enter as well as on click. */
function Tile({ asset, mode, selected, onSelect }: {
  asset: NetworkMapAsset; mode: ColourMode; selected: boolean; onSelect: (id: string) => void;
}) {
  const tone = assetTone(asset, mode);
  const pending = asset.asset_status === 'pending_approval';
  const name = asset.display_name || 'Unnamed asset';
  const detail = [asset.address, classLabel(asset.class_key) || asset.class_key, tone ? TONE_LABEL[tone] : 'No services observed', pending ? 'waiting for approval' : '']
    .filter(Boolean).join(' · ');
  return (
    <button
      data-testid="network-map-tile"
      data-tone={tone ?? 'none'}
      onClick={() => onSelect(asset.asset_id)}
      title={`${name}\n${detail}`}
      aria-label={`${name}, ${detail}`}
      aria-pressed={selected}
      style={{
        position: 'relative', width: 32, height: 32, flexShrink: 0, padding: 0, cursor: 'pointer',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        borderRadius: 8, background: 'var(--app-panel)', color: selected ? 'var(--accent)' : 'var(--app-t2)',
        border: `1px ${pending ? 'dashed' : 'solid'} var(--app-border2)`,
        outline: selected ? '2px solid var(--accent)' : 'none', outlineOffset: 1,
      }}
    >
      <Icon name={assetIcon(asset.class_key)} size={16} />
      {tone && (
        <span aria-hidden style={{
          position: 'absolute', right: -5, bottom: -5, minWidth: 14, height: 14, borderRadius: 7, padding: '0 3px',
          fontSize: 9.5, lineHeight: '14px', fontWeight: 700, textAlign: 'center',
          background: HOLLOW_TONES.has(tone) ? 'var(--app-panel)' : TONE_COLOR[tone],
          color: HOLLOW_TONES.has(tone) ? 'var(--app-t3)' : 'var(--app-bg)',
          border: HOLLOW_TONES.has(tone) ? '1px solid var(--app-border2)' : '1px solid var(--app-panel)',
        }}>
          {badgeCount(asset)}
        </span>
      )}
    </button>
  );
}

function Tiles({ assets, ctx }: { assets: readonly NetworkMapAsset[]; ctx: Ctx }) {
  if (!assets.length) return <span style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>No devices</span>;
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 7 }}>
      {assets.map((a) => (
        <Tile key={a.asset_id} asset={a} mode={ctx.mode} selected={a.asset_id === ctx.selected} onSelect={ctx.onSelect} />
      ))}
    </div>
  );
}

/** A network's Networks-zoom summary: what kinds of device, and their tones. */
function TraySummary({ assets, mode }: { assets: readonly NetworkMapAsset[]; mode: ColourMode }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
        {groupCounts(assets).map(({ group, count }) => (
          <span key={group} title={CLASS_GROUP_STYLES[group].label}
            style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 11.5, color: 'var(--app-t2)' }}>
            <Icon name={CLASS_GROUP_STYLES[group].icon} size={13} style={{ color: 'var(--app-t3)' }} />{count}
          </span>
        ))}
      </div>
      <ToneBreakdown assets={assets} mode={mode} />
    </div>
  );
}

/** The gateway line on a network. Never guessed (D3): until the segment
 * records its gateway this says so, rather than naming the `.1`. */
function GatewayNote() {
  return (
    <span title="No device has been recorded as this network's gateway yet."
      style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--app-t3)' }}>
      <Icon name="router" size={12} style={{ opacity: 0.55 }} />gateway not recorded
    </span>
  );
}

function TrayBox({ tray, ctx, compact }: { tray: Tray; ctx: Ctx; compact?: boolean }) {
  return (
    <div data-testid="network-map-tray"
      style={{ border: '1px solid var(--app-border)', borderRadius: 12, background: 'var(--app-bg2)', padding: '8px 9px 10px', minWidth: 0 }}>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 2 }}>
        <span style={{ fontSize: 12.5, fontWeight: 650, color: 'var(--app-t1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {tray.name}
        </span>
        <span style={{ fontSize: 11.5, color: 'var(--app-t3)', marginLeft: 'auto' }}>{tray.assets.length}</span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, flexWrap: 'wrap' }}>
        {tray.detail && <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>{tray.detail}</span>}
        {tray.segmentId && !compact && <GatewayNote />}
      </div>
      {ctx.zoom === 1 ? <TraySummary assets={tray.assets} mode={ctx.mode} /> : <Tiles assets={tray.assets} ctx={ctx} />}
    </div>
  );
}

const SITE_ICON: Readonly<Record<SiteGroup['kind'], string>> = {
  site: 'map-pin',
  cloud: 'cloud',
  unassigned: 'circle-dashed',
};

function SiteNode({ site, onFocus }: { site: SiteGroup; onFocus: (key: string) => void }) {
  return (
    <button data-site-node onClick={() => onFocus(site.key)} title={`Focus on ${site.name}`}
      className="ui-btn sm"
      style={{ fontSize: 12, borderStyle: site.kind === 'unassigned' ? 'dashed' : 'solid', maxWidth: '100%' }}>
      <Icon name={SITE_ICON[site.kind]} size={13} />
      <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{site.name}</span>
    </button>
  );
}

function SiteCard({ site, ctx }: { site: SiteGroup; ctx: Ctx }) {
  const withCrypto = site.assets.filter(hasCrypto).length;
  return (
    <button onClick={() => ctx.onFocus(site.key)} data-testid="network-map-site-card"
      style={{
        width: '100%', textAlign: 'left', cursor: 'pointer', padding: '11px 13px',
        border: '1px solid var(--app-border)', borderRadius: 12, background: 'var(--app-panel)',
      }}>
      <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--app-t1)' }}>{site.name}</div>
      <div style={{ fontSize: 11.5, color: 'var(--app-t3)', margin: '2px 0 9px' }}>
        {site.assets.length} device{site.assets.length === 1 ? '' : 's'} · {site.trays.length} network{site.trays.length === 1 ? '' : 's'} · {withCrypto} with crypto
      </div>
      <ToneBreakdown assets={site.assets} mode={ctx.mode} />
    </button>
  );
}

// ------------------------------------------------------------------ views --

interface Ctx {
  zoom: Zoom;
  mode: ColourMode;
  selected: string | null;
  onSelect: (id: string) => void;
  onFocus: (siteKey: string) => void;
}

/** Curves from the root node to each site node, measured after layout. */
function useWires(container: React.RefObject<HTMLDivElement | null>, root: React.RefObject<HTMLDivElement | null>, deps: unknown[]) {
  const [paths, setPaths] = useState<string[]>([]);
  useLayoutEffect(() => {
    const draw = () => {
      const c = container.current;
      const r = root.current;
      if (!c || !r) return;
      const cb = c.getBoundingClientRect();
      const rb = r.getBoundingClientRect();
      const x0 = rb.left + rb.width / 2 - cb.left;
      const y0 = rb.bottom - cb.top;
      const next: string[] = [];
      c.querySelectorAll<HTMLElement>('[data-site-node]').forEach((el) => {
        const b = el.getBoundingClientRect();
        const x = b.left + b.width / 2 - cb.left;
        const y = b.top - cb.top;
        next.push(`M${x0} ${y0} C ${x0} ${y0 + 22}, ${x} ${y - 22}, ${x} ${y}`);
      });
      setPaths((prev) => (prev.join('|') === next.join('|') ? prev : next));
    };
    draw();
    if (typeof ResizeObserver === 'undefined' || !container.current) return;
    const ro = new ResizeObserver(draw);
    ro.observe(container.current);
    return () => ro.disconnect();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return paths;
}

function FunnelView({ sites, ctx, focused }: { sites: SiteGroup[]; ctx: Ctx; focused: boolean }) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const rootRef = useRef<HTMLDivElement | null>(null);
  const paths = useWires(containerRef, rootRef, [sites, ctx.zoom]);
  return (
    <div ref={containerRef} data-testid="network-map-funnel" style={{ position: 'relative' }}>
      <svg aria-hidden style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', pointerEvents: 'none', overflow: 'visible' }}>
        {paths.map((d, i) => <path key={i} d={d} fill="none" stroke="var(--app-border2)" strokeWidth={1.2} />)}
      </svg>
      <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 36 }}>
        <div ref={rootRef} style={{
          display: 'inline-flex', alignItems: 'center', gap: 6, padding: '5px 11px', fontSize: 12,
          border: '1px solid var(--app-border2)', borderRadius: 9, background: 'var(--app-panel)', color: 'var(--app-t1)',
        }}>
          <Icon name="globe" size={13} />Internet
        </div>
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 14, alignItems: 'flex-start' }}>
        {sites.map((site) => (
          <div key={site.key} style={{
            // Wider for bigger sites, so a 30-device network gets room and a
            // 2-device one does not hog a column; wraps when sites outnumber
            // the width.
            flex: focused ? '1 1 100%' : `${Math.max(1, Math.sqrt(site.assets.length))} 1 220px`,
            minWidth: 0, display: 'flex', flexDirection: 'column', alignItems: 'center',
          }}>
            <SiteNode site={site} onFocus={ctx.onFocus} />
            <svg viewBox="0 0 100 20" preserveAspectRatio="none" aria-hidden style={{ width: '100%', height: 24, display: 'block' }}>
              <path d="M44 0 L56 0 L100 20 L0 20 Z" fill="var(--app-panel2)" stroke="var(--app-border2)" strokeWidth={0.6} vectorEffect="non-scaling-stroke" />
            </svg>
            {ctx.zoom === 0 ? (
              <SiteCard site={site} ctx={ctx} />
            ) : (
              <div style={{
                width: '100%', display: 'grid', gap: 8,
                gridTemplateColumns: focused && site.trays.length > 1 ? 'repeat(auto-fit, minmax(240px, 1fr))' : 'minmax(0, 1fr)',
              }}>
                {site.trays.map((t) => <TrayBox key={t.key} tray={t} ctx={ctx} />)}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function CircuitView({ sites, ctx }: { sites: SiteGroup[]; ctx: Ctx }) {
  const trunk = 'var(--app-border2)';
  return (
    <div data-testid="network-map-circuit" style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      {sites.map((site) => (
        <div key={site.key} style={{ display: 'flex', alignItems: 'stretch' }}>
          <div style={{ width: 190, flexShrink: 0, paddingTop: 1, paddingRight: 10 }}>
            <SiteNode site={site} onFocus={ctx.onFocus} />
            <div style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 5 }}>
              {site.assets.length} device{site.assets.length === 1 ? '' : 's'}
            </div>
          </div>
          <div style={{ flex: 1, minWidth: 0, borderLeft: `2px solid ${trunk}` }}>
            {ctx.zoom === 0 ? (
              <div style={{ display: 'flex', alignItems: 'center' }}>
                <div style={{ width: 16, height: 2, background: trunk, flexShrink: 0 }} />
                <div style={{ flex: 1 }}><SiteCard site={site} ctx={ctx} /></div>
              </div>
            ) : site.trays.map((t) => (
              <div key={t.key} style={{ display: 'flex', alignItems: 'flex-start', margin: '2px 0 12px' }}>
                <div style={{ width: 16, height: 2, background: trunk, marginTop: 10, flexShrink: 0 }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'baseline', gap: 9, borderBottom: `2px solid ${trunk}`, padding: '0 4px 4px', flexWrap: 'wrap' }}>
                    <span style={{ fontSize: 12.5, fontWeight: 650, color: 'var(--app-t1)' }}>{t.name}</span>
                    {t.detail && <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>{t.detail}</span>}
                    {t.segmentId && <GatewayNote />}
                    <span style={{ fontSize: 11.5, color: 'var(--app-t3)', marginLeft: 'auto' }}>{t.assets.length}</span>
                  </div>
                  {ctx.zoom === 1 ? (
                    <div style={{ padding: '9px 4px 0' }}><TraySummary assets={t.assets} mode={ctx.mode} /></div>
                  ) : (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0 8px', padding: '0 4px' }}>
                      {t.assets.length === 0 && <span style={{ fontSize: 11.5, color: 'var(--app-t3)', paddingTop: 8 }}>No devices</span>}
                      {t.assets.map((a) => (
                        <div key={a.asset_id} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                          <div aria-hidden style={{ width: 2, height: 8, background: trunk }} />
                          <Tile asset={a} mode={ctx.mode} selected={a.asset_id === ctx.selected} onSelect={ctx.onSelect} />
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function RadialView({ sites, ctx, centreLabel }: { sites: SiteGroup[]; ctx: Ctx; centreLabel: string }) {
  const W = 560;
  const c = W / 2;
  // Ring radii per zoom: the rings that are drawn fill the disc, so a Sites
  // zoom is one fat ring rather than a thin one lost in empty space.
  const rings: [number, number][] = ctx.zoom === 0
    ? [[52, 170]]
    : ctx.zoom === 1
      ? [[52, 120], [124, 222]]
      : [[52, 104], [108, 166], [170, 262]];
  const gap = 0.012;
  const sitesArcs = splitArc(0, Math.PI * 2, sites.map((s) => s.assets.length));
  const shapes: ReactNode[] = [];
  const labels: ReactNode[] = [];

  const label = (key: string, text: string, a0: number, a1: number, r0: number, r1: number, muted = false) => {
    if (a1 - a0 < 0.28) return;
    const m = (a0 + a1) / 2;
    const r = (r0 + r1) / 2;
    labels.push(
      <text key={key} x={c + r * Math.sin(m)} y={c - r * Math.cos(m)} textAnchor="middle" dominantBaseline="central"
        style={{ fontSize: 11, fill: muted ? 'var(--app-t3)' : 'var(--app-t2)', pointerEvents: 'none' }}>
        {text.length > 18 ? `${text.slice(0, 17)}…` : text}
      </text>,
    );
  };

  sites.forEach((site, si) => {
    const { a0, a1 } = sitesArcs[si];
    const [s0, s1] = rings[0];
    shapes.push(
      <path key={`s-${site.key}`} d={arcPath(c, c, s0, s1, a0 + gap, a1 - gap)} role="button" tabIndex={0}
        aria-label={`${site.name}, ${site.assets.length} devices. Focus on this site.`}
        onClick={() => ctx.onFocus(site.key)}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); ctx.onFocus(site.key); } }}
        style={{ fill: 'var(--app-panel2)', stroke: 'var(--app-border2)', strokeWidth: 0.6, cursor: 'pointer' }}>
        <title>{`${site.name} · ${site.assets.length} devices`}</title>
      </path>,
    );
    label(`sl-${site.key}`, site.name, a0, a1, s0, s1);
    if (ctx.zoom === 0) return;

    const trayArcs = splitArc(a0, a1, site.trays.map((t) => t.assets.length));
    site.trays.forEach((tray, ti) => {
      const t = trayArcs[ti];
      const [n0, n1] = rings[1];
      shapes.push(
        <path key={`t-${site.key}-${tray.key}`} d={arcPath(c, c, n0, n1, t.a0 + gap, t.a1 - gap)}
          style={{ fill: 'var(--app-panel)', stroke: 'var(--app-border2)', strokeWidth: 0.6 }}>
          <title>{`${tray.name} · ${tray.assets.length} devices`}</title>
        </path>,
      );
      if (ctx.zoom === 1) label(`tl-${site.key}-${tray.key}`, tray.name, t.a0, t.a1, n0, n1, true);
      if (ctx.zoom !== 2) return;

      const [d0, d1] = rings[2];
      const each = (t.a1 - t.a0) / Math.max(1, tray.assets.length);
      tray.assets.forEach((a, i) => {
        const e0 = t.a0 + i * each;
        const tone = assetTone(a, ctx.mode);
        const hollow = !tone || HOLLOW_TONES.has(tone);
        // Tall and coloured with crypto; short and grey without, so the ring
        // reads as "where the crypto is" before any colour is decoded.
        const outer = hollow ? d0 + (d1 - d0) * 0.42 : d1;
        const selected = a.asset_id === ctx.selected;
        shapes.push(
          <path key={`d-${a.asset_id}`} d={arcPath(c, c, d0, outer, e0 + gap / 3, e0 + each - gap / 3)}
            role="button" tabIndex={0} data-testid="network-map-wedge"
            aria-label={`${a.display_name || 'Unnamed asset'}, ${tone ? TONE_LABEL[tone] : 'no services observed'}`}
            onClick={() => ctx.onSelect(a.asset_id)}
            onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); ctx.onSelect(a.asset_id); } }}
            style={{
              fill: hollow ? 'var(--app-panel2)' : TONE_COLOR[tone],
              stroke: selected ? 'var(--accent)' : 'var(--app-border)',
              strokeWidth: selected ? 2 : 0.5, cursor: 'pointer',
            }}>
            <title>{`${a.display_name || 'Unnamed asset'}${a.address ? ` · ${a.address}` : ''}`}</title>
          </path>,
        );
      });
    });
  });

  return (
    <div data-testid="network-map-radial">
      <svg viewBox={`0 0 ${W} ${W}`} role="group" aria-label="Radial network map"
        style={{ width: '100%', maxWidth: W, display: 'block', margin: '0 auto' }}>
        <circle cx={c} cy={c} r={48} style={{ fill: 'var(--app-panel)', stroke: 'var(--app-border2)', strokeWidth: 0.6 }} />
        <text x={c} y={c} textAnchor="middle" dominantBaseline="central" style={{ fontSize: 12, fill: 'var(--app-t1)' }}>
          {centreLabel.length > 14 ? `${centreLabel.slice(0, 13)}…` : centreLabel}
        </text>
        {shapes}
        {labels}
      </svg>
      {ctx.zoom === 2 && (
        <div style={{ textAlign: 'center', fontSize: 11.5, color: 'var(--app-t3)', marginTop: 4 }}>
          Outer ring: one wedge per device. Tall coloured wedges carry crypto; short grey ones do not.
        </div>
      )}
    </div>
  );
}

const TRAIT_COLOR: Readonly<Record<TraitTone, string>> = {
  bad: 'var(--danger)',
  warn: 'var(--warn)',
  good: 'var(--ok)',
  neutral: 'var(--app-border2)',
};

function CryptoView({ assets, ctx }: { assets: NetworkMapAsset[]; ctx: Ctx }) {
  const [showAll, setShowAll] = useState(false);
  const traits = useMemo(() => cryptoTraits(assets), [assets]);
  const byId = useMemo(() => new Map(assets.map((a) => [a.asset_id, a])), [assets]);
  const shown = showAll ? traits : traits.filter((t) => !t.quiet);
  const hidden = traits.length - shown.length;

  if (!traits.length) {
    return (
      <div data-testid="network-map-crypto-empty" style={{ fontSize: 12.5, color: 'var(--app-t3)', border: '1px dashed var(--app-border2)', borderRadius: 12, padding: '18px 16px' }}>
        No crypto has been assessed on these devices yet. Once services are measured, devices are grouped here by
        the algorithms and certificates they share.
      </div>
    );
  }
  return (
    <div data-testid="network-map-crypto">
      <div style={{ fontSize: 12, color: 'var(--app-t3)', marginBottom: 8 }}>
        Devices grouped by the crypto they share, worst first. Fixing one row fixes every device in it.
      </div>
      {shown.map((t) => (
        <div key={t.key} data-testid="network-map-trait"
          style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '8px 0', borderTop: '1px solid var(--app-border)' }}>
          <div style={{ width: 300, flexShrink: 0, display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
            <span aria-hidden style={{ width: 3, alignSelf: 'stretch', minHeight: 18, borderRadius: 2, background: TRAIT_COLOR[t.tone], flexShrink: 0 }} />
            <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t1)', wordBreak: 'break-word' }}>
              {t.label}
              {t.offeredOnly && <span style={{ color: 'var(--app-t3)' }}> · offered, not used</span>}
            </span>
          </div>
          <span style={{ width: 28, textAlign: 'right', fontSize: 12, color: 'var(--app-t3)', flexShrink: 0 }}>{t.assetIds.length}</span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <Tiles assets={t.assetIds.map((id) => byId.get(id)).filter((a): a is NetworkMapAsset => !!a)} ctx={ctx} />
          </div>
        </div>
      ))}
      {(hidden > 0 || showAll) && (
        <button className="ui-btn sm ghost" style={{ fontSize: 12, marginTop: 8 }} onClick={() => setShowAll((v) => !v)}>
          {showAll ? 'Show only what needs attention' : `Show ${hidden} strong component${hidden === 1 ? '' : 's'} too`}
        </button>
      )}
    </div>
  );
}

// ------------------------------------------------------------- the view ---

function Centered({ testId, icon, title, message, tone, action }: {
  testId: string; icon: string; title: string; message: string; tone?: string; action?: ReactNode;
}) {
  return (
    <div data-testid={testId} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 9, padding: '60px 26px', textAlign: 'center' }}>
      <Icon name={icon} size={26} style={{ color: tone ?? 'var(--app-t3)' }} />
      <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--app-t1)' }}>{title}</div>
      <div style={{ fontSize: 12.5, color: 'var(--app-t3)', maxWidth: 520, lineHeight: 1.6 }}>{message}</div>
      {action}
    </div>
  );
}

export function NetworkMapView() {
  const q = useNetworkMap();
  const map = q.data;
  const [params, setParams] = useSearchParams();
  const focus = params.get('site');
  const selected = params.get('asset');

  // Prefs are read once the estate's size is known, because the default
  // depends on it (D1); after that the user's own choice wins.
  const totalAssets = map?.total_assets;
  const savedPrefs = useMemo(
    () => (totalAssets === undefined ? null : loadPrefs(defaultPrefs(totalAssets))),
    [totalAssets],
  );
  const [chosen, setChosen] = useState<NetworkMapPrefs | null>(null);
  const prefs = chosen ?? savedPrefs;
  const setPrefs = useCallback((patch: Partial<NetworkMapPrefs>) => {
    const next = { ...(prefs ?? defaultPrefs(0)), ...patch };
    savePrefs(next);
    setChosen(next);
  }, [prefs]);

  const setParam = useCallback((key: string, value: string | null) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value); else next.delete(key);
    setParams(next, { replace: true });
  }, [params, setParams]);

  const assets = useMemo(() => visibleAssets(map, prefs?.onlyCrypto ?? false), [map, prefs?.onlyCrypto]);
  const allSites = useMemo(() => groupSites(map, assets), [map, assets]);
  const sites = useMemo(() => (focus ? allSites.filter((s) => s.key === focus) : allSites), [allSites, focus]);
  const focusedSite = focus ? allSites.find((s) => s.key === focus) : undefined;
  const scopedAssets = useMemo(() => sites.flatMap((s) => s.assets), [sites]);
  const selectedAsset = useMemo(() => (map?.assets ?? []).find((a) => a.asset_id === selected), [map, selected]);

  const showNeighbourhood = useCallback((id: string) => {
    const next = new URLSearchParams(params);
    next.set('view', 'neighbourhood');
    next.set('focus', id);
    next.delete('site');
    next.delete('asset');
    setParams(next, { replace: false });
  }, [params, setParams]);

  if (q.isLoading) {
    return <Centered testId="network-map-loading" icon="loader" title="Drawing the network…" message="Placing every asset by site and network." />;
  }
  if (q.isError || !map || !prefs) {
    return (
      <Centered testId="network-map-error" icon="alert-triangle" tone="var(--danger-text)"
        title="Couldn't load the network map"
        message={`${q.error instanceof Error ? q.error.message : 'The request failed.'} Nothing is drawn rather than an out-of-date picture.`}
        action={<button className="ui-btn sm" onClick={() => { void q.refetch(); }}>Retry</button>} />
    );
  }
  if (map.total_assets === 0) {
    return (
      <Centered testId="network-map-empty" icon="map" title="Nothing discovered yet"
        message="The network map places every discovered asset by site and network and shows the crypto each one serves. Run a discovery or add assets and they appear here."
        action={<Link to="/discovery" className="ui-btn sm" style={{ textDecoration: 'none' }}>Go to Discovery</Link>} />
    );
  }

  const p = prefs;
  const ctx: Ctx = {
    zoom: p.zoom,
    mode: p.colour,
    selected,
    onSelect: (id) => setParam('asset', id === selected ? null : id),
    onFocus: (key) => {
      const next = new URLSearchParams(params);
      next.set('site', key);
      setParams(next, { replace: true });
      if (p.zoom === 0) setPrefs({ zoom: 2 });
    },
  };
  const truncation = networkTruncationNotice(map);
  const emptyNetworks = emptySegmentCount(map);

  return (
    <div data-testid="network-map-view" style={{ flex: 1, minHeight: 0, overflow: 'auto', padding: '4px 26px 30px' }}>
      {/* ---- controls ---- */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px 22px', alignItems: 'center', marginBottom: 10 }}>
        <Segmented testId="network-map-view-select" label="View" value={p.view}
          options={NETWORK_VIEWS.map((v) => ({ value: v, label: NETWORK_VIEW_LABEL[v] }))}
          onChange={(view) => setPrefs({ view })} />
        {p.view !== 'crypto' && (
          <Segmented testId="network-map-zoom" label="Zoom" value={p.zoom}
            options={([0, 1, 2] as Zoom[]).map((z) => ({ value: z, label: ZOOM_LABEL[z] }))}
            onChange={(zoom) => setPrefs({ zoom })} />
        )}
        <Segmented testId="network-map-colour" label="Colour by" value={p.colour}
          options={[{ value: 'risk', label: 'Crypto risk' }, { value: 'pqc', label: 'Quantum readiness' }]}
          onChange={(colour) => setPrefs({ colour })} />
        <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--app-t3)' }}>
          <input type="checkbox" checked={p.onlyCrypto} onChange={(e) => setPrefs({ onlyCrypto: e.target.checked })} />
          Only devices with crypto
        </label>
      </div>

      {/* ---- crumbs + legend ---- */}
      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '6px 18px', marginBottom: 14 }}>
        <div data-testid="network-map-crumbs" style={{ fontSize: 13, color: 'var(--app-t2)', display: 'flex', alignItems: 'center', gap: 6 }}>
          {focusedSite ? (
            <>
              <button className="ui-btn sm ghost" style={{ fontSize: 12.5 }} onClick={() => setParam('site', null)}>All sites</button>
              <Icon name="chevron-right" size={12} style={{ color: 'var(--app-t3)' }} />
              <span style={{ color: 'var(--app-t1)', fontWeight: 650 }}>{focusedSite.name}</span>
            </>
          ) : (
            <span>
              All sites <span style={{ color: 'var(--app-t3)' }}>· {scopedAssets.length} device{scopedAssets.length === 1 ? '' : 's'} · click a site to focus on it</span>
            </span>
          )}
        </div>
        <div data-testid="network-map-legend" style={{ display: 'flex', flexWrap: 'wrap', gap: 11, marginLeft: 'auto' }}>
          {legendTones(p.colour).map((t) => (
            <span key={t} style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5, color: 'var(--app-t3)' }}>
              <ToneDot tone={t} />{TONE_LABEL[t]}
            </span>
          ))}
          <span style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>· badge = crypto services</span>
        </div>
      </div>

      {truncation && (
        <div data-testid="network-map-truncated" style={{
          display: 'flex', alignItems: 'center', gap: 9, marginBottom: 12, padding: '8px 13px', borderRadius: 11,
          border: '1px solid color-mix(in srgb, var(--warn) 35%, transparent)', background: 'color-mix(in srgb, var(--warn) 8%, transparent)',
        }}>
          <Icon name="alert-triangle" size={14} style={{ color: 'var(--warn)', flexShrink: 0 }} />
          <span style={{ fontSize: 12.5, color: 'var(--app-t1)' }}>{truncation}</span>
        </div>
      )}

      {/* ---- the stage ---- */}
      {focus && !focusedSite ? (
        <Centered testId="network-map-no-site" icon="map-pin" title="That site isn't on the map"
          message="It may have no devices left, or none that match the current filter."
          action={<button className="ui-btn sm" onClick={() => setParam('site', null)}>Show all sites</button>} />
      ) : sites.length === 0 ? (
        <Centered testId="network-map-filtered-empty" icon="filter-x" title="No devices match"
          message="No device carries crypto yet. Clear “Only devices with crypto” to see everything that was discovered."
          action={<button className="ui-btn sm" onClick={() => setPrefs({ onlyCrypto: false })}>Show all devices</button>} />
      ) : p.view === 'funnel' ? (
        <FunnelView sites={sites} ctx={ctx} focused={!!focusedSite} />
      ) : p.view === 'circuit' ? (
        <CircuitView sites={sites} ctx={ctx} />
      ) : p.view === 'radial' ? (
        <RadialView sites={sites} ctx={ctx} centreLabel={focusedSite?.name ?? 'Internet'} />
      ) : (
        <CryptoView assets={scopedAssets} ctx={ctx} />
      )}

      {emptyNetworks > 0 && !focusedSite && (
        <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 14 }}>
          {emptyNetworks} active network{emptyNetworks === 1 ? ' has' : 's have'} no devices on it and {emptyNetworks === 1 ? 'is' : 'are'} not drawn.{' '}
          <Link to={SEGMENTS_SETTINGS_PATH} style={{ color: 'var(--accent)' }}>Network segments</Link>
        </div>
      )}

      {selectedAsset && (
        <ExplodedDevice
          key={selectedAsset.asset_id}
          asset={selectedAsset}
          onClose={() => setParam('asset', null)}
          onShowNeighbourhood={showNeighbourhood}
        />
      )}
    </div>
  );
}

export default NetworkMapView;
