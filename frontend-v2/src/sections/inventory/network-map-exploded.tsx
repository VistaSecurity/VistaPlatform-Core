// A device, exploded (feature: network-crypto-map).
//
// The device on the left, one card per service on the right, joined by
// connectors, and each service's crypto laid out as chips: protocol, the
// components the catalogue assessed, key size, certificate. Opened by clicking
// any device in any Network view.
//
// Every read here already exists and is shared with the inventory drawers —
// same query keys, so a device opened in both places is fetched once:
//   endpoints   GET /infrastructure-assets/{id}/endpoints
//   configs     GET /crypto-configurations?asset_id=
//   components  GET /crypto-configurations/{id}/components  (catalogue assessment)
//   certificate GET /certificates/{id}
import { useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link } from 'react-router';
import { useQueries, useQuery } from '@tanstack/react-query';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { strengthRank } from '@vistasecurity/primitives/ratings';
import { Icon } from '../../components/ui';
import { clients } from '../../lib/clients';
import { useAssetConfigs, useAssetEndpoints } from './asset-queries';
import { classLabel } from './asset-shape';
import { ROLE_LABEL, assetIcon, type NetworkMapAsset } from './network-map-model';

type Component = inventoryComponents['schemas']['CryptoComponentAssessment'];
type Certificate = inventoryComponents['schemas']['Certificate'];
type Endpoint = inventoryComponents['schemas']['AssetEndpoint'];
type Config = inventoryComponents['schemas']['CryptoImplementation'];

type ChipTone = 'bad' | 'warn' | 'good' | 'neutral';

const CHIP_STYLE: Readonly<Record<ChipTone, { bg: string; fg: string }>> = {
  bad: { bg: 'color-mix(in srgb, var(--danger) 14%, transparent)', fg: 'var(--danger-text)' },
  warn: { bg: 'color-mix(in srgb, var(--warn) 16%, transparent)', fg: 'var(--app-t1)' },
  good: { bg: 'color-mix(in srgb, var(--ok) 16%, transparent)', fg: 'var(--app-t1)' },
  neutral: { bg: 'var(--app-panel2)', fg: 'var(--app-t2)' },
};

/** A component's tone, from the catalogue strength. Unrecorded strength is
 *  neutral — unassessed, not strong. */
function strengthTone(c: { strength: string; is_pqc: boolean }): ChipTone {
  const r = strengthRank(c.strength);
  if (r === 0) return 'bad';
  if (r === 1) return 'warn';
  if (c.is_pqc) return 'good';
  return 'neutral';
}

function daysUntil(iso?: string | null): number | null {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  return Number.isFinite(t) ? Math.floor((t - Date.now()) / 86_400_000) : null;
}

/** One service: an endpoint and every crypto configuration measured on it. */
interface Service {
  key: string;
  endpoint: Endpoint | null;
  configs: Config[];
}

function groupServices(endpoints: readonly Endpoint[], configs: readonly Config[]): { crypto: Service[]; plain: Endpoint[] } {
  const byEndpoint = new Map<string, Config[]>();
  const orphan: Config[] = [];
  for (const c of configs) {
    const eid = c.endpoint_id;
    if (eid) {
      const list = byEndpoint.get(eid) ?? [];
      list.push(c);
      byEndpoint.set(eid, list);
    } else orphan.push(c);
  }
  const crypto: Service[] = [];
  const plain: Endpoint[] = [];
  const sorted = [...endpoints].sort((a, b) => (a.port ?? 0) - (b.port ?? 0));
  const seen = new Set<string>();
  for (const e of sorted) {
    const list = byEndpoint.get(e.id);
    seen.add(e.id);
    if (list?.length) crypto.push({ key: e.id, endpoint: e, configs: list });
    else plain.push(e);
  }
  // Configurations whose endpoint is not in the endpoint list (retired since,
  // or never tied to one) still belong on the device.
  for (const [eid, list] of byEndpoint) {
    if (!seen.has(eid)) orphan.push(...list);
  }
  if (orphan.length) crypto.push({ key: '~unbound~', endpoint: null, configs: orphan });
  return { crypto, plain };
}

export function ExplodedDevice({ asset, onClose, onShowNeighbourhood }: {
  asset: NetworkMapAsset;
  onClose: () => void;
  onShowNeighbourhood: (assetId: string) => void;
}) {
  const endpointsQ = useAssetEndpoints(asset.asset_id);
  const configsQ = useAssetConfigs(asset.asset_id, asset.crypto_service_count > 0);
  const endpoints = useMemo(() => endpointsQ.data ?? [], [endpointsQ.data]);
  const configs = useMemo(() => (configsQ.data ?? []) as Config[], [configsQ.data]);

  const { crypto, plain } = useMemo(() => groupServices(endpoints, configs), [endpoints, configs]);
  // A multi-homed device (a router with an address per network) answers on
  // the same port at several addresses. Without the address, two ":443" cards
  // read as a duplicate rather than as two interfaces.
  const multiHomed = useMemo(
    () => new Set(endpoints.map((e) => stripMask(e.address)).filter(Boolean)).size > 1,
    [endpoints],
  );

  const loading = endpointsQ.isLoading || (asset.crypto_service_count > 0 && configsQ.isLoading);
  const failed = endpointsQ.isError || configsQ.isError;

  // The connectors: one curve from the device card to each service card,
  // measured after layout so they follow the cards wherever they wrap.
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const deviceRef = useRef<HTMLDivElement | null>(null);
  const [paths, setPaths] = useState<string[]>([]);
  useLayoutEffect(() => {
    const draw = () => {
      const wrap = wrapRef.current;
      const dev = deviceRef.current;
      if (!wrap || !dev) return;
      const wb = wrap.getBoundingClientRect();
      const db = dev.getBoundingClientRect();
      const x0 = db.right - wb.left;
      const y0 = db.top + db.height / 2 - wb.top;
      const next: string[] = [];
      wrap.querySelectorAll<HTMLElement>('[data-service-card]').forEach((el) => {
        const b = el.getBoundingClientRect();
        const x = b.left - wb.left;
        const y = b.top + b.height / 2 - wb.top;
        next.push(`M${x0} ${y0} C ${x0 + 30} ${y0}, ${x - 30} ${y}, ${x} ${y}`);
      });
      setPaths((prev) => (prev.join('|') === next.join('|') ? prev : next));
    };
    draw();
    if (typeof ResizeObserver === 'undefined' || !wrapRef.current) return;
    const ro = new ResizeObserver(draw);
    ro.observe(wrapRef.current);
    return () => ro.disconnect();
  }, [crypto, plain, loading, failed]);

  return (
    <section
      data-testid="network-map-exploded"
      aria-label={`Services and crypto on ${asset.display_name || 'this device'}`}
      style={{ marginTop: 18, paddingTop: 16, borderTop: '1px solid var(--app-border)' }}
    >
      <div ref={wrapRef} style={{ position: 'relative', display: 'flex', gap: 56, alignItems: 'center' }}>
        <svg aria-hidden style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', pointerEvents: 'none', overflow: 'visible' }}>
          {paths.map((d, i) => (
            <path key={i} d={d} fill="none" stroke="var(--app-border2)" strokeWidth={1.2} />
          ))}
        </svg>

        <div
          ref={deviceRef}
          style={{
            width: 196, flexShrink: 0, position: 'relative', textAlign: 'center',
            border: '1px solid var(--app-border2)', borderRadius: 13, background: 'var(--app-panel)', padding: '14px 12px',
          }}
        >
          <button className="ui-btn sm ghost" onClick={onClose} title="Close" aria-label="Close"
            style={{ position: 'absolute', top: 5, right: 5, padding: '2px 5px' }}>
            <Icon name="x" size={12} />
          </button>
          <Icon name={assetIcon(asset.class_key)} size={26} style={{ color: 'var(--app-t2)' }} />
          <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--app-t1)', marginTop: 5, wordBreak: 'break-word' }}>
            {asset.display_name || 'Unnamed asset'}
          </div>
          {asset.address && <div className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>{asset.address}</div>}
          <div style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 3 }}>
            {classLabel(asset.class_key) || asset.class_key}
            {asset.risk_assessed ? ` · risk ${asset.risk_score}` : ' · risk not assessed'}
          </div>
          {asset.asset_status === 'pending_approval' && (
            <div style={{ fontSize: 11, color: 'var(--warn)', marginTop: 4 }}>Waiting for approval</div>
          )}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 11 }}>
            <Link to={`/inventory/assets/${asset.asset_id}`} className="ui-btn sm" style={{ textDecoration: 'none', fontSize: 12, justifyContent: 'center' }}>
              <Icon name="external-link" size={12} />Open asset
            </Link>
            <button className="ui-btn sm ghost" style={{ fontSize: 12, justifyContent: 'center' }} onClick={() => onShowNeighbourhood(asset.asset_id)}>
              <Icon name="waypoints" size={12} />Show neighbourhood
            </button>
          </div>
        </div>

        <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 9 }}>
          {loading && (
            <div data-service-card data-testid="exploded-loading" style={dashedCard}>
              <Icon name="loader" size={13} /> Loading this device&rsquo;s services…
            </div>
          )}
          {!loading && failed && (
            <div data-service-card data-testid="exploded-error" style={{ ...dashedCard, color: 'var(--danger-text)' }}>
              Couldn&rsquo;t load this device&rsquo;s services. This is not an answer of &ldquo;none&rdquo;.{' '}
              <button className="ui-btn sm ghost" style={{ fontSize: 12 }}
                onClick={() => { void endpointsQ.refetch(); void configsQ.refetch(); }}>
                Retry
              </button>
            </div>
          )}
          {!loading && !failed && crypto.map((s) => <ServiceCard key={s.key} service={s} showAddress={multiHomed} />)}
          {!loading && !failed && plain.length > 0 && (
            <div data-service-card data-testid="exploded-plain" style={dashedCard}>
              <div style={{ fontSize: 12, color: 'var(--app-t2)', marginBottom: 7 }}>
                {plain.length} open service{plain.length === 1 ? '' : 's'}, no crypto observed yet
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {plain.map((e) => (
                  <Chip key={e.id} tone="neutral">
                    {multiHomed && stripMask(e.address) ? `${stripMask(e.address)}:` : ''}{e.port ? `${e.port} ` : ''}{e.service_name || e.protocol || e.transport || 'service'}
                  </Chip>
                ))}
              </div>
            </div>
          )}
          {!loading && !failed && crypto.length === 0 && plain.length === 0 && (
            <div data-service-card data-testid="exploded-empty" style={dashedCard}>
              No services observed. This device was seen on the network, so it is on the map, but nothing it serves has
              been measured yet.
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

const dashedCard = {
  border: '1px dashed var(--app-border2)', borderRadius: 12, padding: '10px 12px',
  fontSize: 12, color: 'var(--app-t3)', lineHeight: 1.55,
} as const;

function Chip({ tone, children, dashed, title }: { tone: ChipTone; children: ReactNode; dashed?: boolean; title?: string }) {
  const s = CHIP_STYLE[tone];
  return (
    <span
      className="mono"
      title={title}
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 11, padding: '2px 7px', borderRadius: 7,
        background: dashed ? 'transparent' : s.bg, color: s.fg,
        border: dashed ? `1px dashed ${tone === 'neutral' ? 'var(--app-border2)' : s.fg}` : '1px solid transparent',
      }}
    >
      {children}
    </span>
  );
}

/**
 * One service card. Its configurations are MERGED: a service measured more
 * than once (a passive observation and an active probe) carries several rows
 * with overlapping components, and listing them separately would show the same
 * key exchange three times.
 */
/** `10.0.0.1/32` → `10.0.0.1`: endpoints store inet, and a host mask is noise. */
function stripMask(addr?: string | null): string {
  return (addr ?? '').replace(/\/(32|128)$/, '');
}

function ServiceCard({ service, showAddress }: { service: Service; showAddress: boolean }) {
  const { endpoint, configs } = service;
  const componentQs = useQueries({
    queries: configs.map((c) => ({
      queryKey: ['config-components', c.id],
      queryFn: async (): Promise<Component[]> => {
        const { data, error } = await clients.inventory.GET('/crypto-configurations/{id}/components', {
          params: { path: { id: c.id } },
        });
        if (error || !data) throw new Error('Failed to load assessment');
        return data.components ?? [];
      },
    })),
  });

  const certIds = useMemo(
    () => [...new Set(configs.map((c) => c.certificate_id as string | undefined).filter((x): x is string => !!x))],
    [configs],
  );

  const components = useMemo(() => {
    // Observed wins over offered: if any configuration uses a component, it is
    // used, however many other rows only list it as offered.
    const merged = new Map<string, Component>();
    for (const q of componentQs) {
      for (const c of q.data ?? []) {
        const key = `${c.algorithm_type}|${c.name}`;
        const prev = merged.get(key);
        if (!prev || (prev.is_inferred && !c.is_inferred)) merged.set(key, c);
      }
    }
    return [...merged.values()];
  }, [componentQs]);

  const observed = components.filter((c) => !c.is_inferred);
  // Offered-only components are shown only when they are a weakness. A server
  // offering twelve strong MACs it never negotiated is noise; one offering
  // hmac-sha1 is a reachable weak option, which is a finding.
  const offeredWeak = components.filter((c) => c.is_inferred && (strengthRank(c.strength) ?? 9) <= 1);
  const loadingComponents = componentQs.some((q) => q.isLoading);
  const componentsFailed = componentQs.some((q) => q.isError);

  const keySizes = [...new Set(configs.map((c) => c.key_size).filter((k): k is number => typeof k === 'number' && k > 0))];

  const addr = endpoint && showAddress ? stripMask(endpoint.address) : '';
  const title = endpoint
    ? `${addr ? `${addr}:` : ''}${endpoint.port ?? ''}`
    : 'Not tied to a service';
  const subtitle = endpoint
    ? [endpoint.protocol || endpoint.transport, endpoint.service_name].filter(Boolean).join(' · ')
    : 'Crypto measured on this device without an endpoint';

  const roleOrder: Component['algorithm_type'][] = ['protocol_version', 'key_exchange', 'cipher_suite', 'symmetric', 'signature', 'hash'];
  observed.sort((a, b) => roleOrder.indexOf(a.algorithm_type) - roleOrder.indexOf(b.algorithm_type) || (a.name < b.name ? -1 : 1));

  return (
    <div data-service-card data-testid="exploded-service"
      style={{ border: '1px solid var(--app-border)', borderRadius: 12, background: 'var(--app-panel)', padding: '9px 12px' }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'baseline', marginBottom: 7 }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--app-t1)' }}>{title}</span>
        <span style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>{subtitle}</span>
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
        {loadingComponents && <Chip tone="neutral">assessing…</Chip>}
        {!loadingComponents && componentsFailed && <Chip tone="neutral">couldn&rsquo;t load the assessment</Chip>}
        {!loadingComponents && !componentsFailed && observed.length === 0 && offeredWeak.length === 0 && (
          <Chip tone="neutral" title="Nothing on this service resolved against the algorithm catalogue. That is not a clean result.">
            not assessed
          </Chip>
        )}
        {observed.map((c) => (
          <Chip key={`${c.algorithm_type}|${c.name}`} tone={strengthTone(c)}
            title={`${ROLE_LABEL[c.algorithm_type]} — in use. Catalogue: ${c.strength || 'no strength recorded'}${c.is_pqc ? ', post-quantum' : ''}`}>
            {c.is_pqc && <Icon name="shield-check" size={11} />}
            {c.name}
          </Chip>
        ))}
        {offeredWeak.map((c) => (
          <Chip key={`offer|${c.algorithm_type}|${c.name}`} tone={strengthTone(c)} dashed
            title={`${ROLE_LABEL[c.algorithm_type]} — offered by the server but not used in the observed session. A reachable weak option is still a weakness.`}>
            also offers {c.name}
          </Chip>
        ))}
        {keySizes.map((k) => <Chip key={`k${k}`} tone="neutral">{k}-bit key</Chip>)}
        {certIds.map((id) => <CertChip key={id} certId={id} />)}
      </div>
    </div>
  );
}

function CertChip({ certId }: { certId: string }) {
  const q = useQuery({
    queryKey: ['cert-detail', certId],
    queryFn: async (): Promise<Certificate> => {
      const { data, error } = await clients.inventory.GET('/certificates/{id}', { params: { path: { id: certId } } });
      if (error || !data) throw new Error('Failed to load certificate');
      return data.certificate;
    },
  });
  if (q.isLoading) return <Chip tone="neutral">certificate…</Chip>;
  if (q.isError || !q.data) return <Chip tone="neutral">certificate unavailable</Chip>;
  const c = q.data;
  const days = daysUntil(c.not_after);
  const tone: ChipTone = days === null ? 'neutral' : days < 0 ? 'bad' : days < 90 ? 'warn' : 'neutral';
  const expiry = c.not_after
    ? days !== null && days < 0
      ? `expired ${String(c.not_after).slice(0, 10)}`
      : `expires ${String(c.not_after).slice(0, 10)}${days !== null && days < 90 ? ` (${days} days)` : ''}`
    : 'no expiry recorded';
  return (
    <Chip tone={tone} title={c.subject_dn}>
      <Icon name="file-badge" size={11} />
      {(c.common_name) || 'certificate'} · {expiry}
    </Chip>
  );
}
