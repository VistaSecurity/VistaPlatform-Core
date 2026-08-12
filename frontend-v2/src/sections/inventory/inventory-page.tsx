import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import { useQuery, useMutation, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import type { Asset } from '@vistasecurity/api-contract';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { Icon, Modal, RiskChip, LevelDot, levelFromScore } from '../../components/ui';
import { findLens } from './lenses';
import { AssetDrawer, CertDrawer, ConfigDrawer, KeyDrawer, type Certificate, type CryptoConfig, type Key, type OpenAsset, type OpenCert, type OpenConfig, type OpenKey } from './drawers';
import { AssetFormModal } from './asset-form-modal';
import { CertificateUploadModal } from './certificate-upload-modal';
import { StaleRowActions, StaleBulkBar } from './bulk-actions';

// Inventory — lens-based view. One backend dataset reshaped by angle. The active
// lens comes from the URL (`?lens=`); the switcher lives in the LEFT SIDEBAR.
//
//   infrastructure  → grouped accordion: asset header → expand → its configs
//   network         → accordion grouped by network segment → asset child rows
//   stale           → flat asset table filtered to not-seen-recently / non-active
//   connections     → 3rd-party external connections (own dataset)
//   certificate / configuration / tls / ssh → flat config tables
//
// Drill-down goes through one drawer STACK: config (base) → asset → certificate,
// any direction, top drawer closes first (Esc / scrim).

const PAGE_SIZE = 50;
const STALE_DAYS = 14;

// Count of discovered assets waiting in the approval queue. New discoveries
// land as pending_approval and are EXCLUDED from every inventory lens until a
// user approves them (Discovery → Approvals) — without this count, a fresh
// tenant sees sensors reporting and an empty Inventory with nothing saying why.
// page_size 1: only pagination.total is needed.
function usePendingApprovalCount() {
  return useQuery({
    queryKey: ['inventory', 'pending-approval-count'],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/infrastructure-assets', {
        params: { query: { asset_status: 'pending_approval', page: 1, page_size: 1 } },
      });
      if (error || !data) throw new Error('Failed to load pending-approval count');
      return data.pagination?.total ?? (data.assets?.length ?? 0);
    },
  });
}

function useAssets(page: number, search: string, enabled: boolean, lastSeenBefore?: string) {
  return useQuery({
    queryKey: ['inventory', 'assets', page, search, lastSeenBefore ?? ''],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/infrastructure-assets', {
        params: { query: { page, page_size: PAGE_SIZE, ...(search ? { search } : {}), ...(lastSeenBefore ? { last_seen_before: lastSeenBefore } : {}) } },
      });
      if (error || !data) throw new Error('Failed to load assets');
      return data;
    },
    enabled, placeholderData: keepPreviousData,
  });
}

function useCerts(page: number, search: string, enabled: boolean, ownership?: 'internal' | 'third_party' | 'unknown') {
  return useQuery({
    queryKey: ['inventory', 'certs', page, search, ownership ?? ''],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/certificates', {
        params: { query: { page, page_size: PAGE_SIZE, ...(search ? { search } : {}), ...(ownership ? { ownership } : {}), sort_by: 'not_after', sort_order: 'asc' } },
      });
      if (error || !data) throw new Error('Failed to load certificates');
      return data;
    },
    enabled, placeholderData: keepPreviousData,
  });
}

// Keys are NOT server-paginated — GET /keys returns the full set under `keys`
// (key counts are modest; the endpoint deliberately returns all). The lens
// filters client-side by search, consistent with that envelope.
function useKeys(enabled: boolean) {
  return useQuery({
    queryKey: ['inventory', 'keys'],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/keys');
      if (error || !data) throw new Error('Failed to load keys');
      return (data.keys ?? []) as Key[];
    },
    enabled, placeholderData: keepPreviousData,
  });
}

function useConfigs(page: number, search: string, enabled: boolean) {
  return useQuery({
    queryKey: ['inventory', 'configs', page, search],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/crypto-configurations', {
        params: { query: { page, page_size: PAGE_SIZE, ...(search ? { search } : {}) } },
      });
      if (error || !data) throw new Error('Failed to load crypto configurations');
      return data;
    },
    enabled, placeholderData: keepPreviousData,
  });
}

function useConnections(page: number, search: string, enabled: boolean) {
  return useQuery({
    queryKey: ['inventory', 'connections', page, search],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/external-connections', {
        params: { query: { page, page_size: PAGE_SIZE, ...(search ? { search } : {}) } },
      });
      if (error || !data) throw new Error('Failed to load external connections');
      return data;
    },
    enabled, placeholderData: keepPreviousData,
  });
}

// Elevate a 3rd-party connection to a managed/monitored asset. The new
// asset surfaces in the Infrastructure + Certificate lenses; the connection row
// then shows an "Elevated" badge instead of the action.
function useElevateConnection() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const { data, error } = await clients.inventory.POST('/external-connections/{id}/elevate', {
        params: { path: { id } },
      });
      if (error || !data) throw new Error('Failed to elevate connection');
      return data;
    },
    onSuccess: () => toast.success('Connection elevated to managed inventory'),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Elevation failed'),
    onSettled: () => {
      qc.invalidateQueries({ queryKey: ['inventory', 'connections'] });
      qc.invalidateQueries({ queryKey: ['inventory'] });
    },
  });
}

function useSegments(enabled: boolean) {
  return useQuery({
    queryKey: ['inventory', 'segments'],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/network-segments');
      if (error || !data) throw new Error('Failed to load network segments');
      return data.network_segments ?? [];
    },
    enabled,
  });
}

function daysSince(iso?: string | null): number | null {
  if (!iso) return null;
  return Math.floor((Date.now() - new Date(iso).getTime()) / 86400000);
}
function daysUntil(iso?: string | null): number | null {
  if (!iso) return null;
  return Math.floor((new Date(iso).getTime() - Date.now()) / 86400000);
}
function daysAgo(iso?: string | null): string {
  const d = daysSince(iso);
  return d == null ? '—' : d < 1 ? 'today' : `${d}d ago`;
}

// ---- client-side filters (mock parity: Environment / Risk / Strength) ----
// Server lists support only search, so these cut the current page ( tracks
// pushing staleness/status — and eventually these — into query params).
type Strength = 'Weak' | 'Acceptable' | 'Strong';
const STRENGTH_META: Record<Strength, { color: string; icon: string }> = {
  Weak: { color: 'var(--danger)', icon: 'shield-x' },
  Acceptable: { color: 'var(--warn)', icon: 'shield' },
  Strong: { color: 'var(--ok)', icon: 'shield-check' },
};
function strengthOfLevel(level: string): Strength {
  const l = level.toLowerCase();
  if (l === 'critical' || l === 'high') return 'Weak';
  if (l === 'medium') return 'Acceptable';
  return 'Strong';
}
const ENV_OPTS = ['All', 'Production', 'Staging', 'Development', 'Test'];
const RISK_OPTS = ['All', 'Critical', 'High', 'Medium', 'Low', 'Informational'];
const STRENGTH_OPTS = ['All', 'Weak', 'Acceptable', 'Strong'];

function downloadCsv(filename: string, header: string[], rows: (string | number | null | undefined)[][]) {
  const esc = (v: string | number | null | undefined) => {
    let s = v == null ? '' : String(v);
    // Neutralize formula injection: a leading = + - @ tab or CR makes
    // Excel/Sheets execute the cell. Inventory values (hostnames, tags, BUs)
    // are attacker-influenceable via discovery.
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  const csv = [header, ...rows].map((r) => r.map(esc).join(',')).join('\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

// A drawer stack — pushing config/asset/cert entries; the top one is `active`
// (closes on Esc / scrim) and paints highest (depth → z-index in DrawerShell).
type DrawerEntry =
  | { kind: 'config'; config: CryptoConfig }
  | { kind: 'asset'; assetId: string; seed?: Partial<Asset> }
  | { kind: 'cert'; certId: string }
  | { kind: 'key'; keyId: string };

const CFG_GRID = '22px minmax(0,1.5fr) 1fr minmax(0,1.4fr) 1fr 110px';
const CERT_GRID = '18px minmax(0,1.6fr) minmax(0,1.2fr) 1fr 90px 120px';
const KEY_GRID = '18px minmax(0,1.6fr) minmax(0,1.2fr) 100px 90px 120px';
const STALE_GRID = '22px minmax(0,1.6fr) 1fr 1fr 110px 70px 84px';
const CONN_GRID = '22px minmax(0,1.6fr) 1fr minmax(0,1.4fr) 90px 100px 90px 104px';

export function InventoryPage() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const pendingCount = usePendingApprovalCount().data ?? 0;
  const def = findLens(params.get('lens'));
  const lens = def.key;
  const isConfig = def.anchor === 'config';
  const [page, setPage] = useState(1);
  // Seed the search box from `?q=` so the command palette (⌘K) can deep-link to
  // a specific asset/cert: navigating to /inventory?lens=…&q=<name> pre-filters.
  const [search, setSearch] = useState(() => params.get('q') ?? '');
  const [fEnv, setFEnv] = useState('All');
  const [fRisk, setFRisk] = useState('All');
  const [fStrength, setFStrength] = useState('All');
  // Cert-lens ownership filter: All | 3rd-party | Internal.
  const [fCertOwner, setFCertOwner] = useState('All');
  const hasFilters = fEnv !== 'All' || fRisk !== 'All' || fStrength !== 'All';
  const clearFilters = () => { setFEnv('All'); setFRisk('All'); setFStrength('All'); };
  const [stack, setStack] = useState<DrawerEntry[]>([]);
  // Elevate-connection confirm: holds the connection pending confirmation.
  const elevate = useElevateConnection();
  const [confirmConn, setConfirmConn] = useState<{ id: string; label: string } | null>(null);
  // Asset create/edit modal (page-level so the fixed-position scrim isn't
  // constrained by the transformed drawer ancestors).
  const [formOpen, setFormOpen] = useState(false);
  const [editAsset, setEditAsset] = useState<Asset | null>(null);
  const [certUploadOpen, setCertUploadOpen] = useState(false);

  const openConfig: OpenConfig = (config) => setStack((s) => [...s, { kind: 'config', config }]);
  const openAsset: OpenAsset = (assetId, seed) => setStack((s) => [...s, { kind: 'asset', assetId, seed }]);
  const openCert: OpenCert = (certId) => setStack((s) => [...s, { kind: 'cert', certId }]);
  const openKey: OpenKey = (keyId) => setStack((s) => [...s, { kind: 'key', keyId }]);
  const popTop = () => setStack((s) => s.slice(0, -1));

  // Reset page + close any drawers whenever the lens changes (filters persist —
  // they describe the user's slice of interest, not the lens).
  useEffect(() => { setPage(1); setStack([]); setFCertOwner('All'); }, [lens]);

  // Re-seed search when the palette deep-links again while we're already mounted
  // (URL `?q=` changes without a remount). Only acts when q is present, so it
  // never clobbers a search the user typed directly.
  const qParam = params.get('q');
  useEffect(() => { if (qParam !== null) { setSearch(qParam); setPage(1); } }, [qParam]);

  const isConn = lens === 'connections';
  const isCert = def.anchor === 'cert';
  const isKey = def.anchor === 'key';
  // Stale lens: SERVER-SIDE staleness cut (/) — last_seen_before with an
  // hour-stable cutoff so the query key doesn't churn every render. The whole
  // dataset is filtered (correct totals + pagination), not just the page.
  const staleCutoff = lens === 'stale'
    ? new Date(Math.floor(Date.now() / 3600000) * 3600000 - STALE_DAYS * 86400000).toISOString()
    : undefined;
  const assetsQ = useAssets(page, search, def.anchor === 'asset' && !isConn, staleCutoff);
  const certOwnership = fCertOwner === '3rd-party' ? 'third_party' : fCertOwner === 'Internal' ? 'internal' : undefined;
  const certsQ = useCerts(page, search, isCert, isCert ? certOwnership : undefined);
  const keysQ = useKeys(isKey);
  const configsQ = useConfigs(page, search, isConfig);
  const connsQ = useConnections(page, search, isConn);
  const segsQ = useSegments(lens === 'network');
  const q = isConn ? connsQ : isCert ? certsQ : isKey ? keysQ : isConfig ? configsQ : assetsQ;

  const levelOfA = (a: Asset) => a.risk_level || levelFromScore(typeof a.risk_score === 'number' ? a.risk_score : 0);
  const levelOfC = (c: CryptoConfig) => (c.risk_level as string) || levelFromScore(typeof c.risk_score === 'number' ? c.risk_score : 0);

  let assets = assetsQ.data?.assets ?? [];
  if (fEnv !== 'All') assets = assets.filter((a) => (a.environment || '').toLowerCase() === fEnv.toLowerCase());
  if (fRisk !== 'All') assets = assets.filter((a) => levelOfA(a) === fRisk);

  const certs = (certsQ.data?.certificates ?? []) as Certificate[];

  // Keys: client-side search (the endpoint returns the full set, unpaginated).
  let keys = (keysQ.data ?? []) as Key[];
  if (isKey && search.trim()) {
    const needle = search.trim().toLowerCase();
    keys = keys.filter((k) => [k.key_type, k.material_type, k.curve, k.algorithm_ref, k.public_fingerprint, k.state]
      .some((v) => (v || '').toLowerCase().includes(needle)));
  }

  let configs = configsQ.data?.crypto_implementations ?? [];
  if (def.protocol) configs = configs.filter((c) => (c.protocol || '').toUpperCase() === def.protocol);
  if (fEnv !== 'All') configs = configs.filter((c) => (c.asset_environment || '').toLowerCase() === fEnv.toLowerCase());
  if (fRisk !== 'All') configs = configs.filter((c) => levelOfC(c as CryptoConfig) === fRisk);
  if (fStrength !== 'All') configs = configs.filter((c) => strengthOfLevel(levelOfC(c as CryptoConfig)) === fStrength);

  const conns = connsQ.data?.connections ?? [];
  // Server already applied the staleness cut for the stale lens.
  const staleAssets = assets;

  // Keys aren't server-paginated, so their total is just the (search-filtered) length.
  const total = (isConn ? connsQ.data?.pagination?.total : isCert ? certsQ.data?.pagination?.total : isKey ? keys.length : isConfig ? configsQ.data?.pagination?.total : assetsQ.data?.pagination?.total) ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const unit = isConn ? 'connections' : isCert ? 'certs' : isKey ? 'keys' : isConfig ? 'configs' : 'assets';
  const shown = isConn ? conns.length : isCert ? certs.length : isKey ? keys.length : isConfig ? configs.length : assets.length;
  const countLabel = lens === 'stale' ? `${total} stale`
    : hasFilters && !isConn ? `${shown} of ${total} ${unit}` : `${total} ${unit}`;

  const exportCsv = () => {
    const stamp = new Date().toISOString().slice(0, 10);
    if (isConn) {
      downloadCsv(`vista-inventory-connections-${stamp}.csv`,
        ['destination', 'port', 'source', 'protocol', 'version', 'cipher_suite', 'crypto_strength', 'cert_not_after', 'last_seen_at'],
        conns.map((cn) => [cn.dest_hostname || cn.dest_ip, cn.dest_port, cn.source_hostname || cn.source_ip, cn.protocol, cn.protocol_version, cn.cipher_suite, cn.crypto_strength, cn.cert_not_after, cn.last_seen_at]));
    } else if (isCert) {
      downloadCsv(`vista-inventory-certificates-${stamp}.csv`,
        ['common_name', 'subject', 'issuer', 'key_algorithm', 'key_size', 'signature_algorithm', 'not_after', 'days_remaining', 'state', 'data_source', 'deployment_count'],
        certs.map((c) => {
          const d = daysUntil(c.not_after as string | undefined);
          return [c.common_name, c.subject_dn, c.issuer_dn, c.public_key_algorithm, c.public_key_size, c.signature_algorithm, (c.not_after as string | undefined)?.slice(0, 10), d, c.certificate_state, c.data_source, c.deployment_count ?? 0];
        }));
    } else if (isKey) {
      downloadCsv(`vista-inventory-keys-${stamp}.csv`,
        ['key_type', 'material_type', 'size_bits', 'curve', 'algorithm', 'state', 'format', 'expires_at', 'fingerprint', 'deployment_count'],
        keys.map((k) => [k.key_type, k.material_type, k.size_bits as number, k.curve, k.algorithm_ref, k.state, k.format, (k.expires_at as string | undefined)?.slice(0, 10), k.public_fingerprint, k.deployment_count ?? 0]));
    } else if (isConfig) {
      downloadCsv(`vista-inventory-${lens}-${stamp}.csv`,
        ['host', 'environment', 'protocol', 'version', 'cipher_suite', 'key_exchange', 'signature', 'symmetric', 'hash', 'key_size', 'risk_level', 'risk_score'],
        configs.map((c) => [c.asset_hostname, c.asset_environment, c.protocol, c.protocol_version, c.cipher_suite, c.key_exchange_algorithm, c.signature_algorithm, c.symmetric_encryption, c.hash_algorithm, c.key_size as number, levelOfC(c as CryptoConfig), c.risk_score as number]));
    } else {
      const rows = lens === 'stale' ? staleAssets : assets;
      downloadCsv(`vista-inventory-${lens}-${stamp}.csv`,
        ['hostname', 'ip', 'port', 'type', 'environment', 'segment', 'status', 'last_seen_at', 'risk_score'],
        rows.map((a) => [a.hostname, a.ip_address, a.port, a.asset_type, a.environment, a.network_segment_name || a.business_unit, a.asset_status, a.last_seen_at, typeof a.risk_score === 'number' ? a.risk_score : 0]));
    }
  };

  const renderBody = () => {
    if (q.isError) return <Center icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load inventory" message={q.error instanceof Error ? q.error.message : 'Request failed'} />;
    if (q.isLoading) return <Center icon="loader" tone="var(--app-t3)" title="Loading…" message="Fetching the tenant's inventory." />;

    if (isConn) {
      if (conns.length === 0) return <Center icon="link" tone="var(--accent)" title="No 3rd-party connections" message={search ? 'Nothing matches your search.' : 'Outbound TLS endpoints your assets talk to (SaaS, partners, APIs) appear here once discovered.'} />;
      return (
        <>
          <Header grid={CONN_GRID} cols={['', 'Destination', 'Protocol', 'Cipher suite', 'Strength', 'Cert expires', 'Last seen', '']} />
          {conns.map((cn) => {
            const strength = cn.crypto_strength || 'unknown';
            const tone = strength === 'good' ? 'var(--ok)' : strength === 'weak' ? 'var(--danger)' : 'var(--warn)';
            const certDays = cn.cert_not_after ? -(daysSince(cn.cert_not_after) ?? 0) : null;
            return (
              <div key={cn.id} className="row-hover" style={{ display: 'grid', gridTemplateColumns: CONN_GRID, gap: 12, padding: '0 16px', minHeight: 46, alignItems: 'center', borderBottom: '1px solid var(--app-border)' }}>
                <LevelDot level={strength === 'weak' ? 'High' : strength === 'good' ? 'Informational' : 'Medium'} />
                <div style={{ minWidth: 0 }}>
                  <div className="mono" style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{cn.dest_hostname || cn.dest_ip}:{cn.dest_port}</div>
                  <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>from {cn.source_hostname || cn.source_ip}</div>
                </div>
                <Mono v={`${cn.protocol || ''} ${cn.protocol_version || ''}`.trim()} />
                <Mono v={cn.cipher_suite} small />
                <span style={{ fontSize: 11, fontWeight: 600, color: tone, background: `color-mix(in srgb, ${tone} 11%, transparent)`, borderRadius: 40, padding: '2px 9px', justifySelf: 'start', textTransform: 'capitalize' }}>{strength}</span>
                <Mono v={certDays == null ? '—' : cn.cert_is_expired ? 'expired' : `${certDays}d`} />
                <Mono v={daysAgo(cn.last_seen_at)} small />
                <div style={{ justifySelf: 'end' }}>
                  {cn.elevated_asset_id ? (
                    <span title="Promoted to managed inventory — tracked like an internal asset" style={{ fontSize: 10.5, fontWeight: 600, color: 'var(--ok)', background: 'color-mix(in srgb, var(--ok) 11%, transparent)', borderRadius: 40, padding: '2px 8px', display: 'inline-flex', alignItems: 'center', gap: 4, whiteSpace: 'nowrap' }}>
                      <Icon name="shield-check" size={11} /> Elevated
                    </span>
                  ) : (
                    <PermissionGate permission={TENANT_PERMISSIONS.assets.update}>
                      <button
                        className="ui-btn"
                        style={{ fontSize: 11, padding: '3px 10px' }}
                        disabled={elevate.isPending}
                        title="Promote this vendor connection to a monitored asset"
                        onClick={(e) => { e.stopPropagation(); setConfirmConn({ id: cn.id, label: `${cn.dest_hostname || cn.dest_ip}:${cn.dest_port}` }); }}
                      >Elevate</button>
                    </PermissionGate>
                  )}
                </div>
              </div>
            );
          })}
        </>
      );
    }

    if (isCert) {
      if (certs.length === 0) return <Center icon="file-badge" tone="var(--accent)" title="No certificates" message={search ? 'Nothing matches your search.' : 'Upload a certificate or run discovery to populate this view.'} />;
      return (
        <>
          <Header grid={CERT_GRID} cols={['', 'Certificate', 'Issuer', 'Key', 'Expires', 'Deployed on']} />
          {certs.map((c) => <CertRow key={c.id as string} cert={c} onClick={() => openCert(c.id as string)} />)}
        </>
      );
    }

    if (isKey) {
      if (keys.length === 0) return <Center icon="key-round" tone="var(--accent)" title="No keys" message={search ? 'Nothing matches your search.' : 'Cryptographic keys discovered across your environment appear here.'} />;
      return (
        <>
          <Header grid={KEY_GRID} cols={['', 'Key', 'Algorithm', 'State', 'Expires', 'Used by']} />
          {keys.map((k) => <KeyRow key={k.id as string} keyItem={k} onClick={() => openKey(k.id as string)} />)}
        </>
      );
    }

    if (lens === 'network') {
      const segs = segsQ.data ?? [];
      const byName = new Map<string, Asset[]>();
      // Pre-seed with all known segments so empty ones still render
      for (const seg of segs) byName.set(seg.name as string, []);
      for (const a of assets) {
        const k = a.network_segment_name || 'Unsegmented';
        if (!byName.has(k)) byName.set(k, []);
        byName.get(k)!.push(a);
      }
      if (byName.size === 0) return <Center icon="inbox" tone="var(--app-t3)" title="Nothing here" message={search ? 'Nothing matches your search.' : 'No assets discovered yet.'} />;
      const groups = [...byName.entries()].sort((x, y) => y[1].length - x[1].length);
      return groups.map(([name, list], gi) => {
        const meta = segs.find((s) => s.name === name);
        return <SegmentGroup key={name} name={name} meta={meta} assets={list} openAsset={openAsset} defaultOpen={gi < 3} />;
      });
    }

    if (lens === 'stale') {
      if (staleAssets.length === 0) return <Center icon="clock-alert" tone="var(--ok)" title="No stale assets" message={`Nothing has gone unseen for over ${STALE_DAYS} days.`} />;
      return (
        <>
          <StaleBulkBar assetIds={staleAssets.map((a) => a.id as string)} />
          <Header grid={STALE_GRID} cols={['', 'Host', 'Type', 'Segment', 'Status', 'Last seen', '']} />
          {staleAssets.map((a) => {
            const risk = typeof a.risk_score === 'number' ? a.risk_score : 0;
            const level = a.risk_level || levelFromScore(risk);
            const d = daysSince(a.last_seen_at);
            return (
              <div key={a.id} className="row-hover" onClick={() => openAsset(a.id as string, a)} style={{ display: 'grid', gridTemplateColumns: STALE_GRID, gap: 12, padding: '0 16px', minHeight: 46, alignItems: 'center', borderBottom: '1px solid var(--app-border)', cursor: 'pointer' }}>
                <RiskChip level={level} size={22} />
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{a.hostname || '—'}</div>
                  <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>{a.ip_address || ''}</div>
                </div>
                <Txt v={a.asset_type} />
                <Txt v={a.network_segment_name || a.business_unit} />
                <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--warn)', background: 'color-mix(in srgb, var(--warn) 11%, transparent)', borderRadius: 40, padding: '2px 9px', justifySelf: 'start', textTransform: 'capitalize' }}>{a.asset_status || 'unknown'}</span>
                <span className="mono" style={{ fontSize: 12, color: 'var(--warn-strong)' }}>{d != null ? `${d}d` : '—'}</span>
                <StaleRowActions assetId={a.id as string} />
              </div>
            );
          })}
        </>
      );
    }

    if (lens === 'configuration') {
      // mock parity: configs grouped by strength (Weak / Acceptable / Strong)
      if (configs.length === 0) return <Center icon="inbox" tone="var(--app-t3)" title="Nothing here" message={search || hasFilters ? 'Nothing matches your filters.' : 'No crypto configurations yet.'} />;
      const order: Strength[] = ['Weak', 'Acceptable', 'Strong'];
      return order
        .map((st) => ({ st, list: configs.filter((c) => strengthOfLevel(levelOfC(c as CryptoConfig)) === st) }))
        .filter((g) => g.list.length > 0)
        .map((g) => <StrengthGroup key={g.st} strength={g.st} configs={g.list as CryptoConfig[]} openConfig={openConfig} defaultOpen={g.st === 'Weak'} />);
    }

    if (isConfig) {
      if (configs.length === 0) return <Center icon="inbox" tone="var(--app-t3)" title="Nothing here" message={search ? 'Nothing matches your search.' : 'No crypto configurations for this lens.'} />;
      return (
        <>
          <Header grid={CFG_GRID} cols={['', 'Host', 'Protocol', 'Cipher suite', 'Key', 'Hash']} />
          {configs.map((c) => (
            <div key={c.id} className="row-hover" onClick={() => openConfig(c as CryptoConfig)} style={{ display: 'grid', gridTemplateColumns: CFG_GRID, gap: 12, padding: '0 16px', minHeight: 46, alignItems: 'center', borderBottom: '1px solid var(--app-border)', cursor: 'pointer' }}>
              <RiskChip level={c.risk_level || levelFromScore(typeof c.risk_score === 'number' ? c.risk_score : 0)} size={22} />
              <div style={{ minWidth: 0 }}>
                <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{c.asset_hostname || '—'}</div>
                <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>{c.asset_environment || ''}</div>
              </div>
              <Mono v={`${c.protocol || ''} ${c.protocol_version || ''}`.trim()} />
              <Mono v={c.cipher_suite} small />
              <Mono v={[c.signature_algorithm || c.key_exchange_algorithm, c.key_size ? `${c.key_size}b` : ''].filter(Boolean).join(' · ')} />
              <Mono v={c.hash_algorithm} small />
            </div>
          ))}
        </>
      );
    }

    // infrastructure — grouped accordion: asset header → expand → its configs
    if (assets.length === 0) {
      const emptyMsg = search
        ? 'Nothing matches your search.'
        : pendingCount > 0
          ? `${pendingCount} discovered asset${pendingCount === 1 ? '' : 's'} are awaiting approval in Discovery → Approvals — they appear here once approved.`
          : 'No assets discovered yet.';
      return <Center icon="inbox" tone="var(--app-t3)" title="Nothing here" message={emptyMsg} />;
    }
    return assets.map((a) => <AssetGroup key={a.id} asset={a} openConfig={openConfig} openAsset={openAsset} />);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 }}>
      {/* toolbar — lens title + search + count (the lens SWITCHER is in the sidebar) */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '16px 26px 12px', flexWrap: 'wrap' }}>
        <h2 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 16, color: 'var(--app-t1)', display: 'flex', alignItems: 'center', gap: 9 }}>
          <Icon name={def.icon} size={17} style={{ color: 'var(--accent)' }} />{def.label}
        </h2>
        <div style={{ position: 'relative', width: 220, marginLeft: 8 }}>
          <Icon name="search" size={14} style={{ position: 'absolute', left: 11, top: 9, color: 'var(--app-t3)' }} />
          <input value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); }} placeholder="Search inventory…"
            style={{ width: '100%', height: 33, padding: '0 12px 0 33px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 13, outline: 'none' }} />
        </div>
        {isCert && (
          <FilterSelect label="Ownership" value={fCertOwner} onChange={setFCertOwner} options={['All', '3rd-party', 'Internal']} />
        )}
        {!isConn && !isCert && !isKey && (
          <>
            <FilterSelect label="Environment" value={fEnv} onChange={setFEnv} options={ENV_OPTS} />
            <FilterSelect label="Risk" value={fRisk} onChange={setFRisk} options={RISK_OPTS} />
            {isConfig && <FilterSelect label="Strength" value={fStrength} onChange={setFStrength} options={STRENGTH_OPTS} />}
            {hasFilters && (
              <button onClick={clearFilters} className="ui-btn ghost" style={{ height: 31, padding: '0 9px', fontSize: 12.5 }}>
                <Icon name="x" size={13} />Clear
              </button>
            )}
          </>
        )}
        <div style={{ flex: 1 }} />
        <span className="mono" style={{ fontSize: 12.5, color: 'var(--app-t3)' }}>
          {q.isLoading ? 'loading…' : countLabel}{q.isFetching && !q.isLoading ? ' · refreshing' : ''}
        </span>
        <button onClick={exportCsv} disabled={q.isLoading || shown === 0} className="ui-btn" style={{ height: 31, padding: '0 11px', fontSize: 12.5, opacity: q.isLoading || shown === 0 ? 0.5 : 1 }} title="Export the current view as CSV">
          <Icon name="download" size={13} />Export
        </button>
        <PermissionGate permission={TENANT_PERMISSIONS.assets.manage}>
          <button onClick={() => setCertUploadOpen(true)} className="ui-btn" style={{ height: 31, padding: '0 11px', fontSize: 12.5 }} title="Upload a certificate (PEM)">
            <Icon name="file-up" size={13} />Upload cert
          </button>
        </PermissionGate>
        <PermissionGate permission={TENANT_PERMISSIONS.assets.create}>
          <button onClick={() => { setEditAsset(null); setFormOpen(true); }} className="ui-btn accent" style={{ height: 31, padding: '0 11px', fontSize: 12.5 }} title="Add an infrastructure asset">
            <Icon name="plus" size={13} />New asset
          </button>
        </PermissionGate>
      </div>

      {/* Pending-approval pointer — new discoveries wait in Discovery → Approvals
          and are invisible to every lens until approved, so say so here. */}
      {pendingCount > 0 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, margin: '0 26px 10px', padding: '8px 14px', borderRadius: 12, border: '1px solid color-mix(in srgb, var(--warn) 35%, transparent)', background: 'color-mix(in srgb, var(--warn) 8%, transparent)' }}>
          <Icon name="inbox" size={15} style={{ color: 'var(--warn)', flexShrink: 0 }} />
          <span style={{ fontSize: 12.5, color: 'var(--app-t1)' }}>
            <strong>{pendingCount}</strong> discovered asset{pendingCount === 1 ? '' : 's'} awaiting approval — approved assets join Inventory with their certificates and crypto configurations.
          </span>
          <div style={{ flex: 1 }} />
          <button className="ui-btn sm" onClick={() => navigate('/discovery/approvals')}>
            Review<Icon name="chevron-right" size={13} />
          </button>
        </div>
      )}

      <div className="panel" style={{ flex: 1, minHeight: 0, margin: '0 26px 14px', overflow: 'auto', borderRadius: 14 }}>
        {renderBody()}
      </div>

      {!q.isLoading && !q.isError && !isKey && total > PAGE_SIZE && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 10, padding: '0 26px 18px' }}>
          <button className="ui-btn sm" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))} style={{ opacity: page <= 1 ? 0.5 : 1 }}><Icon name="chevron-left" size={14} />Prev</button>
          <span className="mono" style={{ fontSize: 12, color: 'var(--app-t3)' }}>{page} / {pages}</span>
          <button className="ui-btn sm" disabled={page >= pages} onClick={() => setPage((p) => Math.min(pages, p + 1))} style={{ opacity: page >= pages ? 0.5 : 1 }}>Next<Icon name="chevron-right" size={14} /></button>
        </div>
      )}

      {/* drawer stack — config (base) → asset → certificate; top closes first */}
      {stack.map((d, i) => {
        const active = i === stack.length - 1;
        if (d.kind === 'config') return <ConfigDrawer key={i} config={d.config} onOpenAsset={openAsset} onOpenCert={openCert} onClose={popTop} active={active} depth={i} />;
        if (d.kind === 'asset') return <AssetDrawer key={i} assetId={d.assetId} seed={d.seed} onOpenConfig={openConfig} onClose={popTop} onEdit={(a) => { setEditAsset(a); setFormOpen(true); }} active={active} depth={i} />;
        if (d.kind === 'key') return <KeyDrawer key={i} keyId={d.keyId} onOpenAsset={openAsset} onClose={popTop} active={active} depth={i} />;
        return <CertDrawer key={i} certId={d.certId} onClose={popTop} active={active} depth={i} />;
      })}

      {formOpen && (
        <AssetFormModal
          open={formOpen}
          asset={editAsset}
          onClose={() => { setFormOpen(false); setEditAsset(null); }}
        />
      )}
      {certUploadOpen && (
        <CertificateUploadModal open={certUploadOpen} onClose={() => setCertUploadOpen(false)} />
      )}
      <Modal
        open={!!confirmConn}
        onClose={elevate.isPending ? undefined : () => setConfirmConn(null)}
        dismissible={!elevate.isPending}
        size="sm"
        tone="accent"
        icon="shield-check"
        eyebrow="3rd-Party Connections"
        title="Elevate to managed?"
        description={confirmConn ? `${confirmConn.label} will become a monitored asset on par with your internal inventory — its certificate is tracked and assessed like an internal one. Find it afterward in the Infrastructure and Certificate lenses.` : ''}
        primary={
          <button className="ui-btn accent" disabled={elevate.isPending} onClick={() => { if (confirmConn) elevate.mutate(confirmConn.id); setConfirmConn(null); }}>
            {elevate.isPending ? 'Elevating…' : 'Elevate'}
          </button>
        }
        secondary={
          <button className="ui-btn" disabled={elevate.isPending} onClick={() => setConfirmConn(null)}>Cancel</button>
        }
      />
    </div>
  );
}

// ---- infrastructure accordion group -------------------------------------
function AssetGroup({ asset, openConfig, openAsset }: { asset: Asset; openConfig: OpenConfig; openAsset: OpenAsset }) {
  const a = asset as Record<string, unknown> & Asset;
  const [open, setOpen] = useState(false);
  const risk = typeof a.risk_score === 'number' ? a.risk_score : 0;
  const riskLevel = asset.risk_level || levelFromScore(risk);
  const certCount = typeof a.certificate_count === 'number' ? a.certificate_count : 0;

  // Children lazy-load on first expand; same query key as AssetDrawer → cache reuse.
  const childrenQ = useQuery({
    queryKey: ['asset-configs', a.id],
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/crypto-configurations', { params: { query: { asset_id: a.id as string, page: 1, page_size: 100 } } });
      if (error || !data) throw new Error('Failed to load configs');
      return data.crypto_implementations ?? [];
    },
    enabled: open,
  });
  const kids = childrenQ.data ?? [];
  const sub = [a.asset_type, a.operating_system, a.network_segment_name || a.business_unit].filter(Boolean).join(' · ');

  return (
    <div>
      <div className="row-hover" style={{ display: 'flex', alignItems: 'center', gap: 12, width: '100%', padding: '11px 16px', borderTop: '1px solid var(--app-border)', background: 'var(--app-panel2)' }}>
        <button onClick={() => setOpen((o) => !o)} style={{ display: 'flex', alignItems: 'center', gap: 12, flex: 1, minWidth: 0, border: 'none', background: 'transparent', cursor: 'pointer', textAlign: 'left', padding: 0 }}>
          <Icon name="chevron-right" size={15} style={{ flex: 'none', color: 'var(--app-t3)', transition: 'transform .18s ease', transform: open ? 'rotate(90deg)' : 'none' }} />
          <RiskChip level={riskLevel} size={24} />
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{(a.hostname as string) || '—'}</div>
            <div style={{ fontSize: 11.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{sub || (a.ip_address as string) || ''}</div>
          </div>
        </button>
        <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)', flex: 'none' }}>{certCount ? `${certCount} cert${certCount === 1 ? '' : 's'}` : ''}</span>
        <span className="mono" style={{ fontSize: 12, color: 'var(--app-t2)', flex: 'none', minWidth: 28, textAlign: 'right' }}>{risk || '—'}</span>
        <button onClick={() => openAsset(a.id as string, a)} title="Asset details" className="ui-btn sm ghost" style={{ flex: 'none', height: 28, padding: '0 9px' }}>
          <Icon name="circle-alert" size={14} />Details
        </button>
      </div>
      {open && (
        <div style={{ background: 'var(--app-bg)' }}>
          {childrenQ.isLoading ? (
            <ChildNote text="Loading configurations…" />
          ) : childrenQ.isError ? (
            <ChildNote text="Couldn't load configurations." />
          ) : kids.length === 0 ? (
            <ChildNote text="No crypto configurations on this asset." />
          ) : (
            kids.map((c) => <ConfigChildRow key={(c as CryptoConfig).id} config={c as CryptoConfig} onClick={() => openConfig(c as CryptoConfig)} />)
          )}
        </div>
      )}
    </div>
  );
}

// ---- network lens: segment accordion -------------------------------------
interface SegmentMeta { value?: string; environment?: string; network_type?: string; location_name?: string }

function SegmentGroup({ name, meta, assets, openAsset, defaultOpen }: {
  name: string; meta?: SegmentMeta; assets: Asset[]; openAsset: OpenAsset; defaultOpen: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const worst = assets.reduce((m, a) => Math.max(m, typeof a.risk_score === 'number' ? a.risk_score : 0), 0);
  const sub = [meta?.value, meta?.environment, meta?.location_name].filter(Boolean).join(' · ');
  return (
    <div>
      <button onClick={() => setOpen((o) => !o)} className="row-hover" style={{ display: 'flex', alignItems: 'center', gap: 12, width: '100%', padding: '11px 16px', border: 'none', borderTop: '1px solid var(--app-border)', background: 'var(--app-panel2)', cursor: 'pointer', textAlign: 'left' }}>
        <Icon name="chevron-right" size={15} style={{ flex: 'none', color: 'var(--app-t3)', transition: 'transform .18s ease', transform: open ? 'rotate(90deg)' : 'none' }} />
        <RiskChip level={levelFromScore(worst)} size={24} />
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--app-t1)' }}>{name}</div>
          <div className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>{sub || `${assets.length} assets`}</div>
        </div>
        <span className="mono" style={{ fontSize: 12, color: 'var(--app-t2)', flex: 'none' }}>{assets.length}</span>
      </button>
      {open && (
        <div style={{ background: 'var(--app-bg)' }}>
          {assets.length === 0
            ? <ChildNote text="No assets discovered in this segment yet." />
            : assets.map((a) => <AssetChildRow key={a.id} asset={a} onClick={() => openAsset(a.id as string, a)} />)}
        </div>
      )}
    </div>
  );
}

const ASSET_CHILD_GRID = '18px minmax(0,1.6fr) 1fr 1fr 90px';

function AssetChildRow({ asset, onClick }: { asset: Asset; onClick: () => void }) {
  const a = asset as Record<string, unknown> & Asset;
  const risk = typeof a.risk_score === 'number' ? a.risk_score : 0;
  const riskLevel = asset.risk_level || levelFromScore(risk);
  return (
    <button onClick={onClick} className="row-hover" style={{ display: 'grid', gridTemplateColumns: ASSET_CHILD_GRID, gap: 12, alignItems: 'center', width: '100%', padding: '0 16px 0 40px', minHeight: 38, border: 'none', borderBottom: '1px solid var(--app-border)', background: 'transparent', cursor: 'pointer', textAlign: 'left' }}>
      <LevelDot level={riskLevel} />
      <div style={{ minWidth: 0 }}>
        <div className="mono" style={{ fontSize: 12.5, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{(a.hostname as string) || '—'}</div>
        <div style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{[a.asset_type, a.operating_system].filter(Boolean).join(' · ')}</div>
      </div>
      <Txt v={a.environment as string} cap />
      <Mono v={(a.ip_address as string) || ''} small />
      <span className="mono" style={{ fontSize: 12, color: 'var(--app-t2)', textAlign: 'right' }}>{risk || '—'}</span>
    </button>
  );
}

const CHILD_GRID = '18px minmax(0,1.5fr) minmax(0,1.3fr) 1fr 56px';

function ConfigChildRow({ config, onClick, showHost }: { config: CryptoConfig; onClick: () => void; showHost?: boolean }) {
  const c = config as Record<string, unknown> & CryptoConfig;
  const level = (c.risk_level as string) || levelFromScore(typeof c.risk_score === 'number' ? c.risk_score : 0);
  return (
    <button onClick={onClick} className="row-hover" style={{ display: 'grid', gridTemplateColumns: CHILD_GRID, gap: 12, alignItems: 'center', width: '100%', padding: '0 16px 0 40px', minHeight: 38, border: 'none', borderBottom: '1px solid var(--app-border)', background: 'transparent', cursor: 'pointer', textAlign: 'left' }}>
      <LevelDot level={level} />
      <div style={{ minWidth: 0 }}>
        <div className="mono" style={{ fontSize: 12.5, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{c.protocol as string} · {c.protocol_version as string}</div>
        <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{showHost ? (c.asset_hostname as string) || '' : (c.cipher_suite as string) || ''}</div>
      </div>
      <Mono v={[(c.signature_algorithm as string) || (c.key_exchange_algorithm as string), c.key_size ? `${c.key_size}b` : ''].filter(Boolean).join(' · ')} />
      <Mono v={[c.symmetric_encryption as string, c.hash_algorithm as string].filter(Boolean).join(' · ')} small />
      <span className="mono" style={{ fontSize: 12, color: 'var(--app-t2)', textAlign: 'right' }}>{typeof c.risk_score === 'number' && c.risk_score ? c.risk_score : '—'}</span>
    </button>
  );
}

// ---- configuration lens: strength accordion -------------------------------
function StrengthGroup({ strength, configs, openConfig, defaultOpen }: {
  strength: Strength; configs: CryptoConfig[]; openConfig: OpenConfig; defaultOpen: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const meta = STRENGTH_META[strength];
  return (
    <div>
      <button onClick={() => setOpen((o) => !o)} className="row-hover" style={{ display: 'flex', alignItems: 'center', gap: 12, width: '100%', padding: '11px 16px', border: 'none', borderTop: '1px solid var(--app-border)', background: 'var(--app-panel2)', cursor: 'pointer', textAlign: 'left' }}>
        <Icon name="chevron-right" size={15} style={{ flex: 'none', color: 'var(--app-t3)', transition: 'transform .18s ease', transform: open ? 'rotate(90deg)' : 'none' }} />
        <span style={{ width: 24, height: 24, borderRadius: 7, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: `color-mix(in srgb, ${meta.color} 13%, transparent)`, color: meta.color }}>
          <Icon name={meta.icon} size={14} />
        </span>
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--app-t1)' }}>{strength} configurations</div>
          <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>{configs.length} config{configs.length === 1 ? '' : 's'}</div>
        </div>
        <span className="mono" style={{ fontSize: 12, color: 'var(--app-t2)', flex: 'none' }}>{configs.length}</span>
      </button>
      {open && (
        <div style={{ background: 'var(--app-bg)' }}>
          {configs.map((c) => <ConfigChildRow key={c.id as string} config={c} onClick={() => openConfig(c)} showHost />)}
        </div>
      )}
    </div>
  );
}

function CertRow({ cert, onClick }: { cert: Certificate; onClick: () => void }) {
  const c = cert as Record<string, unknown> & Certificate;
  const expDays = daysUntil(c.not_after as string | undefined);
  const expTone = expDays == null ? 'var(--app-t3)' : expDays < 0 ? 'var(--danger)' : expDays < 90 ? 'var(--warn-strong)' : 'var(--ok)';
  const deployCount = typeof c.deployment_count === 'number' ? c.deployment_count : null;
  const isManual = c.data_source === 'manual';
  const issuerCN = (() => {
    const dn = c.issuer_dn as string | undefined;
    if (!dn) return null;
    const m = dn.match(/CN=([^,]+)/i);
    return m ? m[1] : dn;
  })();
  return (
    <div className="row-hover" onClick={onClick} style={{ display: 'grid', gridTemplateColumns: CERT_GRID, gap: 12, padding: '0 16px', minHeight: 46, alignItems: 'center', borderBottom: '1px solid var(--app-border)', cursor: 'pointer' }}>
      <span style={{ width: 10, height: 10, borderRadius: '50%', background: expTone, flex: 'none' }} />
      <div style={{ minWidth: 0 }}>
        <div className="mono" style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{(c.common_name as string) || c.subject_dn || '—'}</div>
        {isManual && <div style={{ fontSize: 10.5, color: 'var(--warn)' }}>uploaded</div>}
      </div>
      <Mono v={issuerCN} small />
      <Mono v={c.public_key_algorithm ? `${c.public_key_algorithm} ${c.public_key_size ?? ''}`.trim() : null} small />
      <span className="mono" style={{ fontSize: 11.5, color: expTone }}>
        {expDays == null ? '—' : expDays < 0 ? `expired ${-expDays}d ago` : `${expDays}d`}
      </span>
      {deployCount === 0 || deployCount === null ? (
        <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--warn)', background: 'color-mix(in srgb, var(--warn) 11%, transparent)', borderRadius: 40, padding: '2px 9px', justifySelf: 'start' }}>Unassigned</span>
      ) : (
        <Mono v={`${deployCount} asset${deployCount === 1 ? '' : 's'}`} />
      )}
    </div>
  );
}

const KEY_STATE_TONE: Record<string, string> = {
  active: 'var(--ok)',
  'pre-activation': 'var(--app-t3)',
  suspended: 'var(--warn)',
  deactivated: 'var(--warn-strong)',
  compromised: 'var(--danger)',
  destroyed: 'var(--danger)',
};

function KeyRow({ keyItem, onClick }: { keyItem: Key; onClick: () => void }) {
  const k = keyItem as Record<string, unknown> & Key;
  const state = (k.state as string) || '';
  const stateTone = KEY_STATE_TONE[state] || 'var(--app-t2)';
  const expDays = daysUntil(k.expires_at as string | undefined);
  const expTone = expDays == null ? 'var(--app-t3)' : expDays < 0 ? 'var(--danger)' : expDays < 90 ? 'var(--warn-strong)' : 'var(--ok)';
  const deployCount = typeof k.deployment_count === 'number' ? k.deployment_count : null;
  const sizeLabel = k.size_bits ? `${k.size_bits}-bit` : (k.curve as string) || '';
  const algo = [k.algorithm_ref as string, sizeLabel].filter(Boolean).join(' · ') || '—';
  const title = [k.key_type as string, sizeLabel].filter(Boolean).join(' · ') || (k.material_type as string) || '—';
  return (
    <div className="row-hover" onClick={onClick} style={{ display: 'grid', gridTemplateColumns: KEY_GRID, gap: 12, padding: '0 16px', minHeight: 46, alignItems: 'center', borderBottom: '1px solid var(--app-border)', cursor: 'pointer' }}>
      <span style={{ width: 10, height: 10, borderRadius: '50%', background: stateTone, flex: 'none' }} />
      <div style={{ minWidth: 0 }}>
        <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{title}</div>
        <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>{(k.material_type as string) || ''}</div>
      </div>
      <Mono v={algo} small />
      <span style={{ fontSize: 11, fontWeight: 600, color: stateTone, background: `color-mix(in srgb, ${stateTone} 11%, transparent)`, borderRadius: 40, padding: '2px 9px', justifySelf: 'start', textTransform: 'capitalize' }}>{state || 'unknown'}</span>
      <span className="mono" style={{ fontSize: 11.5, color: expTone }}>{expDays == null ? '—' : expDays < 0 ? `expired` : `${expDays}d`}</span>
      {deployCount === 0 || deployCount === null ? (
        <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--warn)', background: 'color-mix(in srgb, var(--warn) 11%, transparent)', borderRadius: 40, padding: '2px 9px', justifySelf: 'start' }}>Unlinked</span>
      ) : (
        <Mono v={`${deployCount} asset${deployCount === 1 ? '' : 's'}`} />
      )}
    </div>
  );
}

function FilterSelect({ label, value, onChange, options }: { label: string; value: string; onChange: (v: string) => void; options: string[] }) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)} title={label}
      style={{ height: 31, padding: '0 8px', borderRadius: 9, border: '1px solid ' + (value !== 'All' ? 'var(--accent)' : 'var(--app-border2)'), background: 'var(--app-panel2)', color: value !== 'All' ? 'var(--app-t1)' : 'var(--app-t2)', fontSize: 12.5, outline: 'none', cursor: 'pointer' }}>
      {options.map((o) => <option key={o} value={o}>{o === 'All' ? label : o}</option>)}
    </select>
  );
}
function ChildNote({ text }: { text: string }) {
  return <div style={{ padding: '12px 16px 12px 40px', fontSize: 12, color: 'var(--app-t3)' }}>{text}</div>;
}

function Header({ grid, cols }: { grid: string; cols: string[] }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: grid, gap: 12, padding: '0 16px', height: 34, alignItems: 'center', borderBottom: '1px solid var(--app-border2)', position: 'sticky', top: 0, background: 'var(--app-panel)', zIndex: 1 }}>
      {cols.map((h, i) => <span key={i} className="eyebrow-app">{h}</span>)}
    </div>
  );
}
function Txt({ v, cap }: { v?: string | null; cap?: boolean }) {
  return <span style={{ fontSize: 12.5, color: 'var(--app-t2)', textTransform: cap ? 'capitalize' : 'none', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{v || '—'}</span>;
}
function Mono({ v, small }: { v?: string | null; small?: boolean }) {
  return <span className="mono" style={{ fontSize: small ? 11 : 12, color: 'var(--app-t2)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{v || '—'}</span>;
}
function Center({ icon, tone, title, message }: { icon: string; tone: string; title: string; message: string }) {
  return (
    <div style={{ padding: '64px 24px', textAlign: 'center', color: 'var(--app-t3)' }}>
      <Icon name={icon} size={26} style={{ color: tone, opacity: 0.8 }} />
      <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--app-t1)', marginTop: 12 }}>{title}</div>
      <div style={{ fontSize: 12.5, marginTop: 4 }}>{message}</div>
    </div>
  );
}
