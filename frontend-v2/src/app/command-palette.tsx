// Global search command palette — ⌘K / Ctrl+K (or the top-bar search button)
// opens a quick-find overlay. Ported from the legacy web-ui command palette
// (_legacy/web-ui/src/components/common/command-palette.tsx), re-targeted to
// frontend-v2 routes + the typed @vistasecurity/api-contract clients.
//
// Frontend-only by design (feature): there is NO backend /search endpoint.
// It fans out to existing per-entity endpoints and merges client-side —
//   • assets / certificates → server-side `search` param
//   • devices / sensors     → full list, filtered in the browser (small lists)
// Empty query shows a static Quick-Navigation list. Selecting an asset/cert
// navigates to the inventory lens seeded with `?q=` so the item surfaces.
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router';
import { useQuery, keepPreviousData } from '@tanstack/react-query';
import { useFeatures, type FeatureName } from '@vistasecurity/primitives/features';
import { clients } from '../lib/clients';
import { Icon, levelFromScore } from '../components/ui';

type ResultKind = 'nav' | 'asset' | 'cert' | 'device' | 'sensor';

interface CommandItem {
  id: string;
  kind: ResultKind;
  label: string;
  sublabel?: string;
  badge?: string;
  to: string;
  /** Entitlement key this quick-nav target requires; omitted = every edition. */
  feature?: FeatureName;
}

const KIND_LABEL: Record<ResultKind, string> = {
  nav: 'Quick Navigation',
  asset: 'Infrastructure Assets',
  cert: 'Certificates',
  device: 'Devices',
  sensor: 'Sensors',
};

const KIND_ICON: Record<ResultKind, string> = {
  nav: 'arrow-right',
  asset: 'server',
  cert: 'file-badge',
  device: 'monitor-smartphone',
  sensor: 'wifi',
};

// Static quick-jump targets — frontend-v2 5-section IA. Shown when the query is
// empty, and also filtered by the typed query (so "post" finds Posture).
const NAV_ITEMS: CommandItem[] = [
  { id: 'nav-dashboard', kind: 'nav', label: 'Dashboard', sublabel: 'Health overview', to: '/dashboard' },
  { id: 'nav-inventory', kind: 'nav', label: 'Inventory', sublabel: 'Assets, certificates, keys, configurations', to: '/inventory' },
  { id: 'nav-inv-infra', kind: 'nav', label: 'Inventory · Infrastructure', sublabel: 'Assets', to: '/inventory?lens=infrastructure' },
  { id: 'nav-inv-cert', kind: 'nav', label: 'Inventory · Certificates', sublabel: 'All certificates', to: '/inventory?lens=certificate' },
  { id: 'nav-inv-keys', kind: 'nav', label: 'Inventory · Cryptographic Keys', to: '/inventory?lens=keys' },
  { id: 'nav-inv-config', kind: 'nav', label: 'Inventory · Configuration', to: '/inventory?lens=configuration' },
  { id: 'nav-inv-network', kind: 'nav', label: 'Inventory · Network', to: '/inventory?lens=network' },
  { id: 'nav-inv-conn', kind: 'nav', label: 'Inventory · 3rd Party Connections', to: '/inventory?lens=connections' },
  { id: 'nav-posture', kind: 'nav', label: 'Risk & Compliance · Posture', sublabel: 'Compliance posture & frameworks', to: '/risk-compliance/posture' },
  { id: 'nav-findings', kind: 'nav', label: 'Risk & Compliance · Findings', to: '/risk-compliance/findings' },
  { id: 'nav-cbom', kind: 'nav', label: 'CBOM', sublabel: 'Cryptographic Bill of Materials', to: '/risk-compliance/cbom' },
  // Enterprise-only (cbom-service/ee/diff) — filtered out below when the
  // cbom_signing entitlement is off, so ⌘K never offers a locked page.
  { id: 'nav-cbom-compare', kind: 'nav', label: 'Compare CBOMs', to: '/risk-compliance/cbom/compare', feature: 'cbom_signing' },
  { id: 'nav-discovery', kind: 'nav', label: 'Discovery', sublabel: 'Sensors, jobs, devices, scans', to: '/discovery' },
  { id: 'nav-sensors', kind: 'nav', label: 'Discovery · Sensors', to: '/discovery/sensors' },
  { id: 'nav-devices', kind: 'nav', label: 'Discovery · Devices', to: '/discovery/devices' },
  { id: 'nav-remediation', kind: 'nav', label: 'Remediation · Queue', to: '/remediation/queue' },
  { id: 'nav-settings', kind: 'nav', label: 'Settings', sublabel: 'Organization configuration', to: '/settings' },
];

const invSearchTo = (lens: string, term: string) =>
  `/inventory?lens=${lens}${term ? `&q=${encodeURIComponent(term)}` : ''}`;

export function CommandPalette({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [dq, setDq] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const { features } = useFeatures();
  // Drop quick-nav targets this edition/plan doesn't ship before anything else
  // sees them — both the empty-query list and the typed filter read this.
  const navItems = useMemo(
    () => NAV_ITEMS.filter((n) => !n.feature || features[n.feature]),
    [features],
  );

  const close = useCallback(() => { onOpenChange(false); }, [onOpenChange]);

  // Global ⌘K / Ctrl+K toggle — active whether or not the palette is open.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault();
        onOpenChange(!open);
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onOpenChange]);

  // Reset + focus on open.
  useEffect(() => {
    if (!open) return;
    setQuery('');
    setDq('');
    setActiveIndex(0);
    const t = setTimeout(() => inputRef.current?.focus(), 40);
    return () => clearTimeout(t);
  }, [open]);

  // Debounce the query (300ms) so we don't fan out on every keystroke.
  useEffect(() => {
    const t = setTimeout(() => setDq(query.trim()), 300);
    return () => clearTimeout(t);
  }, [query]);

  const enabled = open && dq.length >= 2;

  // Assets — server-side search, top 6.
  const assetsQ = useQuery({
    queryKey: ['cmd', 'assets', dq],
    enabled,
    staleTime: 30_000,
    placeholderData: keepPreviousData,
    queryFn: async (): Promise<CommandItem[]> => {
      const { data } = await clients.inventory.GET('/infrastructure-assets', {
        params: { query: { page: 1, page_size: 6, search: dq } },
      });
      return (data?.assets ?? []).map((a) => {
        const name = a.hostname || a.ip_address || a.id;
        // Only badge Medium+ risk (>=40) — every score maps to a level, so
        // badging all of them would just print "Informational" on everything.
        const badge = typeof a.risk_score === 'number' && a.risk_score >= 40 ? (a.risk_level || levelFromScore(a.risk_score)) : undefined;
        return {
          id: `asset-${a.id}`,
          kind: 'asset' as const,
          label: name,
          sublabel: [a.ip_address, a.asset_type, a.environment].filter(Boolean).join(' · ') || undefined,
          badge,
          to: invSearchTo('infrastructure', a.hostname || a.ip_address || ''),
        };
      });
    },
  });

  // Certificates — server-side search, top 5 (soonest-expiring first).
  const certsQ = useQuery({
    queryKey: ['cmd', 'certs', dq],
    enabled,
    staleTime: 30_000,
    placeholderData: keepPreviousData,
    queryFn: async (): Promise<CommandItem[]> => {
      const { data } = await clients.inventory.GET('/certificates', {
        params: { query: { page: 1, page_size: 5, search: dq, sort_by: 'not_after', sort_order: 'asc' } },
      });
      return (data?.certificates ?? []).map((c) => {
        const label = c.common_name || c.subject_dn || c.id;
        const days = c.not_after ? Math.ceil((new Date(c.not_after).getTime() - Date.now()) / 86_400_000) : undefined;
        const badge = days !== undefined && days <= 30 ? (days <= 0 ? 'Expired' : `Expires ${days}d`) : undefined;
        return {
          id: `cert-${c.id}`,
          kind: 'cert' as const,
          label,
          sublabel: c.issuer_dn || undefined,
          badge,
          to: invSearchTo('certificate', c.common_name || c.subject_dn || ''),
        };
      });
    },
  });

  // Devices & sensors — small lists, cached and filtered client-side.
  const devicesQ = useQuery({
    queryKey: ['cmd', 'devices'],
    enabled,
    staleTime: 60_000,
    queryFn: async () => {
      const { data } = await clients.devices.GET('/devices', {});
      return data?.devices ?? [];
    },
  });
  const sensorsQ = useQuery({
    queryKey: ['cmd', 'sensors'],
    enabled,
    staleTime: 60_000,
    queryFn: async () => {
      const { data } = await clients.sensors.GET('/sensors', {});
      return data?.sensors ?? [];
    },
  });

  const isFetching = enabled && (assetsQ.isFetching || certsQ.isFetching);

  const items: CommandItem[] = useMemo(() => {
    if (!enabled) {
      return navItems;
    }
    const q = dq.toLowerCase();
    const out: CommandItem[] = [];

    // Quick-nav entries that match the typed text, first.
    out.push(...navItems.filter((n) => n.label.toLowerCase().includes(q) || (n.sublabel ?? '').toLowerCase().includes(q)));

    out.push(...(assetsQ.data ?? []));
    out.push(...(certsQ.data ?? []));

    (devicesQ.data ?? [])
      .filter((d) => (d.hostname ?? '').toLowerCase().includes(q) || (d.ip_address ?? '').toLowerCase().includes(q))
      .slice(0, 4)
      .forEach((d) => out.push({
        id: `device-${d.id}`,
        kind: 'device',
        label: d.hostname || d.management_url || d.ip_address || d.id,
        sublabel: [d.device_type, d.ip_address, d.connection_status].filter(Boolean).join(' · ') || undefined,
        to: '/discovery/devices',
      }));

    (sensorsQ.data ?? [])
      .filter((s) => (s.name ?? '').toLowerCase().includes(q) || (s.ip_address ?? '').toLowerCase().includes(q))
      .slice(0, 4)
      .forEach((s) => out.push({
        id: `sensor-${s.id}`,
        kind: 'sensor',
        label: s.name || s.id,
        sublabel: [s.platform, s.ip_address].filter(Boolean).join(' · ') || undefined,
        badge: s.status && s.status !== 'active' ? s.status : undefined,
        to: '/discovery/sensors',
      }));

    return out;
  }, [enabled, dq, navItems, assetsQ.data, certsQ.data, devicesQ.data, sensorsQ.data]);

  // Keep the highlight in range as results change.
  useEffect(() => { setActiveIndex(0); }, [dq]);
  useEffect(() => {
    if (activeIndex > items.length - 1) setActiveIndex(Math.max(0, items.length - 1));
  }, [items.length, activeIndex]);

  const go = useCallback((item: CommandItem) => { navigate(item.to); close(); }, [navigate, close]);

  // Arrow / Enter / Esc navigation while open.
  const onInputKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') { e.preventDefault(); close(); return; }
    if (e.key === 'ArrowDown') { e.preventDefault(); setActiveIndex((i) => Math.min(i + 1, items.length - 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActiveIndex((i) => Math.max(i - 1, 0)); }
    else if (e.key === 'Enter') { e.preventDefault(); const it = items[activeIndex]; if (it) go(it); }
  };

  // Scroll the active row into view.
  useEffect(() => {
    listRef.current?.querySelector<HTMLElement>('[data-active="true"]')?.scrollIntoView({ block: 'nearest' });
  }, [activeIndex]);

  // Section grouping (contiguous runs of the same kind).
  const sections = useMemo(() => {
    const out: { kind: ResultKind; start: number; count: number }[] = [];
    let last: ResultKind | null = null;
    items.forEach((it, i) => {
      if (it.kind !== last) { out.push({ kind: it.kind, start: i, count: 1 }); last = it.kind; }
      else out[out.length - 1].count++;
    });
    return out;
  }, [items]);

  if (!open) return null;

  return (
    <div
      role="presentation"
      onClick={(e) => { if (e.target === e.currentTarget) close(); }}
      style={{
        position: 'fixed', inset: 0, zIndex: 1000, display: 'flex', alignItems: 'flex-start',
        justifyContent: 'center', paddingTop: '12vh', padding: '12vh 16px 16px',
        background: 'var(--app-scrim)', backdropFilter: 'blur(3px)',
      }}
    >
      <div
        role="dialog" aria-modal="true" aria-label="Global search"
        style={{
          width: 'min(640px, 100%)', background: 'var(--app-panel)', border: '1px solid var(--app-border)',
          borderRadius: 14, boxShadow: 'var(--app-shadow)', overflow: 'hidden', display: 'flex', flexDirection: 'column',
        }}
      >
        {/* Input row */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 11, padding: '13px 16px', borderBottom: '1px solid var(--app-border)' }}>
          <Icon name="search" size={17} />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={onInputKey}
            placeholder="Search assets, certificates, devices, sensors — or jump to a page…"
            aria-label="Search"
            autoComplete="off"
            style={{ flex: 1, background: 'transparent', border: 'none', outline: 'none', color: 'var(--app-t1)', fontSize: 14, fontFamily: 'var(--font-body)' }}
          />
          {isFetching && <Icon name="loader" size={15} style={{ animation: 'spin 1.1s linear infinite' }} />}
          <style>{'@keyframes spin { to { transform: rotate(360deg); } }'}</style>
          <button onClick={close} aria-label="Close" className="ui-btn ghost" style={{ flex: 'none', padding: '0 8px' }}><Icon name="x" size={15} /></button>
        </div>

        {/* Results */}
        <div ref={listRef} role="listbox" style={{ maxHeight: '56vh', overflowY: 'auto', padding: '4px 0' }}>
          {items.length === 0 && (
            <p style={{ padding: '36px 16px', textAlign: 'center', fontSize: 13, color: 'var(--app-t3)' }}>
              {enabled ? 'No results found' : 'Start typing to search…'}
            </p>
          )}

          {sections.map(({ kind, start, count }) => (
            <div key={`${kind}-${start}`}>
              <div style={{ padding: '9px 16px 3px', fontSize: 9.5, fontWeight: 700, letterSpacing: '.1em', textTransform: 'uppercase', color: 'var(--app-t3)', userSelect: 'none' }}>
                {KIND_LABEL[kind]}
              </div>
              {items.slice(start, start + count).map((item, rel) => {
                const abs = start + rel;
                const active = abs === activeIndex;
                return (
                  <button
                    key={item.id}
                    data-active={active}
                    role="option"
                    aria-selected={active}
                    onClick={() => go(item)}
                    onMouseMove={() => setActiveIndex(abs)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 11, width: '100%', textAlign: 'left',
                      padding: '9px 16px', border: 'none', cursor: 'pointer',
                      background: active ? 'var(--rail-active)' : 'transparent',
                      color: active ? 'var(--rail-accent)' : 'var(--app-t2)',
                    }}
                  >
                    <Icon name={KIND_ICON[kind]} size={15} />
                    <span style={{ flex: 1, minWidth: 0 }}>
                      <span style={{ display: 'block', fontSize: 13, fontWeight: 600, color: active ? 'var(--rail-accent)' : 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{item.label}</span>
                      {item.sublabel && (
                        <span style={{ display: 'block', fontSize: 11, color: 'var(--app-t3)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{item.sublabel}</span>
                      )}
                    </span>
                    {item.badge && (
                      <span style={{ flex: 'none', fontSize: 10.5, fontWeight: 600, textTransform: 'capitalize', padding: '2px 7px', borderRadius: 6, background: 'var(--app-panel2)', color: 'var(--app-t2)' }}>{item.badge}</span>
                    )}
                  </button>
                );
              })}
            </div>
          ))}
        </div>

        {/* Footer hints */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '8px 16px', borderTop: '1px solid var(--app-border)', fontSize: 11, color: 'var(--app-t3)', userSelect: 'none' }}>
          <span>↑↓ navigate</span>
          <span>↵ open</span>
          <span>esc close</span>
          <span style={{ marginLeft: 'auto' }}>⌘K toggle</span>
        </div>
      </div>
    </div>
  );
}

export default CommandPalette;
