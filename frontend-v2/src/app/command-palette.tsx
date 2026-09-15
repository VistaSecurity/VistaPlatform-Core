// Global command palette — ⌘K / Ctrl+K (or the top-bar search button) opens a
// quick-find overlay with TWO modes (ADR-0006 D9).
//
//   search  the deterministic one, in every edition. Fans out to existing
//           per-entity endpoints and merges client-side — assets and
//           certificates by server-side `search`, devices and sensors filtered
//           in the browser, classes from the generated registry, and the
//           relationships of the best asset match. There is no backend /search
// endpoint (feature).
//   ask     Enterprise, and only when a provider is configured. A question in
//           words becomes a query-language predicate the server wrote,
//           validated, and ran; the rows it selected are rendered as the SAME
//           result rows search mode uses, and the query is shown with "Open in
//           Inventory" so it can be edited and saved as a view.
//
// The toggle is not rendered at all when the query seam is not live for this
// tenant. That is D9's rule and it is the honest one: a toggle that led to a
// 402 or a 403 would leave the user unable to tell whether they are broken or
// switched off.
//
// Selecting an ASSET opens its page (`/inventory/assets/:id`) — the ops journey
// in ADR-0006's personas is "⌘K → type a hostname → the asset page opens", and
// handing back a filtered list made the user choose their own result twice. A
// certificate still seeds the certificate lens with `?q=`: certificates have no
// page of their own.
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router';
import { useQuery, keepPreviousData } from '@tanstack/react-query';
import { useFeatures } from '@vistasecurity/primitives/features';
import { clients } from '../lib/clients';
import { Icon } from '../components/ui';
import { ServerQueryErrors } from '../sections/inventory/query-editor';
import { INVENTORY_LENSES } from '../sections/inventory/lenses';
import {
  KIND_ICON, KIND_LABEL, assetItem, classesOfAssets, inventoryQueryLink, inventorySearchLink,
  matchingClasses, relationshipItem, sectionsOf,
  type CommandItem, type ResultKind,
} from './palette-results';
import { askRows, askToggleVisible, readableSummary, useAsk, useAskAvailability, type AskResult } from './ask-mode';

export type { CommandItem, ResultKind };

/**
 * The inventory quick-jump targets, DERIVED from the lens registry.
 *
 * The hand-written list they replace advertised `infrastructure` and `network`
 * — retired keys that only redirect — and offered none of the lenses added
 * since. A palette is a map of the product; one drawn by hand goes out of date
 * the first time a lens is added, and nothing fails when it does.
 *
 * Sub-lenses (TLS/SSH under Configuration) are left out: the palette lists
 * places, and those are filters of one.
 */
export const LENS_NAV_ITEMS: CommandItem[] = INVENTORY_LENSES
  .filter((l) => l.primary)
  .map((l) => ({
    id: `nav-inv-${l.key}`,
    kind: 'nav' as const,
    label: `Inventory · ${l.label}`,
    // A placeholder lens is a real destination — it explains what is coming —
    // but saying so here means nobody arrives expecting data.
    sublabel: l.placeholder ? `${l.placeholder.phase} — not built yet` : undefined,
    to: `/inventory?lens=${l.key}`,
  }));

// Static quick-jump targets — frontend-v2 5-section IA. Shown when the query is
// empty, and also filtered by the typed query (so "post" finds Posture).
export const NAV_ITEMS: CommandItem[] = [
  { id: 'nav-dashboard', kind: 'nav', label: 'Dashboard', sublabel: 'Health overview', to: '/dashboard' },
  { id: 'nav-inventory', kind: 'nav', label: 'Inventory', sublabel: 'Assets, certificates, keys, configurations', to: '/inventory' },
  ...LENS_NAV_ITEMS,
  { id: 'nav-posture', kind: 'nav', label: 'Risk & Compliance · Posture', sublabel: 'Compliance posture & frameworks', to: '/risk-compliance/posture' },
  { id: 'nav-findings', kind: 'nav', label: 'Risk & Compliance · Findings', to: '/risk-compliance/findings' },
  // The sublabel spells the four kinds out because the palette matches on
  // label AND sublabel: without them, someone typing "SBOM" — the whole reason
  // the page was renamed from "CBOM" (ADR-0005 D6) — found nothing here, in the
  // one control whose job is to answer "where is the thing I am looking for".
  {
    id: 'nav-cbom',
    kind: 'nav',
    label: 'Risk & Compliance · Bills of Materials',
    sublabel: 'CBOM, SBOM, HBOM and full-inventory snapshots',
    to: '/risk-compliance/cbom',
  },
  // Enterprise-only (cbom-service/ee/diff) — filtered out below when the
  // cbom_signing entitlement is off, so ⌘K never offers a locked page.
  {
    id: 'nav-cbom-compare',
    kind: 'nav',
    label: 'Risk & Compliance · Compare artifacts',
    sublabel: 'Diff two bills of materials of the same kind',
    to: '/risk-compliance/cbom/compare',
    feature: 'cbom_signing',
  },
  { id: 'nav-discovery', kind: 'nav', label: 'Discovery', sublabel: 'Sensors, jobs, devices, scans', to: '/discovery' },
  { id: 'nav-sensors', kind: 'nav', label: 'Discovery · Sensors', to: '/discovery/sensors' },
  { id: 'nav-devices', kind: 'nav', label: 'Discovery · Devices', to: '/discovery/devices' },
  { id: 'nav-remediation', kind: 'nav', label: 'Remediation · Queue', to: '/remediation/queue' },
  { id: 'nav-settings', kind: 'nav', label: 'Settings', sublabel: 'Organization configuration', to: '/settings' },
  // The two pages that explain how the inventory is DECIDED (ADR-0006 D7).
  // They are the answer to "why is this thing a server?" and "why did these
  // two sightings become one asset?", and they sit deep in Settings where
  // nobody looking for that answer would think to go.
  { id: 'nav-settings-classes', kind: 'nav', label: 'Settings · Classes', sublabel: 'The asset class taxonomy and its attributes', to: '/settings/classes' },
  { id: 'nav-settings-identification-rules', kind: 'nav', label: 'Settings · Identification rules', sublabel: 'How a sighting is matched to an existing asset', to: '/settings/identification-rules' },
];

type Mode = 'search' | 'ask';

export function CommandPalette({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const navigate = useNavigate();
  const [requestedMode, setMode] = useState<Mode>('search');
  const [query, setQuery] = useState('');
  const [dq, setDq] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const { features } = useFeatures();
  const ask = useAskAvailability();
  const askCall = useAsk();
  const [askResult, setAskResult] = useState<AskResult | null>(null);
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

  // Reset + focus on open. The MODE resets too: a palette that reopened in ask
  // mode would spend a model call on someone who pressed ⌘K to jump to a page.
  useEffect(() => {
    if (!open) return;
    setMode('search');
    setQuery('');
    setDq('');
    setActiveIndex(0);
    setAskResult(null);
    askCall.reset();
    const t = setTimeout(() => inputRef.current?.focus(), 40);
    return () => clearTimeout(t);
    // askCall.reset is stable; re-running this on every render of the mutation
    // would clear the box mid-typing.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  // The toggle appears only when something can actually answer. `loading` is a
  // third state and renders nothing: telling a user a capability is off before
  // we have looked is the failure this whole area is written against.
  const canAsk = askToggleVisible(ask);

  // The mode actually IN FORCE, derived rather than stored.
  //
  // Losing the capability mid-session — a tenant admin switches the assistant
  // off in another tab and the status refetches — must not leave the palette in
  // a mode nothing can answer. Deriving it makes that fall out for free; an
  // effect correcting a stored value would render one frame of an ask box that
  // cannot ask.
  const mode: Mode = canAsk ? requestedMode : 'search';

  // Debounce the query (300ms) so we don't fan out on every keystroke. Ask mode
  // never fans out — it runs on Enter — so the debounce is search's alone.
  useEffect(() => {
    const t = setTimeout(() => setDq(query.trim()), 300);
    return () => clearTimeout(t);
  }, [query]);

  const searching = mode === 'search';
  const enabled = open && searching && dq.length >= 2;

  // Assets — server-side search, top 6.
  const assetsQ = useQuery({
    queryKey: ['cmd', 'assets', dq],
    enabled,
    staleTime: 30_000,
    placeholderData: keepPreviousData,
    queryFn: async () => {
      const { data } = await clients.inventory.GET('/infrastructure-assets', {
        params: { query: { page: 1, page_size: 6, search: dq } },
      });
      return data?.assets ?? [];
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
          to: inventorySearchLink('certificate', c.common_name || c.subject_dn || ''),
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

  // Relationships of the BEST asset match (ADR-0006 D9).
  //
  // One asset, not all six: the ops journey is "the switch being replaced on
  // Friday — what is behind it?", which is a question about one thing, and
  // fanning out to six assets' edges would spend six requests to bury the
  // answer. There is no tenant-wide relationship search to use instead.
  // In ASK mode the best match is the answer's first row, not a search result —
  // search mode's queries are disabled there. Deriving one `topAsset` for both
  // modes is what lets the relationship rows below be the SAME rows (D9) rather
  // than a second, ask-shaped copy of them.
  // Memoised, not a bare conditional: a fresh `[]` on every render would make
  // the results `useMemo` below re-run on every keystroke of a mode that does
  // not fetch on keystrokes.
  const askAnswerRows = useMemo(
    () => (askResult?.kind === 'answer' ? (askResult.answer.rows ?? []) : []),
    [askResult],
  );
  const topAsset = mode === 'ask' ? askAnswerRows[0] : assetsQ.data?.[0];
  const relsQ = useQuery({
    queryKey: ['cmd', 'rels', topAsset?.id],
    // `open`, not `enabled`: `enabled` carries "search mode and two characters
    // typed", which is never true in ask mode — gating on it is what left ask
    // answers with no relationship rows at all.
    enabled: open && !!topAsset?.id,
    staleTime: 60_000,
    queryFn: async () => {
      const { data } = await clients.inventory.GET('/infrastructure-assets/{id}/relationships', {
        params: { path: { id: topAsset!.id }, query: { direction: 'both', limit: 4 } },
      });
      return data?.relationships ?? [];
    },
  });

  const isFetching = enabled && (assetsQ.isFetching || certsQ.isFetching);

  const items: CommandItem[] = useMemo(() => {
    if (mode === 'ask') {
      if (askResult?.kind !== 'answer') return [];
      // The same three kinds search mode offers, built by the same builders
      // (D9: "renders the tool results as the same result rows"). Ask mode used
      // to render assets alone, so one surface had two behaviours depending on
      // how the user phrased the question.
      const out = askRows(askResult.answer);
      out.push(...classesOfAssets(askAnswerRows));
      if (topAsset) {
        const name = topAsset.display_name || topAsset.hostname || topAsset.id;
        out.push(...(relsQ.data ?? []).map((rel) => relationshipItem(topAsset.id, name, rel)));
      }
      return out;
    }
    if (!enabled) {
      return navItems;
    }
    const q = dq.toLowerCase();
    const out: CommandItem[] = [];

    // Quick-nav entries that match the typed text, first.
    out.push(...navItems.filter((n) => n.label.toLowerCase().includes(q) || (n.sublabel ?? '').toLowerCase().includes(q)));

    out.push(...(assetsQ.data ?? []).map(assetItem));
    out.push(...(certsQ.data ?? []));

    // Classes (D9) — from the generated registry, no request.
    out.push(...matchingClasses(dq));

    // Relationships (D9) — the top asset's edges, read from its own side.
    if (topAsset) {
      const name = topAsset.display_name || topAsset.hostname || topAsset.id;
      out.push(...(relsQ.data ?? []).map((rel) => relationshipItem(topAsset.id, name, rel)));
    }

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
  }, [mode, askResult, askAnswerRows, enabled, dq, navItems, assetsQ.data, certsQ.data, devicesQ.data, sensorsQ.data, relsQ.data, topAsset]);

  // Keep the highlight in range as results change. Ask mode starts with NOTHING
  // highlighted (-1) so Enter asks the question rather than opening a row.
  useEffect(() => { setActiveIndex(mode === 'ask' ? -1 : 0); }, [dq, mode]);
  useEffect(() => {
    if (activeIndex > items.length - 1) setActiveIndex(Math.max(mode === 'ask' ? -1 : 0, items.length - 1));
  }, [items.length, activeIndex, mode]);

  const go = useCallback((item: CommandItem) => { void navigate(item.to); close(); }, [navigate, close]);

  const runAsk = useCallback(() => {
    const question = query.trim();
    if (!question) return;
    setAskResult(null);
    askCall.mutate(question, { onSuccess: (r) => { setAskResult(r); setActiveIndex(-1); } });
  }, [query, askCall]);

  // Arrow / Enter / Esc navigation while open.
  const onInputKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') { e.preventDefault(); close(); return; }
    if (e.key === 'ArrowDown') { e.preventDefault(); setActiveIndex((i) => Math.min(i + 1, items.length - 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActiveIndex((i) => Math.max(i - 1, mode === 'ask' ? -1 : 0)); }
    else if (e.key === 'Enter') {
      e.preventDefault();
      // In ask mode with nothing highlighted, Enter ASKS. Once the user has
      // arrowed into the rows, it opens the highlighted one — so the keyboard
      // reaches both without a second key to learn.
      if (mode === 'ask' && activeIndex < 0) { runAsk(); return; }
      const it = items[activeIndex];
      if (it) go(it);
    }
  };

  // Scroll the active row into view.
  useEffect(() => {
    listRef.current?.querySelector<HTMLElement>('[data-active="true"]')?.scrollIntoView({ block: 'nearest' });
  }, [activeIndex]);

  const sections = useMemo(() => sectionsOf(items), [items]);

  if (!open) return null;

  const answer = askResult?.kind === 'answer' ? askResult.answer : null;
  const refusal = askResult?.kind === 'refusal' ? askResult.refusal : null;
  const askError = askResult?.kind === 'error' ? askResult.message : null;

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
        {/* Mode toggle — rendered ONLY when the query seam can answer for this
            tenant (ADR-0006 D9). Absent, not disabled: a control that cannot be
            used tells a reader nothing about why. */}
        {canAsk && (
          <div
            role="tablist"
            aria-label="Palette mode"
            data-testid="palette-mode-toggle"
            style={{ display: 'flex', gap: 4, padding: '8px 12px 0' }}
          >
            {(['search', 'ask'] as Mode[]).map((m) => (
              <button
                key={m}
                role="tab"
                aria-selected={mode === m}
                onClick={() => { setMode(m); setAskResult(null); inputRef.current?.focus(); }}
                className="ui-btn ghost"
                style={{
                  fontSize: 12, padding: '4px 10px', borderRadius: 8,
                  background: mode === m ? 'var(--rail-active)' : 'transparent',
                  color: mode === m ? 'var(--rail-accent)' : 'var(--app-t3)',
                }}
              >
                {m === 'search' ? 'Search' : 'Ask'}
              </button>
            ))}
          </div>
        )}

        {/* Input row */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 11, padding: '13px 16px', borderBottom: '1px solid var(--app-border)' }}>
          <Icon name={mode === 'ask' ? 'sparkles' : 'search'} size={17} />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={onInputKey}
            placeholder={mode === 'ask'
              ? 'Ask about your inventory — “production servers with a certificate expiring this month”'
              : 'Search assets, certificates, devices, sensors — or jump to a page…'}
            aria-label={mode === 'ask' ? 'Ask about your inventory' : 'Search'}
            autoComplete="off"
            style={{ flex: 1, background: 'transparent', border: 'none', outline: 'none', color: 'var(--app-t1)', fontSize: 14, fontFamily: 'var(--font-body)' }}
          />
          {(isFetching || askCall.isPending) && <Icon name="loader" size={15} style={{ animation: 'spin 1.1s linear infinite' }} />}
          <style>{'@keyframes spin { to { transform: rotate(360deg); } }'}</style>
          <button onClick={close} aria-label="Close" className="ui-btn ghost" style={{ flex: 'none', padding: '0 8px' }}><Icon name="x" size={15} /></button>
        </div>

        {/* The answer panel: the QUERY first, then the rows, then the prose.
            That order is the design — the query is the checkable artefact, and a
            user who disagrees with the summary edits it. */}
        {mode === 'ask' && answer && (
          <div data-testid="ask-answer" style={{ padding: '12px 16px', borderBottom: '1px solid var(--app-border)', display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <code
                data-testid="ask-canonical-query"
                style={{ fontSize: 12, fontFamily: 'var(--font-mono)', background: 'var(--app-panel2)', padding: '4px 8px', borderRadius: 6, color: 'var(--app-t1)', wordBreak: 'break-word' }}
              >
                {answer.query || 'no query was echoed'}
              </code>
              {answer.query && (
                <button
                  data-testid="ask-open-in-inventory"
                  className="ui-btn ghost"
                  style={{ fontSize: 12, padding: '3px 9px' }}
                  onClick={() => go({ id: 'ask-open', kind: 'nav', label: 'Open in Inventory', to: inventoryQueryLink(answer.query) })}
                >
                  Open in Inventory
                </button>
              )}
            </div>
            {answer.text && (
              <p style={{ margin: 0, fontSize: 13, lineHeight: 1.5, color: 'var(--app-t2)' }}>{readableSummary(answer.text)}</p>
            )}
            {/* ADR-0008 D4.1: a generated answer says so, and says what wrote it. */}
            <span style={{ fontSize: 11, color: 'var(--app-t3)' }}>
              Written from the rows below{answer.provenance?.model_id ? ` by ${answer.provenance.model_id}` : ''}. Check them.
            </span>
          </div>
        )}

        {/* A refusal is an ANSWER, not an error: a provider replied and the
            validator said exactly why it could not be used. The diagnostics go
            out verbatim, through the same renderer the query editor uses. */}
        {mode === 'ask' && refusal && (
          <div data-testid="ask-refusal" style={{ padding: '12px 16px', borderBottom: '1px solid var(--app-border)', display: 'flex', flexDirection: 'column', gap: 10 }}>
            <p style={{ margin: 0, fontSize: 13, color: 'var(--app-t2)' }}>{refusal.error}</p>
            {refusal.query && <ServerQueryErrors query={refusal.query} errors={refusal.errors} />}
            {!refusal.query && refusal.errors.length > 0 && (
              <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12, color: 'var(--app-t2)' }}>
                {refusal.errors.map((e, i) => (
                  <li key={`${e.code}-${i}`}>{e.code}: {e.message}{e.suggestion ? ` — ${e.suggestion}` : ''}</li>
                ))}
              </ul>
            )}
            {refusal.query && (
              <button
                data-testid="ask-edit-refused-query"
                className="ui-btn ghost"
                style={{ fontSize: 12, padding: '3px 9px', alignSelf: 'flex-start' }}
                onClick={() => go({ id: 'ask-edit', kind: 'nav', label: 'Edit in Inventory', to: inventoryQueryLink(refusal.query!) })}
              >
                Edit it in Inventory
              </button>
            )}
          </div>
        )}

        {mode === 'ask' && askError && (
          <p data-testid="ask-error" style={{ margin: 0, padding: '14px 16px', fontSize: 13, color: 'var(--app-t2)', borderBottom: '1px solid var(--app-border)' }}>
            {askError}
          </p>
        )}

        {/* Results */}
        <div ref={listRef} role="listbox" style={{ maxHeight: '56vh', overflowY: 'auto', padding: '4px 0' }}>
          {items.length === 0 && (
            <p style={{ padding: '36px 16px', textAlign: 'center', fontSize: 13, color: 'var(--app-t3)' }}>
              {mode === 'ask'
                ? (askCall.isPending ? 'Writing a query…' : askResult ? 'No assets matched.' : 'Ask a question and press ↵.')
                : enabled ? 'No results found' : 'Start typing to search…'}
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
                    data-kind={item.kind}
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
          <span>{mode === 'ask' ? '↵ ask' : '↵ open'}</span>
          <span>esc close</span>
          <span style={{ marginLeft: 'auto' }}>⌘K toggle</span>
        </div>
      </div>
    </div>
  );
}

export default CommandPalette;
