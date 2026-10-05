import { useState, type FormEvent } from 'react';
import { Link, useSearchParams } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { TENANT_PERMISSIONS, usePermissions } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { PROVISIONAL_INVENTORY_HREF } from '../inventory/facet-query';
import { BulkBar, BulkDialog, type BulkAction } from './observation-bulk';
import {
  CHIPS, PAGE_SIZES, bulkFailureMessage, chipLabel, isSelectable, loadView, nextNonEmptyChip, saveView,
  type ChipKey, type Observation, type ObservationState,
} from './observation-review';
import { ObservationTable, type RowFailure, type SortKey } from './observation-table';
import { useBulkObservationDecision, useObservation, useObservationList, type ObservationListQuery } from './queries';

type StateFilter = ObservationState | 'all';
const STATE_OPTIONS: { value: StateFilter; label: string }[] = [
  { value: 'unresolved', label: 'Unresolved (last 30 days)' },
  { value: 'conflict', label: 'Identity conflict' },
  { value: 'linked', label: 'Linked' },
  { value: 'dismissed', label: 'Dismissed' },
  { value: 'expired', label: 'Expired' },
  { value: 'all', label: 'Every state' },
];

export function IdentityCoverage() {
  const q = useQuery({ queryKey: ['identity-summary'], queryFn: async () => {
    const { data, response } = await clients.inventory.GET('/identity/summary');
    if (!response.ok || !data) throw new Error('Unable to load identity coverage');
    return data;
  }});
  if (q.isPending) return <p role="status">Loading identity coverage…</p>;
  if (q.isError) return <p role="alert">Identity coverage unavailable. <button className="ui-btn sm" onClick={() => { void q.refetch(); }}>Retry</button></p>;
  const d = q.data;
  return <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', padding: '10px 26px', fontSize: 12 }}>
    <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
      <strong>Monitored inventory:</strong>
      <span>{d.established} established</span><span>{d.operator_confirmed} operator-confirmed</span>
      <span title="These records have not had their identity established by the evidence checks. This does not describe their age or security posture.">{d.legacy} not evaluated</span>
    </div>
    {d.admission_mode === 'disabled' && <span>Identity assessment is not activated. <Link to="/settings/sensor-config">Configure discovery</Link></span>}
    {d.admission_mode === 'observe' && <span>Identity assessment is observing evidence; inventory identities are not being established.</span>}
    {d.admission_mode === 'paused' && <span>Identity assessment and enrichment are paused.</span>}
    <Link to="/discovery/observations">{d.unresolved} unresolved observations</Link>
    <Link to="/discovery/approvals">{d.conflicted} assets with identity conflicts</Link>
    {/* The inventory page's ONE filter is the query string (`?query=`), which is
        what the facet rail writes and what a saved view stores. The predicate
        itself is derived from the rail's own writer — see
        PROVISIONAL_INVENTORY_HREF for why a bare `identity_status:provisional`
        would land on an empty list. */}
    <Link to={PROVISIONAL_INVENTORY_HREF}>{d.provisional} provisional items</Link>
  </div>;
}


interface BulkOutcome { action: BulkAction; ok: number; failed: number }
interface KeptFailure { failure: RowFailure; row?: Observation }

const visuallyHidden = { position: 'absolute', width: 1, height: 1, overflow: 'hidden', clip: 'rect(0,0,0,0)', whiteSpace: 'nowrap' } as const;

function outcomeText(o: BulkOutcome): string {
  const done = `${o.ok} ${o.action === 'confirm' ? 'confirmed' : o.action === 'link' ? 'linked' : 'dismissed'}`;
  return o.failed === 0 ? `${done}.` : `${done}, ${o.failed} need${o.failed === 1 ? 's' : ''} another look.`;
}

/**
 * Discovery → Observations: identity evidence the platform kept but could not
 * turn into an asset by itself, as a review table. Opens on Ready to
 * confirm (D3); the server says what each row needs and proposes the reason
 * (D1); bulk Confirm and bulk Link are homogeneous, and a Link only ever goes
 * to the owner the server named (D4).
 */
export function ObservationsPage() {
  const [params, setParams] = useSearchParams();
  const assetID = params.get('asset_id') ?? undefined;
  const observationID = params.get('observation_id') ?? undefined;
  const permissions = usePermissions();
  const canDecide = permissions.hasPermission(TENANT_PERMISSIONS.assets.update);

  const [remembered] = useState(loadView);
  // Evidence for one asset is read across every state, as it always was.
  const [chip, setChipState] = useState<ChipKey>(assetID ? 'all' : remembered.chip);
  const [stateFilter, setStateFilter] = useState<StateFilter>(assetID ? 'all' : 'unresolved');
  const [pageSize, setPageSize] = useState(remembered.pageSize);
  const [page, setPage] = useState(1);
  const [sort, setSort] = useState<SortKey>('last_seen_desc');
  const [search, setSearch] = useState('');
  const [draft, setDraft] = useState('');
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  const [kept, setKept] = useState<ReadonlyMap<string, KeptFailure>>(new Map());
  const [outcome, setOutcome] = useState<BulkOutcome | null>(null);
  const [dialog, setDialog] = useState<BulkAction | null>(null);
  const bulk = useBulkObservationDecision();

  const q = search.trim();
  const query: ObservationListQuery = {
    ...(chip === 'all' ? { state: stateFilter } : { state: 'unresolved', needs: [chip] }),
    page, page_size: pageSize, sort,
    ...(q ? { q } : {}),
    ...(assetID ? { asset_id: assetID } : {}),
  };
  const list = useObservationList(query, { enabled: !observationID });
  const focus = useObservation(observationID);

  const rows = list.data?.observations ?? [];
  const counts = list.data?.counts;
  // The selection is ids; what it MEANS is always re-read from the current
  // rows, so a refetch that changes a row changes what the bar offers.
  const selectedRows = rows.filter((r) => selected.has(r.id) && isSelectable(r));
  const failures = new Map([...kept].map(([id, k]) => [id, k.failure]));
  const pinned = [...kept.values()].flatMap((k) => (k.row && !rows.some((r) => r.id === k.row!.id) ? [k.row] : []));

  // Any change of view clears the selection: a tick is a decision about a row
  // you can see, and carrying it to rows you cannot is how a bulk action ends
  // up deciding something nobody looked at.
  const resetSelection = () => { setSelected(new Set()); setKept(new Map()); setOutcome(null); };
  const changeView = () => { setPage(1); resetSelection(); };
  const pickChip = (c: ChipKey) => { setChipState(c); changeView(); saveView({ chip: c, pageSize }); };
  const pickPageSize = (n: number) => { setPageSize(n); changeView(); saveView({ chip, pageSize: n }); };
  const pickSort = (s: SortKey) => { setSort(s); changeView(); };
  const applySearch = (e: FormEvent) => { e.preventDefault(); setSearch(draft); changeView(); };
  const clearSearch = () => { setDraft(''); setSearch(''); changeView(); };
  const turnPage = (p: number) => { setPage(p); resetSelection(); };
  const clearAsset = () => { const next = new URLSearchParams(params); next.delete('asset_id'); setParams(next); changeView(); };

  const toggle = (id: string) => setSelected((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  const toggleAll = (ids: string[], on: boolean) => setSelected((s) => { const n = new Set(s); for (const id of ids) { if (on) n.add(id); else n.delete(id); } return n; });

  const openDialog = (a: BulkAction) => { bulk.reset(); setDialog(a); };
  const submit = (action: BulkAction, reason: string) => {
    const decided = selectedRows;
    bulk.mutate({ action, ids: decided.map((r) => r.id), reason }, {
      onSuccess: (data) => {
        // A failed row stays on screen with its reason — pinned above the
        // table if the refreshed page no longer holds it (it may have changed
        // state, which is often exactly why it failed).
        setKept((prev) => {
          const next = new Map(prev);
          for (const r of data.results) {
            if (r.outcome === 'ok') next.delete(r.id);
            else next.set(r.id, { failure: { message: bulkFailureMessage(r), code: r.code, status: r.status }, row: decided.find((d) => d.id === r.id) });
          }
          return next;
        });
        const ok = data.results.filter((r) => r.outcome === 'ok').length;
        setOutcome({ action, ok, failed: data.results.length - ok });
        setSelected(new Set());
        setDialog(null);
      },
    });
  };

  if (observationID) {
    return <section style={{ padding: 26 }}>
      <h1 style={{ margin: '0 0 6px', fontFamily: 'var(--font-head)', fontSize: 20 }}>Observations</h1>
      <p>Identity evidence was retained for resolution. <Link to="/discovery/observations">View all observations</Link></p>
      <IdentityCoverage />
      {focus.isPending && <p role="status">Loading observation…</p>}
      {focus.isError && <div role="alert"><p>Couldn’t load this observation.</p><button className="ui-btn sm" onClick={() => { void focus.refetch(); }}>Retry</button></div>}
      {focus.data && <ObservationTable rows={[focus.data]} loading={false} canDecide={canDecide} selectable={false} selected={new Set()} onToggle={() => {}} onToggleAll={() => {}}
        sort={sort} onSort={() => {}} failures={new Map()} expandFirst />}
    </section>;
  }

  const total = list.data?.total ?? 0;
  const empty = list.isSuccess && rows.length === 0 && pinned.length === 0;
  const suggestion = empty ? nextNonEmptyChip(chip, counts) : null;
  const unresolvedView = chip !== 'all' || stateFilter === 'unresolved';

  return <section style={{ padding: 26 }}>
    <h1 style={{ margin: '0 0 6px', fontFamily: 'var(--font-head)', fontSize: 20 }}>Observations</h1>
    <p style={{ margin: '0 0 8px', color: 'var(--app-t2)', fontSize: 13 }}>Evidence the platform kept but could not turn into an asset by itself. Each row says what it needs from you. An observation is not necessarily a distinct device.</p>
    <IdentityCoverage />

    <div role="group" aria-label="Show observations that" style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', margin: '12px 0' }}>
      {CHIPS.map((c) => <button key={c.key} type="button" className={`chip${chip === c.key ? ' active' : ''}`} aria-pressed={chip === c.key} onClick={() => pickChip(c.key)}>
        {c.label}{counts ? <span className="mono" style={{ color: 'var(--app-t3)' }}>{counts[c.key]}</span> : null}
      </button>)}
      {assetID && <span className="chip active" style={{ cursor: 'default' }}>
        Evidence for one asset
        <button type="button" className="ui-btn sm ghost" style={{ height: 18, padding: '0 4px' }} aria-label="Clear the asset filter" onClick={clearAsset}><span aria-hidden="true">×</span></button>
      </span>}
      {assetID && <Link to={`/inventory/assets/${assetID}`} style={{ fontSize: 12 }}>Back to asset</Link>}
    </div>

    <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'flex-end', marginBottom: 12 }}>
      <form role="search" onSubmit={applySearch} style={{ display: 'flex', gap: 6, alignItems: 'flex-end' }}>
        <input className="ui-input" type="search" aria-label="Search observations" placeholder="Address, name, network or sensor" value={draft} onChange={(e) => setDraft(e.target.value)} style={{ width: 280 }} />
        <button className="ui-btn sm" type="submit">Search</button>
        {q && <button className="ui-btn sm ghost" type="button" onClick={clearSearch}>Clear search</button>}
      </form>
      {chip === 'all' && <label style={{ fontSize: 12 }}>State
        <select className="ui-input" style={{ width: 220 }} aria-label="Observation state" value={stateFilter} onChange={(e) => { setStateFilter(e.target.value as StateFilter); changeView(); }}>
          {STATE_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
      </label>}
    </div>

    <p role="status" style={visuallyHidden}>{selectedRows.length > 0 ? `${selectedRows.length} selected` : ''}</p>
    <div role="status">
      {outcome && <p style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 13, margin: '0 0 10px' }}>
        <strong>{outcomeText(outcome)}</strong>
        {outcome.failed > 0 && <span style={{ color: 'var(--app-t2)' }}>The rows that need another look stay in the table with the reason.</span>}
        <button type="button" className="ui-btn sm ghost" onClick={() => { setOutcome(null); setKept(new Map()); }}>Done</button>
      </p>}
    </div>

    {canDecide && selectedRows.length > 0 && <BulkBar rows={selectedRows} pending={bulk.isPending} onAction={openDialog} onClear={() => setSelected(new Set())} />}
    {dialog && <BulkDialog action={dialog} rows={selectedRows} pending={bulk.isPending} error={bulk.isError ? bulk.error.message : null}
      onSubmit={(reason) => submit(dialog, reason)} onClose={() => setDialog(null)} />}

    {list.isError ? <div role="alert" className="panel" style={{ padding: 24, borderRadius: 14 }}>
      <p style={{ margin: '0 0 8px', fontWeight: 600 }}>Couldn’t load observations</p>
      <button className="ui-btn sm" onClick={() => { void list.refetch(); }}>Retry</button>
    </div> : empty ? <div className="panel" style={{ padding: 24, borderRadius: 14 }} data-empty>
      <p style={{ margin: '0 0 6px', fontWeight: 600 }}>{q ? `No observations match “${q}”.` : unresolvedView ? 'Nothing needs you right now' : 'No observations in this view.'}</p>
      {!q && unresolvedView && <p style={{ margin: '0 0 8px', fontSize: 12.5, color: 'var(--app-t2)' }}>Unresolved observations leave the active view after 30 days without a sighting.</p>}
      {q ? <button className="ui-btn sm" onClick={clearSearch}>Clear search</button>
        : suggestion && counts && <button className="ui-btn sm" onClick={() => pickChip(suggestion)}>Show {chipLabel(suggestion)} ({counts[suggestion]})</button>}
    </div> : <>
      <ObservationTable rows={rows} pinned={pinned} loading={list.isPending} canDecide={canDecide} selectable selected={selected}
        onToggle={toggle} onToggleAll={toggleAll} sort={sort} onSort={pickSort} failures={failures} skeletonRows={Math.min(pageSize, 8)} />
      {list.data && <nav aria-label="Observation pages" style={{ display: 'flex', gap: 12, alignItems: 'center', marginTop: 16, fontSize: 12.5 }}>
        <button className="ui-btn sm" disabled={page === 1} onClick={() => turnPage(page - 1)}>Previous</button>
        <span>Page {page} · {total} observations</span>
        <button className="ui-btn sm" disabled={page * pageSize >= total} onClick={() => turnPage(page + 1)}>Next</button>
        <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>Rows per page
          <select className="ui-input" style={{ width: 80, marginTop: 0 }} value={pageSize} onChange={(e) => pickPageSize(Number(e.target.value))}>
            {PAGE_SIZES.map((n) => <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
      </nav>}
    </>}
  </section>;
}
