// Inventory → Cabling (DCIM BUILD_PLAN row 3.4; ADR-0010 D6/D10): every cable
// of the tenant — label, A end and B end as asset:port, type, status (a
// proposed cable from a neighbour observation reads "Proposed"), length,
// colour, site / rack — filtered by site, rack, asset, type, status and port
// kind. A row opens the cable drawer: both ends linking to their assets, the
// cable's type / label / colour / length / link status editable, Trace from
// either end, Disconnect, and the change log. Export downloads the rows on
// screen as CSV (the bulk export has no `cable` kind).
//
// States: loading, error, empty (no cables yet / none match), the table, and
// the drawer's save result.
import { useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS, usePermissions } from '@vistasecurity/primitives/rbac';
import {
  CABLE_LENGTH_UNITS, CABLE_LENGTH_UNIT_LABELS, CABLE_STATUSES, CABLE_STATUS_LABELS, CABLE_TYPES, CABLE_TYPE_LABELS,
} from '@vistasecurity/primitives/dcim';
import { useDebouncedValue } from '@vistasecurity/primitives/shared';
import { DrawerCloseBtn, DrawerShell, Icon, Modal, ModalField, ModalInput, ModalSelect, SectionLabel } from '../../../components/ui';
import { useAssetsQuery } from '../asset-queries';
import { ObjectChanges } from '../dcim/object-changes';
import { PanelEmpty, PanelError, PanelLoading } from '../dcim/substrate-states';
import { useDisconnectCable, type Cable, type CableTerminationRef } from '../dcim/cable-queries';
import { useRacks } from '../racks/racks-queries';
import { useSites } from '../sites/sites-queries';
import { KIND_LABEL, CONNECTABLE_KINDS } from '../dcim/cable-column';
import { CABLE_LIST_PAGE, isTraceKind, useCable, useCableList, useUpdateCable, type CableFilters, type CableUpdateInput } from './cabling-queries';
import { STATUS_FILTERS, cablesCsv, endText, lengthText, statusFilter, statusText, typeText, whereText } from './cabling-model';
import { TraceBody } from './trace-view';

const COLS = '0.9fr 1.4fr 1.4fr 0.9fr 0.9fr 0.6fr 0.4fr 1fr';

function downloadCsv(rows: readonly Cable[]) {
  const blob = new Blob([cablesCsv(rows)], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'cables.csv';
  a.click();
  URL.revokeObjectURL(url);
}

function Ends({ ts }: { ts: readonly CableTerminationRef[] }) {
  if (ts.length === 0) return <span style={{ color: 'var(--app-t3)' }}>—</span>;
  return (
    <span className="mono" style={{ fontSize: 12 }} onClick={(e) => e.stopPropagation()}>
      {ts.map((t, i) => (
        <span key={t.termination_id}>
          {i > 0 && ', '}
          {t.asset_id
            ? <Link to={`/inventory/assets/${t.asset_id}/ports`} style={{ color: 'var(--accent)' }}>{t.asset_name}:{t.name}</Link>
            : t.circuit_id
              ? <Link to={`/inventory?lens=circuits&circuit=${t.circuit_id}`} style={{ color: 'var(--accent)' }}>{t.name}</Link>
              : t.name}
        </span>
      ))}
    </span>
  );
}

function Swatch({ color }: { color: string | null }) {
  if (!color) return <span style={{ color: 'var(--app-t3)' }}>—</span>;
  return <span data-testid="cable-swatch" title={`#${color}`} style={{ display: 'inline-block', width: 14, height: 14, borderRadius: 3, background: `#${color}`, border: '1px solid var(--app-border)' }} />;
}

/** The asset filter: a search that sets `asset`, a chip once set. */
function AssetFilter({ assetId, assetName, onPick }: { assetId: string; assetName: string | null; onPick: (id: string | null, name?: string) => void }) {
  const [q, setQ] = useState('');
  const term = useDebouncedValue(q).trim();
  const results = useAssetsQuery(JSON.stringify(term), 1, term.length >= 2 && !assetId);
  if (assetId) {
    return (
      <span data-testid="asset-filter-chip" className="ui-btn sm" style={{ cursor: 'default' }}>
        <Icon name="server" size={12} />{assetName ?? assetId.slice(0, 8)}
        <button type="button" aria-label="Clear asset filter" className="ui-btn sm ghost" style={{ padding: 0 }} onClick={() => onPick(null)}><Icon name="x" size={11} /></button>
      </span>
    );
  }
  return (
    <span style={{ position: 'relative' }}>
      <input aria-label="Asset" placeholder="Any asset" value={q} onChange={(e) => setQ(e.target.value)} className="ui-input" style={{ width: 150 }} />
      {term.length >= 2 && (
        <div style={{ position: 'absolute', zIndex: 5, top: '100%', left: 0, minWidth: 200, background: 'var(--app-panel)', border: '1px solid var(--app-border)', borderRadius: 8 }}>
          {results.isLoading && <div style={{ padding: 6, fontSize: 12, color: 'var(--app-t3)' }}>Searching…</div>}
          {results.isError && <div style={{ padding: 6, fontSize: 12, color: 'var(--danger-text)' }}>Couldn&rsquo;t search</div>}
          {(results.data?.assets ?? []).slice(0, 8).map((a) => {
            const name = [a.display_name, a.hostname].find((x): x is string => !!x) ?? a.id.slice(0, 8);
            return <button key={a.id} type="button" onClick={() => { setQ(''); onPick(a.id, name); }} style={{ display: 'block', width: '100%', textAlign: 'left', padding: '5px 8px', border: 'none', background: 'transparent', fontSize: 12.5, cursor: 'pointer', color: 'var(--app-t1)' }}>{name}</button>;
          })}
          {results.data && results.data.assets.length === 0 && <div style={{ padding: 6, fontSize: 12, color: 'var(--app-t3)' }}>No assets match.</div>}
        </div>
      )}
    </span>
  );
}

export function CablingLens() {
  const [params, setParams] = useSearchParams();
  const set = (patch: Record<string, string | null>) => {
    const n = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) { if (v) n.set(k, v); else n.delete(k); }
    setParams(n, { replace: true });
  };
  const site = params.get('site') ?? '';
  const rack = params.get('rack') ?? '';
  const asset = params.get('asset') ?? '';
  const type = params.get('type') ?? '';
  const status = params.get('status') ?? '';
  const kind = params.get('kind') ?? '';
  const selected = params.get('cable');
  const [q, setQ] = useState('');
  const [assetName, setAssetName] = useState<string | null>(null);
  const search = useDebouncedValue(q).trim();
  const filters: CableFilters = useMemo(() => ({
    site_id: site || undefined, rack_id: rack || undefined, asset_id: asset || undefined, type: type || undefined,
    termination_kind: kind || undefined, q: search || undefined, ...statusFilter(status),
  }), [site, rack, asset, type, kind, search, status]);
  // A filter change starts again at the first page (keyed, not an effect).
  const fkey = JSON.stringify(filters);
  const [pg, setPg] = useState({ key: fkey, offset: 0 });
  const offset = pg.key === fkey ? pg.offset : 0;
  const setOffset = (o: number) => setPg({ key: fkey, offset: o });
  const cables = useCableList(filters, offset);
  const sites = useSites();
  const racks = useRacks({ siteId: site || undefined });
  const rows = cables.data?.rows ?? [];
  const total = cables.data?.total ?? 0;
  const filtered = Object.values(filters).some(Boolean);

  return (
    <div data-testid="cabling-lens" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <h1 style={{ margin: 0, fontSize: 18, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
          <Icon name="cable" size={17} style={{ color: 'var(--accent)' }} />Cabling
        </h1>
        <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>{cables.data ? `${total} ${total === 1 ? 'cable' : 'cables'}` : ''}</span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <input aria-label="Search cables" placeholder="Label or description…" value={q} onChange={(e) => setQ(e.target.value)} className="ui-input" style={{ width: 160 }} />
          <select aria-label="Site" value={site} onChange={(e) => set({ site: e.target.value || null, rack: null })} className="ui-input">
            <option value="">{sites.isError ? 'Couldn’t load sites' : 'Any site'}</option>
            {(sites.data ?? []).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
          </select>
          <select aria-label="Rack" value={rack} onChange={(e) => set({ rack: e.target.value || null })} className="ui-input">
            <option value="">{racks.isError ? 'Couldn’t load racks' : 'Any rack'}</option>
            {(racks.data ?? []).map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
          </select>
          <AssetFilter assetId={asset} assetName={assetName} onPick={(id, name) => { setAssetName(name ?? null); set({ asset: id }); }} />
          <select aria-label="Cable type" value={type} onChange={(e) => set({ type: e.target.value || null })} className="ui-input">
            <option value="">Any type</option>
            {CABLE_TYPES.map((t) => <option key={t} value={t}>{CABLE_TYPE_LABELS[t]}</option>)}
          </select>
          <select aria-label="Status" value={status} onChange={(e) => set({ status: e.target.value || null })} className="ui-input">
            <option value="">Any status</option>
            {STATUS_FILTERS.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
          </select>
          <select aria-label="Port kind" value={kind} onChange={(e) => set({ kind: e.target.value || null })} className="ui-input">
            <option value="">Any port kind</option>
            {CONNECTABLE_KINDS.map((k) => <option key={k} value={k}>{KIND_LABEL[k]}</option>)}
          </select>
          <button type="button" className="ui-btn sm" data-testid="export-cables" disabled={rows.length === 0} onClick={() => downloadCsv(rows)} title="Download the cables on screen as CSV">
            <Icon name="download" size={13} />Export
          </button>
        </div>
      </div>

      <div style={{ border: '1px solid var(--app-border)', borderRadius: 12, background: 'var(--app-panel)', overflow: 'hidden' }}>
        <div style={{ display: 'grid', gridTemplateColumns: COLS, gap: 10, padding: '8px 12px', fontSize: 11, fontWeight: 600, color: 'var(--app-t3)', borderBottom: '1px solid var(--app-border)' }}>
          <span>Label</span><span>A end</span><span>B end</span><span>Type</span><span>Status</span><span>Length</span><span>Colour</span><span>Site / rack</span>
        </div>
        {cables.isLoading && <div style={{ padding: 14 }}><PanelLoading label="Loading cables…" /></div>}
        {cables.isError && <div style={{ padding: 14 }}><PanelError message={cables.error instanceof Error ? cables.error.message : 'Request failed'} onRetry={() => { void cables.refetch(); }} /></div>}
        {cables.data && rows.length === 0 && (
          <PanelEmpty icon="cable" title={filtered ? 'No cables match' : 'No cables yet'}
            message={filtered ? 'Nothing matches these filters.' : 'Connect a port from an asset’s Ports or Interfaces tab — or paste a whole switch’s cabling with “Edit cables as table” on its faceplate. Cables proposed from LLDP/CDP neighbours appear here as Proposed.'} />
        )}
        {rows.map((c) => (
          <div key={c.id} data-testid="cable-row" data-status={c.status} role="button" tabIndex={0} onClick={() => set({ cable: c.id })}
            onKeyDown={(e) => { if (e.key === 'Enter') set({ cable: c.id }); }}
            style={{ display: 'grid', gridTemplateColumns: COLS, gap: 10, alignItems: 'center', padding: '7px 12px', borderBottom: '1px solid var(--app-border)', fontSize: 12.5, cursor: 'pointer', background: selected === c.id ? 'var(--app-panel2)' : undefined, borderLeft: c.status === 'pending' ? '3px dashed var(--warn)' : undefined }}>
            <span className="mono" style={{ fontWeight: 600 }}>{c.label?.trim() ? c.label : '—'}</span>
            <Ends ts={c.a_terminations} />
            <Ends ts={c.b_terminations} />
            <span style={{ color: 'var(--app-t2)' }}>{typeText(c.type)}</span>
            <span style={{ color: c.status === 'pending' || c.operational_status !== 'connected' ? 'var(--warn)' : 'var(--app-t2)' }}>{statusText(c)}</span>
            <span className="mono" style={{ fontSize: 12 }}>{lengthText(c)}</span>
            <Swatch color={c.color} />
            <span style={{ color: 'var(--app-t3)', fontSize: 12 }}>{whereText(c)}</span>
          </div>
        ))}
      </div>
      {total > CABLE_LIST_PAGE && (
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', justifyContent: 'flex-end', fontSize: 12 }}>
          <button type="button" className="ui-btn sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - CABLE_LIST_PAGE))}>Previous</button>
          <span>{offset + 1}–{Math.min(total, offset + CABLE_LIST_PAGE)} of {total}</span>
          <button type="button" className="ui-btn sm" disabled={offset + CABLE_LIST_PAGE >= total} onClick={() => setOffset(offset + CABLE_LIST_PAGE)}>Next</button>
        </div>
      )}
      {selected && <CableDrawer id={selected} fallback={rows.find((c) => c.id === selected)} onClose={() => set({ cable: null })} />}
    </div>
  );
}

interface Draft { type: string; label: string; color: string; length: string; length_unit: string; operational_status: string }

export function draftOf(c: Cable): Draft {
  return {
    type: c.type ?? '', label: c.label ?? '', color: c.color ?? '', length: c.length == null ? '' : String(c.length),
    length_unit: c.length_unit ?? 'm', operational_status: c.operational_status,
  };
}

/** The PATCH a draft makes: only the fields that changed. */
export function patchOf(c: Cable, d: Draft): CableUpdateInput {
  const p: CableUpdateInput = {};
  const before = draftOf(c);
  if (d.type !== before.type) p.type = (d.type || null) as CableUpdateInput['type'];
  if (d.label !== before.label) p.label = d.label.trim() || null;
  if (d.color !== before.color) p.color = d.color.trim().replace(/^#/, '').toLowerCase() || null;
  if (d.length !== before.length || (d.length && d.length_unit !== before.length_unit)) {
    p.length = d.length.trim() ? Number(d.length) : null;
    p.length_unit = (d.length.trim() ? d.length_unit : null) as CableUpdateInput['length_unit'];
  }
  if (d.operational_status !== before.operational_status) p.operational_status = d.operational_status as CableUpdateInput['operational_status'];
  return p;
}

function CableDrawer({ id, fallback, onClose }: { id: string; fallback: Cable | undefined; onClose: () => void }) {
  const q = useCable(id);
  const c = q.data ?? fallback;
  const perms = usePermissions();
  const canManage = perms.hasPermission(TENANT_PERMISSIONS.dcim.manage);
  const disconnect = useDisconnectCable();
  const [confirm, setConfirm] = useState(false);
  const [traceFrom, setTraceFrom] = useState<CableTerminationRef | null>(null);
  const traceable = c ? [...c.a_terminations, ...c.b_terminations].filter((t) => isTraceKind(t.termination_kind)) : [];
  const from = traceFrom ?? traceable[0] ?? null;

  return (
    <DrawerShell onClose={onClose} width={560}>
      <div data-testid="cable-drawer" style={{ padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Icon name="cable" size={18} style={{ color: 'var(--accent)' }} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="mono" style={{ fontWeight: 700, fontSize: 15 }}>{c?.label?.trim() ? c.label : 'Cable'}</div>
            {c && <div style={{ fontSize: 12, color: 'var(--app-t3)' }}>{typeText(c.type)} · {statusText(c)}</div>}
          </div>
          <PermissionGate permission={TENANT_PERMISSIONS.dcim.manage}>
            {c && <button type="button" className="ui-btn sm ghost" data-testid="cable-disconnect" style={{ color: 'var(--danger-text)' }} onClick={() => setConfirm(true)}><Icon name="unplug" size={13} />Disconnect</button>}
          </PermissionGate>
          <DrawerCloseBtn onClose={onClose} />
        </div>
        {!c && q.isLoading && <PanelLoading label="Loading the cable…" />}
        {!c && q.isError && <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />}
        {c && (
          <>
            {c.status === 'pending' && (
              <div data-testid="cable-proposed" style={{ marginTop: 10, fontSize: 12.5, color: 'var(--warn)' }}>
                Proposed from a neighbour observation and awaiting approval in Discovery → Approvals.
              </div>
            )}
            <SectionLabel icon="ethernet-port">Ends</SectionLabel>
            {(['A', 'B'] as const).map((side) => (
              <div key={side} data-testid={`cable-end-${side}`} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 0', borderBottom: '1px solid var(--app-border)', fontSize: 12.5 }}>
                <span className="mono" style={{ fontWeight: 700, width: 16 }}>{side}</span>
                <span style={{ flex: 1 }}><Ends ts={side === 'A' ? c.a_terminations : c.b_terminations} /></span>
                <span style={{ color: 'var(--app-t3)', fontSize: 11.5 }}>{(side === 'A' ? c.a_terminations : c.b_terminations).map((t) => [t.site_name, t.rack_name].filter(Boolean).join(' / ')).filter(Boolean)[0] ?? ''}</span>
                {(side === 'A' ? c.a_terminations : c.b_terminations).filter((t) => isTraceKind(t.termination_kind)).slice(0, 1).map((t) => (
                  <button key={t.termination_id} type="button" className="ui-btn sm" data-testid={`trace-from-${side}`} onClick={() => setTraceFrom(t)}>
                    <Icon name="route" size={12} />Trace
                  </button>
                ))}
              </div>
            ))}

            <SectionLabel icon="sliders-horizontal">Cable</SectionLabel>
            <CableEditor key={`${c.id}:${c.updated_at}`} cable={c} canManage={canManage} />

            <SectionLabel icon="route">Trace{from ? ` from ${from.asset_name ? `${from.asset_name}:` : ''}${from.name ?? ''}` : ''}</SectionLabel>
            {from && isTraceKind(from.termination_kind)
              ? <TraceBody kind={from.termination_kind} id={from.termination_id} />
              : <PanelEmpty icon="route" title="Nothing to trace" message="Neither end of this cable is a port with a cable path (power cables have none)." />}

            <SectionLabel icon="git-compare">Changes</SectionLabel>
            <ObjectChanges kind="cable" id={c.id} />
          </>
        )}
      </div>
      {confirm && c && (
        <Modal open onClose={() => setConfirm(false)} size="sm" tone="danger" icon="unplug" title="Disconnect this cable?"
          description={`Deletes the cable between ${endText(c.a_terminations)} and ${endText(c.b_terminations)}. Both ends become free; the change log keeps the cable.`}
          secondary={<button type="button" className="ui-btn" onClick={() => setConfirm(false)}>Cancel</button>}
          primary={<button type="button" className="ui-btn danger" disabled={disconnect.isPending} onClick={() => disconnect.mutate(c.id, { onSuccess: () => { setConfirm(false); onClose(); } })}>Disconnect</button>} />
      )}
    </DrawerShell>
  );
}

/** The cable's editable fields. Keyed by the cable's id and updated_at, so a
 *  saved (or refetched) cable starts a fresh draft without an effect. */
function CableEditor({ cable: c, canManage }: { cable: Cable; canManage: boolean }) {
  const update = useUpdateCable();
  const [draft, setDraft] = useState<Draft>(() => draftOf(c));
  const patch = patchOf(c, draft);
  const dirty = Object.keys(patch).length > 0;
  const colourBad = !!draft.color.trim() && !/^#?[0-9a-fA-F]{6}$/.test(draft.color.trim());
  return (
    <>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <ModalField label="Type">
                  <ModalSelect aria-label="Cable type" disabled={!canManage} value={draft.type} onChange={(e) => setDraft({ ...draft, type: e.target.value })}>
                    <option value="">Not recorded</option>
                    {CABLE_TYPES.map((t) => <option key={t} value={t}>{CABLE_TYPE_LABELS[t]}</option>)}
                  </ModalSelect>
                </ModalField>
                <ModalField label="Status">
                  <ModalSelect aria-label="Cable status" disabled={!canManage} value={draft.operational_status} onChange={(e) => setDraft({ ...draft, operational_status: e.target.value })}>
                    {CABLE_STATUSES.map((s) => <option key={s} value={s}>{CABLE_STATUS_LABELS[s]}</option>)}
                  </ModalSelect>
                </ModalField>
                <ModalField label="Label">
                  <ModalInput aria-label="Cable label" disabled={!canManage} maxLength={100} value={draft.label} onChange={(e) => setDraft({ ...draft, label: e.target.value })} />
                </ModalField>
                <ModalField label="Colour" hint="Six hex digits.">
                  <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                    <ModalInput aria-label="Cable colour" disabled={!canManage} value={draft.color} onChange={(e) => setDraft({ ...draft, color: e.target.value })} />
                    <Swatch color={/^#?[0-9a-fA-F]{6}$/.test(draft.color.trim()) ? draft.color.trim().replace(/^#/, '') : null} />
                  </div>
                </ModalField>
                <ModalField label="Length">
                  <div style={{ display: 'flex', gap: 6 }}>
                    <ModalInput aria-label="Cable length" type="number" min={0} step="0.01" disabled={!canManage} value={draft.length} onChange={(e) => setDraft({ ...draft, length: e.target.value })} />
                    <ModalSelect aria-label="Length unit" disabled={!canManage} value={draft.length_unit} onChange={(e) => setDraft({ ...draft, length_unit: e.target.value })}>
                      {CABLE_LENGTH_UNITS.map((u) => <option key={u} value={u}>{CABLE_LENGTH_UNIT_LABELS[u]}</option>)}
                    </ModalSelect>
                  </div>
                </ModalField>
              </div>
            {colourBad && <div style={{ fontSize: 12, color: 'var(--warn)' }}>A colour is six hex digits.</div>}
            {update.isError && <div role="alert" data-testid="cable-save-error" style={{ fontSize: 12.5, color: 'var(--danger-text)' }}>{update.error instanceof Error ? update.error.message : 'Failed to save'}</div>}
            {canManage && (
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
                <button type="button" className="ui-btn sm" disabled={!dirty} onClick={() => setDraft(draftOf(c))}>Reset</button>
                <button type="button" className="ui-btn sm primary" data-testid="cable-save" disabled={!dirty || colourBad || update.isPending}
                  onClick={() => update.mutate({ id: c.id, patch })}>{update.isPending ? 'Saving…' : 'Save'}</button>
              </div>
            )}

    </>
  );
}
