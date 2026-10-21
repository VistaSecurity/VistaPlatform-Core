// Spares & RMA (DCIM gap 8) — `/inventory/manage/spares`, Infrastructure →
// Catalog & Data. Two tables:
//
//   - Stock: every inventory item on no asset — spares in stock or reserved at
//     a stock location, units out for RMA, retired parts — with role,
//     manufacturer and part, location, quantity and state. Add a spare,
//     install one on an asset, open an RMA, reserve or retire.
//   - RMA cases: open cases by default (or all), each with its vendor, case
//     number, dates and state, and the next steps it can take (shipped,
//     replacement received, closed).
//
// Each table has its states: loading, error (never "no spares"), empty (none
// recorded, which is not "this organisation has none"), the rows. dcim.read
// opens the page (the WorkspacePage gate); every write control sits behind
// dcim.manage.
import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon, ModalSelect, SectionLabel } from '../../../components/ui';
import { SCard, SPage } from '../../settings/kit';
import type { SettingsNavItem } from '../../settings/nav';
import { PanelEmpty, PanelError, PanelLoading } from '../dcim/substrate-states';
import { useInventoryItemRoles, useManufacturers, type InventoryItem } from '../dcim/hardware-queries';
import { AddSpareModal, InstallSpareModal, OpenRmaModal, useLocationPaths } from './spare-actions';
import {
  RMA_NEXT, RMA_STATE_LABELS, STOCK_STATE_LABELS, unitCount, useInventoryItem, usePatchSpare, useRmaCases, useSpares, useUpdateRmaCase,
  type RmaCase, type StockState,
} from './spares-queries';

const MANAGE = TENANT_PERMISSIONS.dcim.manage;
const th = { padding: '8px 11px', fontWeight: 600 } as const;
const td = { padding: '8px 11px', color: 'var(--app-t2)' } as const;
const errMsg = (e: unknown) => (e instanceof Error ? e.message : 'Request failed');

export function SparesPage({ meta }: { meta: SettingsNavItem }) {
  const [adding, setAdding] = useState(false);
  return (
    <SPage
      eyebrow="Infrastructure" title="Spares & RMA" job={meta.job} maxWidth={1180}
      actions={(
        <PermissionGate permission={MANAGE}>
          <button type="button" className="ui-btn sm accent" onClick={() => setAdding(true)}><Icon name="plus" size={14} />Add spare</button>
        </PermissionGate>
      )}
    >
      <div data-testid="spares-page" style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
        <StockTable />
        <RmaCasesTable />
      </div>
      {adding && <AddSpareModal onClose={() => setAdding(false)} />}
    </SPage>
  );
}

function StockTable() {
  const [state, setState] = useState<StockState | ''>('');
  const spares = useSpares({ state });
  const roles = useInventoryItemRoles();
  const mfrs = useManufacturers();
  const paths = useLocationPaths();
  const patch = usePatchSpare();
  const [installing, setInstalling] = useState<InventoryItem | null>(null);
  const [rma, setRma] = useState<InventoryItem | null>(null);
  const [error, setError] = useState<string | null>(null);
  const roleName = useMemo(() => new Map((roles.data ?? []).map((r) => [r.id, r.name])), [roles.data]);
  const mfrName = useMemo(() => new Map((mfrs.data ?? []).map((m) => [m.id, m.name])), [mfrs.data]);
  const rows = spares.data ?? [];

  let body: React.ReactNode;
  if (spares.isLoading) body = <PanelLoading label="Loading the spares…" />;
  else if (spares.isError) body = <PanelError message={errMsg(spares.error)} onRetry={() => { void spares.refetch(); }} />;
  else if (rows.length === 0) {
    body = (
      <div data-testid="spares-empty">
        <PanelEmpty icon="package" title={state ? `No spares ${STOCK_STATE_LABELS[state].toLowerCase()}` : 'No spares recorded'}
          message="Nothing is recorded in stock, which says nothing about what is on your shelves. Add a spare, or remove a part from an asset's Hardware tab to stock." />
      </div>
    );
  } else {
    body = (
      <div style={{ border: '1px solid var(--app-border)', borderRadius: 10, overflowX: 'auto' }}>
        <table data-testid="spares-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
          <thead>
            <tr style={{ textAlign: 'left', color: 'var(--app-t3)', fontSize: 11.5 }}>
              {['Item', 'Role', 'Manufacturer / part', 'Location', 'Quantity', 'State', ''].map((h) => <th key={h} style={th}>{h}</th>)}
            </tr>
          </thead>
          <tbody>
            {rows.map((i) => (
              <tr key={i.id} data-testid="spare-row" style={{ borderTop: '1px solid var(--app-border)' }}>
                <td style={td}>
                  <span className="mono" style={{ fontWeight: 600, color: 'var(--app-t1)' }}>{i.name}</span>
                  {i.serial && <span className="mono" style={{ marginLeft: 6, fontSize: 11.5, color: 'var(--app-t3)' }}>SN {i.serial}</span>}
                </td>
                <td style={td}>{i.role_id ? roleName.get(i.role_id) ?? '—' : '—'}</td>
                <td style={td}>
                  {i.manufacturer_id ? mfrName.get(i.manufacturer_id) ?? '—' : '—'}
                  {i.part_id && <span className="mono" style={{ marginLeft: 6 }}>{i.part_id}</span>}
                </td>
                <td style={td}>{i.location_id ? paths.get(i.location_id) ?? 'a location' : <span style={{ color: 'var(--app-t3)' }}>{i.stock_state === 'rma' ? 'with the vendor' : 'none'}</span>}</td>
                <td style={td} className="mono">{i.quantity}</td>
                <td style={td}><span data-testid="spare-state">{STOCK_STATE_LABELS[i.stock_state]}</span></td>
                <td style={{ ...td, textAlign: 'right', whiteSpace: 'nowrap' }}>
                  <PermissionGate permission={MANAGE}>
                    {(i.stock_state === 'in_stock' || i.stock_state === 'reserved') && (
                      <>
                        <button type="button" className="ui-btn sm" aria-label={`Install ${i.name}`} onClick={() => setInstalling(i)}>Install</button>{' '}
                        <button type="button" className="ui-btn sm" aria-label={`Open RMA for ${i.name}`} onClick={() => setRma(i)}>RMA</button>{' '}
                        <button type="button" className="ui-btn sm ghost" aria-label={i.stock_state === 'reserved' ? `Release ${i.name}` : `Reserve ${i.name}`}
                          onClick={() => { setError(null); patch.mutate({ id: i.id, patch: { stock_state: i.stock_state === 'reserved' ? 'in_stock' : 'reserved' } }, { onError: (e) => setError(e.message) }); }}>
                          {i.stock_state === 'reserved' ? 'Release' : 'Reserve'}
                        </button>{' '}
                        <button type="button" className="ui-btn sm ghost" aria-label={`Retire ${i.name}`}
                          onClick={() => { setError(null); patch.mutate({ id: i.id, patch: { stock_state: 'retired' } }, { onError: (e) => setError(e.message) }); }}>
                          Retire
                        </button>
                      </>
                    )}
                  </PermissionGate>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }
  return (
    <SCard>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
        <SectionLabel icon="package">Stock</SectionLabel>
        {spares.data && rows.length > 0 && <span data-testid="spares-units" style={{ fontSize: 12, color: 'var(--app-t3)' }}>{unitCount(rows)} unit{unitCount(rows) === 1 ? '' : 's'} in {rows.length} row{rows.length === 1 ? '' : 's'}</span>}
        <div style={{ marginLeft: 'auto', width: 200 }}>
          <ModalSelect aria-label="Stock state" value={state} onChange={(e) => setState(e.target.value as StockState | '')}>
            <option value="">Every state</option>
            {(['in_stock', 'reserved', 'rma', 'retired'] as const).map((s) => <option key={s} value={s}>{STOCK_STATE_LABELS[s]}</option>)}
          </ModalSelect>
        </div>
      </div>
      {body}
      {error && <div role="alert" data-testid="spares-error" style={{ fontSize: 12, color: 'var(--danger-text)', marginTop: 6 }}>{error}</div>}
      {installing && <InstallSpareModal item={installing} onClose={() => setInstalling(null)} />}
      {rma && <OpenRmaModal item={rma} onClose={() => setRma(null)} />}
    </SCard>
  );
}

function RmaCasesTable() {
  const [showAll, setShowAll] = useState(false);
  const cases = useRmaCases(showAll ? null : true);
  const update = useUpdateRmaCase();
  const paths = useLocationPaths();
  const [error, setError] = useState<string | null>(null);
  const rows = cases.data ?? [];
  const step = (c: RmaCase, state: RmaCase['state']) => {
    setError(null);
    update.mutate({ id: c.id, patch: { state } }, { onError: (e) => setError(e.message) });
  };

  let body: React.ReactNode;
  if (cases.isLoading) body = <PanelLoading label="Loading the RMA cases…" />;
  else if (cases.isError) body = <PanelError message={errMsg(cases.error)} onRetry={() => { void cases.refetch(); }} />;
  else if (rows.length === 0) {
    body = (
      <div data-testid="rma-empty">
        <PanelEmpty icon="recycle" title={showAll ? 'No RMA cases' : 'No open RMA cases'}
          message="Open one from a spare's RMA action, or from a part on an asset's Hardware tab." />
      </div>
    );
  } else {
    body = (
      <div style={{ border: '1px solid var(--app-border)', borderRadius: 10, overflowX: 'auto' }}>
        <table data-testid="rma-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
          <thead>
            <tr style={{ textAlign: 'left', color: 'var(--app-t3)', fontSize: 11.5 }}>
              {['Item', 'Vendor', 'Case', 'Opened', 'Shipped', 'Received', 'Replacement to', 'State', ''].map((h) => <th key={h} style={th}>{h}</th>)}
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => (
              <tr key={c.id} data-testid="rma-row" style={{ borderTop: '1px solid var(--app-border)' }}>
                <td style={td}><RmaItem id={c.inventory_item_id} /></td>
                <td style={td}>{c.vendor ?? <span style={{ color: 'var(--app-t3)' }}>not recorded</span>}</td>
                <td style={td} className="mono">{c.case_number ?? '—'}</td>
                <td style={td} className="mono">{c.opened_at}</td>
                <td style={td} className="mono">{c.shipped_at ?? '—'}</td>
                <td style={td} className="mono">{c.received_at ?? '—'}</td>
                <td style={td}>{c.replacement_location_id ? paths.get(c.replacement_location_id) ?? 'a location' : '—'}</td>
                <td style={td}><span data-testid="rma-state">{RMA_STATE_LABELS[c.state]}</span></td>
                <td style={{ ...td, textAlign: 'right', whiteSpace: 'nowrap' }}>
                  <PermissionGate permission={MANAGE}>
                    {RMA_NEXT[c.state].map((s) => (
                      <button key={s} type="button" className="ui-btn sm" style={{ marginLeft: 4 }} aria-label={`Mark ${c.case_number ?? 'case'} ${RMA_STATE_LABELS[s].toLowerCase()}`}
                        disabled={update.isPending} onClick={() => step(c, s)}>
                        {s === 'shipped' ? 'Shipped' : s === 'received' ? 'Received' : 'Close'}
                      </button>
                    ))}
                  </PermissionGate>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }
  return (
    <SCard>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
        <SectionLabel icon="recycle">RMA cases</SectionLabel>
        <label style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6, fontSize: 12.5, color: 'var(--app-t2)' }}>
          <input type="checkbox" aria-label="Show closed cases" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} />Show closed cases
        </label>
      </div>
      {body}
      {error && <div role="alert" data-testid="rma-error" style={{ fontSize: 12, color: 'var(--danger-text)', marginTop: 6 }}>{error}</div>}
    </SCard>
  );
}

/** The unit a case is for: its name, and where it is now. */
function RmaItem({ id }: { id: string }) {
  const item = useInventoryItem(id);
  if (item.isLoading) return <span style={{ color: 'var(--app-t3)' }}>…</span>;
  if (item.isError || !item.data) return <span style={{ color: 'var(--app-t3)' }}>unavailable</span>;
  const i = item.data;
  return (
    <span>
      <span className="mono" style={{ fontWeight: 600, color: 'var(--app-t1)' }}>{i.name}</span>
      {i.serial && <span className="mono" style={{ marginLeft: 6, fontSize: 11.5, color: 'var(--app-t3)' }}>SN {i.serial}</span>}
      {i.asset_id && <Link to={`/inventory/assets/${i.asset_id}/hardware`} style={{ marginLeft: 6, fontSize: 11.5, color: 'var(--accent)' }}>in its asset</Link>}
    </span>
  );
}
