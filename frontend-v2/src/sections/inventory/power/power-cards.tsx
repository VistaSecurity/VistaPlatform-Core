// The power cards (DCIM BUILD_PLAN row 6.1; ADR-0010 D9): the site page's
// Power panels card (the site's panels, add / delete, each panel's feeds with
// add / delete) and the rack page's Power feeds card (the feeds serving the
// rack: status, rating, available power, the PDU inlet they power). The rack's
// power budget bar is part 2 (row 6.2).
//
// States per card: loading, error (never "no panels"), empty (none declared,
// which is not "this site has no power"), the list. Reads need dcim.read (the
// pages' gate); every write control sits behind dcim.manage.
import { useState, type ReactNode } from 'react';
import { Link } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon, Modal, ModalField, ModalInput, ModalSelect, SectionLabel } from '../../../components/ui';
import { PanelEmpty, PanelError, PanelLoading } from '../dcim/substrate-states';
import { flattenNodes, useLocations } from '../sites/sites-queries';
import { useRacks } from '../racks/racks-queries';
import {
  FEED_PHASES, FEED_STATUSES, FEED_STATUS_LABELS, FEED_SUPPLIES, FEED_TYPES, PowerWriteError, feedRating,
  useCreatePowerFeed, useCreatePowerPanel, useDeletePowerFeed, useDeletePowerPanel, usePowerFeeds, usePowerPanels,
  type PowerFeed, type PowerFeedCreateInput, type PowerPanel,
} from './power-queries';

const MANAGE = TENANT_PERMISSIONS.dcim.manage;

function Card({ children, testId }: { children: ReactNode; testId?: string }) {
  return <div data-testid={testId} style={{ border: '1px solid var(--app-border)', borderRadius: 12, background: 'var(--app-panel)', padding: 16, minWidth: 0 }}>{children}</div>;
}

const statusColor = (s: PowerFeed['operational_status']) =>
  s === 'active' ? 'var(--ok)' : s === 'failed' ? 'var(--danger-text)' : 'var(--app-t3)';

function FeedLine({ f, showRack, onDelete }: { f: PowerFeed; showRack: boolean; onDelete?: () => void }) {
  const ep = f.connected_endpoint;
  return (
    <div data-testid="power-feed-row" style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12.5, padding: '5px 0', borderBottom: '1px solid var(--app-border)', flexWrap: 'wrap' }}>
      <span aria-hidden style={{ width: 8, height: 8, borderRadius: 4, background: statusColor(f.operational_status), flex: 'none' }} />
      <span style={{ fontWeight: 600, color: 'var(--app-t1)' }}>{f.name}</span>
      <span style={{ color: 'var(--app-t3)' }}>{FEED_STATUS_LABELS[f.operational_status]} · {f.type}</span>
      {showRack && (f.rack
        ? <Link to={`/inventory/racks/${f.rack.id}`} style={{ color: 'var(--accent)' }}>{f.rack.name}</Link>
        : <span style={{ color: 'var(--app-t3)' }}>no rack</span>)}
      <span style={{ color: 'var(--app-t2)' }}>{feedRating(f)}</span>
      <span data-testid="feed-available" className="mono" style={{ marginLeft: 'auto', color: 'var(--app-t1)' }}>{f.available_power} VA</span>
      <span data-testid="feed-endpoint" style={{ flexBasis: '100%', paddingLeft: 16, color: 'var(--app-t3)' }}>
        {ep
          ? <>powers {ep.asset_id
            ? <Link to={`/inventory/assets/${ep.asset_id}/ports`} className="mono" style={{ color: 'var(--accent)' }}>{ep.asset_name ?? 'asset'}:{ep.name}</Link>
            : <span className="mono">{ep.name}</span>}</>
          : f.cable_id ? 'cabled; the far end is not a power port' : f.mark_connected ? 'marked connected (cable not modelled)' : 'not cabled to a PDU or device'}
      </span>
      {onDelete && (
        <PermissionGate permission={MANAGE} fallback={null}>
          <button type="button" className="ui-btn sm ghost" aria-label={`Delete ${f.name}`} onClick={onDelete}><Icon name="trash-2" size={12} /></button>
        </PermissionGate>
      )}
    </div>
  );
}

// ------------------------------------------------------------- site card --

/** The site page's Power panels card. */
export function SitePowerCard({ siteId }: { siteId: string }) {
  const panels = usePowerPanels(siteId);
  const feeds = usePowerFeeds({ site_id: siteId });
  const [adding, setAdding] = useState(false);
  const [feedFor, setFeedFor] = useState<PowerPanel | null>(null);
  const [deleting, setDeleting] = useState<{ panel?: PowerPanel; feed?: PowerFeed } | null>(null);
  const delPanel = useDeletePowerPanel();
  const delFeed = useDeletePowerFeed();
  const rows = panels.data ?? [];

  let body: ReactNode;
  if (panels.isLoading) body = <PanelLoading label="Loading power panels…" />;
  else if (panels.isError) body = <PanelError message={panels.error instanceof Error ? panels.error.message : "Couldn't load the site's power panels."} onRetry={() => { void panels.refetch(); }} />;
  else if (rows.length === 0) {
    body = <div data-testid="power-panels-empty" style={{ fontSize: 12, color: 'var(--app-t3)' }}>No power panels are declared at this site, so nothing here says where its racks draw power from.</div>;
  } else {
    body = rows.map((p) => {
      const mine = (feeds.data ?? []).filter((f) => f.power_panel_id === p.id);
      return (
        <div key={p.id} data-testid="power-panel" style={{ marginBottom: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12.5, padding: '4px 0' }}>
            <Icon name="power" size={12} style={{ color: 'var(--app-t3)' }} />
            <span style={{ fontWeight: 700, color: 'var(--app-t1)' }}>{p.name}</span>
            {p.location && <span style={{ color: 'var(--app-t3)' }}>· {p.location.name}</span>}
            <span className="mono" style={{ marginLeft: 'auto', fontSize: 11.5, color: 'var(--app-t3)' }}>{p.feed_count ?? mine.length} feed{(p.feed_count ?? mine.length) === 1 ? '' : 's'}</span>
            <PermissionGate permission={MANAGE} fallback={null}>
              <button type="button" className="ui-btn sm ghost" aria-label={`Add a feed to ${p.name}`} onClick={() => setFeedFor(p)}><Icon name="plus" size={12} /></button>
              <button type="button" className="ui-btn sm ghost" aria-label={`Delete ${p.name}`} onClick={() => setDeleting({ panel: p })}><Icon name="trash-2" size={12} /></button>
            </PermissionGate>
          </div>
          <div style={{ paddingLeft: 18 }}>
            {feeds.isLoading ? <div style={{ fontSize: 12, color: 'var(--app-t3)' }}>Loading feeds…</div>
              : feeds.isError ? <div role="alert" style={{ fontSize: 12, color: 'var(--danger-text)' }}>Couldn&rsquo;t load the feeds.</div>
                : mine.length === 0 ? <div style={{ fontSize: 12, color: 'var(--app-t3)' }}>No feeds declared on this panel.</div>
                  : mine.map((f) => <FeedLine key={f.id} f={f} showRack onDelete={() => setDeleting({ feed: f })} />)}
          </div>
        </div>
      );
    });
  }

  const what = deleting?.panel ?? deleting?.feed;
  return (
    <Card testId="site-power">
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <SectionLabel icon="power">Power panels</SectionLabel>
        <PermissionGate permission={MANAGE} fallback={null}>
          <button type="button" className="ui-btn sm" style={{ marginLeft: 'auto', marginTop: 10 }} onClick={() => setAdding(true)}>
            <Icon name="plus" size={12} />Add panel
          </button>
        </PermissionGate>
      </div>
      {body}
      {adding && <AddPanelModal siteId={siteId} onClose={() => setAdding(false)} />}
      {feedFor && <AddFeedModal panel={feedFor} onClose={() => setFeedFor(null)} />}
      <Modal
        open={!!what}
        onClose={() => setDeleting(null)}
        size="sm"
        tone="danger"
        icon="trash-2"
        title={`Delete ${what?.name ?? ''}?`}
        description={deleting?.panel ? 'Its feeds are deleted with it and their cables detached. The change log keeps what they were.' : 'Its cable is detached. The change log keeps what it was.'}
        secondary={<button type="button" className="ui-btn" onClick={() => setDeleting(null)}>Cancel</button>}
        primary={(
          <button type="button" className="ui-btn danger" disabled={delPanel.isPending || delFeed.isPending}
            onClick={() => {
              if (deleting?.panel) delPanel.mutate(deleting.panel, { onSettled: () => setDeleting(null) });
              else if (deleting?.feed) delFeed.mutate(deleting.feed, { onSettled: () => setDeleting(null) });
            }}>
            Delete
          </button>
        )}
      />
    </Card>
  );
}

function AddPanelModal({ siteId, onClose }: { siteId: string; onClose: () => void }) {
  const [name, setName] = useState('');
  const [locationId, setLocationId] = useState('');
  const [description, setDescription] = useState('');
  const locations = useLocations(siteId, true);
  const create = useCreatePowerPanel();
  const problem = !name.trim() ? 'A name is required.' : name.trim().length > 100 ? 'A name is at most 100 characters.' : null;
  const submit = () => {
    if (problem) return;
    create.mutate({ site_id: siteId, name: name.trim(), location_id: locationId || null, description: description.trim() || null }, { onSuccess: onClose });
  };
  return (
    <Modal open onClose={onClose} size="sm" icon="power" title="Add power panel"
      description="An electrical panel at this site; its feeds serve the racks."
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
      primary={<button type="button" className="ui-btn primary" disabled={!!problem || create.isPending} onClick={submit}>Add panel</button>}>
      <div data-testid="add-panel-modal">
        <ModalField label="Name"><ModalInput aria-label="Panel name" value={name} onChange={(e) => setName(e.target.value)} /></ModalField>
        <ModalField label="Location" hint="Optional: a location inside this site.">
          <ModalSelect aria-label="Panel location" value={locationId} onChange={(e) => setLocationId(e.target.value)}>
            <option value="">{locations.isError ? 'Couldn’t load locations' : 'None'}</option>
            {flattenNodes(locations.data ?? []).map(({ node, depth }) => <option key={node.id} value={node.id}>{' '.repeat(depth * 2)}{node.name}</option>)}
          </ModalSelect>
        </ModalField>
        <ModalField label="Description"><ModalInput aria-label="Panel description" value={description} onChange={(e) => setDescription(e.target.value)} /></ModalField>
        {create.isError && <div role="alert" data-testid="power-form-error" style={{ fontSize: 12.5, color: 'var(--danger-text)' }}>{create.error instanceof PowerWriteError ? create.error.message : 'Failed to add the power panel'}</div>}
      </div>
    </Modal>
  );
}

export interface FeedDraft {
  name: string; rack_id: string; operational_status: string; type: string; supply: string; phase: string;
  voltage: string; amperage: string; max_utilization: string;
}

export const emptyFeedDraft = (): FeedDraft => ({
  name: '', rack_id: '', operational_status: 'active', type: 'primary', supply: 'ac', phase: 'single-phase',
  voltage: '120', amperage: '20', max_utilization: '80',
});

/** What stops a feed saving, before the server is asked (the server holds the
 *  same rules: NetBox PowerFeed.clean). */
export function feedProblem(d: FeedDraft): string | null {
  if (!d.name.trim()) return 'A name is required.';
  const v = Number(d.voltage);
  if (!Number.isInteger(v) || v === 0) return 'Voltage is a whole number of volts, not zero (negative for a DC plant).';
  const a = Number(d.amperage);
  if (!Number.isInteger(a) || a < 1) return 'Amperage is a whole number from 1.';
  const u = Number(d.max_utilization);
  if (!Number.isInteger(u) || u < 1 || u > 100) return 'Maximum utilisation is a percentage from 1 to 100.';
  if (d.supply === 'dc' && d.phase === 'three-phase') return 'A DC supply cannot be three-phase.';
  return null;
}

/** NetBox's available power, for the form's preview (the server computes the stored one). */
export function availablePower(d: Pick<FeedDraft, 'voltage' | 'amperage' | 'max_utilization' | 'phase'>): number {
  const va = Math.abs(Number(d.voltage)) * Number(d.amperage) * Number(d.max_utilization) / 100;
  return Math.round(d.phase === 'three-phase' ? va * 1.732 : va);
}

function AddFeedModal({ panel, onClose }: { panel: PowerPanel; onClose: () => void }) {
  const [d, setD] = useState<FeedDraft>(emptyFeedDraft);
  const racks = useRacks({ siteId: panel.site_id });
  const create = useCreatePowerFeed();
  const set = <K extends keyof FeedDraft>(k: K, v: FeedDraft[K]) => setD((cur) => ({ ...cur, [k]: v }));
  const problem = feedProblem(d);
  const submit = () => {
    if (problem) return;
    const body: PowerFeedCreateInput = {
      power_panel_id: panel.id, name: d.name.trim(), rack_id: d.rack_id || null,
      operational_status: d.operational_status as PowerFeedCreateInput['operational_status'],
      type: d.type as PowerFeedCreateInput['type'], supply: d.supply as PowerFeedCreateInput['supply'],
      phase: d.phase as PowerFeedCreateInput['phase'],
      voltage: Number(d.voltage), amperage: Number(d.amperage), max_utilization: Number(d.max_utilization),
    };
    create.mutate(body, { onSuccess: onClose });
  };
  const select = (label: string, k: keyof FeedDraft, values: readonly string[]) => (
    <ModalField label={label}>
      <ModalSelect aria-label={`Feed ${label.toLowerCase()}`} value={d[k]} onChange={(e) => set(k, e.target.value)}>
        {values.map((v) => <option key={v} value={v}>{v}</option>)}
      </ModalSelect>
    </ModalField>
  );
  return (
    <Modal open onClose={onClose} size="md" icon="zap" title={`Add a feed to ${panel.name}`}
      description="One circuit from this panel, optionally serving a rack at the same site."
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
      primary={<button type="button" className="ui-btn primary" disabled={!!problem || create.isPending} onClick={submit}>Add feed</button>}>
      <div data-testid="add-feed-modal">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          <ModalField label="Name"><ModalInput aria-label="Feed name" value={d.name} onChange={(e) => set('name', e.target.value)} /></ModalField>
          <ModalField label="Rack" hint="Optional: the rack this feed serves.">
            <ModalSelect aria-label="Feed rack" value={d.rack_id} onChange={(e) => set('rack_id', e.target.value)}>
              <option value="">{racks.isError ? 'Couldn’t load racks' : 'None'}</option>
              {(racks.data ?? []).map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
            </ModalSelect>
          </ModalField>
          <ModalField label="Status">
            <ModalSelect aria-label="Feed status" value={d.operational_status} onChange={(e) => set('operational_status', e.target.value)}>
              {FEED_STATUSES.map((s) => <option key={s} value={s}>{FEED_STATUS_LABELS[s]}</option>)}
            </ModalSelect>
          </ModalField>
          {select('Type', 'type', FEED_TYPES)}
          {select('Supply', 'supply', FEED_SUPPLIES)}
          {select('Phase', 'phase', FEED_PHASES)}
          <ModalField label="Voltage (V)"><ModalInput aria-label="Feed voltage" inputMode="numeric" value={d.voltage} onChange={(e) => set('voltage', e.target.value)} /></ModalField>
          <ModalField label="Amperage (A)"><ModalInput aria-label="Feed amperage" inputMode="numeric" value={d.amperage} onChange={(e) => set('amperage', e.target.value)} /></ModalField>
          <ModalField label="Maximum utilisation (%)"><ModalInput aria-label="Feed maximum utilisation" inputMode="numeric" value={d.max_utilization} onChange={(e) => set('max_utilization', e.target.value)} /></ModalField>
        </div>
        {problem
          ? <div role="alert" data-testid="power-form-error" style={{ fontSize: 12.5, color: 'var(--danger-text)' }}>{problem}</div>
          : <div data-testid="feed-preview" style={{ fontSize: 12.5, color: 'var(--app-t2)' }}>Available power: {availablePower(d)} VA</div>}
        {create.isError && <div role="alert" data-testid="power-write-error" style={{ fontSize: 12.5, color: 'var(--danger-text)' }}>{create.error instanceof PowerWriteError ? create.error.message : 'Failed to add the power feed'}</div>}
      </div>
    </Modal>
  );
}

// ------------------------------------------------------------- rack card --

/** The rack page's Power feeds card. */
export function RackPowerCard({ rackId }: { rackId: string }) {
  const feeds = usePowerFeeds({ rack_id: rackId });
  const rows = feeds.data ?? [];
  let body: ReactNode;
  if (feeds.isLoading) body = <PanelLoading label="Loading power feeds…" />;
  else if (feeds.isError) body = <PanelError message={feeds.error instanceof Error ? feeds.error.message : "Couldn't load the rack's power feeds."} onRetry={() => { void feeds.refetch(); }} />;
  else if (rows.length === 0) {
    body = <PanelEmpty icon="zap" title="No power feeds" message="No feed is declared as serving this rack, so nothing here says where it draws power from. Add feeds from the site's Power panels card." />;
  } else {
    const total = rows.filter((f) => f.operational_status === 'active').reduce((n, f) => n + f.available_power, 0);
    body = (
      <>
        <div data-testid="rack-power-total" style={{ fontSize: 12, color: 'var(--app-t3)', marginBottom: 4 }}>
          {rows.length} feed{rows.length === 1 ? '' : 's'} · {total} VA available on the active ones
        </div>
        {rows.map((f) => (
          <div key={f.id}>
            <div style={{ fontSize: 11.5, color: 'var(--app-t3)', paddingTop: 4 }}>{f.power_panel?.name ?? 'Panel'}</div>
            <FeedLine f={f} showRack={false} />
          </div>
        ))}
      </>
    );
  }
  return (
    <Card testId="rack-power">
      <SectionLabel icon="zap">Power feeds</SectionLabel>
      {body}
    </Card>
  );
}
