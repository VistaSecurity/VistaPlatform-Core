// The Cable column of the asset page's Interfaces and Ports tabs, with the
// Connect modal and Disconnect (DCIM BUILD_PLAN row 3.2; asset-inventory
// ADR-0010 D6), upgraded by row 3.4: the Connect flow picks the far end by
// site › rack › asset › port kind › port, or a circuit's termination; the
// compatibility matrix is checked inline; a cabled port offers Trace.
//
// A cabled port names its far end as asset:port, linking to the far asset. An
// uncabled one offers Connect. States: the asset's cables loading, failing
// (never shown as "not cabled"), cabled (pending ones say "proposed"),
// uncabled, marked connected.
import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import type { UseQueryResult } from '@tanstack/react-query';
import { useDebouncedValue } from '@vistasecurity/primitives/shared';
import {
  CABLE_LENGTH_UNITS, CABLE_LENGTH_UNIT_LABELS, CABLE_STATUSES, CABLE_STATUS_LABELS, CABLE_TYPES, CABLE_TYPE_LABELS,
  cableCompatible,
} from '@vistasecurity/primitives/dcim';
import { Icon, Modal, ModalField, ModalInput, ModalSelect } from '../../../components/ui';
import { useAssetsQuery } from '../asset-queries';
import { quoteValue } from '../facet-query';
import { useSites } from '../sites/sites-queries';
import { useRacks } from '../racks/racks-queries';
import { useCircuitList } from '../circuits/circuits-queries';
import { TraceModal } from '../cabling/trace-view';
import { isTraceKind } from '../cabling/cabling-queries';
import {
  farEndText, proposedBy, useConnectCable, useDisconnectCable,
  type CableCreateInput, type CableIndex, type CableTerminationKind,
} from './cable-queries';
import { useAssetPorts, type PortKind } from './component-queries';
import { useAssetInterfaces } from './interface-queries';

/** A port that can take a cable, as its tab knows it. */
export interface CablePort {
  kind: CableTerminationKind;
  id: string;
  name: string;
  cableId: string | null;
  markConnected: boolean;
}

/** Far-end kinds the Connect modal offers (power has no UI, ADR-0010 D9). */
export const CONNECTABLE_KINDS = ['interface', 'front_port', 'rear_port', 'console_port', 'console_server_port', 'circuit_termination'] as const;
export type ConnectableKind = (typeof CONNECTABLE_KINDS)[number];

export const KIND_LABEL: Record<ConnectableKind, string> = {
  interface: 'Interface',
  front_port: 'Front port',
  rear_port: 'Rear port',
  console_port: 'Console port',
  console_server_port: 'Console server port',
  circuit_termination: 'Circuit termination',
};

const KIND_ROUTE: Record<Exclude<ConnectableKind, 'interface' | 'circuit_termination'>, PortKind> = {
  front_port: 'front-ports',
  rear_port: 'rear-ports',
  console_port: 'console-ports',
  console_server_port: 'console-server-ports',
};

export function CableCell({ port, cables, canManage }: { port: CablePort; cables: UseQueryResult<CableIndex>; canManage: boolean }) {
  const [connecting, setConnecting] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const [tracing, setTracing] = useState(false);
  const disconnect = useDisconnectCable();

  if (cables.isLoading) return <span data-testid="cable-loading" style={{ color: 'var(--app-t3)' }}>…</span>;
  if (cables.isError) {
    // A failed read is not "not cabled": say so instead of offering Connect.
    return <span data-testid="cable-error" title={cables.error instanceof Error ? cables.error.message : ''} style={{ color: 'var(--danger-text)' }}>Couldn&rsquo;t load</span>;
  }
  const end = cables.data?.get(port.id);
  if (end) {
    const far = end.far[0];
    const text = farEndText(end.far);
    return (
      <span data-testid="cable-peer" style={{ display: 'inline-flex', alignItems: 'center', gap: 6, whiteSpace: 'nowrap' }}>
        {end.cable.color && <span aria-hidden style={{ width: 8, height: 8, borderRadius: 4, background: `#${end.cable.color}` }} />}
        {far?.asset_id
          ? <Link to={`/inventory/assets/${far.asset_id}`} style={{ color: 'var(--accent)' }} className="mono">{text}</Link>
          : <span className="mono">{text}</span>}
        {end.cable.status === 'pending' && (
          <span data-testid="cable-pending" style={{ fontSize: 11, color: 'var(--warn)' }} title="Proposed from a neighbour observation, not yet approved">Proposed</span>
        )}
        {end.cable.operational_status !== 'connected' && (
          <span style={{ fontSize: 11, color: 'var(--warn)' }}>{CABLE_STATUS_LABELS[end.cable.operational_status]}</span>
        )}
        {/* A cable an LLDP / CDP neighbour proposed (row 3.3) is not a cable of
            record until someone approves it in Discovery → Approvals. */}
        {end.cable.status === 'pending' && (
          <Link
            to="/discovery/approvals"
            data-testid="cable-proposed"
            title={`Proposed from ${proposedBy(end.cable)} — review it in Discovery → Approvals`}
            style={{ fontSize: 11, padding: '1px 7px', borderRadius: 999, border: '1px dashed var(--warn)', color: 'var(--warn)', textDecoration: 'none' }}
          >
            Proposed
          </Link>
        )}
        {end.cable.status === 'rejected' && (
          <span data-testid="cable-rejected" title="A proposed cable someone rejected; delete it to free both ports" style={{ fontSize: 11, color: 'var(--app-t3)' }}>Rejected</span>
        )}
        {isTraceKind(port.kind) && (
          <button type="button" className="ui-btn sm ghost" aria-label={`Trace ${port.name}`} onClick={() => setTracing(true)}>
            <Icon name="route" size={12} />
          </button>
        )}
        {tracing && isTraceKind(port.kind) && <TraceModal kind={port.kind} id={port.id} name={port.name} onClose={() => setTracing(false)} />}
        {canManage && (
          <button type="button" className="ui-btn sm ghost" aria-label={`Disconnect ${port.name}`} onClick={() => setConfirm(true)}>
            <Icon name="unplug" size={12} />
          </button>
        )}
        <Modal
          open={confirm}
          onClose={() => setConfirm(false)}
          size="sm"
          tone="danger"
          icon="unplug"
          title={`Disconnect ${port.name}?`}
          description={`Deletes the cable to ${text}. Both ports become free; the change log keeps the cable.`}
          secondary={<button type="button" className="ui-btn" onClick={() => setConfirm(false)}>Cancel</button>}
          primary={(
            <button type="button" className="ui-btn danger" disabled={disconnect.isPending}
              onClick={() => disconnect.mutate(end.cable.id, { onSettled: () => setConfirm(false) })}>
              Disconnect
            </button>
          )}
        />
      </span>
    );
  }
  if (port.cableId) return <span style={{ color: 'var(--app-t3)' }}>Cabled</span>;
  if (port.markConnected) {
    return <span data-testid="cable-marked" title="Marked connected: there is a cable here that is not modelled" style={{ color: 'var(--app-t2)' }}>Marked connected</span>;
  }
  return (
    <span data-testid="cable-none" style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
      <span style={{ color: 'var(--app-t3)' }}>—</span>
      {canManage && (
        <button type="button" className="ui-btn sm" aria-label={`Connect ${port.name}`} onClick={() => setConnecting(true)}>
          <Icon name="cable" size={12} />Connect
        </button>
      )}
      {connecting && <ConnectCableModal port={port} onClose={() => setConnecting(false)} />}
    </span>
  );
}

/** An asset's display name, else hostname, else its id's head (empty strings skipped). */
function assetName(a: { id: string; display_name?: string | null; hostname?: string | null }): string {
  return [a.display_name, a.hostname].find((x) => !!x) ?? a.id.slice(0, 8);
}

interface FarPort { id: string; name: string; cabled: boolean }

function useFarPorts(assetId: string | undefined, kind: ConnectableKind): { rows: FarPort[]; isLoading: boolean; isError: boolean } {
  const isIface = kind === 'interface';
  const isPort = !isIface && kind !== 'circuit_termination';
  const ifaces = useAssetInterfaces(assetId, '', !!assetId && isIface);
  const route: PortKind = isPort ? KIND_ROUTE[kind] : 'front-ports';
  const ports = useAssetPorts(isPort ? assetId : undefined, route);
  if (isIface) {
    return {
      rows: (ifaces.data?.rows ?? []).map((i) => ({ id: i.id, name: i.name, cabled: !!i.cable_id || i.mark_connected })),
      isLoading: ifaces.isLoading, isError: ifaces.isError,
    };
  }
  return {
    rows: (ports.data?.rows ?? []).map((p) => ({ id: p.id, name: p.name, cabled: !!p.cable_id || p.mark_connected })),
    isLoading: ports.isLoading, isError: ports.isError,
  };
}

/** Why a far end cannot take this cable, from the compatibility matrix
 *  (standards/cable-types.yaml, the same table the server checks) and the
 *  one-cable-per-port rule; null when it can. */
export function connectProblem(local: CableTerminationKind, far: ConnectableKind, farPort?: FarPort | null): string | null {
  if (!cableCompatible(local, far)) {
    const a = (w: string) => `${/^[aeiou]/.test(w) ? 'an' : 'a'} ${w}`;
    const near = a(KIND_LABEL[local as ConnectableKind]?.toLowerCase() ?? local.replace(/_/g, ' '));
    return `${near.charAt(0).toUpperCase()}${near.slice(1)} cannot be cabled to ${a(KIND_LABEL[far].toLowerCase())} (cable compatibility matrix).`;
  }
  if (farPort?.cabled) return `${farPort.name} is already cabled or marked connected; each port takes one cable.`;
  return null;
}

/** The asset search the far-end picker runs: free text, narrowed by the
 *  chosen rack (else site). Empty when there is nothing to search on. */
export function farAssetQuery(term: string, siteId: string, rackId: string): string {
  const scope = rackId ? `rack.id:${quoteValue(rackId)}` : siteId ? `site.id:${quoteValue(siteId)}` : '';
  const free = term ? JSON.stringify(term) : '';
  return [scope, free].filter(Boolean).join(' and ');
}

export function ConnectCableModal({ port, onClose }: { port: CablePort; onClose: () => void }) {
  const firstCompatible = CONNECTABLE_KINDS.find((k) => cableCompatible(port.kind, k)) ?? 'interface';
  const [siteId, setSiteId] = useState('');
  const [rackId, setRackId] = useState('');
  const [search, setSearch] = useState('');
  const [asset, setAsset] = useState<{ id: string; name: string } | null>(null);
  const [circuit, setCircuit] = useState<{ id: string; name: string } | null>(null);
  const [kind, setKind] = useState<ConnectableKind>(firstCompatible);
  const [farId, setFarId] = useState('');
  const [type, setType] = useState<string>(port.kind.startsWith('console') ? '' : 'cat6');
  const [status, setStatus] = useState<string>('connected');
  const [label, setLabel] = useState('');
  const [color, setColor] = useState('');
  const [length, setLength] = useState('');
  const [unit, setUnit] = useState('m');
  const connect = useConnectCable();
  const isCircuit = kind === 'circuit_termination';

  const sites = useSites();
  const racks = useRacks({ siteId: siteId || undefined }, !isCircuit);
  const term = useDebouncedValue(search).trim();
  // A chosen rack lists its assets with no search term; otherwise two characters.
  const query = farAssetQuery(term.length >= 2 ? term : '', siteId, rackId);
  const results = useAssetsQuery(query, 1, !isCircuit && !asset && (!!rackId || term.length >= 2));
  const candidates = useMemo(() => (results.data?.assets ?? []).slice(0, rackId ? 48 : 8), [results.data, rackId]);
  const circuits = useCircuitList('circuits', term ? { q: term } : {}, { enabled: isCircuit && !circuit && term.length >= 2 });
  const circuitTerms = useCircuitList('circuit-terminations', { circuit_id: circuit?.id ?? '' }, { enabled: isCircuit && !!circuit });
  const far = useFarPorts(isCircuit ? undefined : asset?.id, kind);
  const farRows: FarPort[] = isCircuit
    ? (circuitTerms.data?.rows ?? []).map((t) => ({ id: t.id, name: `Side ${t.term_side}`, cabled: !!t.cable_id || t.mark_connected }))
    : far.rows;
  const farLoading = isCircuit ? circuitTerms.isLoading : far.isLoading;
  const farError = isCircuit ? circuitTerms.isError : far.isError;
  const picked = farRows.find((r) => r.id === farId) ?? null;
  const problem = connectProblem(port.kind, kind, picked);
  const showList = isCircuit ? !circuit && term.length >= 2 : !asset && (!!rackId || term.length >= 2);

  const ready = !!farId && !problem && !connect.isPending;
  const submit = () => {
    const body: CableCreateInput = {
      a_terminations: [{ termination_kind: port.kind, termination_id: port.id }],
      b_terminations: [{ termination_kind: kind, termination_id: farId }],
      operational_status: status as CableCreateInput['operational_status'],
    };
    if (type) body.type = type as CableCreateInput['type'];
    if (label.trim()) body.label = label.trim();
    if (color.trim()) body.color = color.trim().replace(/^#/, '').toLowerCase();
    if (length.trim()) {
      body.length = Number(length);
      body.length_unit = unit as CableCreateInput['length_unit'];
    }
    connect.mutate(body, { onSuccess: onClose });
  };
  const resetFar = () => { setAsset(null); setCircuit(null); setFarId(''); };

  return (
    <Modal
      open
      onClose={onClose}
      size="md"
      icon="cable"
      title={`Connect ${port.name}`}
      description="Pick the port on the other end of the cable: by site, rack and asset, or a circuit's end. Each port takes one cable."
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Cancel</button>}
      primary={<button type="button" className="ui-btn primary" aria-label="Connect cable" disabled={!ready} onClick={submit}>{connect.isPending ? 'Connecting…' : 'Connect'}</button>}
    >
      <div data-testid="connect-cable-modal">
        <ModalField label="Far end is">
          <ModalSelect aria-label="Far port kind" value={kind} onChange={(e) => { setKind(e.target.value as ConnectableKind); setFarId(''); if ((e.target.value === 'circuit_termination') !== isCircuit) resetFar(); }}>
            {CONNECTABLE_KINDS.map((k) => (
              <option key={k} value={k}>{KIND_LABEL[k]}{cableCompatible(port.kind, k) ? '' : ' (not compatible)'}</option>
            ))}
          </ModalSelect>
        </ModalField>
        {!isCircuit && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <ModalField label="Site" hint="Optional: narrows the asset search.">
              <ModalSelect aria-label="Site" value={siteId} onChange={(e) => { setSiteId(e.target.value); setRackId(''); resetFar(); }}>
                <option value="">{sites.isError ? 'Couldn’t load sites' : 'Any site'}</option>
                {(sites.data ?? []).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
              </ModalSelect>
            </ModalField>
            <ModalField label="Rack" hint="Optional: lists the rack's assets.">
              <ModalSelect aria-label="Rack" value={rackId} onChange={(e) => { setRackId(e.target.value); resetFar(); }}>
                <option value="">{racks.isError ? 'Couldn’t load racks' : 'Any rack'}</option>
                {(racks.data ?? []).map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
              </ModalSelect>
            </ModalField>
          </div>
        )}
        <ModalField label={isCircuit ? 'Circuit' : 'Asset'}>
          <ModalInput
            aria-label={isCircuit ? 'Search for the circuit' : 'Search for the far asset'}
            placeholder={isCircuit ? 'Search by circuit ID…' : rackId ? 'Filter this rack’s assets…' : 'Search by name, hostname or identifier…'}
            value={isCircuit ? (circuit ? circuit.name : search) : asset ? asset.name : search}
            onChange={(e) => { resetFar(); setSearch(e.target.value); }}
          />
        </ModalField>
        {showList && (
          <div data-testid="far-asset-results" style={{ marginTop: -8, marginBottom: 14, border: '1px solid var(--app-border)', borderRadius: 10, overflow: 'hidden', maxHeight: 220, overflowY: 'auto' }}>
            {(isCircuit ? circuits.isLoading : results.isLoading) && <div style={{ padding: '8px 11px', fontSize: 12, color: 'var(--app-t3)' }}>Searching…</div>}
            {(isCircuit ? circuits.isError : results.isError) && (
              <div data-testid="far-asset-error" style={{ padding: '8px 11px', fontSize: 12, color: 'var(--danger-text)' }}>
                Couldn&rsquo;t search — this is not a result of &ldquo;no matches&rdquo;.
              </div>
            )}
            {isCircuit && circuits.data && circuits.data.rows.length === 0 && (
              <div style={{ padding: '8px 11px', fontSize: 12, color: 'var(--app-t3)' }}>No circuits match that.</div>
            )}
            {!isCircuit && results.data && candidates.length === 0 && (
              <div style={{ padding: '8px 11px', fontSize: 12, color: 'var(--app-t3)' }}>{rackId && !term ? 'Nothing is placed in this rack.' : 'No assets match that.'}</div>
            )}
            {isCircuit
              ? (circuits.data?.rows ?? []).slice(0, 8).map((c) => (
                <button key={c.id} type="button" onClick={() => setCircuit({ id: c.id, name: c.cid })} style={pickStyle}>{c.cid}</button>
              ))
              : candidates.map((a) => (
                <button key={a.id} type="button" onClick={() => setAsset({ id: a.id, name: assetName(a) })} style={pickStyle}>{assetName(a)}</button>
              ))}
          </div>
        )}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          <ModalField label="Port">
            <ModalSelect aria-label="Far port" value={farId} disabled={(isCircuit ? !circuit : !asset) || farLoading} onChange={(e) => setFarId(e.target.value)}>
              <option value="">{(isCircuit ? !circuit : !asset) ? `Pick ${isCircuit ? 'a circuit' : 'an asset'} first` : farLoading ? 'Loading…' : farError ? 'Couldn’t load ports' : farRows.length === 0 ? 'None here' : 'Choose…'}</option>
              {farRows.filter((r) => r.id !== port.id).map((r) => (
                <option key={r.id} value={r.id} disabled={r.cabled}>{r.name}{r.cabled ? ' (in use)' : ''}</option>
              ))}
            </ModalSelect>
          </ModalField>
          <ModalField label="Cable type">
            <ModalSelect aria-label="Cable type" value={type} onChange={(e) => setType(e.target.value)}>
              <option value="">Not recorded</option>
              {CABLE_TYPES.map((t) => <option key={t} value={t}>{CABLE_TYPE_LABELS[t]}</option>)}
            </ModalSelect>
          </ModalField>
          <ModalField label="Status">
            <ModalSelect aria-label="Cable status" value={status} onChange={(e) => setStatus(e.target.value)}>
              {CABLE_STATUSES.map((s) => <option key={s} value={s}>{CABLE_STATUS_LABELS[s]}</option>)}
            </ModalSelect>
          </ModalField>
          <ModalField label="Label">
            <ModalInput aria-label="Cable label" value={label} maxLength={100} onChange={(e) => setLabel(e.target.value)} />
          </ModalField>
          <ModalField label="Colour" hint="Six hex digits, e.g. 2f6fdb.">
            <ModalInput aria-label="Cable colour" value={color} onChange={(e) => setColor(e.target.value)} />
          </ModalField>
          <ModalField label="Length">
            <div style={{ display: 'flex', gap: 6 }}>
              <ModalInput aria-label="Cable length" type="number" min={0} step="0.01" value={length} onChange={(e) => setLength(e.target.value)} />
              <ModalSelect aria-label="Length unit" value={unit} onChange={(e) => setUnit(e.target.value)}>
                {CABLE_LENGTH_UNITS.map((u) => <option key={u} value={u}>{CABLE_LENGTH_UNIT_LABELS[u]}</option>)}
              </ModalSelect>
            </div>
          </ModalField>
        </div>
        {problem && (
          <div data-testid="connect-problem" role="alert" style={{ fontSize: 12.5, color: 'var(--danger-text)', marginBottom: 6 }}>{problem}</div>
        )}
        {color.trim() && !/^#?[0-9a-fA-F]{6}$/.test(color.trim()) && (
          <div data-testid="connect-colour-problem" style={{ fontSize: 12, color: 'var(--warn)' }}>A colour is six hex digits.</div>
        )}
        {connect.isError && (
          <div data-testid="connect-error" role="alert" style={{ fontSize: 12.5, color: 'var(--danger-text)' }}>
            {connect.error instanceof Error ? connect.error.message : 'Failed to connect the cable'}
          </div>
        )}
      </div>
    </Modal>
  );
}

const pickStyle: React.CSSProperties = {
  display: 'block', width: '100%', textAlign: 'left', padding: '7px 11px', border: 'none', borderBottom: '1px solid var(--app-border)',
  background: 'transparent', cursor: 'pointer', fontSize: 12.5, color: 'var(--app-t1)',
};
