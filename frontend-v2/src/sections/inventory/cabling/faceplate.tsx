// The asset faceplate (DCIM BUILD_PLAN row 3.4; ADR-0010 D10): the asset's
// interfaces — and its console, console server, front and rear ports in their
// own rows — drawn as ports in the device type's template order, wrapping at
// 24 per row (a 48-port switch is two rows). Each port shows its link state
// (border), whether it is cabled (a dot; a proposed or planned cable dashed),
// and, with the crypto overlay on (the default), a tint from the weakest crypto
// observed behind it, with a lock for a weak protocol version.
//
// Click (or Enter/Space) a port → a panel with its name, type, state, the
// cable's far end, Connect / Disconnect, Trace and the crypto behind it. Arrow
// keys move between ports. "Edit cables as table" opens the bulk editor.
//
// States: loading, error, empty (no ports reported or declared — not "this
// asset has none"), the faceplate; the overlay itself loading/failing says so
// in the legend rather than drawing every port as clean.
import { useMemo, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import type { Asset } from '@vistasecurity/api-contract';
import { usePermissions, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../../components/ui';
import { LEVEL_COLOR, LEVELS } from '../../../components/ui/risk';
import { clients } from '../../../lib/clients';
import { CableCell, type CablePort } from '../dcim/cable-column';
import { farEndText, useAssetCables, type CableIndex } from '../dcim/cable-queries';
import { useAssetHardware, useAssetPorts } from '../dcim/component-queries';
import { useAssetInterfaces } from '../dcim/interface-queries';
import { PanelEmpty, PanelError, PanelLoading } from '../dcim/substrate-states';
import { BulkCableEditor } from './bulk-cable-editor';
import { useInterfacePosture, type InterfacePosture } from './cabling-queries';
import {
  FACEPLATE_KINDS, FACEPLATE_KIND_LABEL, PORT_STATE_COLOR, PORT_STATE_LABEL, TEMPLATE_ROUTE,
  cableMark, faceplateRows, interfaceState, isPhysicalInterface, orderPorts, shortLabel,
  type CableMark, type FaceplateKind, type FacePort,
} from './faceplate-model';
import { overlayTooltip, portOverlay, UNASSESSED_COLOR } from './port-overlay';
import { TraceModal } from './trace-view';

interface Reply { data?: unknown; error?: unknown }
const loose = () => clients.inventory as unknown as { GET: (p: string, i?: object) => Promise<Reply> };

/** The device type's template names per kind, in template order. */
function useTemplateOrder(deviceTypeId: string | null | undefined) {
  return useQuery({
    queryKey: ['dcim-faceplate-templates', deviceTypeId ?? ''],
    enabled: !!deviceTypeId,
    staleTime: 300_000,
    queryFn: async (): Promise<Partial<Record<FaceplateKind, string[]>>> => {
      const out: Partial<Record<FaceplateKind, string[]>> = {};
      await Promise.all(FACEPLATE_KINDS.map(async (k) => {
        const { data, error } = await loose().GET(`/dcim/device-types/{id}/${TEMPLATE_ROUTE[k]}`, {
          params: { path: { id: deviceTypeId! }, query: { limit: 1000 } },
        });
        const rows = (data as { data?: { name: string }[] } | undefined)?.data;
        if (!error && rows) out[k] = rows.map((r) => r.name);
      }));
      return out;
    },
  });
}

/** Every faceplate port of the asset, grouped by kind and ordered. */
export function useFaceplatePorts(asset: Pick<Asset, 'id'>) {
  const ifaces = useAssetInterfaces(asset.id);
  const lists = {
    console_port: useAssetPorts(asset.id, 'console-ports'),
    console_server_port: useAssetPorts(asset.id, 'console-server-ports'),
    front_port: useAssetPorts(asset.id, 'front-ports'),
    rear_port: useAssetPorts(asset.id, 'rear-ports'),
  };
  const hardware = useAssetHardware(asset.id);
  const templates = useTemplateOrder(hardware.data?.device_type?.id);
  const isLoading = ifaces.isLoading || Object.values(lists).some((l) => l.isLoading);
  const failed = [ifaces, ...Object.values(lists)].find((q) => q.isError);
  const groups = useMemo(() => {
    const out: { kind: FaceplateKind; ports: FacePort[] }[] = [];
    const t = templates.data ?? {};
    const physical = (ifaces.data?.rows ?? []).filter((i) => isPhysicalInterface(i.type));
    out.push({
      kind: 'interface',
      ports: orderPorts(physical.map((i): FacePort => ({
        kind: 'interface', id: i.id, name: i.name, label: i.label, type: i.type_label || i.type,
        state: interfaceState(i), cableId: i.cable_id, markConnected: i.mark_connected,
      })), t.interface),
    });
    for (const k of ['console_port', 'console_server_port', 'front_port', 'rear_port'] as const) {
      const rows = (lists[k].data?.rows ?? []) as { id: string; name: string; label: string | null; type: string | null; cable_id: string | null; mark_connected: boolean }[];
      out.push({
        kind: k,
        ports: orderPorts(rows.map((r): FacePort => ({
          kind: k, id: r.id, name: r.name, label: r.label, type: r.type ?? '', state: 'passive', cableId: r.cable_id, markConnected: r.mark_connected,
        })), t[k]),
      });
    }
    return out.filter((g) => g.ports.length > 0);
  }, [ifaces.data, lists.console_port.data, lists.console_server_port.data, lists.front_port.data, lists.rear_port.data, templates.data]); // eslint-disable-line react-hooks/exhaustive-deps
  const hidden = (ifaces.data?.rows ?? []).filter((i) => !isPhysicalInterface(i.type)).length;
  return { groups, hidden, isLoading, error: failed?.error ?? null, refetch: () => { void ifaces.refetch(); for (const l of Object.values(lists)) void l.refetch(); } };
}

const MARK_TEXT: Record<CableMark, string> = {
  none: 'not cabled', cabled: 'cabled', pending: 'proposed cable', planned: 'planned cable', marked: 'marked connected',
};

function portAria(p: FacePort, mark: CableMark, cables: CableIndex | undefined, overlay: string | null): string {
  const end = cables?.get(p.id);
  const parts = [p.name, PORT_STATE_LABEL[p.state], end ? `cabled to ${farEndText(end.far)}` : MARK_TEXT[mark]];
  if (overlay) parts.push(overlay);
  return parts.join(', ');
}

function PortTile({ p, mark, cables, posture, overlayOn, selected, onPick, onKey }: {
  p: FacePort; mark: CableMark; cables: CableIndex | undefined; posture: InterfacePosture | undefined; overlayOn: boolean;
  selected: boolean; onPick: () => void; onKey: (e: React.KeyboardEvent<HTMLButtonElement>) => void;
}) {
  const ov = overlayOn && p.kind === 'interface' ? portOverlay(posture) : null;
  const tint = ov?.color ?? null;
  const border = PORT_STATE_COLOR[p.state];
  const dashed = mark === 'pending' || mark === 'planned';
  return (
    <button
      type="button"
      data-testid="face-port"
      data-port-id={p.id}
      data-state={p.state}
      data-mark={mark}
      data-tint={tint ?? ''}
      data-weak={ov?.weakProtocol ? 'true' : undefined}
      aria-label={portAria(p, mark, cables, ov && ov.kind !== 'none' ? ov.label : null)}
      aria-pressed={selected}
      title={ov ? overlayTooltip(p.name, posture) : `${p.name}\n${PORT_STATE_LABEL[p.state]}`}
      onClick={onPick}
      onKeyDown={onKey}
      style={{
        position: 'relative', width: 30, height: 26, padding: 0, borderRadius: 4, cursor: 'pointer',
        border: `2px ${dashed ? 'dashed' : 'solid'} ${p.state === 'passive' || p.state === 'unknown' ? 'var(--app-border-strong, var(--app-t3))' : border}`,
        background: tint ? `color-mix(in srgb, ${tint} 55%, transparent)` : 'var(--app-panel2)',
        outline: selected ? '2px solid var(--accent)' : undefined, outlineOffset: 1,
        fontSize: 9.5, fontFamily: 'var(--font-mono, monospace)', color: 'var(--app-t1)',
      }}
    >
      {shortLabel(p.name)}
      {mark !== 'none' && (
        <span aria-hidden style={{
          position: 'absolute', bottom: 1, right: 1, width: 6, height: 6, borderRadius: 3,
          background: mark === 'cabled' ? 'var(--accent)' : 'transparent', border: mark === 'cabled' ? 'none' : '1px dashed var(--accent)',
        }} />
      )}
      {ov?.weakProtocol && <Icon name="lock" size={9} style={{ position: 'absolute', top: 1, left: 1, color: 'var(--danger)' }} aria-hidden />}
    </button>
  );
}

function PortPanel({ p, canManage, cables, posture, overlayOn, onClose }: {
  p: FacePort; canManage: boolean; cables: ReturnType<typeof useAssetCables>; posture: InterfacePosture | undefined; overlayOn: boolean; onClose: () => void;
}) {
  const [tracing, setTracing] = useState(false);
  const port: CablePort = { kind: p.kind, id: p.id, name: p.name, cableId: p.cableId, markConnected: p.markConnected };
  const cabled = !!cables.data?.get(p.id) || !!p.cableId;
  const ov = p.kind === 'interface' ? portOverlay(posture) : null;
  return (
    <div role="dialog" aria-label={`Port ${p.name}`} data-testid="port-panel"
      onKeyDown={(e) => { if (e.key === 'Escape') onClose(); }}
      style={{ marginTop: 10, border: '1px solid var(--app-border)', borderRadius: 10, padding: '10px 12px', background: 'var(--app-panel)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span className="mono" style={{ fontWeight: 700 }}>{p.name}</span>
        {p.label && <span style={{ color: 'var(--app-t3)', fontSize: 12 }}>{p.label}</span>}
        <span style={{ fontSize: 12, color: 'var(--app-t2)' }}>{FACEPLATE_KIND_LABEL[p.kind].replace(/s$/, '')} · {p.type || 'type not recorded'} · {PORT_STATE_LABEL[p.state]}</span>
        <span style={{ flex: 1 }} />
        <button type="button" className="ui-btn sm ghost" aria-label="Close port panel" onClick={onClose}><Icon name="x" size={12} /></button>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 8, fontSize: 12.5 }}>
        <span style={{ color: 'var(--app-t3)', width: 70 }}>Cable</span>
        <CableCell port={port} cables={cables} canManage={canManage} />
        {cabled && (
          <button type="button" className="ui-btn sm" data-testid="port-trace" onClick={() => setTracing(true)}>
            <Icon name="route" size={12} />Trace
          </button>
        )}
      </div>
      {ov && (
        <div data-testid="port-crypto" style={{ display: 'flex', gap: 10, marginTop: 8, fontSize: 12.5 }}>
          <span style={{ color: 'var(--app-t3)', width: 70 }}>Crypto</span>
          <span style={{ whiteSpace: 'pre-line', color: overlayOn ? 'var(--app-t1)' : 'var(--app-t2)' }}>{overlayTooltip(p.name, posture).split('\n').slice(1).join('\n')}</span>
        </div>
      )}
      {tracing && <TraceModal kind={p.kind} id={p.id} name={p.name} onClose={() => setTracing(false)} />}
    </div>
  );
}

export function Faceplate({ asset }: { asset: Asset }) {
  const perms = usePermissions();
  const canManage = perms.hasPermission(TENANT_PERMISSIONS.dcim.manage) && !asset.deleted_at && asset.asset_status !== 'archived';
  const { groups, hidden, isLoading, error, refetch } = useFaceplatePorts(asset);
  const cables = useAssetCables(asset.id);
  const [overlayOn, setOverlayOn] = useState(true);
  const posture = useInterfacePosture(asset.id, overlayOn);
  const [selected, setSelected] = useState<string | null>(null);
  const [bulk, setBulk] = useState(false);
  const faceRef = useRef<HTMLDivElement>(null);
  const byIface = useMemo(() => new Map((posture.data?.interfaces ?? []).map((p) => [p.interface_id, p])), [posture.data]);
  const all = groups.flatMap((g) => g.ports);
  const sel = all.find((p) => p.id === selected) ?? null;

  const onKey = (e: React.KeyboardEvent<HTMLButtonElement>) => {
    if (!['ArrowRight', 'ArrowLeft', 'Home', 'End'].includes(e.key)) return;
    const tiles = [...(faceRef.current?.querySelectorAll<HTMLButtonElement>('[data-testid="face-port"]') ?? [])];
    const i = tiles.indexOf(e.currentTarget);
    const next = e.key === 'ArrowRight' ? i + 1 : e.key === 'ArrowLeft' ? i - 1 : e.key === 'Home' ? 0 : tiles.length - 1;
    tiles[Math.max(0, Math.min(tiles.length - 1, next))]?.focus();
    e.preventDefault();
  };

  return (
    <section data-testid="faceplate" id="faceplate" aria-label="Faceplate" style={{ marginBottom: 18 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8, flexWrap: 'wrap' }}>
        <span style={{ fontWeight: 700, fontSize: 13.5, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
          <Icon name="ethernet-port" size={14} />Faceplate
        </span>
        <label style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 12, color: 'var(--app-t2)' }}>
          <input type="checkbox" aria-label="Crypto overlay" checked={overlayOn} onChange={(e) => setOverlayOn(e.target.checked)} />
          Crypto overlay
        </label>
        <span style={{ flex: 1 }} />
        {canManage && all.length > 0 && (
          <button type="button" className="ui-btn sm" data-testid="bulk-cables-open" onClick={() => setBulk(true)}>
            <Icon name="list" size={12} />Edit cables as table
          </button>
        )}
      </div>
      {isLoading && <PanelLoading label="Loading ports…" />}
      {error && <PanelError message={error instanceof Error ? error.message : 'Request failed'} onRetry={refetch} />}
      {!isLoading && !error && all.length === 0 && (
        <PanelEmpty icon="ethernet-port" title="No ports to draw"
          message={`Nothing has reported or declared a physical port on this asset yet.${hidden ? ` ${hidden} virtual or wireless interface${hidden === 1 ? '' : 's'} are not drawn.` : ''} Apply the device type's templates, or add interfaces and ports below.`} />
      )}
      {!isLoading && !error && all.length > 0 && (
        <div ref={faceRef} data-testid="faceplate-body" style={{ border: '1px solid var(--app-border)', borderRadius: 10, padding: '10px 12px', background: 'var(--app-panel)', overflowX: 'auto' }}>
          {groups.map((g) => (
            <div key={g.kind} role="group" aria-label={FACEPLATE_KIND_LABEL[g.kind]} data-testid={`face-group-${g.kind}`} style={{ marginBottom: 8 }}>
              <div style={{ fontSize: 11, color: 'var(--app-t3)', marginBottom: 4 }}>{FACEPLATE_KIND_LABEL[g.kind]} · {g.ports.length}</div>
              {faceplateRows(g.ports).map((row, ri) => (
                <div key={ri} data-testid="face-row" style={{ display: 'flex', gap: 4, marginBottom: 4 }}>
                  {row.map((p) => (
                    <PortTile key={p.id} p={p} mark={cableMark(p, cables.data)} cables={cables.data} posture={byIface.get(p.id)}
                      overlayOn={overlayOn} selected={p.id === selected} onPick={() => setSelected(p.id === selected ? null : p.id)} onKey={onKey} />
                  ))}
                </div>
              ))}
            </div>
          ))}
          <Legend overlayOn={overlayOn} posture={posture} hidden={hidden} />
        </div>
      )}
      {sel && <PortPanel p={sel} canManage={canManage} cables={cables} posture={byIface.get(sel.id)} overlayOn={overlayOn} onClose={() => setSelected(null)} />}
      {bulk && <BulkCableEditor asset={asset} ports={all} cables={cables.data} onClose={() => setBulk(false)} />}
    </section>
  );
}

function Swatch({ color, dashed, label }: { color: string; dashed?: boolean; label: string }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
      <span aria-hidden style={{ width: 10, height: 10, borderRadius: 2, background: dashed ? 'transparent' : color, border: dashed ? `1.5px dashed ${color}` : 'none' }} />{label}
    </span>
  );
}

function Legend({ overlayOn, posture, hidden }: { overlayOn: boolean; posture: ReturnType<typeof useInterfacePosture>; hidden: number }) {
  return (
    <div data-testid="faceplate-legend" style={{ display: 'flex', flexWrap: 'wrap', gap: 12, fontSize: 11, color: 'var(--app-t3)', marginTop: 4 }}>
      <Swatch color={PORT_STATE_COLOR.up} label="Up" />
      <Swatch color={PORT_STATE_COLOR.down} label="Down" />
      <Swatch color={PORT_STATE_COLOR.disabled} label="Disabled" />
      <Swatch color="var(--accent)" label="Cabled" />
      <Swatch color="var(--accent)" dashed label="Proposed / planned" />
      {overlayOn && (
        posture.isLoading ? <span>Crypto overlay loading…</span>
          : posture.isError ? <span data-testid="overlay-error" style={{ color: 'var(--danger-text)' }}>Couldn&rsquo;t load the crypto overlay — ports are not shown as clean.</span>
            : (
              <>
                {LEVELS.map((l) => <Swatch key={l} color={LEVEL_COLOR[l]} label={l} />)}
                <Swatch color={UNASSESSED_COLOR} label="Not assessed" />
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 3 }}><Icon name="lock" size={10} />Weak protocol</span>
                {posture.data?.top_finding && (
                  <span data-testid="asset-top-finding">Worst open finding on this asset: {posture.data.top_finding.severity} — {posture.data.top_finding.summary}</span>
                )}
              </>
            )
      )}
      {hidden > 0 && <span>{hidden} virtual or wireless interface{hidden === 1 ? '' : 's'} not drawn</span>}
    </div>
  );
}
