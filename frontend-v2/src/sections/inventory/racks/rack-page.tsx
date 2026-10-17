// The rack page (DCIM row 2.5) — `/inventory/racks/:id`. The rack's header
// (site › location, role, type, status, utilisation), its front and rear
// elevation with the crypto overlay, drag-to-place, Add device and Unrack,
// the Reservations panel, Contacts and Images, the Devices table, and the
// rack's Changes and Journal. Reached from the Racks lens, the site page's
// Racks card and an asset's Placement card ("Open rack", `?asset=` highlights
// the device).
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { PermissionGate, TENANT_PERMISSIONS, usePermissions } from '@vistasecurity/primitives/rbac';
import { RISK_BANDS } from '@vistasecurity/primitives/ratings';
import { clients } from '../../../lib/clients';
import { Icon, SectionLabel, LEVEL_COLOR } from '../../../components/ui';
import { ObjectChanges } from '../dcim/object-changes';
import { ObjectContacts } from '../dcim/object-contacts';
import { ObjectImages } from '../dcim/object-images';
import { ObjectJournal } from '../dcim/object-journal';
import { PanelEmpty, PanelError, PanelLoading } from '../dcim/substrate-states';
import { imageUrl } from '../dcim/contact-queries';
import { classLabel } from '../asset-shape';
import { AddDeviceModal } from './add-device-modal';
import { ConflictNote } from './placement-card';
import { RackElevationSvg, elevationSize, rackClassColor, type DeviceWithPosture, type PendingMove } from './rack-elevation';
import { documentVar, exportFilename, saveBlob, serializeElevation, svgToPng } from './rack-export';
import { certBadgeText, certDaysLeft, overlayState } from './rack-overlay';
import {
  ALL_RACK_KEYS, PlacementConflict, RACK_STATUSES, deletePlacement, parseUnits, placementError, placementKey, putPlacement,
  unitLabel, unitsLabel, useDeviceTypeImages, useRackElevation, useRackTypes, type ElevationReservation, type RackFace,
} from './racks-queries';

const READ = TENANT_PERMISSIONS.dcim.read;
const MANAGE = TENANT_PERMISSIONS.dcim.manage;

function Card({ children, testId }: { children: ReactNode; testId?: string }) {
  return <div data-testid={testId} style={{ border: '1px solid var(--app-border)', borderRadius: 12, background: 'var(--app-panel)', padding: 16, minWidth: 0 }}>{children}</div>;
}

function Chip({ children }: { children: ReactNode }) {
  return <span style={{ fontSize: 10.5, fontWeight: 700, color: 'var(--app-t2)', border: '1px solid var(--app-border2)', borderRadius: 40, padding: '1px 8px' }}>{children}</span>;
}

/** A used/total bar. Utilisation is a proportion, not a rating: one colour. */
export function UtilisationBar({ used, total, pct }: { used: number; total: number; pct: number | null }) {
  const width = pct == null ? 0 : Math.min(Math.max(pct, 0), 100);
  return (
    <span data-testid="rack-utilisation" style={{ display: 'inline-flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
      <span aria-hidden style={{ width: 90, height: 6, borderRadius: 4, background: 'var(--app-panel2)', overflow: 'hidden', flex: 'none' }}>
        <span style={{ display: 'block', width: `${width}%`, height: '100%', background: 'var(--accent)' }} />
      </span>
      <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t2)', whiteSpace: 'nowrap' }}>
        {pct == null ? 'not computed yet' : `${used} / ${total}U · ${pct}%`}
      </span>
    </span>
  );
}

/** The posture badge the Devices table and the legend share. */
export function PostureBadge({ device }: { device: DeviceWithPosture }) {
  const s = overlayState(device.posture);
  const days = certDaysLeft(device.posture);
  return (
    <span data-testid="device-posture" data-kind={s.kind} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11.5, color: 'var(--app-t2)' }}>
      <span style={{ width: 8, height: 8, borderRadius: 8, background: s.kind === 'unassessed' ? 'transparent' : s.color, border: `1.5px ${s.kind === 'unassessed' ? 'dashed' : 'solid'} ${s.color}`, flex: 'none' }} />
      {s.label}
      {device.posture?.weak_protocol && <Icon name="lock" size={12} style={{ color: 'var(--danger)' }} />}
      {days != null && <span title={certBadgeText(days) ?? ''} style={{ fontSize: 10.5, fontWeight: 700, color: 'var(--warn-text, var(--warn))' }}>{days < 0 ? 'cert expired' : `cert ${days}d`}</span>}
    </span>
  );
}

function OverlayLegend() {
  return (
    <div data-testid="overlay-legend" style={{ display: 'flex', flexWrap: 'wrap', gap: '6px 14px', fontSize: 11.5, color: 'var(--app-t2)', marginTop: 10 }}>
      {RISK_BANDS.map((b) => (
        <span key={b.label} style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
          <span style={{ width: 10, height: 10, borderRadius: 3, background: LEVEL_COLOR[b.label] }} />{b.label}
        </span>
      ))}
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
        <span style={{ width: 10, height: 10, borderRadius: 3, border: '1.5px dashed var(--app-t3)' }} />Not assessed
      </span>
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}><Icon name="lock" size={12} style={{ color: 'var(--danger)' }} />Weak protocol</span>
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
        <span style={{ fontSize: 9.5, fontWeight: 700, color: 'var(--app-bg, #fff)', background: 'var(--warn)', borderRadius: 7, padding: '0 5px' }}>12d</span>Certificate expiring ≤ 30 days
      </span>
    </div>
  );
}

export function RackPage() {
  const { id } = useParams();
  const [params] = useSearchParams();
  const highlight = params.get('asset');
  const navigate = useNavigate();
  const qc = useQueryClient();
  const q = useRackElevation(id);
  const images = useDeviceTypeImages(!!q.data);
  const types = useRackTypes(!!q.data);
  const perms = usePermissions();
  const canManage = perms.hasPermission(MANAGE);
  const [overlay, setOverlay] = useState(true);
  const [pending, setPending] = useState<PendingMove | null>(null);
  const [moveError, setMoveError] = useState<Error | null>(null);
  const [adding, setAdding] = useState<{ position?: number; face?: RackFace } | null>(null);
  const [tab, setTab] = useState<'changes' | 'journal'>('changes');
  const [exportError, setExportError] = useState<string | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);

  const invalidate = async (assetId?: string) => {
    if (assetId) void qc.invalidateQueries({ queryKey: placementKey(assetId) });
    await Promise.all(ALL_RACK_KEYS.map((k) => qc.invalidateQueries({ queryKey: k })));
  };

  const move = useMutation({
    mutationFn: (m: PendingMove) => putPlacement(m.assetId, { rack_id: id!, position: m.position, face: m.face }),
    onMutate: (m) => { setMoveError(null); setPending(m); },
    onSuccess: async (_d, m) => { await invalidate(m.assetId); setPending(null); },
    // A refusal: the block snaps back to where it was and the message says why.
    onError: (err) => { setPending(null); setMoveError(err instanceof Error ? err : new Error('Could not move the device')); },
  });
  const unrack = useMutation({
    mutationFn: (assetId: string) => deletePlacement(assetId),
    onSuccess: (_d, assetId) => invalidate(assetId),
  });

  // Bring a highlighted device into view once it is drawn.
  useEffect(() => {
    if (!highlight || !q.data) return;
    const el = svgRef.current?.querySelector(`[data-asset="${CSS.escape(highlight)}"]`) as (Element & { scrollIntoView?: (o: ScrollIntoViewOptions) => void }) | null;
    el?.scrollIntoView?.({ block: 'center', behavior: 'smooth' });
  }, [highlight, q.data]);

  const resolveImage = useMemo(() => {
    const map = images.data;
    return (ref: string | null | undefined) => {
      const att = ref ? map?.get(ref) : undefined;
      return att ? imageUrl(att) : null;
    };
  }, [images.data]);

  const back = (
    <Link to="/inventory?lens=racks" style={{ display: 'inline-flex', alignItems: 'center', gap: 3, fontSize: 12.5, color: 'var(--app-t3)', textDecoration: 'none' }}>
      <Icon name="chevron-left" size={13} />Racks
    </Link>
  );
  if (q.isLoading) return <div style={{ padding: '22px 26px' }}>{back}<div style={{ marginTop: 14 }}><PanelLoading label="Loading rack…" /></div></div>;
  if (q.isError || !q.data) {
    const notFound = q.error instanceof Error && q.error.message === 'not-found';
    return (
      <div style={{ padding: '22px 26px' }}>
        {back}
        <div style={{ marginTop: 14 }}>
          {notFound
            ? <PanelEmpty icon="search-x" title="Rack not found" message="This rack no longer exists. It may have been deleted; its devices stay in their site." />
            : <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />}
        </div>
      </div>
    );
  }

  const el = q.data;
  const rack = el.rack;
  const devices = el.devices as DeviceWithPosture[];
  const typeName = rack.rack_type_id ? types.data?.find((t) => t.id === rack.rack_type_id)?.model : null;
  const util = el.utilization;
  const statusLabel = RACK_STATUSES.find((s) => s.value === rack.operational_status)?.label ?? rack.operational_status;
  const sorted = [...devices].sort((a, b) => b.position - a.position || a.face.localeCompare(b.face));
  const conflict = moveError instanceof PlacementConflict ? moveError : null;

  const openAsset = (d: DeviceWithPosture) => {
    // With the overlay on, a block with open findings opens the asset's
    // findings (its risk view); otherwise its overview.
    const risk = overlay && (d.posture?.open_findings ?? 0) > 0;
    void navigate(`/inventory/assets/${d.asset_id}${risk ? '/findings' : ''}`);
  };

  const doExport = async (kind: 'svg' | 'png') => {
    setExportError(null);
    const svg = svgRef.current;
    if (!svg) return;
    try {
      const text = serializeElevation(svg, documentVar);
      if (kind === 'svg') {
        saveBlob(exportFilename(rack.name, 'svg'), new Blob([text], { type: 'image/svg+xml' }));
      } else {
        const { width, height } = elevationSize(rack);
        saveBlob(exportFilename(rack.name, 'png'), await svgToPng(text, width, height));
      }
    } catch (e) {
      setExportError(e instanceof Error ? e.message : 'The export failed');
    }
  };

  return (
    <div data-testid="rack-page" style={{ padding: '14px 26px 40px', display: 'flex', flexDirection: 'column', gap: 16, overflowY: 'auto', height: '100%' }}>
      {back}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 16, flexWrap: 'wrap' }}>
        <div style={{ minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
            <Icon name="server" size={14} style={{ color: 'var(--app-t3)' }} />
            <span className="eyebrow-app" data-testid="rack-breadcrumb">
              Rack · {rack.site ? <Link to={`/inventory/sites/${rack.site.id}`}>{rack.site.name}</Link> : '—'}
              {rack.location ? ` › ${locationTrail(rack.location)}` : ''}
            </span>
            {rack.role && <Chip>{rack.role.name}</Chip>}
            {typeName && <Chip>{typeName}</Chip>}
            <Chip>{statusLabel}</Chip>
          </div>
          <h1 style={{ margin: '3px 0 4px', fontFamily: 'var(--font-head)', fontSize: 19, fontWeight: 700, color: 'var(--app-t1)' }}>
            {rack.name}{rack.facility_id ? <span style={{ fontWeight: 400, fontSize: 14, color: 'var(--app-t3)' }}> · {rack.facility_id}</span> : null}
          </h1>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap', fontSize: 12, color: 'var(--app-t3)' }}>
            <UtilisationBar used={util?.used_units ?? 0} total={util?.total_units ?? rack.u_height} pct={util ? util.utilization : null} />
            <span>{rack.u_height}U · {rack.width}″{rack.desc_units ? ' · units numbered top-down' : ''}</span>
            <span>{devices.length} {devices.length === 1 ? 'device' : 'devices'}{el.non_racked ? ` · ${el.non_racked} without a position` : ''}</span>
          </div>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <label data-testid="overlay-toggle" style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12.5, color: 'var(--app-t2)', cursor: 'pointer' }}>
            <input type="checkbox" checked={overlay} onChange={(e) => setOverlay(e.target.checked)} aria-label="Crypto overlay" />
            <Icon name="shield-alert" size={13} />Crypto overlay
          </label>
          <button type="button" className="ui-btn sm" data-testid="export-png" onClick={() => { void doExport('png'); }}><Icon name="download" size={13} />PNG</button>
          <button type="button" className="ui-btn sm" data-testid="export-svg" onClick={() => { void doExport('svg'); }}><Icon name="download" size={13} />SVG</button>
          <PermissionGate permission={MANAGE}>
            <button type="button" className="ui-btn sm accent" data-testid="add-device" onClick={() => setAdding({})}><Icon name="plus" size={13} />Add device</button>
          </PermissionGate>
        </div>
      </div>
      {exportError && <div role="alert" style={{ fontSize: 12, color: 'var(--danger-text)' }}>{exportError}</div>}

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(260px, 320px)', gap: 14, alignItems: 'start' }} className="rack-page-grid">
        <Card testId="rack-elevation-card">
          {moveError && (conflict
            ? <div data-testid="move-refused"><ConflictNote conflict={conflict} /></div>
            : <div data-testid="move-refused" role="alert" style={{ fontSize: 12.5, color: 'var(--danger-text)', marginBottom: 8 }}>{moveError.message}</div>)}
          {devices.length === 0 && (
            <div data-testid="rack-empty" style={{ fontSize: 12.5, color: 'var(--app-t3)', marginBottom: 10 }}>
              No devices in this rack yet. {canManage ? 'Click an empty unit or use Add device to place one.' : 'Devices are placed from their Placement card.'}
            </div>
          )}
          <div style={{ overflowX: 'auto' }}>
            <RackElevationSvg svgRef={svgRef} rack={rack} devices={devices} reservations={el.reservations} overlay={overlay}
              highlight={highlight} canManage={canManage} imageUrl={resolveImage} pending={pending}
              onMove={(d, position, face) => move.mutate({ assetId: d.asset_id, position, face })}
              onOpen={openAsset}
              onEmptyUnit={canManage ? (unit, face) => setAdding({ position: unit, face }) : undefined} />
          </div>
          {overlay && <OverlayLegend />}
          {canManage && <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 8 }}>Drag a device to move it, across to the other face to turn it; arrow keys move a focused device by half a unit.</div>}
        </Card>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 14, minWidth: 0 }}>
          <ReservationsPanel rackId={rack.id} rackName={rack.name} reservations={el.reservations} />
          <Card>
            <PermissionGate permission={READ}>
              <SectionLabel icon="users">Contacts</SectionLabel>
              <div data-testid="rack-contacts"><ObjectContacts kind="rack" id={rack.id} /></div>
              <SectionLabel icon="image-plus">Images</SectionLabel>
              <div data-testid="rack-images"><ObjectImages kind="rack" id={rack.id} /></div>
            </PermissionGate>
          </Card>
        </div>
      </div>

      <Card testId="rack-devices">
        <SectionLabel icon="server">Devices</SectionLabel>
        {sorted.length === 0 ? (
          <div style={{ fontSize: 12.5, color: 'var(--app-t3)' }}>Nothing is placed in this rack.</div>
        ) : (
          <div role="table" style={{ fontSize: 12.5 }}>
            <div role="row" style={{ display: 'grid', gridTemplateColumns: DEV_COLS, gap: 10, padding: '6px 0', fontSize: 11, fontWeight: 600, color: 'var(--app-t3)', borderBottom: '1px solid var(--app-border)' }}>
              <span>U</span><span>Face</span><span>Asset</span><span>Device type</span><span>Serial</span><span>Posture</span><span />
            </div>
            {sorted.map((d) => (
              <div key={d.asset_id} role="row" data-testid="rack-device-row" style={{ display: 'grid', gridTemplateColumns: DEV_COLS, gap: 10, alignItems: 'center', padding: '7px 0', borderBottom: '1px solid var(--app-border)', background: highlight === d.asset_id ? 'color-mix(in srgb, var(--accent) 8%, transparent)' : undefined }}>
                <span className="mono">{unitLabel(d.position)}{d.u_height !== 1 ? <span style={{ color: 'var(--app-t3)' }}> · {d.u_height}U</span> : null}</span>
                <span style={{ color: 'var(--app-t2)' }}>{d.face === 'front' ? 'Front' : 'Rear'}{d.is_full_depth ? <span style={{ color: 'var(--app-t3)' }}> · full</span> : null}</span>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
                  <span style={{ width: 8, height: 8, borderRadius: 2, background: rackClassColor(d.class_key), flex: 'none' }} />
                  <Link to={`/inventory/assets/${d.asset_id}`} style={{ fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.name}</Link>
                </span>
                <span style={{ color: 'var(--app-t2)' }}>{d.device_type?.model ?? <span style={{ color: 'var(--app-t3)' }}>{classLabel(d.class_key) || '—'}</span>}</span>
                <span className="mono" style={{ color: 'var(--app-t2)' }}>{d.serial?.trim().length ? d.serial : '—'}</span>
                <PostureBadge device={d} />
                <span style={{ textAlign: 'right' }}>
                  <PermissionGate permission={MANAGE}>
                    <button type="button" className="ui-btn sm ghost" data-testid="unrack" disabled={unrack.isPending} onClick={() => unrack.mutate(d.asset_id)}>Unrack</button>
                  </PermissionGate>
                </span>
              </div>
            ))}
          </div>
        )}
        {unrack.isError && <div role="alert" style={{ fontSize: 12, color: 'var(--danger-text)', marginTop: 6 }}>{unrack.error.message}</div>}
      </Card>

      <Card>
        <div role="tablist" style={{ display: 'flex', gap: 4, borderBottom: '1px solid var(--app-border)' }}>
          {(['changes', 'journal'] as const).map((t) => (
            <button key={t} type="button" role="tab" aria-selected={tab === t} className="ui-btn ghost sm"
              style={{ borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent', borderRadius: 0 }} onClick={() => setTab(t)}>
              {t === 'changes' ? 'Changes' : 'Journal'}
            </button>
          ))}
        </div>
        <div style={{ marginTop: 8 }}>
          {tab === 'changes' ? <ObjectChanges kind="rack" id={rack.id} /> : <ObjectJournal kind="rack" id={rack.id} />}
        </div>
      </Card>

      {adding && rack.site && (
        <AddDeviceModal rack={rack} siteId={rack.site.id} initial={adding} onClose={() => setAdding(null)} />
      )}
    </div>
  );
}

/** "Hall 2 › Cage 7" from the location's "Site / Hall 2 / Cage 7" path. */
function locationTrail(loc: { name: string; path?: string }): string {
  const parts = (loc.path ?? '').split(' / ').slice(1);
  return parts.length ? parts.join(' › ') : loc.name;
}

const DEV_COLS = '70px 70px minmax(0,1.4fr) minmax(0,1fr) minmax(0,0.8fr) minmax(0,1.3fr) 80px';

function ReservationsPanel({ rackId, rackName, reservations }: { rackId: string; rackName: string; reservations: readonly ElevationReservation[] }) {
  const qc = useQueryClient();
  const [units, setUnits] = useState('');
  const [description, setDescription] = useState('');
  const parsed = parseUnits(units);
  const invalidate = () => { for (const k of ALL_RACK_KEYS) void qc.invalidateQueries({ queryKey: k }); };
  const add = useMutation({
    mutationFn: async () => {
      const { error } = await clients.inventory.POST('/dcim/rack-reservations', { body: { rack_id: rackId, units: parsed ?? [], description: description.trim() } });
      if (error) throw placementError(error, 'Could not reserve those units');
    },
    onSuccess: () => { invalidate(); setUnits(''); setDescription(''); },
  });
  const remove = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await clients.inventory.DELETE('/dcim/rack-reservations/{id}', { params: { path: { id } } });
      if (error) throw new Error('Could not remove the reservation');
    },
    onSuccess: invalidate,
  });
  const conflict = add.error instanceof PlacementConflict ? add.error : null;
  return (
    <Card testId="rack-reservations">
      <SectionLabel icon="calendar-clock">Reservations</SectionLabel>
      {reservations.length === 0
        ? <div data-testid="reservations-empty" style={{ fontSize: 12.5, color: 'var(--app-t3)' }}>No units of {rackName} are reserved.</div>
        : reservations.map((r) => (
          <div key={r.id} data-testid="reservation-row" style={{ display: 'flex', alignItems: 'flex-start', gap: 8, padding: '6px 0', borderBottom: '1px solid var(--app-border)', fontSize: 12.5 }}>
            <span className="mono" style={{ flex: 'none', color: 'var(--warn-text, var(--app-t1))', fontWeight: 600 }}>{unitsLabel(r.units)}</span>
            <span style={{ color: 'var(--app-t2)', flex: 1, minWidth: 0 }}>{r.description}</span>
            <PermissionGate permission={MANAGE}>
              <button type="button" className="ui-btn sm ghost" aria-label={`Release ${unitsLabel(r.units)}`} disabled={remove.isPending} onClick={() => remove.mutate(r.id)}><Icon name="x" size={12} /></button>
            </PermissionGate>
          </div>
        ))}
      <PermissionGate permission={MANAGE}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 10 }}>
          <input className="ui-input" aria-label="Units to reserve" placeholder="Units, e.g. 1-2, 7" value={units} onChange={(e) => setUnits(e.target.value)} style={{ fontSize: 12.5 }} />
          <input className="ui-input" aria-label="Reservation description" placeholder="What the units are held for" value={description} onChange={(e) => setDescription(e.target.value)} style={{ fontSize: 12.5 }} />
          <button type="button" className="ui-btn sm" data-testid="reserve-units" disabled={!parsed || !description.trim() || add.isPending} onClick={() => add.mutate()}>
            <Icon name="plus" size={12} />Reserve
          </button>
          {conflict ? <ConflictNote conflict={conflict} /> : add.isError ? <div role="alert" style={{ fontSize: 12, color: 'var(--danger-text)' }}>{add.error.message}</div> : null}
        </div>
      </PermissionGate>
    </Card>
  );
}
