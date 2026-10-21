// The site page's Floor plan tab (DCIM gap 9). Pick one of the site's
// locations; its plan is drawn as a grid in its unit (m or ft), each rack on
// it a rectangle the size of its outer footprint, turned the way its front
// faces (the thick edge), labelled by name and coloured by unit utilisation
// or by its power budget (the Facilities capacity colour, 80 % / 95 %). A
// click opens the rack page. Behind dcim.manage: drag a rack to move it, drag
// one from the "Unplaced racks" tray onto the plan (or press Place), arrow keys
// nudge the focused rack (Shift: a whole unit), R turns it; a place that runs
// past the edge is shown in red and not written. A location without a plan
// offers "Set up a plan" to a manager.
import { useEffect, useMemo, useRef, useState, type CSSProperties, type KeyboardEvent, type PointerEvent as ReactPointerEvent, type ReactElement } from 'react';
import { Link, useNavigate } from 'react-router';
import { useQueryClient } from '@tanstack/react-query';
import { PermissionGate, TENANT_PERMISSIONS, usePermissions } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../../components/ui';
import { PanelEmpty, PanelError, PanelLoading } from '../dcim/substrate-states';
import { CAPACITY_CRITICAL, CAPACITY_WARN, fillColor } from '../../dashboard/facilities-dashboard-metrics';
import { RACKS_KEY } from '../racks/racks-queries';
import { LOCATIONS_KEY, flattenNodes, useLocations, type Location } from './sites-queries';
import {
  clampToPlan, fitsPlan, floorExtent, fmtSize, gridStep, nextRotation, nudge, planScale, rackColour, round2, snap,
  type FloorColourMode, type FloorPlanBox, type FloorRotation,
} from './floor-plan-geometry';
import { patchRackFloor, putLocationPlan, useLocationFloorPlan, type FloorPlanRack, type FloorPlanUnit, type LocationFloorPlan } from './floor-plan-queries';

const PAD = 28;

const hasPlan = (l: Pick<Location, 'floor_plan_width' | 'floor_plan_depth' | 'floor_plan_unit'>) =>
  l.floor_plan_width != null && l.floor_plan_depth != null && l.floor_plan_unit != null;

/** The tab. */
export function SiteFloorPlan({ siteId }: { siteId: string }) {
  const locations = useLocations(siteId, !!siteId);
  const rows = useMemo(() => flattenNodes(locations.data ?? []), [locations.data]);
  const [picked, setPicked] = useState<string>('');
  const locId = picked || (rows.find((r) => hasPlan(r.node)) ?? rows[0])?.node.id || '';

  if (locations.isLoading) return <PanelLoading label="Loading locations…" />;
  if (locations.isError) return <PanelError message="Couldn't load the site's locations." onRetry={() => { void locations.refetch(); }} />;
  if (rows.length === 0) {
    return <PanelEmpty icon="map" title="No locations yet" message="A floor plan belongs to a location: a hall, a room or a cage. Add one from Infrastructure → Sites & locations, then lay out its racks here." />;
  }
  return (
    <div data-testid="site-floor-plan" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12.5, color: 'var(--app-t2)' }}>
        Location
        <select className="ui-input" data-testid="floor-plan-location" value={locId} onChange={(e) => setPicked(e.target.value)} style={{ minWidth: 220 }}>
          {rows.map(({ node, depth }) => (
            <option key={node.id} value={node.id}>{`${'  '.repeat(depth)}${node.name}${hasPlan(node) ? '' : ' (no plan)'}`}</option>
          ))}
        </select>
      </label>
      {locId && <LocationFloorPlanView key={locId} locationId={locId} />}
    </div>
  );
}

function LocationFloorPlanView({ locationId }: { locationId: string }) {
  const fp = useLocationFloorPlan(locationId);
  const canManage = usePermissions().hasPermission(TENANT_PERMISSIONS.dcim.manage);
  const [editing, setEditing] = useState(false);

  if (fp.isLoading) return <PanelLoading label="Loading the floor plan…" />;
  if (fp.isError || !fp.data) return <PanelError message="Couldn't load the floor plan." onRetry={() => { void fp.refetch(); }} />;
  const data = fp.data;
  const loc = data.location;
  const plan = loc.floor_plan_width != null && loc.floor_plan_depth != null && loc.floor_plan_unit != null
    ? { width: loc.floor_plan_width, depth: loc.floor_plan_depth, unit: loc.floor_plan_unit } : null;

  if (!plan || editing) {
    return (
      <div data-testid="floor-plan-none" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {!plan && (
          <div style={{ fontSize: 12.5, color: 'var(--app-t3)' }}>
            {loc.name} has no floor plan yet{data.racks.length ? ` · ${data.racks.length} rack${data.racks.length === 1 ? '' : 's'} in it` : ''}.
            {!canManage && ' A person who manages DCIM records can set one up.'}
          </div>
        )}
        <PermissionGate permission={TENANT_PERMISSIONS.dcim.manage}>
          <PlanSizeForm locationId={locationId} initial={plan} onDone={() => setEditing(false)} onCancel={plan ? () => setEditing(false) : undefined} />
        </PermissionGate>
      </div>
    );
  }
  return <FloorPlanBoard data={data} plan={plan} canManage={canManage} onEditSize={() => setEditing(true)} />;
}

function PlanSizeForm({ locationId, initial, onDone, onCancel }: {
  locationId: string; initial: { width: number; depth: number; unit: FloorPlanUnit } | null; onDone: () => void; onCancel?: () => void;
}) {
  const qc = useQueryClient();
  const [width, setWidth] = useState(initial ? String(initial.width) : '');
  const [depth, setDepth] = useState(initial ? String(initial.depth) : '');
  const [unit, setUnit] = useState<FloorPlanUnit>(initial?.unit ?? 'm');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const w = Number(width); const d = Number(depth);
  const valid = width !== '' && depth !== '' && w > 0 && d > 0 && w <= 10000 && d <= 10000;

  const save = async () => {
    setBusy(true); setErr(null);
    try {
      await putLocationPlan(locationId, { width: w, depth: d, unit });
      await Promise.all([qc.invalidateQueries({ queryKey: RACKS_KEY }), qc.invalidateQueries({ queryKey: LOCATIONS_KEY })]);
      onDone();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Could not save the floor plan');
    } finally {
      setBusy(false);
    }
  };
  const input: CSSProperties = { width: 90 };
  return (
    <form data-testid="floor-plan-size-form" onSubmit={(e) => { e.preventDefault(); if (valid && !busy) void save(); }}
      style={{ display: 'flex', alignItems: 'flex-end', gap: 10, flexWrap: 'wrap', border: '1px solid var(--app-border)', borderRadius: 10, padding: 12 }}>
      <div style={{ width: '100%', fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>{initial ? 'Floor plan size' : 'Set up a plan'}</div>
      <label style={{ display: 'flex', flexDirection: 'column', gap: 3, fontSize: 11.5, color: 'var(--app-t3)' }}>Width
        <input className="ui-input" aria-label="Plan width" type="number" min="0" step="0.1" value={width} onChange={(e) => setWidth(e.target.value)} style={input} />
      </label>
      <label style={{ display: 'flex', flexDirection: 'column', gap: 3, fontSize: 11.5, color: 'var(--app-t3)' }}>Depth
        <input className="ui-input" aria-label="Plan depth" type="number" min="0" step="0.1" value={depth} onChange={(e) => setDepth(e.target.value)} style={input} />
      </label>
      <label style={{ display: 'flex', flexDirection: 'column', gap: 3, fontSize: 11.5, color: 'var(--app-t3)' }}>Unit
        <select className="ui-input" aria-label="Plan unit" value={unit} onChange={(e) => setUnit(e.target.value as FloorPlanUnit)}>
          <option value="m">metres</option>
          <option value="ft">feet</option>
        </select>
      </label>
      <button type="submit" className="ui-btn accent sm" disabled={!valid || busy}>{busy ? 'Saving…' : initial ? 'Save size' : 'Create plan'}</button>
      {onCancel && <button type="button" className="ui-btn ghost sm" onClick={onCancel} disabled={busy}>Cancel</button>}
      {err && <div role="alert" style={{ width: '100%', fontSize: 12, color: 'var(--danger-text)' }}>{err}</div>}
    </form>
  );
}

type Place = { x: number; y: number; rotation: FloorRotation };
interface DragState {
  rack: FloorPlanRack; fromTray: boolean; startX: number; startY: number; orig: Place; moved: boolean; target: Place | null;
}

const placeOf = (r: FloorPlanRack): Place | null =>
  r.floor_x != null && r.floor_y != null ? { x: r.floor_x, y: r.floor_y, rotation: r.floor_rotation ?? 0 } : null;

function FloorPlanBoard({ data, plan, canManage, onEditSize }: {
  data: LocationFloorPlan; plan: FloorPlanBox & { unit: FloorPlanUnit }; canManage: boolean; onEditSize: () => void;
}) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [mode, setMode] = useState<FloorColourMode>('utilization');
  const [pending, setPending] = useState<Record<string, Place | null>>({});
  const [message, setMessage] = useState<{ tone: 'error' | 'info'; text: string } | null>(null);
  const [drag, setDragState] = useState<DragState | null>(null);
  const dragRef = useRef<DragState | null>(null);
  const setDrag = (d: DragState | null) => { dragRef.current = d; setDragState(d); };
  const svgRef = useRef<SVGSVGElement | null>(null);

  const scale = planScale(plan);
  const W = plan.width * scale + 2 * PAD;
  const H = plan.depth * scale + 2 * PAD;
  const fw = (r: FloorPlanRack) => r.footprint_width ?? 0.6;
  const fd = (r: FloorPlanRack) => r.footprint_depth ?? 1;

  const racks = data.racks.map((r) => {
    if (!(r.id in pending)) return r;
    const p = pending[r.id];
    return { ...r, floor_x: p ? p.x : null, floor_y: p ? p.y : null, floor_rotation: p ? p.rotation : null };
  });
  const placed = racks.filter((r) => placeOf(r));
  const unplaced = racks.filter((r) => !placeOf(r));
  const anyDefault = racks.some((r) => r.footprint_default);

  const write = async (r: FloorPlanRack, place: Place | null) => {
    setPending((p) => ({ ...p, [r.id]: place }));
    setMessage(null);
    try {
      await patchRackFloor(r.id, place ? { floor_x: place.x, floor_y: place.y, floor_rotation: place.rotation } : null);
      await qc.invalidateQueries({ queryKey: RACKS_KEY });
      setMessage({ tone: 'info', text: place ? `${r.name} placed at ${place.x}, ${place.y} ${plan.unit}.` : `${r.name} taken off the plan.` });
    } catch (e) {
      setMessage({ tone: 'error', text: e instanceof Error ? e.message : 'Could not move the rack' });
    } finally {
      setPending((p) => { const n = { ...p }; delete n[r.id]; return n; });
    }
  };

  /** Writes a place when it fits; says why not when it does not. */
  const tryPlace = (r: FloorPlanRack, place: Place) => {
    if (!fitsPlan(plan, place.x, place.y, fw(r), fd(r), place.rotation)) {
      setMessage({ tone: 'error', text: `${r.name} would run past the edge of the plan there.` });
      return;
    }
    void write(r, place);
  };

  const toPlan = (clientX: number, clientY: number) => {
    const rect = svgRef.current?.getBoundingClientRect();
    const sx = rect && rect.width ? W / rect.width : 1;
    const sy = rect && rect.height ? H / rect.height : 1;
    const px = (clientX - (rect?.left ?? 0)) * sx;
    const py = (clientY - (rect?.top ?? 0)) * sy;
    return { x: (px - PAD) / scale, y: (py - PAD) / scale };
  };

  useEffect(() => {
    if (!drag) return;
    const move = (e: PointerEvent | MouseEvent) => {
      const cur = dragRef.current;
      if (!cur) return;
      const p = toPlan(e.clientX, e.clientY);
      const moved = cur.moved || Math.abs(p.x - cur.startX) + Math.abs(p.y - cur.startY) > 3 / scale;
      const target: Place = cur.fromTray
        ? { x: snap(p.x), y: snap(p.y), rotation: 0 }
        : { x: snap(cur.orig.x + p.x - cur.startX), y: snap(cur.orig.y + p.y - cur.startY), rotation: cur.orig.rotation };
      // A reader's press never becomes a move: no ghost, no target.
      setDrag({ ...cur, moved, target: moved && canManage ? target : null });
    };
    const up = () => {
      const cur = dragRef.current;
      setDrag(null);
      if (!cur) return;
      if (!cur.moved) {
        if (!cur.fromTray) void navigate(`/inventory/racks/${cur.rack.id}`);
        return;
      }
      if (!canManage) return;
      if (cur.target && (cur.fromTray || cur.target.x !== cur.orig.x || cur.target.y !== cur.orig.y)) tryPlace(cur.rack, cur.target);
    };
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', up);
    return () => { window.removeEventListener('pointermove', move); window.removeEventListener('pointerup', up); };
    // toPlan and tryPlace read the current plan; drag identity is what (re)binds the listeners.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [drag !== null, plan.width, plan.depth, scale, canManage]);

  const startDrag = (e: ReactPointerEvent, r: FloorPlanRack, fromTray: boolean) => {
    if (e.button !== undefined && e.button !== 0) return;
    const p = toPlan(e.clientX, e.clientY);
    const orig = placeOf(r) ?? { x: p.x, y: p.y, rotation: 0 };
    if (canManage) e.preventDefault();
    // A reader's press is only ever a click: it never becomes a move.
    if (!canManage && fromTray) return;
    setDrag({ rack: r, fromTray, startX: p.x, startY: p.y, orig, moved: false, target: null });
  };

  const onRackKey = (e: KeyboardEvent, r: FloorPlanRack) => {
    const cur = placeOf(r);
    if (!cur) return;
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); void navigate(`/inventory/racks/${r.id}`); return; }
    if (!canManage) return;
    if (e.key === 'r' || e.key === 'R') { e.preventDefault(); tryPlace(r, { ...cur, rotation: nextRotation(cur.rotation) }); return; }
    const n = nudge(e.key, e.shiftKey);
    if (!n) return;
    e.preventDefault();
    tryPlace(r, { ...cur, x: round2(cur.x + n.dx), y: round2(cur.y + n.dy) });
  };

  const placeFromTray = (r: FloorPlanRack) => {
    const c = clampToPlan(plan, plan.width / 2, plan.depth / 2, fw(r), fd(r), 0);
    tryPlace(r, { x: c.x, y: c.y, rotation: 0 });
  };

  const step = gridStep(plan);
  const grid: ReactElement[] = [];
  for (let gx = 0; gx <= plan.width + 1e-9; gx += step) {
    grid.push(<line key={`x${gx}`} x1={PAD + gx * scale} y1={PAD} x2={PAD + gx * scale} y2={PAD + plan.depth * scale} stroke="var(--app-border)" strokeWidth="1" />);
  }
  for (let gy = 0; gy <= plan.depth + 1e-9; gy += step) {
    grid.push(<line key={`y${gy}`} x1={PAD} y1={PAD + gy * scale} x2={PAD + plan.width * scale} y2={PAD + gy * scale} stroke="var(--app-border)" strokeWidth="1" />);
  }

  const ghost = drag?.moved && drag.target ? drag.target : null;
  const ghostFits = ghost && drag ? fitsPlan(plan, ghost.x, ghost.y, fw(drag.rack), fd(drag.rack), ghost.rotation) : true;

  return (
    <div data-testid="floor-plan-board" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <span className="mono" style={{ fontSize: 12, color: 'var(--app-t3)' }}>{fmtSize(plan.width, plan.depth, plan.unit)}</span>
        <div role="group" aria-label="Colour racks by" style={{ display: 'flex', gap: 4, marginLeft: 8 }}>
          {(['utilization', 'power'] as const).map((m) => (
            <button key={m} type="button" className={`ui-btn sm${mode === m ? ' accent' : ' ghost'}`} aria-pressed={mode === m} onClick={() => setMode(m)}>
              <Icon name={m === 'utilization' ? 'gauge' : 'zap'} size={12} />{m === 'utilization' ? 'Utilisation' : 'Power'}
            </button>
          ))}
        </div>
        {canManage && <button type="button" className="ui-btn ghost sm" style={{ marginLeft: 'auto' }} onClick={onEditSize}><Icon name="ruler" size={12} />Edit plan size</button>}
      </div>

      <div style={{ overflowX: 'auto' }}>
        <svg ref={svgRef} data-testid="floor-plan-canvas" viewBox={`0 0 ${W} ${H}`} width={W} height={H} role="group"
          aria-label={`Floor plan of ${data.location.name}, ${fmtSize(plan.width, plan.depth, plan.unit)}`}
          style={{ maxWidth: '100%', height: 'auto', touchAction: drag ? 'none' : undefined, userSelect: 'none', fontFamily: 'var(--font-body, system-ui, sans-serif)' }}>
          <rect x={PAD} y={PAD} width={plan.width * scale} height={plan.depth * scale} fill="var(--app-panel2, var(--app-panel))" stroke="var(--app-border2, var(--app-border))" strokeWidth="1.5" />
          {grid}
          <text x={PAD} y={PAD - 8} fontSize="10.5" fill="var(--app-t3)">0</text>
          <text x={PAD + plan.width * scale} y={PAD - 8} fontSize="10.5" textAnchor="end" fill="var(--app-t3)">{round2(plan.width)} {plan.unit}</text>
          <text x={PAD - 6} y={PAD + plan.depth * scale} fontSize="10.5" textAnchor="end" fill="var(--app-t3)">{round2(plan.depth)}</text>
          {placed.map((r) => {
            const p = placeOf(r)!;
            const dragging = drag?.rack.id === r.id && drag.moved;
            return (
              <RackShape key={r.id} rack={r} place={p} scale={scale} mode={mode} canManage={canManage} dim={dragging || r.id in pending}
                onPointerDown={(e) => startDrag(e, r, false)} onKeyDown={(e) => onRackKey(e, r)} />
            );
          })}
          {ghost && drag && (() => {
            const { ex, ey } = floorExtent(fw(drag.rack), fd(drag.rack), ghost.rotation);
            return (
              <g data-testid="floor-plan-ghost" data-fits={ghostFits ? 'true' : 'false'} pointerEvents="none">
                <rect x={PAD + (ghost.x - ex / 2) * scale} y={PAD + (ghost.y - ey / 2) * scale} width={ex * scale} height={ey * scale}
                  fill="none" stroke={ghostFits ? 'var(--accent)' : 'var(--danger-text)'} strokeWidth="2" strokeDasharray="5 3" />
                <text x={PAD + ghost.x * scale} y={PAD + (ghost.y - ey / 2) * scale - 5} fontSize="11" fontWeight="700" textAnchor="middle"
                  fill={ghostFits ? 'var(--accent)' : 'var(--danger-text)'}>
                  {ghostFits ? `${ghost.x}, ${ghost.y}` : 'Outside the plan'}
                </text>
              </g>
            );
          })()}
        </svg>
      </div>

      <div aria-live="polite" style={{ minHeight: 16 }}>
        {message && (
          <div role={message.tone === 'error' ? 'alert' : 'status'} data-testid="floor-plan-message"
            style={{ fontSize: 12, color: message.tone === 'error' ? 'var(--danger-text)' : 'var(--app-t2)' }}>{message.text}</div>
        )}
      </div>

      <Legend mode={mode} />
      {anyDefault && (
        <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>
          Racks marked * have no recorded outer width or depth; they are drawn at the default {data.default_footprint.width} × {data.default_footprint.depth} {data.default_footprint.unit}.
        </div>
      )}
      {canManage && placed.length > 0 && (
        <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>Drag a rack to move it. With a rack focused, arrow keys nudge it ({plan.unit === 'm' ? '10 cm' : '0.1 ft'}, Shift for a whole {plan.unit === 'm' ? 'metre' : 'foot'}) and R turns it.</div>
      )}

      <div data-testid="floor-plan-tray" style={{ border: '1px solid var(--app-border)', borderRadius: 10, padding: 10 }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--app-t2)', marginBottom: 6 }}>Unplaced racks{unplaced.length ? ` · ${unplaced.length}` : ''}</div>
        {unplaced.length === 0
          ? <div style={{ fontSize: 12, color: 'var(--app-t3)' }}>{racks.length === 0
            ? 'No racks in this location yet. Give a rack this location from its page or from Infrastructure → Racks.'
            : 'Every rack in this location is on the plan.'}</div>
          : unplaced.map((r) => (
            <div key={r.id} data-testid="floor-plan-unplaced" style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 0', fontSize: 12.5 }}>
              <span onPointerDown={(e) => startDrag(e, r, true)} style={{ cursor: canManage ? 'grab' : 'default', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                <Icon name="server" size={12} style={{ color: 'var(--app-t3)' }} />
                <Link to={`/inventory/racks/${r.id}`} style={{ fontWeight: 600, color: 'var(--app-t1)', textDecoration: 'none' }}>{r.name}{r.footprint_default ? ' *' : ''}</Link>
              </span>
              <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>
                {r.footprint_width != null && r.footprint_depth != null ? fmtSize(r.footprint_width, r.footprint_depth, plan.unit) : ''}
              </span>
              {canManage && <button type="button" className="ui-btn ghost sm" style={{ marginLeft: 'auto' }} onClick={() => placeFromTray(r)}>Place</button>}
            </div>
          ))}
      </div>

      {canManage && placed.length > 0 && (
        <div data-testid="floor-plan-placed" style={{ border: '1px solid var(--app-border)', borderRadius: 10, padding: 10 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--app-t2)', marginBottom: 6 }}>On this plan · {placed.length}</div>
          {placed.map((r) => {
            const p = placeOf(r)!;
            return (
              <div key={r.id} data-testid="floor-plan-placed-row" style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '3px 0', fontSize: 12.5 }}>
                <Link to={`/inventory/racks/${r.id}`} style={{ fontWeight: 600, color: 'var(--app-t1)', textDecoration: 'none' }}>{r.name}</Link>
                <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>{p.x}, {p.y} {plan.unit} · {p.rotation}°</span>
                <button type="button" className="ui-btn ghost sm" style={{ marginLeft: 'auto' }} aria-label={`Turn ${r.name}`}
                  onClick={() => tryPlace(r, { ...p, rotation: nextRotation(p.rotation) })}><Icon name="refresh-cw" size={12} />Turn</button>
                <button type="button" className="ui-btn ghost sm" aria-label={`Take ${r.name} off the plan`} onClick={() => { void write(r, null); }}>Take off</button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function RackShape({ rack: r, place, scale, mode, canManage, dim, onPointerDown, onKeyDown }: {
  rack: FloorPlanRack; place: Place; scale: number; mode: FloorColourMode; canManage: boolean; dim: boolean;
  onPointerDown: (e: ReactPointerEvent) => void; onKeyDown: (e: KeyboardEvent) => void;
}) {
  const w = (r.footprint_width ?? 0.6) * scale;
  const d = (r.footprint_depth ?? 1) * scale;
  const cx = PAD + place.x * scale;
  const cy = PAD + place.y * scale;
  const c = rackColour(mode, r);
  const label = `${r.name}${r.footprint_default ? ' *' : ''}`;
  const title = [`${r.name} · ${place.x}, ${place.y} · front ${['towards the bottom', 'to the left', 'towards the top', 'to the right'][place.rotation / 90] ?? ''}`,
    c.label, `${r.device_count} device${r.device_count === 1 ? '' : 's'}`].join('\n');
  return (
    <g data-testid="floor-plan-rack" data-rack={r.id} data-x={place.x} data-y={place.y} data-rotation={place.rotation} data-colour={c.kind}
      tabIndex={0} role="button" aria-label={`${r.name}, ${c.label}`} onPointerDown={onPointerDown} onKeyDown={onKeyDown}
      style={{ cursor: canManage ? 'grab' : 'pointer', opacity: dim ? 0.45 : 1, outline: 'none' }}>
      <title>{title}</title>
      <g transform={`translate(${cx} ${cy}) rotate(${place.rotation})`}>
        <rect x={-w / 2} y={-d / 2} width={w} height={d} rx="2"
          fill={c.kind === 'value' ? c.color : 'var(--app-panel)'} fillOpacity={c.kind === 'value' ? c.opacity : 1}
          stroke={c.color} strokeWidth="1.5" strokeDasharray={c.kind === 'unrecorded' ? '4 3' : undefined} />
        {/* The front edge. */}
        <line x1={-w / 2} y1={d / 2} x2={w / 2} y2={d / 2} stroke="var(--app-t1)" strokeWidth="3" />
      </g>
      <text x={cx} y={cy + 4} fontSize="10.5" fontWeight="700" textAnchor="middle" fill="var(--app-t1)" pointerEvents="none">{label}</text>
    </g>
  );
}

function Legend({ mode }: { mode: FloorColourMode }) {
  const item = (color: string, text: string, dashed = false) => (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
      <span style={{ width: 12, height: 10, borderRadius: 2, border: `1.5px ${dashed ? 'dashed' : 'solid'} ${color}`, background: dashed ? 'transparent' : `color-mix(in srgb, ${color} 35%, transparent)` }} />
      {text}
    </span>
  );
  return (
    <div data-testid="floor-plan-legend" style={{ display: 'flex', gap: 14, flexWrap: 'wrap', fontSize: 11.5, color: 'var(--app-t3)' }}>
      <span>{mode === 'utilization' ? 'Units used' : 'Power allocated'}:</span>
      {item(fillColor(0), `up to ${CAPACITY_WARN}%`)}
      {item(fillColor(CAPACITY_WARN + 1), `over ${CAPACITY_WARN}%`)}
      {item(fillColor(CAPACITY_CRITICAL + 1), `over ${CAPACITY_CRITICAL}%`)}
      {item('var(--app-t3)', mode === 'utilization' ? 'not recorded' : 'no power budget', true)}
      <span>The thick edge is the rack's front.</span>
    </div>
  );
}
