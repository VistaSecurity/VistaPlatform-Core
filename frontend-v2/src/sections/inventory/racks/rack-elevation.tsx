// The drawn rack elevation (DCIM row 2.5): front and rear side by side in one
// SVG, a unit grid that honours `starting_unit` / `desc_units`, each device a
// block over its U span on its face (full-depth devices on both, the far side
// drawn faint and dashed), half-U positions, hatched reservations and
// clickable empty units. A manager drags a block to a new position or across
// to the other face; the page calls PUT placement and snaps the block back on
// a 409. With the crypto overlay on, each block is tinted by its worst open
// finding through the ratings bands (rack-overlay.ts), badged for an expiring
// certificate and marked with a lock for a weak protocol. With the power
// overlay on instead (row 6.2), each block is tinted by its share of the
// rack's available power (power-overlay.ts).
import { useEffect, useId, useRef, useState, type KeyboardEvent, type PointerEvent as ReactPointerEvent, type RefObject } from 'react';
import { ASSET_CLASSES, type AssetClassKey } from '@vistasecurity/primitives/assets';
import { classGroupOf, classGroupStyle } from '../map-model';
import { classLabel } from '../asset-shape';
import {
  UNIT_PX, devicesOnFace, emptyUnits, positionAtY, reservationBands, snapPosition, spanY, unitY, unitsTopDown, type RackGeom,
} from './rack-geometry';
import { certBadgeText, certDaysLeft, overlayState, overlayTooltip, type DevicePosture } from './rack-overlay';
import type { PowerOverlayState } from './power-overlay';
import { unitLabel, type ElevationDevice, type ElevationReservation, type RackFace } from './racks-queries';

export const FACES: readonly RackFace[] = ['front', 'rear'];
const PAD = 10;
const LABEL_W = 30;
export const FACE_W = 236;
const GAP = LABEL_W + 26;
const TITLE_H = 24;

/** The x of a face's grid. */
export const faceX = (face: RackFace): number => PAD + LABEL_W + (face === 'rear' ? FACE_W + GAP : 0);
export const GRID_TOP = PAD + TITLE_H;

export function elevationSize(g: RackGeom): { width: number; height: number } {
  return { width: faceX('rear') + FACE_W + PAD, height: GRID_TOP + g.u_height * UNIT_PX + PAD };
}

/** Block colour by class: the hardware families get their own categorical
 *  token so a rack of servers, switches and storage reads at a glance; any
 *  other class takes its map group's colour. */
const FAMILY_COLOR: Record<string, string> = {
  computer: 'var(--chart-1)',
  network_device: 'var(--chart-2)',
  storage_device: 'var(--chart-3)',
};
export function rackClassColor(classKey: string | null | undefined): string {
  const cls = classKey ? ASSET_CLASSES[classKey as AssetClassKey] : undefined;
  const family = cls?.path.split('.')[1];
  if (family && FAMILY_COLOR[family]) return FAMILY_COLOR[family];
  return classGroupStyle(classGroupOf(classKey)).color;
}

export type DeviceWithPosture = ElevationDevice & { posture?: DevicePosture | null; power?: PowerOverlayState | null };

export interface PendingMove { assetId: string; position: number; face: RackFace }

interface DragState {
  device: DeviceWithPosture;
  startX: number;
  startY: number;
  origTop: number;
  moved: boolean;
  target: { position: number; face: RackFace } | null;
}

export interface RackElevationProps {
  rack: RackGeom;
  devices: readonly DeviceWithPosture[];
  reservations: readonly ElevationReservation[];
  overlay: boolean;
  /** The power overlay (row 6.2); it replaces the crypto overlay while on. */
  powerOverlay?: boolean;
  highlight?: string | null;
  canManage: boolean;
  /** storage_ref → image attachment URL. */
  imageUrl?: (ref: string | null | undefined) => string | null;
  pending?: PendingMove | null;
  onMove?: (device: DeviceWithPosture, position: number, face: RackFace) => void;
  onOpen?: (device: DeviceWithPosture) => void;
  onEmptyUnit?: (unit: number, face: RackFace) => void;
  svgRef?: RefObject<SVGSVGElement | null>;
  now?: Date;
}

function truncate(text: string, maxChars: number): string {
  if (maxChars <= 1) return '';
  return text.length <= maxChars ? text : `${text.slice(0, Math.max(maxChars - 1, 1))}…`;
}

export function RackElevationSvg(props: RackElevationProps) {
  const { rack, reservations, highlight, canManage, imageUrl, pending, onMove, onOpen, onEmptyUnit, svgRef, now } = props;
  const powerOverlay = !!props.powerOverlay;
  const overlay = props.overlay && !powerOverlay;
  const uid = useId().replace(/[^A-Za-z0-9_-]/g, '');
  const hatchId = `rack-hatch-${uid}`;
  const ownRef = useRef<SVGSVGElement | null>(null);
  const localRef = svgRef ?? ownRef;
  // The drag lives in a ref (read by the window listeners) and is mirrored
  // into state for drawing; both are written only from event handlers.
  const [drag, setDragState] = useState<DragState | null>(null);
  const dragRef = useRef<DragState | null>(null);
  const setDrag = (d: DragState | null) => { dragRef.current = d; setDragState(d); };
  const { width, height } = elevationSize(rack);

  // A pending move draws the block where it was dropped until the write
  // settles; a refusal clears it and the block is back where it was.
  const devices = props.devices.map((d) => (pending && pending.assetId === d.asset_id ? { ...d, position: pending.position, face: pending.face } : d));

  const toLocal = (clientX: number, clientY: number) => {
    const r = localRef.current?.getBoundingClientRect();
    const sx = r && r.width ? width / r.width : 1;
    const sy = r && r.height ? height / r.height : 1;
    return { x: (clientX - (r?.left ?? 0)) * sx, y: (clientY - (r?.top ?? 0)) * sy };
  };

  useEffect(() => {
    if (!drag) return;
    const move = (e: PointerEvent | MouseEvent) => {
      const cur = dragRef.current;
      if (!cur) return;
      const p = toLocal(e.clientX, e.clientY);
      const dx = p.x - cur.startX;
      const dy = p.y - cur.startY;
      const moved = cur.moved || Math.abs(dx) + Math.abs(dy) > 3;
      const face: RackFace = p.x < faceX('rear') - GAP / 2 ? 'front' : 'rear';
      const position = positionAtY(rack, cur.origTop + dy, cur.device.u_height);
      // A reader's press never becomes a move: no ghost, no target.
      setDrag({ ...cur, moved, target: moved && canManage ? { position, face } : null });
    };
    const up = () => {
      const cur = dragRef.current;
      setDrag(null);
      if (!cur) return;
      if (!cur.moved) { onOpen?.(cur.device); return; }
      if (!canManage) return;
      const t = cur.target;
      if (t && (t.position !== cur.device.position || t.face !== cur.device.face)) onMove?.(cur.device, t.position, t.face);
    };
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', up);
    return () => { window.removeEventListener('pointermove', move); window.removeEventListener('pointerup', up); };
    // toLocal reads refs only; drag identity is what (re)binds the listeners.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [drag !== null, rack, canManage, onMove, onOpen]);

  const startDrag = (e: ReactPointerEvent, device: DeviceWithPosture) => {
    if (e.button !== undefined && e.button !== 0) return;
    const p = toLocal(e.clientX, e.clientY);
    const origTop = spanY(rack, device.position, device.u_height).y;
    // A reader's press is only ever a click; a manager's may become a drag.
    if (canManage) e.preventDefault();
    setDrag({ device, startX: p.x, startY: p.y, origTop, moved: false, target: null });
  };

  const onBlockKey = (e: KeyboardEvent, device: DeviceWithPosture) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onOpen?.(device); return; }
    if (!canManage || (e.key !== 'ArrowUp' && e.key !== 'ArrowDown')) return;
    e.preventDefault();
    // "Up" is up on screen: a higher number unless the rack counts downward.
    const up = e.key === 'ArrowUp';
    const step = (up ? 1 : -1) * (rack.desc_units ? -0.5 : 0.5);
    const next = snapPosition(rack, device.position + step, device.u_height);
    if (next !== device.position) onMove?.(device, next, device.face);
  };

  const units = unitsTopDown(rack);
  const bands = reservationBands(reservations);

  return (
    <svg ref={localRef} data-testid="rack-elevation" viewBox={`0 0 ${width} ${height}`} width={width} height={height}
      role="group" aria-label="Rack elevation, front and rear"
      style={{ maxWidth: '100%', height: 'auto', touchAction: drag ? 'none' : undefined, userSelect: 'none', fontFamily: 'var(--font-body, system-ui, sans-serif)' }}>
      <defs>
        <pattern id={hatchId} width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
          <rect width="6" height="6" fill="var(--warn)" fillOpacity="0.08" />
          <line x1="0" y1="0" x2="0" y2="6" stroke="var(--warn)" strokeWidth="2" strokeOpacity="0.55" />
        </pattern>
      </defs>
      {FACES.map((face) => {
        const x0 = faceX(face);
        const blocks = devicesOnFace(devices, face);
        const empties = canManage ? emptyUnits(rack, devices, reservations, face) : [];
        return (
          <g key={face} data-testid={`rack-face-${face}`}>
            <text x={x0 + FACE_W / 2} y={PAD + 14} textAnchor="middle" fontSize="11.5" fontWeight="700" fill="var(--app-t2)" letterSpacing="0.06em">
              {face === 'front' ? 'FRONT' : 'REAR'}
            </text>
            <rect x={x0} y={GRID_TOP} width={FACE_W} height={rack.u_height * UNIT_PX} rx="3" fill="var(--app-panel2)" stroke="var(--app-border2)" />
            {units.map((u) => {
              const y = GRID_TOP + unitY(rack, u);
              return (
                <g key={u}>
                  <line x1={x0} x2={x0 + FACE_W} y1={y} y2={y} stroke="var(--app-border)" strokeWidth="0.6" />
                  <text data-testid={face === 'front' ? 'rack-unit-label' : undefined} data-unit={u} x={x0 - 6} y={y + UNIT_PX / 2 + 4} textAnchor="end" fontSize="10" fill="var(--app-t3)" className="mono">{u}</text>
                </g>
              );
            })}
            {empties.map((u) => (
              <rect key={`e${u}`} data-testid="rack-empty-unit" data-unit={u} data-face={face} data-export="skip"
                x={x0 + 1} y={GRID_TOP + unitY(rack, u) + 1} width={FACE_W - 2} height={UNIT_PX - 2} fill="var(--accent)" fillOpacity="0"
                style={{ cursor: 'pointer' }} onClick={() => onEmptyUnit?.(u, face)}>
                <title>{`U${u} · ${face} · empty — add a device here`}</title>
              </rect>
            ))}
            {bands.map(({ reservation, from, to }) => {
              const { y, h } = spanY(rack, from, to - from + 1);
              return (
                <g key={`${reservation.id}-${from}`} data-testid="rack-reservation" data-from={from} data-to={to} data-face={face}>
                  <rect x={x0 + 2} y={GRID_TOP + y + 1} width={FACE_W - 4} height={h - 2} fill={`url(#${hatchId})`} stroke="var(--warn)" strokeDasharray="4 3" rx="2">
                    <title>{`Reserved ${from === to ? `U${from}` : `U${from}–U${to}`}: ${reservation.description}`}</title>
                  </rect>
                  {h >= 16 && (
                    <text x={x0 + 8} y={GRID_TOP + y + Math.min(h, UNIT_PX) / 2 + 4} fontSize="10.5" fill="var(--warn-text, var(--app-t2))" pointerEvents="none">
                      {truncate(`Reserved · ${reservation.description}`, Math.floor((FACE_W - 16) / 6))}
                    </text>
                  )}
                </g>
              );
            })}
            {blocks.map(({ device: d, mirrored }) => (
              <DeviceBlock key={`${d.asset_id}-${face}`} rack={rack} device={d} face={face} mirrored={mirrored} overlay={overlay} powerOverlay={powerOverlay}
                highlighted={highlight === d.asset_id} dragging={canManage && drag?.device.asset_id === d.asset_id && drag.moved}
                canManage={canManage} imageUrl={imageUrl} now={now}
                onPointerDown={(e) => startDrag(e, d)} onKeyDown={(e) => onBlockKey(e, d)} />
            ))}
          </g>
        );
      })}
      {drag?.moved && drag.target && (() => {
        const { y, h } = spanY(rack, drag.target.position, drag.device.u_height);
        return (
          <g data-testid="rack-drag-ghost" data-position={drag.target.position} data-face={drag.target.face} data-export="skip" pointerEvents="none">
            <rect x={faceX(drag.target.face) + 2} y={GRID_TOP + y + 1} width={FACE_W - 4} height={Math.max(h - 2, 4)} rx="3"
              fill="var(--accent)" fillOpacity="0.18" stroke="var(--accent)" strokeWidth="2" strokeDasharray="5 3" />
            <text x={faceX(drag.target.face) + FACE_W - 8} y={GRID_TOP + y + Math.min(h, UNIT_PX) / 2 + 4} textAnchor="end" fontSize="11" fontWeight="700" fill="var(--accent)">
              {unitLabel(drag.target.position)}
            </text>
          </g>
        );
      })()}
    </svg>
  );
}

function LockGlyph({ x, y, color }: { x: number; y: number; color: string }) {
  return (
    <g data-testid="rack-weak-protocol" transform={`translate(${x},${y})`} pointerEvents="none">
      <rect x="0" y="5" width="10" height="7" rx="1.5" fill={color} />
      <path d="M2.2 5.2V3.6a2.8 2.8 0 0 1 5.6 0v1.6" fill="none" stroke={color} strokeWidth="1.6" />
    </g>
  );
}

function DeviceBlock({ rack, device: d, face, mirrored, overlay, powerOverlay, highlighted, dragging, canManage, imageUrl, now, onPointerDown, onKeyDown }: {
  rack: RackGeom; device: DeviceWithPosture; face: RackFace; mirrored: boolean; overlay: boolean; powerOverlay: boolean; highlighted: boolean; dragging: boolean;
  canManage: boolean; imageUrl?: RackElevationProps['imageUrl']; now?: Date;
  onPointerDown: (e: ReactPointerEvent) => void; onKeyDown: (e: KeyboardEvent) => void;
}) {
  const { y, h } = spanY(rack, d.position, d.u_height);
  const x = faceX(face) + 2;
  const w = FACE_W - 4;
  const top = GRID_TOP + y + 1;
  const hh = Math.max(h - 2, 3);
  const classColor = rackClassColor(d.class_key);
  const state = overlay ? overlayState(d.posture) : null;
  const power: PowerOverlayState | null = powerOverlay ? (d.power ?? { kind: 'unknown', color: 'var(--app-t3)', label: 'Power not loaded' }) : null;
  const powerTint = power && (power.kind === 'share' || power.kind === 'no-budget') ? power : null;
  const finding = state?.kind === 'finding';
  const ref = face === 'front' ? d.device_type?.front_image_ref : d.device_type?.rear_image_ref;
  const img = imageUrl?.(ref) ?? null;
  const model = d.device_type?.model ?? classLabel(d.class_key);
  const certDays = overlay ? certDaysLeft(d.posture, now) : null;
  const badges = (overlay && d.posture?.weak_protocol ? 16 : 0) + (certDays != null ? 34 : 0);
  const maxChars = Math.floor((w - 18 - badges) / 6.3);
  const twoLines = hh >= 30;
  const tooltip = power ? `${d.name}\n${power.label}`
    : overlay ? overlayTooltip(d.name, d.posture, now) : `${d.name}\n${model} · ${unitLabel(d.position)} · ${d.u_height}U${d.is_full_depth ? ' · full depth' : ''}`;
  const stroke = powerTint ? powerTint.color : state && state.kind !== 'unknown' ? state.color : classColor;
  const dashed = mirrored || state?.kind === 'unassessed' || power?.kind === 'unrecorded' || power?.kind === 'unknown';
  return (
    <g data-testid="rack-block" data-asset={d.asset_id} data-face={face} data-mirrored={mirrored ? 'true' : 'false'}
      data-y={y} data-h={h} data-overlay-color={state?.color ?? ''} data-overlay-kind={state?.kind ?? ''}
      data-power-kind={power?.kind ?? ''} data-power-color={powerTint?.color ?? ''}
      role="button" tabIndex={mirrored ? -1 : 0}
      aria-label={`${d.name}, ${unitLabel(d.position)}, ${d.u_height}U, ${d.face}${mirrored ? ' (seen from the other face)' : ''}${state ? `, ${state.label}` : ''}${power ? `, ${power.label}` : ''}`}
      style={{ cursor: canManage ? (dragging ? 'grabbing' : 'grab') : 'pointer', opacity: dragging ? 0.45 : 1, outline: 'none' }}
      onPointerDown={onPointerDown} onKeyDown={onKeyDown}>
      <title>{tooltip}</title>
      <rect x={x} y={top} width={w} height={hh} rx="3" fill={classColor} fillOpacity={mirrored ? 0.07 : 0.17}
        stroke={stroke} strokeWidth={finding || powerTint ? 2 : 1} strokeDasharray={dashed ? '4 3' : undefined} />
      {img && !mirrored && <image href={img} x={x + 1} y={top + 1} width={w - 2} height={hh - 2} preserveAspectRatio="none" opacity="0.92" />}
      {powerTint && (
        <rect data-testid="rack-power-tint" x={x} y={top} width={w} height={hh} rx="3" fill={powerTint.color} fillOpacity={mirrored ? powerTint.opacity / 3 : powerTint.opacity} pointerEvents="none" />
      )}
      {finding && state && (
        <>
          <rect data-testid="rack-overlay-tint" x={x} y={top} width={w} height={hh} rx="3" fill={state.color} fillOpacity={mirrored ? 0.08 : 0.2} pointerEvents="none" />
          <rect x={x} y={top} width="4" height={hh} rx="1.5" fill={state.color} pointerEvents="none" />
        </>
      )}
      {hh >= 9 && (
        <text x={x + 10} y={twoLines ? top + 14 : top + hh / 2 + 4} fontSize="11" fontWeight="600" fill="var(--app-t1)" fillOpacity={mirrored ? 0.55 : 1} pointerEvents="none">
          {truncate(twoLines || !model ? d.name : `${d.name} · ${model}`, maxChars)}
        </text>
      )}
      {twoLines && (
        <text x={x + 10} y={top + 27} fontSize="10" fill="var(--app-t3)" pointerEvents="none">{truncate(model, maxChars)}</text>
      )}
      {overlay && d.posture?.weak_protocol && <LockGlyph x={x + w - 14 - (certDays != null ? 34 : 0)} y={top + Math.min(hh, UNIT_PX) / 2 - 7} color="var(--danger)" />}
      {certDays != null && (
        <g data-testid="rack-cert-badge" pointerEvents="none">
          <title>{certBadgeText(certDays)}</title>
          <rect x={x + w - 36} y={top + Math.min(hh, UNIT_PX) / 2 - 7} width="32" height="14" rx="7" fill="var(--warn)" />
          <text x={x + w - 20} y={top + Math.min(hh, UNIT_PX) / 2 + 3.5} textAnchor="middle" fontSize="9.5" fontWeight="700" fill="var(--app-bg, #fff)">
            {certDays < 0 ? 'exp' : `${certDays}d`}
          </text>
        </g>
      )}
      {highlighted && (
        <rect data-testid="rack-block-highlight" x={x - 1.5} y={top - 1.5} width={w + 3} height={hh + 3} rx="4" fill="none" stroke="var(--accent)" strokeWidth="2.5" pointerEvents="none" />
      )}
    </g>
  );
}
