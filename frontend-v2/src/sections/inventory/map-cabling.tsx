// The map's cabling pieces (DCIM BUILD_PLAN row 3.6): the menu a relationship
// opens on click ("Show physical path"), the trace a cable or that action
// opens, and the legend lines for the two edge styles. The trace itself is row
// 3.4's `TraceBody` — the same reads, states and diagram the Ports tab and the
// Cabling lens show — not a second implementation.
import { useEffect, useRef } from 'react';
import { Link } from 'react-router';
import { Icon, Modal } from '../../components/ui';
import { TraceBody } from './cabling/trace-view';
import {
  CABLE_EDGE_COLOR, CABLE_EDGE_DASH, CABLE_EDGE_WIDTH, cableLensHref, physicalPathTarget,
} from './map-cabling-model';
import type { MapEdge } from './map-model';

/** What the trace modal is opened on: an interface, and the cable it came from when known. */
export interface MapTraceTarget {
  interfaceId: string;
  interfaceName: string;
  cableId?: string;
}

/**
 * The relationship menu: opened by clicking a relationship on the canvas.
 * Escape or a click elsewhere closes it.
 */
export function EdgeActionsMenu({ edge, x, y, onShowPath, onClose }: {
  edge: MapEdge;
  x: number;
  y: number;
  onShowPath: (t: MapTraceTarget) => void;
  onClose: () => void;
}) {
  const ref = useRef<HTMLDivElement | null>(null);
  const target = physicalPathTarget(edge);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    const onDown = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) onClose(); };
    document.addEventListener('keydown', onKey);
    document.addEventListener('mousedown', onDown);
    ref.current?.querySelector<HTMLButtonElement>('button:not([disabled])')?.focus();
    return () => {
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('mousedown', onDown);
    };
  }, [onClose]);

  return (
    <div
      ref={ref}
      role="menu"
      aria-label={`Actions for ${edge.label}`}
      data-testid="map-edge-menu"
      style={{
        position: 'fixed', left: x + 6, top: y + 6, zIndex: 45, minWidth: 230, maxWidth: 300,
        padding: 6, borderRadius: 11, border: '1px solid var(--app-border2)',
        background: 'var(--app-panel)', boxShadow: 'var(--app-shadow)',
      }}
    >
      <div style={{ fontSize: 11, color: 'var(--app-t3)', padding: '3px 8px 6px' }}>{edge.label}</div>
      <button
        type="button"
        role="menuitem"
        className="ui-btn sm ghost"
        data-testid="map-show-physical-path"
        disabled={!target.enabled}
        aria-disabled={!target.enabled}
        title={target.enabled ? `Trace the cable from ${target.interfaceName}` : target.reason}
        onClick={() => {
          if (!target.enabled) return;
          onShowPath({ interfaceId: target.interfaceId, interfaceName: target.interfaceName });
        }}
        style={{ width: '100%', justifyContent: 'flex-start', fontSize: 12, opacity: target.enabled ? 1 : 0.55 }}
      >
        <Icon name="route" size={12} />Show physical path
        {target.enabled && <span className="mono" style={{ color: 'var(--app-t3)', marginLeft: 'auto' }}>{target.interfaceName}</span>}
      </button>
      {!target.enabled && (
        <div data-testid="map-physical-path-reason" style={{ fontSize: 11, color: 'var(--app-t3)', lineHeight: 1.5, padding: '4px 8px 3px' }}>
          {target.reason}
        </div>
      )}
    </div>
  );
}

/** The trace of a cable run or of a relationship's port, in a modal. */
export function MapTraceModal({ target, onClose }: { target: MapTraceTarget; onClose: () => void }) {
  return (
    <Modal
      open onClose={onClose} size="lg" icon="route" title={`Physical path from ${target.interfaceName}`}
      description="Where this port's cable goes, through patch panels and circuits, to the far end."
      secondary={(
        <span style={{ display: 'inline-flex', gap: 7 }}>
          {target.cableId && (
            <Link to={cableLensHref(target.cableId)} className="ui-btn" data-testid="map-trace-open-cable" style={{ textDecoration: 'none' }} onClick={onClose}>
              <Icon name="cable" size={12} />Open cable
            </Link>
          )}
          <button type="button" className="ui-btn" onClick={onClose}>Close</button>
        </span>
      )}
    >
      <div data-testid="map-trace">
        <TraceBody kind="interface" id={target.interfaceId} onNavigate={onClose} />
      </div>
    </Modal>
  );
}

/** The two line styles, for the legend. Shown only when the cabling layer is on. */
export function CablingLegend({ pending }: { pending: boolean }) {
  const line = (style: React.CSSProperties) => <span aria-hidden style={{ width: 22, height: 0, ...style }} />;
  const item = { display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, color: 'var(--app-t2)' } as const;
  return (
    <div data-testid="map-cabling-legend" style={{ display: 'flex', gap: 10, flexWrap: 'wrap', width: '100%', paddingTop: 4, borderTop: '1px solid var(--app-border)' }}>
      <span style={item}>{line({ borderTop: '1.5px solid var(--app-border2)' })}Relationship</span>
      <span style={item}>{line({ borderTop: `${CABLE_EDGE_WIDTH}px solid ${CABLE_EDGE_COLOR}` })}Cable</span>
      {pending && <span style={item}>{line({ borderTop: `${CABLE_EDGE_WIDTH}px dashed ${CABLE_EDGE_COLOR}` })}Proposed cable</span>}
      <span style={{ ...item, color: 'var(--app-t3)' }}>Click a line for its path</span>
    </div>
  );
}

/** The dash pattern a cable run draws with. */
export const cableDash = (pending: boolean): string | undefined => (pending ? CABLE_EDGE_DASH : undefined);
