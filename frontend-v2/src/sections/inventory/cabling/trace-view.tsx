// The cable trace view (DCIM BUILD_PLAN row 3.4; ADR-0010 D6): from any port,
// where the cable goes — a simple left-to-right diagram (port → cable → port,
// through a patch panel's front → rear or a circuit's A → Z) with the far end
// highlighted, the same hops as a list, every asset clickable, and "Copy as
// text". Reads GET /dcim/{kind}/{id}/trace (row 3.2's cached path).
//
// States: loading, error, not cabled (no path — said plainly, never an empty
// diagram), and the paths. A front or rear port answers every path running
// through it, so several paths can show.
import { useState } from 'react';
import { Link } from 'react-router';
import { Icon, Modal } from '../../../components/ui';
import { PanelEmpty, PanelError, PanelLoading } from '../dcim/substrate-states';
import { useTrace, type CablePath, type CablePathNode, type TraceKind } from './cabling-queries';
import { circuitHref } from '../object-pages/object-links';
import { isDestination, kindWord, nodeText, pathHops, pathState, traceText } from './trace-model';

/** Where a hop's node links: its asset page, or the circuit's page. */
export function nodeHref(n: CablePathNode): string | null {
  if (n.asset_id) return `/inventory/assets/${n.asset_id}/ports`;
  if (n.circuit_id) return circuitHref(n.circuit_id);
  return null;
}

function NodeBox({ n, highlight, onNavigate }: { n: CablePathNode; highlight: boolean; onNavigate?: () => void }) {
  const href = nodeHref(n);
  const body = (
    <>
      <div style={{ fontSize: 10.5, color: 'var(--app-t3)', textTransform: 'uppercase', letterSpacing: 0.3 }}>{kindWord(n.kind)}</div>
      <div className="mono" style={{ fontSize: 12, fontWeight: 600, color: 'var(--app-t1)' }}>{n.name}</div>
      {n.asset_name && <div style={{ fontSize: 11.5, color: 'var(--app-t2)' }}>{n.asset_name}</div>}
    </>
  );
  const style: React.CSSProperties = {
    display: 'block', minWidth: 110, padding: '6px 9px', borderRadius: 8, textDecoration: 'none',
    border: `1.5px solid ${highlight ? 'var(--accent)' : 'var(--app-border)'}`,
    background: highlight ? 'color-mix(in srgb, var(--accent) 12%, transparent)' : 'var(--app-panel)',
  };
  return href
    ? <Link to={href} data-testid="trace-node" data-far={highlight || undefined} style={style} onClick={onNavigate}>{body}</Link>
    : <div data-testid="trace-node" data-far={highlight || undefined} style={style}>{body}</div>;
}

function CableLink({ c }: { c: CablePathNode }) {
  const connected = (c.operational_status ?? 'connected') === 'connected';
  const colour = c.color ? `#${c.color}` : 'var(--app-t2)';
  return (
    <div data-testid="trace-cable" title={[c.name, c.type, c.operational_status].filter(Boolean).join(' · ')}
      style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: 70, padding: '0 4px' }}>
      <span style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap' }}>{c.name}</span>
      <span aria-hidden style={{ width: '100%', minWidth: 60, borderTop: `3px ${connected ? 'solid' : 'dashed'} ${colour}`, margin: '3px 0' }} />
      <span style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap' }}>{c.type ?? ''}{!connected && c.operational_status ? ` · ${c.operational_status}` : ''}</span>
    </div>
  );
}

export function TraceDiagram({ path, onNavigate }: { path: CablePath; onNavigate?: () => void }) {
  const hops = pathHops(path);
  return (
    <div data-testid="trace-diagram" style={{ display: 'flex', alignItems: 'center', gap: 4, overflowX: 'auto', padding: '6px 2px 10px' }}>
      {hops.map((h, i) => {
        if (h.type === 'ports') {
          return (
            <div key={i} style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {h.nodes.map((n) => <NodeBox key={n.id} n={n} highlight={h.far && (isDestination(path, n) || !path.destination)} onNavigate={onNavigate} />)}
            </div>
          );
        }
        if (h.type === 'cable') return <div key={i} style={{ display: 'flex', flexDirection: 'column' }}>{h.nodes.map((c) => <CableLink key={c.id} c={c} />)}</div>;
        return (
          <span key={i} data-testid="trace-through" style={{ fontSize: 10.5, color: 'var(--app-t3)', whiteSpace: 'nowrap', padding: '0 4px' }}>
            <Icon name="arrow-right" size={11} /> {h.label}
          </span>
        );
      })}
    </div>
  );
}

export function TraceHopList({ path }: { path: CablePath }) {
  return (
    <ol data-testid="trace-hops" style={{ margin: 0, paddingLeft: 18, fontSize: 12.5, color: 'var(--app-t2)' }}>
      {pathHops(path).map((h, i) => (
        <li key={i} style={{ padding: '2px 0' }}>
          {h.type === 'ports' && (
            <span style={{ fontWeight: h.far ? 700 : 400, color: h.far ? 'var(--app-t1)' : undefined }}>
              {h.nodes.map(nodeText).join(', ')} <span style={{ color: 'var(--app-t3)' }}>({kindWord(h.nodes[0]?.kind ?? '')}{h.far ? ', far end' : ''})</span>
            </span>
          )}
          {h.type === 'cable' && <span>cable {h.nodes.map(nodeText).join(', ')}{h.nodes[0]?.type ? ` · ${h.nodes[0].type}` : ''}</span>}
          {h.type === 'through' && <span style={{ color: 'var(--app-t3)' }}>{h.label}</span>}
        </li>
      ))}
    </ol>
  );
}

/** The trace body, for a modal or a drawer section. */
export function TraceBody({ kind, id, onNavigate }: { kind: TraceKind; id: string; onNavigate?: () => void }) {
  const q = useTrace(kind, id);
  const [copied, setCopied] = useState(false);
  if (q.isLoading) return <PanelLoading label="Tracing the cable path…" />;
  if (q.isError) return <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />;
  const t = q.data!;
  if (t.paths.length === 0) {
    return <PanelEmpty icon="unplug" title="Not cabled" message={`${nodeText(t.object)} has no cable, so there is no path to trace. Connect it from the asset's Ports or Interfaces tab.`} />;
  }
  const copy = () => {
    void navigator.clipboard?.writeText(traceText(t)).then(() => setCopied(true), () => setCopied(false));
  };
  return (
    <div data-testid="trace-body">
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 6 }}>
        <button type="button" className="ui-btn sm ghost" data-testid="trace-copy" onClick={copy}>
          <Icon name={copied ? 'check' : 'copy'} size={12} />{copied ? 'Copied' : 'Copy as text'}
        </button>
      </div>
      {t.paths.map((p, i) => (
        <div key={i} data-testid="trace-path" style={{ borderTop: i ? '1px solid var(--app-border)' : undefined, paddingTop: i ? 10 : 0, marginBottom: 10 }}>
          <div style={{ fontSize: 12, color: 'var(--app-t3)', marginBottom: 4 }}>
            {t.paths.length > 1 ? `Path ${i + 1} from ${nodeText(p.origin)} · ` : ''}{pathState(p)}
          </div>
          <TraceDiagram path={p} onNavigate={onNavigate} />
          <TraceHopList path={p} />
        </div>
      ))}
    </div>
  );
}

export function TraceModal({ kind, id, name, onClose }: { kind: TraceKind; id: string; name: string; onClose: () => void }) {
  return (
    <Modal open onClose={onClose} size="lg" icon="route" title={`Trace ${name}`}
      description="Where this port's cable goes, through patch panels and circuits, to the far end."
      secondary={<button type="button" className="ui-btn" onClick={onClose}>Close</button>}>
      <TraceBody kind={kind} id={id} onNavigate={onClose} />
    </Modal>
  );
}
