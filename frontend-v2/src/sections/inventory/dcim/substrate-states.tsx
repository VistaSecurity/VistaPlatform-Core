// Loading / error / empty blocks shared by the substrate panels. The same
// shapes (and test ids) the asset page's tabs use, so a panel reads as part of
// the page it is mounted on.
import { Icon } from '../../../components/ui';

export function PanelLoading({ label }: { label: string }) {
  return (
    <div data-testid="substrate-loading" style={{ padding: '8px 0' }}>
      {Array.from({ length: 3 }).map((_, i) => (
        <div key={i} style={{ height: 12, borderRadius: 6, background: 'var(--app-panel2)', marginBottom: 8, width: `${86 - i * 15}%` }} />
      ))}
      <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>{label}</span>
    </div>
  );
}

export function PanelError({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div data-testid="substrate-error" role="alert" style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '11px 13px', borderRadius: 12, border: '1px solid var(--danger)', background: 'color-mix(in srgb, var(--danger) 7%, transparent)' }}>
      <Icon name="alert-triangle" size={15} style={{ color: 'var(--danger-text)', flex: 'none', marginTop: 1 }} />
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--app-t1)' }}>Couldn't load this</div>
        <div style={{ fontSize: 12.5, color: 'var(--app-t3)', marginTop: 3 }}>{message}</div>
      </div>
      {onRetry && <button type="button" className="ui-btn sm" onClick={onRetry}><Icon name="refresh-cw" size={12} />Retry</button>}
    </div>
  );
}

export function PanelEmpty({ icon, title, message }: { icon: string; title: string; message: string }) {
  return (
    <div data-testid="substrate-empty" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6, padding: '26px 16px', textAlign: 'center' }}>
      <Icon name={icon} size={22} style={{ color: 'var(--app-t3)' }} />
      <div style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--app-t1)' }}>{title}</div>
      <div style={{ fontSize: 12.5, color: 'var(--app-t3)', maxWidth: 480, lineHeight: 1.6 }}>{message}</div>
    </div>
  );
}

/** Absolute time for a title attribute plus a short relative one to show. */
export function whenText(iso: string): { short: string; full: string } {
  const t = new Date(iso);
  if (Number.isNaN(t.getTime())) return { short: '', full: '' };
  const mins = Math.floor((Date.now() - t.getTime()) / 60000);
  let short: string;
  if (mins < 1) short = 'just now';
  else if (mins < 60) short = `${mins}m ago`;
  else if (mins < 60 * 24) short = `${Math.floor(mins / 60)}h ago`;
  else if (mins < 60 * 24 * 30) short = `${Math.floor(mins / 1440)}d ago`;
  else short = t.toLocaleDateString();
  return { short, full: t.toLocaleString() };
}
