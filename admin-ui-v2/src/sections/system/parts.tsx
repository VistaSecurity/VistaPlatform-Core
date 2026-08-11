// VISTA Operations — System Health shared sub-page parts. Panel chrome + the
// empty/loading/error table row, lifted out of the old tabbed system-page so the
// three left-rail sub-pages (services / gateway / alerts) share one definition.
import type { Activity } from 'lucide-react';

export function Panel({ title, icon: Icon, children }: { title: string; icon?: typeof Activity; children: React.ReactNode }) {
  return (
    <div className="op-panel" style={{ overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '13px 16px', borderBottom: '1px solid var(--op-border)', fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}>
        {Icon && <Icon size={16} style={{ color: 'var(--op-t3)' }} />}{title}
      </div>
      {children}
    </div>
  );
}

export function EmptyRow({ cols, loading, error, onRetry, label }: { cols: number; loading?: boolean; error?: boolean; onRetry?: () => void; label: string }) {
  return (
    <tr>
      <td colSpan={cols} style={{ textAlign: 'center', padding: 40, color: 'var(--op-t3)' }}>
        {loading ? 'Loading…' : error ? <>Couldn't load. {onRetry && <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={onRetry}>Retry</button>}</> : label}
      </td>
    </tr>
  );
}
