// Small presentational pieces ported from the mock (Lenses.jsx GroupBand,
// patterns.jsx EmptyState, Findings.jsx CatChip/ColLabel). Local to the
// Risk & Compliance section — components/ui is stream-1-owned (read-only).
import { Icon, RiskChip, LevelBar, type RiskLevel } from '../../components/ui';
import { CAT } from './model';

export function Caret({ open }: { open: boolean }) {
  return (
    <span style={{ display: 'inline-flex', flex: 'none', transition: 'transform .18s ease', transform: open ? 'rotate(90deg)' : 'none', color: 'var(--app-t3)' }}>
      <Icon name="chevron-right" size={14} />
    </span>
  );
}

/** Group header band with risk distribution. */
export function GroupBand({ label, sub, count, byLevel, worst, open, onClick, accent }: {
  label: string; sub?: string; count: number; byLevel?: Partial<Record<RiskLevel, number>>;
  worst?: string; open: boolean; onClick: () => void; accent?: React.ReactNode;
}) {
  return (
    <button onClick={onClick} className="row-hover" style={{ display: 'flex', alignItems: 'center', gap: 12, width: '100%', padding: '11px 16px', border: 'none', borderTop: '1px solid var(--app-border)', background: 'var(--app-panel2)', cursor: 'pointer', textAlign: 'left' }}>
      <Caret open={open} />
      {accent || (worst && <RiskChip level={worst} size={24} />)}
      <div style={{ minWidth: 0, flex: 1 }}>
        <div style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--app-t1)' }}>{label}</div>
        {sub && <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>{sub}</div>}
      </div>
      {byLevel && <div style={{ width: 120 }}><LevelBar counts={byLevel} h={7} /></div>}
      <span className="mono" style={{ fontSize: 12, color: 'var(--app-t2)', minWidth: 30, textAlign: 'right' }}>{count}</span>
    </button>
  );
}

export function EmptyState({ icon, title, message, variant = 'no-results', compact }: {
  icon?: string; title: string; message?: string; variant?: 'first-run' | 'no-results' | 'all-clear'; compact?: boolean;
}) {
  const ic = icon || (variant === 'all-clear' ? 'check-check' : variant === 'first-run' ? 'inbox' : 'search-x');
  const tone = variant === 'all-clear' ? 'var(--ok)' : 'var(--app-t3)';
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', textAlign: 'center', padding: compact ? '38px 22px' : '64px 24px', gap: 4 }}>
      <span style={{ width: 46, height: 46, borderRadius: 13, display: 'flex', alignItems: 'center', justifyContent: 'center', background: variant === 'all-clear' ? 'color-mix(in srgb, var(--ok) 13%, transparent)' : 'var(--app-panel2)', border: '1px solid var(--app-border)', color: tone, marginBottom: 12 }}>
        <Icon name={ic} size={22} />
      </span>
      <div style={{ fontSize: 14.5, fontWeight: 700, fontFamily: 'var(--font-head)', color: 'var(--app-t1)' }}>{title}</div>
      {message && <div style={{ fontSize: 12.5, color: 'var(--app-t3)', maxWidth: 340, lineHeight: 1.55 }}>{message}</div>}
    </div>
  );
}

export function CatChip({ category }: { category: string }) {
  const cat = CAT[category] ?? { label: 'Other', icon: 'circle-alert' };
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, height: 22, padding: '0 9px', borderRadius: 7, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', fontSize: 11, fontWeight: 600, color: 'var(--app-t2)', whiteSpace: 'nowrap' }}>
      <Icon name={cat.icon} size={12} />{cat.label}
    </span>
  );
}

export function ColLabel({ children, right }: { children: React.ReactNode; right?: boolean }) {
  return <span style={{ fontSize: 10.5, fontWeight: 700, letterSpacing: '.09em', textTransform: 'uppercase', color: 'var(--app-t3)', textAlign: right ? 'right' : 'left' }}>{children}</span>;
}

export function Loading({ label }: { label: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 9, padding: '54px 20px', color: 'var(--app-t3)', fontSize: 12.5 }}>
      <Icon name="loader" size={15} style={{ animation: 'spin 1.1s linear infinite' }} />{label}
      <style>{'@keyframes spin { to { transform: rotate(360deg); } }'}</style>
    </div>
  );
}
