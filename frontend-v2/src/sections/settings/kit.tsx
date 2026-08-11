// Settings UI kit — TS port of the mock's settings/skit.jsx. Shared primitives
// so every settings & profile page is consistent: page shell, cards, form rows,
// inputs, toggles, tables, tags. Inputs/selects/toggles are uncontrolled with an
// optional onChange — read views render current values; editing flows land later.
import { useState, type CSSProperties, type ReactNode } from 'react';
import { Icon } from '../../components/ui';

export function SPage({ eyebrow, title, job, actions, children, maxWidth }: {
  eyebrow?: string; title: string; job?: string; actions?: ReactNode; children?: ReactNode; maxWidth?: number;
}) {
  return (
    <div style={{ flex: 1, minWidth: 0, overflowY: 'auto', padding: '24px 28px 56px' }}>
      <div style={{ maxWidth: maxWidth || 940, margin: '0 auto' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 16, marginBottom: 22, flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 240 }}>
            {eyebrow && <div className="eyebrow-app" style={{ color: 'var(--accent)', marginBottom: 7 }}>{eyebrow}</div>}
            <h2 style={{ margin: '0 0 5px', fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 20, letterSpacing: '-.02em', color: 'var(--app-t1)' }}>{title}</h2>
            {job && <p style={{ margin: 0, fontSize: 13, lineHeight: 1.55, color: 'var(--app-t3)', maxWidth: 680 }}>{job}</p>}
          </div>
          {actions && <div style={{ display: 'flex', gap: 8, flex: 'none', flexWrap: 'wrap' }}>{actions}</div>}
        </div>
        {children}
      </div>
    </div>
  );
}

export function SSection({ title, desc, action, children, style }: {
  title?: string; desc?: string; action?: ReactNode; children?: ReactNode; style?: CSSProperties;
}) {
  return (
    <div style={{ marginBottom: 22, ...style }}>
      {(title || action) && (
        <div style={{ display: 'flex', alignItems: 'flex-end', gap: 12, marginBottom: 11 }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            {title && <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--app-t1)' }}>{title}</div>}
            {desc && <div style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 2 }}>{desc}</div>}
          </div>
          {action}
        </div>
      )}
      {children}
    </div>
  );
}

export function SCard({ children, style, pad = 20 }: { children?: ReactNode; style?: CSSProperties; pad?: number }) {
  return <div className="panel" style={{ padding: pad, ...style }}>{children}</div>;
}

export function SRow({ label, hint, children, last }: { label: string; hint?: string; children?: ReactNode; last?: boolean }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 18, padding: '13px 0', borderBottom: last ? 'none' : '1px solid var(--app-border)' }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--app-t1)' }}>{label}</div>
        {hint && <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 2, lineHeight: 1.5 }}>{hint}</div>}
      </div>
      <div style={{ flex: 'none' }}>{children}</div>
    </div>
  );
}

export function SInput({ value, onChange, placeholder, width = 280, mono, type }: {
  value?: string; onChange?: (v: string) => void; placeholder?: string; width?: number; mono?: boolean; type?: string;
}) {
  const [v, setV] = useState(value ?? '');
  return (
    <input
      type={type || 'text'} value={v} placeholder={placeholder} className={mono ? 'mono' : ''}
      onChange={(e) => { setV(e.target.value); onChange?.(e.target.value); }}
      style={{ width, maxWidth: '100%', height: 36, padding: '0 12px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 13, outline: 'none' }}
    />
  );
}

export function SToggle({ on, onChange }: { on?: boolean; onChange?: (v: boolean) => void }) {
  const [v, setV] = useState(!!on);
  return (
    <button
      onClick={() => { const n = !v; setV(n); onChange?.(n); }} aria-pressed={v}
      style={{ width: 38, height: 22, borderRadius: 40, border: 'none', cursor: 'pointer', padding: 0, background: v ? 'var(--accent-gradient)' : 'var(--app-track)', position: 'relative', flex: 'none', transition: 'background .18s' }}
    >
      <span style={{ position: 'absolute', top: 2, left: v ? 18 : 2, width: 18, height: 18, borderRadius: 50, background: '#fff', transition: 'left .18s', boxShadow: '0 1px 2px rgba(0,0,0,.3)' }} />
    </button>
  );
}

export type SSelectOption = string | [string, string];
export function SSelect({ value, onChange, options, width = 200 }: {
  value?: string; onChange?: (v: string) => void; options: SSelectOption[]; width?: number;
}) {
  const first = options[0];
  const [v, setV] = useState(value ?? (Array.isArray(first) ? first[0] : first));
  return (
    <select
      value={v} onChange={(e) => { setV(e.target.value); onChange?.(e.target.value); }}
      style={{ height: 34, width, appearance: 'none', padding: '0 24px 0 12px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12.5, fontWeight: 600, outline: 'none', cursor: 'pointer' }}
    >
      {options.map((o) => {
        const val = Array.isArray(o) ? o[0] : o;
        const lab = Array.isArray(o) ? o[1] : o;
        return <option key={val} value={val}>{lab}</option>;
      })}
    </select>
  );
}

export function STag({ children, color }: { children?: ReactNode; color?: string }) {
  const c = color || 'var(--app-t2)';
  return <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, padding: '2px 9px', borderRadius: 40, fontSize: 11, fontWeight: 600, color: c, background: `color-mix(in srgb, ${c} 11%, transparent)`, whiteSpace: 'nowrap' }}>{children}</span>;
}

export function SDot({ color }: { color: string }) {
  return <span style={{ width: 7, height: 7, borderRadius: 50, background: color, flex: 'none', display: 'inline-block' }} />;
}

export function SAvatar({ name, size = 32 }: { name?: string | null; size?: number }) {
  const init = (name || '?').split(/[ .@]/).filter(Boolean).slice(0, 2).map((s) => s[0]).join('').toUpperCase();
  return (
    <span style={{ width: size, height: size, borderRadius: 50, background: 'linear-gradient(135deg,#2a2a2a,#454545)', border: '1px solid rgba(255,255,255,.12)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontSize: Math.round(size * 0.38), fontWeight: 700, color: 'var(--accent-light)', flex: 'none' }}>
      {init}
    </span>
  );
}

export interface STableCol { label?: string; w?: string; align?: 'left' | 'right' | 'center' }

export function STable({ cols, children }: { cols: STableCol[]; children?: ReactNode }) {
  const grid = cols.map((c) => c.w || '1fr').join(' ');
  return (
    <div className="panel" style={{ overflow: 'hidden' }}>
      <div style={{ display: 'grid', gridTemplateColumns: grid, gap: 14, padding: '10px 18px', borderBottom: '1px solid var(--app-border2)', background: 'var(--app-panel2)' }}>
        {cols.map((c, i) => (
          <span key={i} style={{ fontSize: 10.5, fontWeight: 700, letterSpacing: '.08em', textTransform: 'uppercase', color: 'var(--app-t3)', textAlign: c.align || 'left' }}>{c.label}</span>
        ))}
      </div>
      {children}
    </div>
  );
}

export function STableRow({ cols, cells, onClick, first, style }: {
  cols: STableCol[]; cells: ReactNode[]; onClick?: () => void; first?: boolean; style?: CSSProperties;
}) {
  const grid = cols.map((c) => c.w || '1fr').join(' ');
  return (
    <div onClick={onClick} className="row-hover" style={{ display: 'grid', gridTemplateColumns: grid, gap: 14, padding: '12px 18px', borderTop: first ? 'none' : '1px solid var(--app-border)', alignItems: 'center', cursor: onClick ? 'pointer' : 'default', ...style }}>
      {cells.map((cell, i) => <div key={i} style={{ minWidth: 0, textAlign: cols[i]?.align || 'left' }}>{cell}</div>)}
    </div>
  );
}

export function SMeter({ pct, label, value, tone }: { pct: number; label: string; value: string; tone?: string }) {
  const c = tone || 'var(--accent)';
  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 6 }}>
        <span style={{ fontSize: 12.5, color: 'var(--app-t2)' }}>{label}</span>
        <span className="mono" style={{ fontSize: 12, color: 'var(--app-t1)', fontWeight: 600 }}>{value}</span>
      </div>
      <div style={{ height: 8, borderRadius: 40, background: 'var(--app-track)', overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${Math.min(100, Math.max(0, pct))}%`, borderRadius: 40, background: pct >= 85 ? 'var(--danger)' : c }} />
      </div>
    </div>
  );
}

export function SDanger({ title, desc, btn, onClick }: { title: string; desc: string; btn: string; onClick?: () => void }) {
  return (
    <div className="panel" style={{ padding: 18, border: '1px solid color-mix(in srgb, var(--danger) 30%, transparent)', display: 'flex', alignItems: 'center', gap: 16 }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--danger-text)' }}>{title}</div>
        <div style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 2, lineHeight: 1.5 }}>{desc}</div>
      </div>
      <button onClick={onClick} className="ui-btn sm" style={{ borderColor: 'color-mix(in srgb, var(--danger) 40%, transparent)', color: 'var(--danger-text)', flex: 'none' }}>{btn}</button>
    </div>
  );
}

/** Centered loading / error / empty notice inside a panel (same shape as the discovery pages). */
export function StateNote({ icon, tone, title, message }: { icon: string; tone: string; title: string; message: string }) {
  return (
    <div style={{ padding: '56px 24px', textAlign: 'center', color: 'var(--app-t3)' }}>
      <Icon name={icon} size={26} style={{ color: tone, opacity: 0.8 }} />
      <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--app-t1)', marginTop: 12 }}>{title}</div>
      <div style={{ fontSize: 12.5, marginTop: 4 }}>{message}</div>
    </div>
  );
}

export function relTime(iso?: string | null): string {
  if (!iso) return '—';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '—';
  const mins = (Date.now() - t) / 60000;
  if (mins < 1) return 'just now';
  if (mins < 60) return `${Math.floor(mins)}m ago`;
  if (mins < 1440) return `${Math.floor(mins / 60)}h ago`;
  return `${Math.floor(mins / 1440)}d ago`;
}

/** Health/status palette shared by settings pages (mock's HEALTH map). */
export const HEALTH: Record<string, string> = { ok: 'var(--ok)', degraded: 'var(--warn)', down: 'var(--danger)' };
export const GREEN = 'var(--ok)';
export const AMBER = 'var(--warn)';
export const RED = 'var(--danger)';
