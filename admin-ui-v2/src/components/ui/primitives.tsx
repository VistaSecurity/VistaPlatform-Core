// VISTA Operations — shared primitives (TS port of the kit's ops-primitives.jsx).
// Instrument-grade, theme-aware, reused across every section. Icons are
// lucide-react components passed in directly (no string registry).
import type { CSSProperties, ReactNode } from 'react';
import { type LucideIcon, Crown, TrendingUp, TrendingDown, ArrowUpRight } from 'lucide-react';

/* ---------------- status color system (operational signals) ---------------- */
type StatusMeta = { c: string; label: string };
const STATUS: Record<string, StatusMeta> = {
  online: { c: 'var(--ok)', label: 'Online' }, operational: { c: 'var(--ok)', label: 'Operational' },
  active: { c: 'var(--ok)', label: 'Active' }, success: { c: 'var(--ok)', label: 'Success' },
  paid: { c: 'var(--ok)', label: 'Paid' }, on: { c: 'var(--ok)', label: 'On' },
  healthy: { c: 'var(--ok)', label: 'Healthy' }, unknown: { c: 'var(--neutral)', label: 'Unknown' },
  running: { c: 'var(--info)', label: 'Running' }, investigating: { c: 'var(--info)', label: 'Investigating' },
  onboarding: { c: 'var(--info)', label: 'Onboarding' },
  queued: { c: 'var(--neutral)', label: 'Queued' }, idle: { c: 'var(--neutral)', label: 'Idle' },
  off: { c: 'var(--neutral)', label: 'Off' }, invited: { c: 'var(--neutral)', label: 'Invited' },
  completed: { c: 'var(--ok)', label: 'Completed' }, pending: { c: 'var(--neutral)', label: 'Pending' },
  cancelled: { c: 'var(--neutral)', label: 'Cancelled' }, canceled_job: { c: 'var(--neutral)', label: 'Cancelled' },
  trial: { c: 'var(--warn-deep)', label: 'Trial' }, open: { c: 'var(--warn-deep)', label: 'Open' },
  degraded: { c: 'var(--warn)', label: 'Degraded' }, partial: { c: 'var(--warn)', label: 'Partial' },
  monitoring: { c: 'var(--warn)', label: 'Monitoring' }, maintenance: { c: 'var(--chart-1)', label: 'Maintenance' },
  past_due: { c: 'var(--danger)', label: 'Past due' }, offline: { c: 'var(--danger)', label: 'Offline' },
  failed: { c: 'var(--danger)', label: 'Failed' }, suspended: { c: 'var(--danger)', label: 'Suspended' },
  down: { c: 'var(--danger)', label: 'Down' }, canceled: { c: 'var(--danger)', label: 'Canceled' },
};
export const statusOf = (k: string): StatusMeta => STATUS[k] ?? { c: 'var(--neutral)', label: k };

export function healthColor(s: number): string {
  if (s >= 85) return 'var(--ok)';
  if (s >= 70) return 'var(--ok-lime)';
  if (s >= 55) return 'var(--warn)';
  if (s >= 40) return 'var(--warn-strong)';
  return 'var(--danger)';
}
export const planColor = (p: string): string =>
  ({ Sovereign: '#E2B033', Fortress: 'var(--info)', Guardian: 'var(--neutral)', Trial: '#646C79' } as Record<string, string>)[p] ?? 'var(--neutral)';

/* ---------------- formatters ---------------- */
export const money = (n: number): string => '$' + Math.round(n).toLocaleString('en-US');
export const moneyK = (n: number): string =>
  n >= 1e6 ? '$' + (n / 1e6).toFixed(2) + 'M' : n >= 1e3 ? '$' + (n / 1e3).toFixed(n >= 1e4 ? 0 : 1) + 'k' : '$' + n;
export const num = (n: number): string => Number(n).toLocaleString('en-US');
export const numK = (n: number): string => (n >= 1e3 ? (n / 1e3).toFixed(n >= 1e4 ? 0 : 1) + 'k' : String(n));

export function initialsFromName(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return '?';
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

/** Short relative time: "8m", "3h", "2d", else an absolute date. null-safe. */
export function relTime(iso?: string | null): string {
  if (!iso) return '—';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '—';
  const sec = Math.max(0, (Date.now() - t) / 1000);
  if (sec < 60) return 'now';
  if (sec < 3600) return Math.floor(sec / 60) + 'm';
  if (sec < 86400) return Math.floor(sec / 3600) + 'h';
  if (sec < 86400 * 7) return Math.floor(sec / 86400) + 'd';
  return new Date(t).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

/* ---------------- components ---------------- */
const PULSE = new Set(['online', 'operational', 'running', 'active']);

export function StatusDot({ status, size = 8, glow = true }: { status: string; size?: number; glow?: boolean }) {
  const c = statusOf(status).c;
  return <span style={{ width: size, height: size, borderRadius: 50, background: c, flex: 'none', display: 'inline-block', boxShadow: glow && PULSE.has(status) ? `0 0 0 3px color-mix(in srgb, ${c} 13%, transparent)` : 'none' }} />;
}

export function Tag({ children, color, tone = 'soft', style, icon: IconC }: { children: ReactNode; color?: string; tone?: 'soft' | 'solid' | 'outline'; style?: CSSProperties; icon?: LucideIcon }) {
  const base = color || 'var(--op-t2)';
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, padding: IconC ? '3px 9px 3px 7px' : '3px 9px', borderRadius: 'var(--r-sm)', fontSize: 11.5, fontWeight: 600, lineHeight: 1.4, color: tone === 'solid' ? '#0A0A0A' : base, background: tone === 'solid' ? base : `color-mix(in srgb, ${base} 11%, transparent)`, border: tone === 'outline' ? `1px solid color-mix(in srgb, ${base} 33%, transparent)` : `1px solid color-mix(in srgb, ${base} 12%, transparent)`, whiteSpace: 'nowrap', ...style }}>
      {IconC && <IconC size={12} />}{children}
    </span>
  );
}

export function StatusTag({ status }: { status: string }) {
  const s = statusOf(status);
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '3px 9px 3px 8px', borderRadius: 'var(--r-sm)', fontSize: 11.5, fontWeight: 600, color: s.c, background: `color-mix(in srgb, ${s.c} 9%, transparent)`, border: `1px solid color-mix(in srgb, ${s.c} 19%, transparent)`, whiteSpace: 'nowrap' }}>
      <StatusDot status={status} size={6} glow={false} />{s.label}
    </span>
  );
}

export function PlanTag({ plan }: { plan: string }) {
  if (plan === 'Sovereign') {
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, padding: '3px 10px', borderRadius: 'var(--r-sm)', fontSize: 11.5, fontWeight: 700, color: 'var(--accent-fg)', background: 'var(--accent-gradient)', whiteSpace: 'nowrap', boxShadow: '0 0 0 1px color-mix(in srgb, var(--accent) 40%, transparent)' }}>
        <Crown size={12} />Sovereign
      </span>
    );
  }
  const c = planColor(plan);
  return <span style={{ display: 'inline-flex', alignItems: 'center', padding: '3px 10px', borderRadius: 'var(--r-sm)', fontSize: 11.5, fontWeight: 600, color: c, background: `color-mix(in srgb, ${c} 10%, transparent)`, border: `1px solid color-mix(in srgb, ${c} 20%, transparent)`, whiteSpace: 'nowrap' }}>{plan}</span>;
}

export function Avatar({ initials, size = 30, brand = false, square = false }: { initials: string; size?: number; brand?: boolean; square?: boolean }) {
  return (
    <span style={{ width: size, height: size, borderRadius: square ? 'var(--r-sm)' : 50, flex: 'none', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontSize: size * 0.4, fontWeight: 700, fontFamily: 'var(--font-head)', letterSpacing: '-.02em', color: brand ? 'var(--accent-fg)' : 'var(--op-t1)', background: brand ? 'var(--accent-gradient)' : 'var(--op-avatar)', border: brand ? 'none' : '1px solid var(--op-border2)' }}>{initials}</span>
  );
}

export function MiniBar({ pct, color = 'var(--op-accent)', h = 6, track = 'var(--op-track)' }: { pct: number; color?: string; h?: number; track?: string }) {
  return (
    <div style={{ height: h, borderRadius: 40, background: track, overflow: 'hidden', width: '100%' }}>
      <div style={{ width: Math.max(0, Math.min(100, pct)) + '%', height: '100%', background: color, borderRadius: 40, transition: 'width .6s ease' }} />
    </div>
  );
}

export function StatTile({ label, value, sub, delta, deltaGood, icon: IconC, accent, brand, onClick }: { label: string; value: ReactNode; sub?: string; delta?: string; deltaGood?: boolean; icon?: LucideIcon; accent?: string; brand?: boolean; onClick?: () => void }) {
  const col = brand ? 'var(--op-accent-text)' : accent || 'var(--op-t1)';
  return (
    <button onClick={onClick} className="op-panel" style={{ textAlign: 'left', cursor: onClick ? 'pointer' : 'default', padding: '14px 15px', display: 'block', width: '100%' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
        {IconC && <span style={{ width: 26, height: 26, borderRadius: 'var(--r-sm)', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--op-panel2)', border: '1px solid var(--op-border)', color: 'var(--op-t3)' }}><IconC size={14} /></span>}
        <span className="op-eyebrow" style={{ flex: 1 }}>{label}</span>
        {onClick && <ArrowUpRight size={14} style={{ color: 'var(--op-t3)' }} />}
      </div>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
        <span className="op-num" style={{ fontSize: 28, fontWeight: 700, color: col, letterSpacing: '-.02em', lineHeight: 1, ...(brand ? { background: 'var(--accent-gradient)', WebkitBackgroundClip: 'text', backgroundClip: 'text', WebkitTextFillColor: 'transparent' } : {}) }}>{value}</span>
        {delta && <span style={{ fontSize: 12, fontWeight: 600, color: deltaGood ? 'var(--ok)' : 'var(--danger)', display: 'inline-flex', alignItems: 'center', gap: 2 }}>{deltaGood ? <TrendingUp size={13} /> : <TrendingDown size={13} />}{delta}</span>}
      </div>
      {sub && <div style={{ fontSize: 12, color: 'var(--op-t3)', marginTop: 6 }}>{sub}</div>}
    </button>
  );
}

export type DonutSegment = { value: number; color: string; label?: string };

export function Donut({ segments, size = 132, stroke = 16, center }: { segments: DonutSegment[]; size?: number; stroke?: number; center?: ReactNode }) {
  const total = segments.reduce((s, x) => s + x.value, 0) || 1;
  const r = (size - stroke) / 2, c = 2 * Math.PI * r;
  let off = 0;
  return (
    <div style={{ position: 'relative', width: size, height: size }}>
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--op-track)" strokeWidth={stroke} />
        {segments.map((s, i) => {
          const len = (s.value / total) * c;
          const el = <circle key={i} cx={size / 2} cy={size / 2} r={r} fill="none" stroke={s.color} strokeWidth={stroke} strokeDasharray={`${len} ${c - len}`} strokeDashoffset={-off} style={{ transition: 'stroke-dasharray .7s ease' }} />;
          off += len; return el;
        })}
      </svg>
      {center && <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', lineHeight: 1 }}>{center}</div>}
    </div>
  );
}

export function AreaChart({ series, w = 600, h = 160, pad = 6 }: { series: { data: number[]; color: string; fill?: boolean }[]; w?: number; h?: number; pad?: number }) {
  const all = series.flatMap((s) => s.data);
  if (all.length === 0) return null;
  const min = Math.min(...all), max = Math.max(...all), rng = max - min || 1;
  const X = (i: number, n: number) => pad + (i / Math.max(1, n - 1)) * (w - pad * 2);
  const Y = (v: number) => pad + (1 - (v - min) / rng) * (h - pad * 2);
  return (
    <svg width="100%" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" style={{ display: 'block' }}>
      <defs>{series.map((s, si) => (
        <linearGradient key={si} id={'ach' + si} x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={s.color} stopOpacity="0.18" /><stop offset="100%" stopColor={s.color} stopOpacity="0" /></linearGradient>
      ))}</defs>
      {[0.25, 0.5, 0.75].map((g, i) => <line key={i} x1={0} x2={w} y1={h * g} y2={h * g} stroke="var(--op-border)" strokeWidth="1" />)}
      {series.map((s, si) => {
        const n = s.data.length;
        const d = s.data.map((v, i) => (i ? 'L' : 'M') + X(i, n).toFixed(1) + ' ' + Y(v).toFixed(1)).join(' ');
        return (
          <g key={si}>
            {s.fill !== false && <path d={d + ` L${X(n - 1, n)} ${h} L${X(0, n)} ${h} Z`} fill={`url(#ach${si})`} />}
            <path d={d} fill="none" stroke={s.color} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
          </g>
        );
      })}
    </svg>
  );
}

export function Sparkline({ data, w = 120, h = 34, color = 'var(--op-accent)', fill = true, strokeW = 1.8 }: { data: number[]; w?: number; h?: number; color?: string; fill?: boolean; strokeW?: number }) {
  if (data.length < 2) return null;
  const min = Math.min(...data), max = Math.max(...data), rng = max - min || 1;
  const pts = data.map((v, i) => [(i / (data.length - 1)) * w, h - ((v - min) / rng) * (h - 6) - 3] as const);
  const d = pts.map((p, i) => (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1)).join(' ');
  const gid = 'spk' + Math.round(data[0] * 7 + data.length + w);
  return (
    <svg width={w} height={h} style={{ display: 'block', overflow: 'visible' }}>
      <defs><linearGradient id={gid} x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={color} stopOpacity="0.22" /><stop offset="100%" stopColor={color} stopOpacity="0" /></linearGradient></defs>
      {fill && <path d={d + ` L${w} ${h} L0 ${h} Z`} fill={`url(#${gid})`} />}
      <path d={d} fill="none" stroke={color} strokeWidth={strokeW} strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={pts[pts.length - 1][0]} cy={pts[pts.length - 1][1]} r="2.4" fill={color} />
    </svg>
  );
}
