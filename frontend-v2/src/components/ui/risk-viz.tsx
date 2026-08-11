import type { CSSProperties } from 'react';
import { LEVEL_ABBR, LEVELS, riskColor, levelFromScore, type RiskLevel } from './risk';

/** Square level chip with abbreviation. */
export function RiskChip({ level, size = 24 }: { level: string; size?: number }) {
  const col = riskColor(level);
  return (
    <span title={level} style={{ width: size, height: size, borderRadius: 7, flex: 'none', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', fontFamily: 'var(--font-head)', fontWeight: 800, fontSize: size * 0.5, color: col, background: `color-mix(in srgb, ${col} 12%, transparent)`, border: `1px solid color-mix(in srgb, ${col} 33%, transparent)` }}>
      {LEVEL_ABBR[level as RiskLevel] ?? '?'}
    </span>
  );
}

export function LevelDot({ level, size = 8 }: { level: string; size?: number }) {
  const c = riskColor(level);
  return <span style={{ width: size, height: size, borderRadius: 50, background: c, flex: 'none', display: 'inline-block', boxShadow: level === 'Critical' ? `0 0 7px ${c}` : 'none' }} />;
}

export function MiniBar({ pct, color = 'var(--accent)', h = 6 }: { pct: number; color?: string; h?: number }) {
  return (
    <div style={{ height: h, borderRadius: 40, background: 'var(--app-track)', overflow: 'hidden', width: '100%' }}>
      <div style={{ width: Math.max(0, Math.min(100, pct)) + '%', height: '100%', background: color, borderRadius: 40, transition: 'width .6s ease' }} />
    </div>
  );
}

/** Stacked risk-level distribution bar. */
export function LevelBar({ counts, h = 10, total }: { counts: Partial<Record<RiskLevel, number>>; h?: number; total?: number }) {
  const t = total || LEVELS.reduce((s, l) => s + (counts[l] || 0), 0) || 1;
  return (
    <div style={{ display: 'flex', height: h, borderRadius: 40, overflow: 'hidden', background: 'var(--app-track)', width: '100%' }}>
      {LEVELS.map((l) => (counts[l] ? <div key={l} title={`${l}: ${counts[l]}`} style={{ width: ((counts[l] || 0) / t) * 100 + '%', background: riskColor(l) }} /> : null))}
    </div>
  );
}

/** Headline circular gauge. */
export function RiskGauge({ score, level, size = 132, label = 'Risk index', stroke = 9 }: { score: number; level?: string; size?: number; label?: string; stroke?: number }) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score)) / 100;
  const lvl = level || levelFromScore(score);
  const col = riskColor(lvl);
  return (
    <div style={{ display: 'inline-flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
      <div style={{ position: 'relative', width: size, height: size }}>
        <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--app-track)" strokeWidth={stroke} />
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={col} strokeWidth={stroke} strokeLinecap="round" strokeDasharray={c} strokeDashoffset={c * (1 - pct)} style={{ transition: 'stroke-dashoffset .9s cubic-bezier(.2,.8,.2,1)' }} />
        </svg>
        <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', lineHeight: 1 }}>
          <span className="mono" style={{ fontWeight: 700, fontSize: size * 0.34, color: col, letterSpacing: '-.02em' }}>{score}</span>
          <span style={{ fontSize: size * 0.092, color: col, fontWeight: 600, marginTop: 4, textTransform: 'uppercase', letterSpacing: '.06em' }}>{lvl}</span>
        </div>
      </div>
      {label && <span className="eyebrow-app">{label}</span>}
    </div>
  );
}

/** Tiny area sparkline. */
export function Sparkline({ data, w = 220, h = 46, color = 'var(--accent)', fill = true }: { data: number[]; w?: number; h?: number; color?: string; fill?: boolean }) {
  if (data.length < 2) return null;
  const min = Math.min(...data), max = Math.max(...data), rng = max - min || 1;
  const pts = data.map((v, i) => [(i / (data.length - 1)) * w, h - ((v - min) / rng) * (h - 6) - 3] as const);
  const d = pts.map((p, i) => (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1)).join(' ');
  const gid = 'spk' + Math.round(data[0] * 13 + data.length);
  const last = pts[pts.length - 1];
  return (
    <svg width={w} height={h} style={{ display: 'block', overflow: 'visible' }}>
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.28" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      {fill && <path d={d + ` L${w} ${h} L0 ${h} Z`} fill={`url(#${gid})`} />}
      <path d={d} fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={last[0]} cy={last[1]} r="3" fill={color} />
    </svg>
  );
}

export function Pill({ children, color, tone = 'soft', style }: { children: React.ReactNode; color?: string; tone?: 'soft' | 'solid' | 'outline'; style?: CSSProperties }) {
  const base = color || 'var(--app-t2)';
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '3px 10px', borderRadius: 40, fontSize: 12, fontWeight: 600, fontFamily: 'var(--font-body)', color: tone === 'solid' ? '#0A0A0A' : base, background: tone === 'solid' ? base : `color-mix(in srgb, ${base} 11%, transparent)`, border: tone === 'outline' ? `1px solid color-mix(in srgb, ${base} 33%, transparent)` : 'none', whiteSpace: 'nowrap', ...style }}>
      {children}
    </span>
  );
}
