/**
 * Circular gauge for a percentage. It carries no qualitative risk band.
 *
 * The value is rounded to a whole percent for display. Callers pass values
 * straight off the API (`pqc_percentage`, a framework's `preview_score`), which
 * are floats — an unrounded gauge read "36.36363636363637%" inside an 86px
 * ring. Rounding here rather than at each call site keeps every gauge in the
 * product agreeing on one precision, the same way `formatScore` already does
 * for the framework rings.
 */
export function PercentageGauge({ value, color = 'var(--accent)', size = 132, label = '', stroke = 9 }: {
  value: number | null;
  color?: string;
  size?: number;
  label?: string;
  stroke?: number;
}) {
  const r = (size - stroke) / 2;
  const circumference = 2 * Math.PI * r;
  const known = typeof value === 'number' && Number.isFinite(value);
  const shown = known ? Math.round(value) : null;
  const bounded = shown === null ? 0 : Math.max(0, Math.min(100, shown));
  const tone = known ? color : 'var(--neutral)';
  return (
    <div style={{ display: 'inline-flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
      <div style={{ position: 'relative', width: size, height: size }} role="img" aria-label={shown !== null ? `${shown}%${label ? ` ${label}` : ''}` : `${label || 'Percentage'} unavailable`}>
        <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--app-track)" strokeWidth={stroke} />
          {known && <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={tone} strokeWidth={stroke} strokeLinecap="round" strokeDasharray={circumference} strokeDashoffset={circumference * (1 - bounded / 100)} style={{ transition: 'stroke-dashoffset .9s cubic-bezier(.2,.8,.2,1)' }} />}
        </svg>
        <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', lineHeight: 1 }}>
          <span className="mono" style={{ fontWeight: 700, fontSize: size * 0.27, color: tone, letterSpacing: '-.02em' }}>{shown !== null ? `${shown}%` : '—'}</span>
        </div>
      </div>
      {label && <span className="eyebrow-app">{label}</span>}
    </div>
  );
}
