import { useState, type ReactNode } from 'react';

export interface DonutSegment {
  key: string;
  label: string;
  count: number;
  color: string;
  /** Rendered translucent — for "no data" slices that must not read as a verdict. */
  muted?: boolean;
  /** Where clicking the slice (or its legend row) goes. Omit for a plain label. */
  onClick?: () => void;
}

export interface DonutArc {
  key: string;
  /** Visible length of the arc along the circumference. */
  length: number;
  /** Distance from the 12 o'clock start to the arc's start. */
  offset: number;
}

/**
 * Lay segments end to end around a circle of the given circumference.
 *
 * Zero-count segments are dropped. A small gap separates neighbours, but only
 * when there is more than one slice — a lone slice is a full ring, and a gap in
 * it would read as a sliver of something missing.
 */
export function donutArcs(segments: Pick<DonutSegment, 'key' | 'count'>[], circumference: number, gap = 3): DonutArc[] {
  const live = segments.filter((s) => Number.isFinite(s.count) && s.count > 0);
  const total = live.reduce((sum, s) => sum + s.count, 0);
  if (total <= 0) return [];
  const g = live.length > 1 ? gap : 0;
  let cursor = 0;
  return live.map((s) => {
    const span = (s.count / total) * circumference;
    const arc = { key: s.key, length: Math.max(0, span - g), offset: cursor };
    cursor += span;
    return arc;
  });
}

/**
 * Part-to-whole ring with a legend that carries the counts.
 *
 * The centre states the headline the caller chose (`centerValue` /
 * `centerLabel`); the ring and legend show what it is made of, so a single
 * percentage never has to explain itself.
 */
export function RiskDonut({ segments, centerValue, centerLabel, size = 132, stroke = 16, ariaLabel, children }: {
  segments: DonutSegment[];
  centerValue: string;
  centerLabel: string;
  size?: number;
  stroke?: number;
  ariaLabel: string;
  /** Extra content rendered inside a legend row, keyed by segment (e.g. a test id'd percentage). */
  children?: (segment: DonutSegment) => ReactNode;
}) {
  const [active, setActive] = useState<string | null>(null);
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const arcs = donutArcs(segments, c);
  const byKey = new Map(segments.map((s) => [s.key, s]));
  const total = segments.reduce((sum, s) => sum + (s.count > 0 ? s.count : 0), 0);

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 18 }}>
      <div style={{ position: 'relative', flex: 'none', width: size, height: size }} role="img" aria-label={ariaLabel}>
        <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }} aria-hidden>
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--app-track)" strokeWidth={stroke} />
          {arcs.map((a) => {
            const seg = byKey.get(a.key)!;
            const dim = active !== null && active !== a.key;
            return (
              <circle
                key={a.key}
                data-testid={`risk-donut-arc-${a.key}`}
                cx={size / 2} cy={size / 2} r={r} fill="none"
                stroke={seg.color}
                strokeWidth={active === a.key ? stroke + 3 : stroke}
                strokeDasharray={`${a.length} ${c - a.length}`}
                strokeDashoffset={-a.offset}
                opacity={dim ? 0.25 : seg.muted ? 0.45 : 1}
                style={{ cursor: seg.onClick ? 'pointer' : 'default', transition: 'opacity .15s, stroke-width .15s' }}
                onMouseEnter={() => setActive(a.key)}
                onMouseLeave={() => setActive(null)}
                onClick={seg.onClick}
              >
                <title>{`${seg.label}: ${seg.count.toLocaleString()}`}</title>
              </circle>
            );
          })}
        </svg>
        <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', lineHeight: 1, textAlign: 'center', padding: stroke + 6 }}>
          <span className="accent-text" style={{ fontFamily: 'var(--font-head)', fontWeight: 800, fontSize: size * 0.27, letterSpacing: '-.03em' }}>{centerValue}</span>
          <span style={{ fontSize: 10, color: 'var(--app-t3)', marginTop: 5, lineHeight: 1.2 }}>{centerLabel}</span>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
        {segments.map((s) => {
          const Row = s.onClick ? 'button' : 'div';
          return (
            <Row
              key={s.key}
              data-testid={`risk-donut-legend-${s.key}`}
              onClick={s.onClick}
              onMouseEnter={() => setActive(s.key)}
              onMouseLeave={() => setActive(null)}
              style={{
                display: 'flex', alignItems: 'center', gap: 8, padding: '3px 6px', margin: '0 -6px', borderRadius: 6,
                background: active === s.key ? 'var(--app-track)' : 'transparent', border: 0, font: 'inherit',
                color: 'inherit', textAlign: 'left', cursor: s.onClick ? 'pointer' : 'default', opacity: s.count > 0 ? 1 : 0.55,
              }}
            >
              <span style={{ width: 9, height: 9, borderRadius: 3, flex: 'none', background: s.color, opacity: s.muted ? 0.45 : 1 }} />
              <span style={{ fontSize: 11.5, color: 'var(--app-t2)', flex: 1, whiteSpace: 'nowrap' }}>{s.label}</span>
              <span className="mono" style={{ fontSize: 12, fontWeight: 700, color: 'var(--app-t1)' }}>{s.count.toLocaleString()}</span>
              {children?.(s)}
            </Row>
          );
        })}
        {total > 0 && (
          <div style={{ fontSize: 10.5, color: 'var(--app-t3)', marginTop: 4 }}>{total.toLocaleString()} monitored assets</div>
        )}
      </div>
    </div>
  );
}
