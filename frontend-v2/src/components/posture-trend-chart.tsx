// Posture trend line (ADR-0007) — the dashboard hero + Posture Overview share
// this. Plots the daily risk index (0–100, % of assets at high risk; the same
// metric the hero gauge shows, higher = worse). The pre-history prefix a brand-
// new tenant gets (points with `seeded: true`, drawn flat at the current
// posture until real snapshots accrue) is rendered dashed + dimmed and labeled
// "baseline" so it never reads as measured history.

export type PostureTrendPoint = { date: string; risk_index: number; seeded: boolean };

const ACCENT = 'var(--accent)';
const VB_W = 700; // viewBox units; the SVG scales to its container width
const PAD = 6; // vertical breathing room (units) so 0 and 100 aren't clipped

function ptX(i: number, n: number): number {
  if (n <= 1) return VB_W / 2;
  return (i / (n - 1)) * VB_W;
}

// risk index 0 (best) at the bottom, 100 (worst) at the top.
function ptY(idx: number, h: number): number {
  const clamped = Math.max(0, Math.min(100, idx));
  return h - PAD - (clamped / 100) * (h - PAD * 2);
}

function polyline(pts: PostureTrendPoint[], from: number, to: number, h: number): string {
  const seg: string[] = [];
  for (let i = from; i <= to; i++) {
    seg.push(`${ptX(i, pts.length).toFixed(1)},${ptY(pts[i].risk_index, h).toFixed(1)}`);
  }
  return seg.join(' ');
}

export function PostureTrendChart({ points, height = 150 }: { points: PostureTrendPoint[]; height?: number }) {
  const h = height;
  const n = points.length;
  if (n === 0) return null;

  // Seeded days are always a contiguous leading prefix; the first non-seeded
  // point is where measured history begins. Draw [0..boundary] dashed and
  // [boundary..end] solid so the two share a vertex and connect cleanly.
  let boundary = points.findIndex((p) => !p.seeded);
  if (boundary < 0) boundary = n - 1; // all seeded (shouldn't happen — today is live)
  const hasSeed = boundary > 0;

  const last = points[n - 1];
  const lastX = ptX(n - 1, n);
  const lastY = ptY(last.risk_index, h);

  // Area fill under the full line.
  const areaPts = polyline(points, 0, n - 1, h);
  const areaPath = `${areaPts} ${VB_W},${h} 0,${h}`;

  const gid = 'posture-trend-fill';

  return (
    <div style={{ width: '100%' }}>
      <svg viewBox={`0 0 ${VB_W} ${h}`} preserveAspectRatio="none" width="100%" height={h} role="img" aria-label="Posture risk-index trend">
        <defs>
          <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={ACCENT} stopOpacity="0.28" />
            <stop offset="100%" stopColor={ACCENT} stopOpacity="0" />
          </linearGradient>
        </defs>

        {/* faint mid reference (risk index 50) */}
        <line x1="0" y1={ptY(50, h)} x2={VB_W} y2={ptY(50, h)} stroke="var(--app-border)" strokeWidth="1" strokeDasharray="3 5" vectorEffect="non-scaling-stroke" />

        <polygon points={areaPath} fill={`url(#${gid})`} />

        {hasSeed && (
          <polyline
            points={polyline(points, 0, boundary, h)}
            fill="none"
            stroke={ACCENT}
            strokeOpacity="0.4"
            strokeWidth="2"
            strokeDasharray="5 5"
            strokeLinecap="round"
            vectorEffect="non-scaling-stroke"
          />
        )}
        <polyline
          points={polyline(points, boundary, n - 1, h)}
          fill="none"
          stroke={ACCENT}
          strokeWidth="2.25"
          strokeLinecap="round"
          strokeLinejoin="round"
          vectorEffect="non-scaling-stroke"
        />

        {/* today marker */}
        <circle cx={lastX} cy={lastY} r="3.5" fill={ACCENT} vectorEffect="non-scaling-stroke" />
      </svg>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 10.5, color: 'var(--app-t3)', marginTop: 6 }}>
        <span>{points.length - 1} days ago</span>
        {hasSeed && (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
            <span style={{ width: 14, height: 0, borderTop: `2px dashed ${ACCENT}`, opacity: 0.5 }} />
            baseline · history still accruing
          </span>
        )}
        <span>today</span>
      </div>
    </div>
  );
}
