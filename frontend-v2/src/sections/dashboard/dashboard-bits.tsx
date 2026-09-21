// Shared chrome for the focused dashboards (Assets · Compliance · PQC).
//
// The Overview dashboard builds its own panels inline; these three do not,
// because they are the same shapes over and over and a fourth hand-rolled copy
// of "a panel with a heading, a caption, and one of five states" is where the
// three states that matter start going missing.
//
// The states are the point. Every panel here takes `loading` and `error`
// EXPLICITLY rather than inferring them from an empty array, because
// "we could not ask" and "there are none" render identically otherwise — and a
// reassuring zero is exactly what a reader takes at face value. This is the
// same rule `inventory-health.ts` spells out for the shared Dashboard's hero,
// applied to a component boundary instead of an arithmetic one.
import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { Icon } from '../../components/ui';
import type { BucketRow } from './assets-dashboard-metrics';

/** The page title block every focused dashboard opens with. */
export function DashboardHeader({ icon, title, blurb }: { icon: string; title: string; blurb: string }) {
  return (
    <div className="fade-up" style={{ display: 'flex', alignItems: 'flex-start', gap: 12, marginBottom: 18 }}>
      <span style={{
        width: 34, height: 34, borderRadius: 10, flex: 'none', display: 'flex', alignItems: 'center',
        justifyContent: 'center', background: 'var(--accent-gradient)', color: 'var(--accent-fg)',
      }}>
        <Icon name={icon} size={18} />
      </span>
      <div>
        <h1 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 19, color: 'var(--app-t1)', letterSpacing: '-.01em' }}>
          {title}
        </h1>
        <p style={{ margin: '3px 0 0', fontSize: 12.5, color: 'var(--app-t3)', maxWidth: 780, lineHeight: 1.45 }}>{blurb}</p>
      </div>
    </div>
  );
}

/** A section heading between bands of panels. */
export function BandHeading({ title, note }: { title: string; note?: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 11 }}>
      <h2 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14.5, color: 'var(--app-t1)' }}>{title}</h2>
      {note && <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>— {note}</span>}
    </div>
  );
}

/**
 * A panel with all five states.
 *
 * `error` wins over `loading` wins over `empty`: a failed request that is also
 * "empty" must never render the empty sentence, which is an assertion about the
 * tenant's data made on the strength of a request that did not answer. That
 * exact collapse turned a 500 from the `site` facet into the sentence "No sites
 * recorded."
 */
export function Panel({
  icon, title, caption, loading, error, empty, emptyText, children, footer, testId,
}: {
  icon?: string;
  title: string;
  caption?: string;
  loading?: boolean;
  error?: boolean;
  empty?: boolean;
  emptyText?: string;
  children: ReactNode;
  footer?: ReactNode;
  testId?: string;
}) {
  return (
    <div className="panel" data-testid={testId} style={{ padding: 20, display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: caption ? 2 : 14 }}>
        {icon && <Icon name={icon} size={14} style={{ color: 'var(--accent)' }} />}
        <h3 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14.5, color: 'var(--app-t1)' }}>{title}</h3>
      </div>
      {caption && <p style={{ margin: '0 0 15px', fontSize: 11.5, color: 'var(--app-t3)' }}>{caption}</p>}
      {error ? (
        <PanelNote tone="var(--danger-text)">Couldn't load this.</PanelNote>
      ) : loading ? (
        <PanelNote>Loading…</PanelNote>
      ) : empty ? (
        <PanelNote>{emptyText ?? 'Nothing to show yet.'}</PanelNote>
      ) : (
        children
      )}
      {footer && !error && !loading && <div style={{ marginTop: 'auto', paddingTop: 13 }}>{footer}</div>}
    </div>
  );
}

export function PanelNote({ children, tone }: { children: ReactNode; tone?: string }) {
  return <div style={{ fontSize: 12, color: tone ?? 'var(--app-t3)', padding: '6px 0' }}>{children}</div>;
}

/**
 * A count with a label, and a `null` that stays null.
 *
 * `value === null` renders an em dash, not a zero. Every tile on these pages
 * that can fail to load goes through here rather than defaulting with `?? 0`,
 * because the whole difference between "none" and "unknown" lives in that one
 * character.
 */
export function StatTile({
  value, label, sub, tone, icon, href, error,
}: {
  value: number | string | null;
  label: string;
  sub?: string;
  tone?: string;
  icon?: string;
  href?: string | null;
  error?: boolean;
}) {
  const shown = error || value === null ? '—' : typeof value === 'number' ? value.toLocaleString() : value;
  const body = (
    <>
      <span style={{ position: 'absolute', left: 0, top: 0, bottom: 0, width: 3, background: tone ?? 'var(--accent)' }} />
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        {icon ? <Icon name={icon} size={16} style={{ color: tone ?? 'var(--accent)' }} /> : <span />}
        {href && <Icon name="arrow-up-right" size={13} style={{ color: 'var(--app-t3)' }} />}
      </div>
      <div className="mono" style={{
        fontSize: 27, fontWeight: 800, margin: '10px 0 3px', letterSpacing: '-.02em',
        color: error ? 'var(--danger-text)' : 'var(--app-t1)',
      }}>{shown}</div>
      <div style={{ fontSize: 11.5, fontWeight: 600, color: 'var(--app-t1)', lineHeight: 1.25 }}>{label}</div>
      <div style={{ fontSize: 10.5, color: error ? 'var(--danger-text)' : 'var(--app-t3)', marginTop: 1 }}>
        {error ? "Couldn't load" : sub}
      </div>
    </>
  );
  const style: React.CSSProperties = {
    padding: '14px 15px', textAlign: 'left', position: 'relative', overflow: 'hidden',
    display: 'flex', flexDirection: 'column', textDecoration: 'none',
  };
  return href && !error ? (
    <Link to={href} className="panel" style={{ ...style, cursor: 'pointer' }}>{body}</Link>
  ) : (
    <div className="panel" style={style}>{body}</div>
  );
}

/** The responsive grid the stat strips and panel bands both use. */
export function Grid({ min = 320, gap = 14, children, style }: { min?: number; gap?: number; children: ReactNode; style?: React.CSSProperties }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: `repeat(auto-fit, minmax(${min}px, 1fr))`, gap, alignItems: 'start', ...style }}>
      {children}
    </div>
  );
}

/**
 * A list of bucket bars.
 *
 * A row whose `href` is null renders as plain text rather than a link. That is
 * deliberate and it is the honest half of this component: the facet levels with
 * no query field behind them (`operating_system`, `has_endpoints`) would
 * otherwise link at the unfiltered asset list — a row reading "12" that opens
 * every asset in the tenant. See `drillThrough`.
 */
export function BucketBars({ rows, total, colorFor }: {
  rows: BucketRow[];
  total: number;
  colorFor?: (row: BucketRow) => string;
}) {
  const max = Math.max(...rows.map((r) => r.count), 1);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 9 }}>
      {rows.map((r) => {
        const share = total > 0 ? Math.round((r.count / total) * 100) : 0;
        const color = colorFor?.(r) ?? 'accent';
        const inner = (
          <>
            <span style={{
              fontSize: 11.5, color: r.other ? 'var(--app-t3)' : 'var(--app-t2)', width: 116, flex: 'none',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            }} title={r.label}>{r.label}</span>
            <div style={{ flex: 1, height: 15, borderRadius: 5, background: 'var(--app-track)', overflow: 'hidden' }}>
              <div style={{
                width: (r.count / max) * 100 + '%', height: '100%', borderRadius: 5,
                background: color === 'accent' ? 'var(--accent-gradient)' : color,
                minWidth: r.count ? 3 : 0,
              }} />
            </div>
            <span className="mono" style={{ fontSize: 12, color: 'var(--app-t2)', width: 42, textAlign: 'right' }}>{r.count.toLocaleString()}</span>
            <span className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)', width: 34, textAlign: 'right' }}>{share}%</span>
          </>
        );
        const rowStyle: React.CSSProperties = { display: 'flex', alignItems: 'center', gap: 10, textDecoration: 'none' };
        return r.href ? (
          <Link key={r.value || r.label} to={r.href} style={{ ...rowStyle, cursor: 'pointer' }} className="bucket-row">{inner}</Link>
        ) : (
          <div key={r.value || r.label} style={rowStyle}>{inner}</div>
        );
      })}
    </div>
  );
}

/** A "see the whole list" link at the foot of a panel. */
export function PanelLink({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Link to={to} style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5, fontWeight: 600, color: 'var(--accent)', textDecoration: 'none' }}>
      {children}
      <Icon name="arrow-up-right" size={12} />
    </Link>
  );
}

/** The whole-page failure state, matching the shared Dashboard's. */
export function PageError({ title, message }: { title: string; message: string }) {
  return (
    <div style={{ padding: '64px 24px', textAlign: 'center', color: 'var(--app-t3)' }}>
      <Icon name="alert-triangle" size={26} style={{ color: 'var(--danger-text)' }} />
      <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--app-t1)', marginTop: 12 }}>{title}</div>
      <div style={{ fontSize: 12.5, marginTop: 4 }}>{message}</div>
    </div>
  );
}

/** The outer padding/scroll container every focused dashboard uses. */
export function DashboardShell({ children, testId }: { children: ReactNode; testId: string }) {
  return (
    <div data-testid={testId} style={{ padding: '20px 26px 44px', height: '100%', overflow: 'auto' }}>
      {children}
    </div>
  );
}
