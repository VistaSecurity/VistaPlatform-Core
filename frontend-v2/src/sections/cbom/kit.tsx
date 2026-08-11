// Shared bits for the CBOM section — page scaffolding, the loading/error/empty
// Note guard, value formatters, and the diff-category palette. Pages compose
// these; nothing here fetches. Mirrors the discovery section's kit pattern so
// the two read alike (components/ui is stream-1-owned and stays read-only).
import { Icon } from '../../components/ui';
import type { DiffChange } from './queries';

// ---- formatters -----------------------------------------------------------
export function fmtBytes(n?: number | null): string {
  if (n == null) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export function fmtDate(iso?: string | null): string {
  if (!iso) return '—';
  return iso.slice(0, 10);
}

export function fmtDateTime(iso?: string | null): string {
  if (!iso) return '—';
  return iso.slice(0, 16).replace('T', ' ');
}

export function relTime(iso?: string | null): string {
  if (!iso) return 'never';
  const mins = (Date.now() - new Date(iso).getTime()) / 60000;
  if (mins < 1) return 'just now';
  if (mins < 60) return `${Math.floor(mins)}m ago`;
  if (mins < 1440) return `${Math.floor(mins / 60)}h ago`;
  return `${Math.floor(mins / 1440)}d ago`;
}

export function shortHash(h?: string | null, n = 12): string {
  return h ? h.slice(0, n) : '—';
}

// ---- diff-category palette ------------------------------------------------
export interface CatMeta { c: string; bg: string; label: string; icon: string }

export const DIFF_CATEGORIES: Record<string, CatMeta> = {
  improvement: { c: 'var(--ok)', bg: 'color-mix(in srgb, var(--ok) 13%, transparent)', label: 'Improvement', icon: 'trending-up' },
  regression: { c: 'var(--danger)', bg: 'color-mix(in srgb, var(--danger) 13%, transparent)', label: 'Regression', icon: 'trending-down' },
  drift: { c: 'var(--warn)', bg: 'color-mix(in srgb, var(--warn) 14%, transparent)', label: 'Drift', icon: 'circle-alert' },
  neutral: { c: 'var(--app-t3)', bg: 'var(--app-panel2)', label: 'Neutral', icon: 'arrow-right' },
};

export function catMeta(cat: string): CatMeta {
  return DIFF_CATEGORIES[cat] ?? DIFF_CATEGORIES.neutral;
}

// Regressions first (the bad news shouldn't hide), then drift, neutral, improvement.
const CAT_RANK: Record<string, number> = { regression: 0, drift: 1, neutral: 2, improvement: 3 };
export function sortChanges(changes: DiffChange[]): DiffChange[] {
  return [...changes].sort((a, b) => (CAT_RANK[a.category] ?? 9) - (CAT_RANK[b.category] ?? 9));
}

// ---- page scaffolding -----------------------------------------------------
export function PageWrap({ title, subtitle, count, actions, children }: {
  title: string; subtitle?: string; count?: number | string; actions?: React.ReactNode; children: React.ReactNode;
}) {
  return (
    <div style={{ padding: '20px 26px 40px', height: '100%', overflowY: 'auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h2 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 16, color: 'var(--app-t1)' }}>{title}</h2>
            {count != null && <span className="mono" style={{ fontSize: 12, color: 'var(--app-t3)' }}>{count}</span>}
          </div>
          {subtitle && <div style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 3 }}>{subtitle}</div>}
        </div>
        {actions}
      </div>
      {children}
    </div>
  );
}

export function Note({ icon, tone, title, message, panel }: { icon: string; tone: string; title: string; message?: string; panel?: boolean }) {
  const body = (
    <div style={{ padding: '56px 24px', textAlign: 'center', color: 'var(--app-t3)' }}>
      <Icon name={icon} size={26} style={{ color: tone, opacity: 0.85 }} />
      <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--app-t1)', marginTop: 12 }}>{title}</div>
      {message && <div style={{ fontSize: 12.5, marginTop: 4, maxWidth: 360, marginLeft: 'auto', marginRight: 'auto', lineHeight: 1.55 }}>{message}</div>}
    </div>
  );
  return panel ? <div className="panel" style={{ borderRadius: 14 }}>{body}</div> : body;
}

// Standard query-state guard: returns a Note to render, or null when data is ready.
export function queryNote(
  q: { isLoading: boolean; isError: boolean; error: unknown },
  empty: boolean,
  names: { thing: string; emptyTitle?: string; emptyMessage?: string; emptyIcon?: string },
): React.ReactNode | null {
  if (q.isError) return <Note panel icon="alert-triangle" tone="var(--danger-text)" title={`Couldn't load ${names.thing}`} message={q.error instanceof Error ? q.error.message : 'Request failed'} />;
  if (q.isLoading) return <Note panel icon="loader" tone="var(--app-t3)" title={`Loading ${names.thing}…`} />;
  if (empty) return <Note panel icon={names.emptyIcon || 'file-badge'} tone="var(--app-t3)" title={names.emptyTitle || `No ${names.thing}`} message={names.emptyMessage || `No ${names.thing} for this tenant yet.`} />;
  return null;
}

export function Pill({ icon, color, bg, children }: { icon?: string; color: string; bg?: string; children: React.ReactNode }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, height: 22, padding: '0 9px', borderRadius: 7, border: '1px solid var(--app-border2)', background: bg || 'var(--app-panel2)', fontSize: 11, fontWeight: 600, color, whiteSpace: 'nowrap' }}>
      {icon && <Icon name={icon} size={12} />}{children}
    </span>
  );
}
