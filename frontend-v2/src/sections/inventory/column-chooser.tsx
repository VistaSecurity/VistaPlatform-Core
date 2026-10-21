// The Columns menu on Inventory → All assets: show any column the lens knows
// (the optional ones, the commercial lifecycle, all of a class's attributes),
// hide a default one, search the list, reset to the default.
//
// The choice is a per-person convenience, remembered the way the lenses'
// other view choices are (the network map's layout, the observations view): in
// the browser's localStorage, under a key that names the signed-in user and the
// lens, so two people sharing a browser do not share a column set. Nothing
// about it is tenant data and nothing else reads it. Storage that is blocked or
// full (a private window) only means the choice is not remembered — the lens
// still renders its defaults.
import { useCallback, useMemo, useState } from 'react';
import { useOptionalAuth } from '@vistasecurity/primitives/auth';
import { Icon } from '../../components/ui';
import { columnGroupsForClass, columnsForClass, isColumnVisible, type ColumnVisibility } from './columns';

const STORAGE_PREFIX = 'vista.inventory.columns.v1';

/** The localStorage key for one person's choice on one lens. */
export function columnPrefsKey(userId: string | null | undefined, lens: string): string {
  return `${STORAGE_PREFIX}:${userId ?? 'anonymous'}:${lens}`;
}

/** A stored value back to an override map; anything malformed is no choice. */
export function parseColumnPrefs(raw: unknown): ColumnVisibility {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const out: Record<string, boolean> = {};
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof v === 'boolean') out[k] = v;
  }
  return out;
}

function load(key: string): ColumnVisibility {
  try {
    const raw = window.localStorage.getItem(key);
    return raw ? parseColumnPrefs(JSON.parse(raw)) : {};
  } catch {
    return {};
  }
}

function save(key: string, v: ColumnVisibility) {
  try {
    if (Object.keys(v).length === 0) window.localStorage.removeItem(key);
    else window.localStorage.setItem(key, JSON.stringify(v));
  } catch {
    // Blocked or full storage: the choice holds for this visit only.
  }
}

/** The signed-in person's column overrides for a lens, and the writers. */
export function useColumnPrefs(lens: string) {
  const userId = useOptionalAuth()?.user?.id;
  const key = columnPrefsKey(userId, lens);
  // Held with the key it was read under, so a different user (or lens) reads
  // their own choice instead of inheriting this one — the session's user
  // arrives after the first render, so the key does change.
  const [state, setState] = useState(() => ({ key, value: load(key) }));
  let overrides = state.value;
  if (state.key !== key) {
    overrides = load(key);
    setState({ key, value: overrides });
  }
  const set = useCallback((next: ColumnVisibility) => {
    save(key, next);
    setState({ key, value: next });
  }, [key]);
  return { overrides, set, reset: useCallback(() => set({}), [set]) };
}

export function ColumnChooser({ classKey, overrides, onChange, onReset }: {
  classKey: string | null | undefined;
  overrides: ColumnVisibility;
  onChange: (next: ColumnVisibility) => void;
  onReset: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const groups = useMemo(() => columnGroupsForClass(classKey), [classKey]);
  const defaults = useMemo(() => new Set(columnsForClass(classKey).map((c) => c.key)), [classKey]);
  const needle = search.trim().toLowerCase();
  const shownGroups = groups
    .map((g) => ({ ...g, columns: g.columns.filter((c) => !needle || c.label.toLowerCase().includes(needle)) }))
    .filter((g) => g.columns.length > 0);
  const all = groups.flatMap((g) => g.columns);
  const shownCount = all.filter((c) => isColumnVisible(c.key, defaults, overrides)).length;
  // "Changed" is about what the table shows, not about stored keys: an
  // override equal to the default changes nothing.
  const changed = all.some((c) => isColumnVisible(c.key, defaults, overrides) !== defaults.has(c.key));

  const toggle = (key: string) => {
    const next: Record<string, boolean> = { ...overrides };
    const want = !isColumnVisible(key, defaults, overrides);
    // Back to the default is no override at all, so the column follows the
    // class facet again.
    if (want === defaults.has(key)) delete next[key];
    else next[key] = want;
    onChange(next);
  };

  return (
    <div style={{ position: 'relative' }}>
      <button
        className="ui-btn" onClick={() => setOpen((o) => !o)} aria-haspopup="dialog" aria-expanded={open}
        title="Choose the columns this list shows"
        style={{ height: 33, padding: '0 11px', fontSize: 12.5 }}
      >
        <Icon name="list-checks" size={13} />Columns
        {changed && <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>{shownCount}</span>}
        <Icon name="chevron-down" size={12} />
      </button>
      {open && (
        <>
          <div onClick={() => setOpen(false)} style={{ position: 'fixed', inset: 0, zIndex: 30 }} />
          <div
            role="dialog" aria-label="Columns" data-testid="column-chooser"
            style={{ position: 'absolute', zIndex: 31, top: 37, right: 0, width: 260, maxHeight: 380, display: 'flex', flexDirection: 'column', borderRadius: 11, border: '1px solid var(--app-border2)', background: 'var(--app-panel)', boxShadow: '0 12px 34px rgba(0,0,0,.24)', padding: 6 }}
          >
            <div style={{ position: 'relative', marginBottom: 4 }}>
              <Icon name="search" size={12} style={{ position: 'absolute', left: 9, top: 9, color: 'var(--app-t3)' }} />
              <input
                aria-label="Search columns" placeholder="Search columns" value={search} onChange={(e) => setSearch(e.target.value)}
                style={{ width: '100%', boxSizing: 'border-box', height: 30, padding: '0 9px 0 27px', fontSize: 12.5, borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)' }}
              />
            </div>
            <div style={{ overflowY: 'auto', flex: 1, minHeight: 0 }}>
              {shownGroups.length === 0 && (
                <div data-testid="column-chooser-empty" style={{ fontSize: 12, color: 'var(--app-t3)', padding: '9px 10px' }}>
                  No column matches “{search.trim()}”.
                </div>
              )}
              {shownGroups.map((g) => (
                <div key={g.key} role="group" aria-label={g.label}>
                  <div className="eyebrow-app" style={{ padding: '6px 9px 2px' }}>{g.label}</div>
                  {g.columns.map((c) => (
                    <label key={c.key} className="row-hover" style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '5px 9px', borderRadius: 7, cursor: 'pointer', fontSize: 12.5, color: 'var(--app-t1)' }}>
                      <input
                        type="checkbox" aria-label={c.label}
                        checked={isColumnVisible(c.key, defaults, overrides)}
                        onChange={() => toggle(c.key)}
                        style={{ margin: 0, accentColor: 'var(--accent)' }}
                      />
                      {c.label}
                    </label>
                  ))}
                </div>
              ))}
            </div>
            <div style={{ borderTop: '1px solid var(--app-border)', marginTop: 4, paddingTop: 4 }}>
              <button
                className="ui-btn sm ghost" disabled={!changed} onClick={onReset}
                title={changed ? 'Show the default columns for this class' : 'Already showing the default columns'}
                style={{ width: '100%', justifyContent: 'flex-start', opacity: changed ? 1 : 0.5 }}
              ><Icon name="refresh" size={12} />Reset to default</button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
