// The Certificates lens's Trust filter and its built-in views ( slice 3).
//
// The lens filters through `GET /certificates` parameters rather than the
// Inventory query language, so this is a multi-select over `trust_status`
// written to the URL (`?trust=untrusted,distrusted`), not a facet-rail term.
// The words are trust-status.ts's, so what a person filters by is what the
// row chip and the drawer say.
//
// No counts beside the values: the certificates endpoint returns a page and a
// total, not per-status counts, and a number here would have to be invented.
import { useState } from 'react';
import { Icon } from '../../components/ui';
import {
  TRUST_FILTER_VALUES, TRUST_TONE_COLOR, trustFilterPresentation, parseTrustFilter,
  type TrustFilterValue,
} from './trust-status';
import { CERTIFICATE_BUILTIN_VIEWS, type CertificateBuiltinView } from './builtin-views';

function sameSelection(a: readonly string[], b: readonly string[]): boolean {
  const x = parseTrustFilter(a.join(','));
  const y = parseTrustFilter(b.join(','));
  return x.length === y.length && x.every((v, i) => v === y[i]);
}

/** The built-in view a selection is exactly, if any — named on the button. */
export function certificateViewFor(trust: readonly string[]): CertificateBuiltinView | undefined {
  if (trust.length === 0) return undefined;
  return CERTIFICATE_BUILTIN_VIEWS.find((v) => sameSelection(v.trust, trust));
}

/** Button text for the filter: "Trust", one label, or "Trust · N". */
export function trustFilterSummary(selected: readonly TrustFilterValue[]): string {
  if (selected.length === 0) return 'Trust';
  if (selected.length === 1) return `Trust: ${trustFilterPresentation(selected[0]).label}`;
  return `Trust · ${selected.length}`;
}

/**
 * Whether the lens shows the Trust filter. Hidden only when the tenant has no
 * certificates at all — a filter over nothing is noise (spec: "facet hidden
 * when 0 certs"). An active selection always shows, so it can be cleared, and
 * an empty page under a search or another filter is not "no certificates".
 */
export function trustFilterVisible(s: { selected: readonly string[]; loaded: boolean; total: number; narrowed: boolean }): boolean {
  return s.selected.length > 0 || !s.loaded || s.total > 0 || s.narrowed;
}

const popover: React.CSSProperties = {
  position: 'absolute', zIndex: 31, top: 35, left: 0, minWidth: 236, borderRadius: 11,
  border: '1px solid var(--app-border2)', background: 'var(--app-panel)', boxShadow: '0 12px 34px rgba(0,0,0,.24)', padding: 6,
};

export function CertTrustFilter({ value, onChange }: { value: readonly TrustFilterValue[]; onChange: (next: TrustFilterValue[]) => void }) {
  const [open, setOpen] = useState(false);
  const active = value.length > 0;
  const toggle = (v: TrustFilterValue) => {
    const next = value.includes(v) ? value.filter((x) => x !== v) : [...value, v];
    onChange(parseTrustFilter(next.join(',')));
  };
  return (
    <div style={{ position: 'relative' }}>
      <button
        type="button"
        aria-haspopup="true"
        aria-expanded={open}
        data-testid="cert-trust-filter"
        onClick={() => setOpen((o) => !o)}
        title="Filter by where each certificate's chain ends, as your organisation's trust decisions see it"
        style={{ height: 31, padding: '0 9px', borderRadius: 9, border: `1px solid ${active ? 'var(--accent)' : 'var(--app-border2)'}`, background: 'var(--app-panel2)', color: active ? 'var(--app-t1)' : 'var(--app-t2)', fontSize: 12.5, cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: 5 }}
      >
        <Icon name="badge-check" size={13} />{trustFilterSummary(value)}<Icon name="chevron-down" size={12} />
      </button>
      {open && (
        <>
          <div onClick={() => setOpen(false)} style={{ position: 'fixed', inset: 0, zIndex: 30 }} />
          <div role="group" aria-label="Trust" style={popover}>
            {TRUST_FILTER_VALUES.map((v) => {
              const p = trustFilterPresentation(v);
              const checked = value.includes(v);
              return (
                <label key={v} title={p.explanation} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '5px 6px', cursor: 'pointer', fontSize: 12.5, color: checked ? 'var(--app-t1)' : 'var(--app-t2)', borderRadius: 7 }}>
                  <input type="checkbox" checked={checked} onChange={() => toggle(v)} aria-label={p.label} style={{ accentColor: 'var(--accent)', width: 13, height: 13 }} />
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: TRUST_TONE_COLOR[p.tone], flex: 'none' }} />
                  <span style={{ flex: 1, fontWeight: checked ? 600 : 400 }}>{p.label}</span>
                </label>
              );
            })}
            {active && (
              <button type="button" className="ui-btn ghost sm" onClick={() => { onChange([]); setOpen(false); }} style={{ width: '100%', justifyContent: 'flex-start', marginTop: 4 }}>
                <Icon name="x" size={12} />Any trust status
              </button>
            )}
          </div>
        </>
      )}
    </div>
  );
}

/** The lens's built-in views. Not saved, shared or deletable — every tenant has them. */
export function CertificateViews({ trust, onApply }: { trust: readonly TrustFilterValue[]; onApply: (trust: TrustFilterValue[]) => void }) {
  const [open, setOpen] = useState(false);
  const current = certificateViewFor(trust);
  return (
    <div style={{ position: 'relative' }}>
      <button type="button" className="ui-btn" onClick={() => setOpen((o) => !o)} title="Views" style={{ height: 31, padding: '0 11px', fontSize: 12.5, maxWidth: 230 }}>
        <Icon name="bookmark" size={13} />
        <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{current ? current.name : 'Views'}</span>
        <Icon name="chevron-down" size={12} />
      </button>
      {open && (
        <>
          <div onClick={() => setOpen(false)} style={{ position: 'fixed', inset: 0, zIndex: 30 }} />
          <div role="menu" style={{ ...popover, minWidth: 268 }}>
            {CERTIFICATE_BUILTIN_VIEWS.map((v) => (
              <button
                key={v.name}
                type="button"
                role="menuitem"
                className="row-hover"
                title={v.description}
                onClick={() => { onApply([...v.trust]); setOpen(false); }}
                style={{ display: 'block', width: '100%', textAlign: 'left', padding: '7px 9px', border: 'none', borderRadius: 8, background: 'transparent', cursor: 'pointer', color: 'var(--app-t1)' }}
              >
                <div style={{ fontSize: 12.5, fontWeight: current === v ? 700 : 500, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Icon name="shield-alert" size={12} style={{ color: 'var(--app-t3)' }} />{v.name}
                </div>
                <div style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>{v.description}</div>
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
