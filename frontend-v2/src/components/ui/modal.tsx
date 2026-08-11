// Modal primitive — TS port of the mock's Modal.jsx, the single shell every
// modal composes (scrim, motion, Esc + scrim-click close, focus trap, scroll
// lock, sizes, header/body/footer anatomy). Compose it; never hand-roll a
// one-off overlay. Scrim/card classes live in styles/tokens.css.
import { useEffect, useRef, type ReactNode } from 'react';
import { Icon } from './icon';

const MODAL_SIZES: Record<string, number> = { sm: 392, md: 524, lg: 688 };
const MODAL_TONES: Record<string, { c: string; bg: string }> = {
  accent: { c: 'var(--accent)', bg: 'color-mix(in srgb, var(--accent) 14%, transparent)' },
  danger: { c: 'var(--danger)', bg: 'color-mix(in srgb, var(--danger) 13%, transparent)' },
  blue: { c: 'var(--info)', bg: 'color-mix(in srgb, var(--info) 14%, transparent)' },
  green: { c: 'var(--ok)', bg: 'color-mix(in srgb, var(--ok) 14%, transparent)' },
};

export function Modal({ open, onClose, size = 'md', tone = 'accent', icon, eyebrow, title, description, children, primary, secondary, dismissible = true, footerNote }: {
  open: boolean;
  onClose?: () => void;
  size?: 'sm' | 'md' | 'lg';
  tone?: 'accent' | 'danger' | 'blue' | 'green';
  icon?: string;
  eyebrow?: string;
  title: string;
  description?: string;
  children?: ReactNode;
  primary?: ReactNode;
  secondary?: ReactNode;
  dismissible?: boolean;
  footerNote?: ReactNode;
}) {
  const cardRef = useRef<HTMLDivElement>(null);
  const lastFocus = useRef<Element | null>(null);

  useEffect(() => {
    if (!open) return;
    lastFocus.current = document.activeElement;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden'; // scroll lock
    const t = setTimeout(() => {
      const card = cardRef.current;
      if (!card) return;
      const f = card.querySelector<HTMLElement>('[data-autofocus]')
        || card.querySelector<HTMLElement>("button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])");
      (f || card).focus();
    }, 30);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && dismissible) { e.stopPropagation(); onClose?.(); return; }
      if (e.key !== 'Tab') return;
      const card = cardRef.current;
      if (!card) return; // focus trap
      const f = Array.from(card.querySelectorAll<HTMLElement>("button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])"))
        .filter((el) => !(el as HTMLButtonElement).disabled && el.offsetParent !== null);
      if (!f.length) return;
      const first = f[0];
      const last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    };
    window.addEventListener('keydown', onKey, true);
    return () => {
      clearTimeout(t);
      window.removeEventListener('keydown', onKey, true);
      document.body.style.overflow = prevOverflow;
      (lastFocus.current as HTMLElement | null)?.focus?.();
    };
  }, [open, dismissible, onClose]);

  if (!open) return null;
  const T = MODAL_TONES[tone] || MODAL_TONES.accent;
  const hasFooter = primary || secondary || footerNote;

  return (
    <div className="vmodal-scrim" onClick={() => dismissible && onClose?.()} role="presentation">
      <div
        ref={cardRef} className="vmodal" role="dialog" aria-modal="true" aria-label={title} tabIndex={-1}
        style={{ maxWidth: MODAL_SIZES[size] || MODAL_SIZES.md }} onClick={(e) => e.stopPropagation()}
      >
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14, padding: '22px 24px 0' }}>
          {icon && <span style={{ width: 38, height: 38, borderRadius: 10, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: T.bg, color: T.c }}><Icon name={icon} size={19} /></span>}
          <div style={{ flex: 1, minWidth: 0, paddingTop: icon ? 1 : 0 }}>
            {eyebrow && <div className="eyebrow-app" style={{ color: T.c, marginBottom: 5 }}>{eyebrow}</div>}
            <h2 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 17.5, letterSpacing: '-.01em', color: 'var(--app-t1)', textWrap: 'balance' }}>{title}</h2>
            {description && <p style={{ margin: '6px 0 0', fontSize: 13, lineHeight: 1.55, color: 'var(--app-t3)', textWrap: 'pretty' }}>{description}</p>}
          </div>
          {dismissible && (
            <button onClick={onClose} aria-label="Close" className="ui-btn ghost" style={{ flex: 'none', marginTop: -2, padding: '0 8px' }}><Icon name="x" size={16} /></button>
          )}
        </div>
        {children != null && <div style={{ padding: '16px 24px 4px', overflowY: 'auto', flex: '0 1 auto' }}>{children}</div>}
        {hasFooter && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '18px 24px 22px', marginTop: 6 }}>
            {footerNote && <div style={{ flex: 1, fontSize: 11.5, color: 'var(--app-t3)' }}>{footerNote}</div>}
            <div style={{ display: 'flex', gap: 9, marginLeft: footerNote ? 0 : 'auto' }}>
              {secondary}
              {primary}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/** Labeled form field for form-archetype modals. */
export function ModalField({ label, hint, children }: { label: string; hint?: string; children?: ReactNode }) {
  return (
    <label style={{ display: 'block', marginBottom: 15 }}>
      <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)', marginBottom: 6 }}>{label}</div>
      {children}
      {hint && <div style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 5 }}>{hint}</div>}
    </label>
  );
}

export function ModalInput(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} style={{ width: '100%', height: 38, padding: '0 12px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 13, outline: 'none', ...(props.style || {}) }} />;
}

export function ModalSelect(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} style={{ width: '100%', height: 38, padding: '0 12px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 13, outline: 'none', cursor: 'pointer', ...(props.style || {}) }} />;
}
