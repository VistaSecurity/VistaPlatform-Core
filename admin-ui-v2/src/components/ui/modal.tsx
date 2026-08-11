// VISTA Operations — Modal primitive. Lean version of the kit's <Modal>: scrim +
// blur, centered panel, header (tone-colored), body, right-aligned footer
// (secondary ghost → primary). Esc + scrim-click dismiss; body scroll-lock.
// Reused for the ratings editor now; impersonation break-glass + confirm/destruct
// archetypes build on this next.
import { useEffect, type ReactNode } from 'react';
import { X } from 'lucide-react';

type Tone = 'blue' | 'danger' | 'accent' | 'neutral';
const TONE: Record<Tone, string> = { blue: 'var(--op-accent)', danger: 'var(--danger)', accent: 'var(--accent)', neutral: 'var(--op-t2)' };

export interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  tone?: Tone;
  size?: 'sm' | 'md' | 'lg';
  children?: ReactNode;
  footerNote?: string;
  primaryLabel?: string;
  onPrimary?: () => void;
  primaryDisabled?: boolean;
  primaryLoading?: boolean;
  secondaryLabel?: string;
}

const WIDTH = { sm: 392, md: 524, lg: 688 };

export function Modal({ open, onClose, title, description, tone = 'blue', size = 'md', children, footerNote, primaryLabel, onPrimary, primaryDisabled, primaryLoading, secondaryLabel = 'Cancel' }: ModalProps) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => { window.removeEventListener('keydown', onKey); document.body.style.overflow = prev; };
  }, [open, onClose]);

  if (!open) return null;
  const accent = TONE[tone];

  return (
    <div onClick={onClose} role="dialog" aria-modal="true" style={{ position: 'fixed', inset: 0, zIndex: 95, background: 'var(--op-scrim)', backdropFilter: 'blur(4px)', display: 'flex', alignItems: 'flex-start', justifyContent: 'center', paddingTop: '14vh', animation: 'opScrim .18s ease both' }}>
      <div onClick={(e) => e.stopPropagation()} style={{ width: WIDTH[size], maxWidth: '94vw', maxHeight: '82vh', display: 'flex', flexDirection: 'column', background: 'var(--op-panel)', border: '1px solid var(--op-border2)', borderRadius: 'var(--r-lg)', boxShadow: 'var(--op-shadow)', overflow: 'hidden', animation: 'opModalIn .24s ease both' }}>
        <div style={{ flex: 'none', display: 'flex', alignItems: 'flex-start', gap: 12, padding: '16px 18px', borderBottom: '1px solid var(--op-border)' }}>
          <span style={{ width: 3, alignSelf: 'stretch', borderRadius: 4, background: accent, flex: 'none' }} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 15.5, color: 'var(--op-t1)' }}>{title}</div>
            {description && <div style={{ fontSize: 12.5, color: 'var(--op-t3)', marginTop: 3, lineHeight: 1.5 }}>{description}</div>}
          </div>
          <button onClick={onClose} className="op-btn icon sm"><X size={14} /></button>
        </div>

        {children && <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', padding: '16px 18px', display: 'flex', flexDirection: 'column', gap: 13 }}>{children}</div>}

        {(primaryLabel || footerNote) && (
          <div style={{ flex: 'none', display: 'flex', alignItems: 'center', gap: 10, padding: '13px 18px', borderTop: '1px solid var(--op-border)' }}>
            {footerNote && <span style={{ fontSize: 11, color: 'var(--op-t3)', flex: 1 }}>{footerNote}</span>}
            <div style={{ flex: footerNote ? 'none' : 1 }} />
            <button onClick={onClose} className="op-btn ghost sm">{secondaryLabel}</button>
            {primaryLabel && (
              <button onClick={onPrimary} disabled={primaryDisabled || primaryLoading} className={'op-btn sm ' + (tone === 'danger' ? 'danger' : tone === 'accent' ? 'accent' : 'primary')}>
                {primaryLoading ? 'Saving…' : primaryLabel}
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

/** Labelled field wrapper for modal forms. */
export function ModalField({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label style={{ display: 'flex', flexDirection: 'column', gap: 5, fontSize: 12, color: 'var(--op-t2)' }}>
      {label}
      {children}
    </label>
  );
}

export const modalInputStyle = {
  height: 34, borderRadius: 'var(--r-btn)', border: '1px solid var(--op-border2)',
  background: 'var(--op-panel2)', color: 'var(--op-t1)', padding: '0 11px', fontSize: 13, outline: 'none',
} as const;
