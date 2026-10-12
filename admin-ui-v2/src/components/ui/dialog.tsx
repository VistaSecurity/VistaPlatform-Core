// VISTA Operations — Dialog primitive. The one accessible overlay shell that
// Modal and the side drawers (tenant, plan builder, role) all sit on: a scrim
// plus a panel with role="dialog" / aria-modal, an accessible name, a focus
// trap (focus moves in on open, Tab cycles, focus returns to the opener on
// close), Esc to close, a ref-counted body scroll lock, and an optional
// `dirty` guard — when set, a scrim click or Esc asks "Discard changes?"
// inline instead of silently dropping what the operator typed.
//
// The caller owns visuals (scrimStyle / panelStyle) so adopting the primitive
// does not change how any overlay looks.
import { useCallback, useEffect, useRef, useState, type CSSProperties, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from 'react';

const FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]):not([type="hidden"]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';

// Body scroll lock, ref-counted: stacked dialogs share one lock and the
// original overflow is restored only when the LAST one closes, whatever order
// they unmount in.
let lockCount = 0;
let lockedFrom = '';
function lockScroll() {
  if (lockCount++ === 0) {
    lockedFrom = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
  }
}
function unlockScroll() {
  if (--lockCount === 0) document.body.style.overflow = lockedFrom;
}

// Open dialogs, topmost last. Esc only ever closes the topmost one.
const stack: symbol[] = [];

export interface DialogProps {
  /** Defaults to true — consumers usually mount the dialog conditionally. */
  open?: boolean;
  onClose: () => void;
  /** Unsaved input: scrim click / Esc ask for confirmation before closing. */
  dirty?: boolean;
  /** id of the element that titles the dialog (aria-labelledby). */
  labelId?: string;
  /** id of an element describing the dialog (aria-describedby). */
  describedById?: string;
  /** Used when there is no visible title element to point labelId at. */
  ariaLabel?: string;
  scrimStyle?: CSSProperties;
  panelStyle?: CSSProperties;
  children?: ReactNode;
}

export function Dialog({ open = true, ...rest }: DialogProps) {
  return open ? <DialogInner {...rest} /> : null;
}

function DialogInner({ onClose, dirty = false, labelId, describedById, ariaLabel, scrimStyle, panelStyle, children }: Omit<DialogProps, 'open'>) {
  const panelRef = useRef<HTMLDivElement>(null);
  const keepRef = useRef<HTMLButtonElement>(null);
  const [confirming, setConfirming] = useState(false);

  // Latest props via refs so the document listener subscribes once, however
  // often the caller re-renders with a fresh inline onClose.
  const onCloseRef = useRef(onClose);
  const dirtyRef = useRef(dirty);
  const confirmingRef = useRef(false);
  useEffect(() => { onCloseRef.current = onClose; dirtyRef.current = dirty; confirmingRef.current = confirming; });

  const requestClose = useCallback(() => {
    if (dirtyRef.current && !confirmingRef.current) { confirmingRef.current = true; setConfirming(true); return; }
    onCloseRef.current();
  }, []);

  useEffect(() => {
    const id = Symbol('dialog');
    stack.push(id);
    lockScroll();
    const opener = document.activeElement as HTMLElement | null;
    const panel = panelRef.current;
    if (panel && !panel.contains(document.activeElement)) {
      (panel.querySelector<HTMLElement>(FOCUSABLE) ?? panel).focus();
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape' || stack[stack.length - 1] !== id) return;
      if (confirmingRef.current) { confirmingRef.current = false; setConfirming(false); return; }
      requestClose();
    };
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onKey);
      stack.splice(stack.indexOf(id), 1);
      unlockScroll();
      if (opener && opener.isConnected) opener.focus();
    };
  }, [requestClose]);

  // Move focus to the safe choice when the confirmation appears.
  useEffect(() => { if (confirming) keepRef.current?.focus(); }, [confirming]);

  const onKeyDown = (e: ReactKeyboardEvent<HTMLDivElement>) => {
    if (e.key !== 'Tab') return;
    const panel = panelRef.current;
    if (!panel) return;
    const items = Array.from(panel.querySelectorAll<HTMLElement>(FOCUSABLE));
    if (items.length === 0) { e.preventDefault(); panel.focus(); return; }
    const first = items[0];
    const last = items[items.length - 1];
    const active = document.activeElement;
    if (e.shiftKey && (active === first || active === panel)) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && active === last) { e.preventDefault(); first.focus(); }
    else if (!panel.contains(active)) { e.preventDefault(); first.focus(); }
  };

  return (
    <div
      data-dialog-scrim
      onClick={(e) => { e.stopPropagation(); if (e.target === e.currentTarget) requestClose(); }}
      style={scrimStyle}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelId}
        aria-describedby={describedById}
        aria-label={labelId ? undefined : ariaLabel}
        tabIndex={-1}
        onKeyDown={onKeyDown}
        style={{ position: 'relative', outline: 'none', ...panelStyle }}
      >
        {children}
        {confirming && (
          <div role="alert" style={{ position: 'absolute', left: 12, right: 12, bottom: 12, zIndex: 1, display: 'flex', alignItems: 'center', gap: 10, padding: '10px 12px', background: 'var(--op-panel2)', border: '1px solid var(--op-border2)', borderRadius: 'var(--r-md, 8px)', boxShadow: 'var(--op-shadow)' }}>
            <span style={{ flex: 1, fontSize: 12.5, color: 'var(--op-t1)' }}>Discard changes?</span>
            <button ref={keepRef} type="button" className="op-btn sm" onClick={() => { confirmingRef.current = false; setConfirming(false); }}>Keep editing</button>
            <button type="button" className="op-btn danger sm" onClick={() => onCloseRef.current()}>Discard</button>
          </div>
        )}
      </div>
    </div>
  );
}
