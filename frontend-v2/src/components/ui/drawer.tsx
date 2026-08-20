import { useEffect } from 'react';
import { Icon } from './icon';

// Shared drawer furniture — promoted from sections/inventory/drawers.tsx so any
// section can build slide-out detail panels. Supports STACKING: render several
// shells with rising `depth`; pass `active` only to the top one so Esc/scrim
// close drawers top-first.

export function DrawerShell({ onClose, width = 480, active = true, depth = 0, children }: {
  onClose: () => void; width?: number; active?: boolean; depth?: number; children: React.ReactNode;
}) {
  useEffect(() => {
    if (!active) return;
    const h = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [onClose, active]);
  const z = 90 + depth * 2;
  return (
    <div onClick={onClose} style={{ position: 'fixed', inset: 0, zIndex: z, background: 'var(--app-scrim)', animation: 'scrimIn .18s ease both', display: 'flex', justifyContent: 'flex-end' }}>
      <div onClick={(e) => e.stopPropagation()} style={{ width, maxWidth: '94vw', height: '100%', background: 'var(--app-panel)', borderLeft: '1px solid var(--app-border2)', boxShadow: 'var(--app-shadow)', animation: 'drawerIn .26s cubic-bezier(.2,.8,.2,1) both', display: 'flex', flexDirection: 'column', overflowY: 'auto' }}>
        {children}
      </div>
    </div>
  );
}

// `v` accepts a node, not just a string, so a row can carry a muted qualifier
// beside its value (see the Service row's confidence label). Emptiness is still
// judged on the primitive cases — '', null, undefined — so every existing
// caller renders exactly as before.
export function MetaRow({ k, v, mono, title }: { k: string; v?: React.ReactNode; mono?: boolean; title?: string }) {
  const empty = v === null || v === undefined || v === '';
  return (
    <div title={title} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--app-border)', gap: 16 }}>
      <span style={{ fontSize: 12.5, color: 'var(--app-t3)', flex: 'none' }}>{k}</span>
      <span className={mono ? 'mono' : ''} style={{ fontSize: 12.5, color: 'var(--app-t1)', fontWeight: 500, textAlign: 'right', wordBreak: 'break-word' }}>{empty ? '—' : v}</span>
    </div>
  );
}

export function SectionLabel({ icon, children }: { icon: string; children: React.ReactNode }) {
  return <div className="eyebrow-app" style={{ margin: '20px 0 6px', display: 'flex', alignItems: 'center', gap: 7 }}><Icon name={icon} size={13} style={{ color: 'var(--accent)' }} />{children}</div>;
}

export function DrawerCloseBtn({ onClose }: { onClose: () => void }) {
  return <button onClick={onClose} title="Close (Esc)" style={{ flex: 'none', width: 28, height: 28, borderRadius: 8, border: '1px solid var(--app-border)', background: 'var(--app-panel2)', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--app-t2)' }}><Icon name="x" size={15} /></button>;
}
