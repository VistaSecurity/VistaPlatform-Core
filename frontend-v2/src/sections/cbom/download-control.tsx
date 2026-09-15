// The per-artifact download control, shared by the list row and the drawer.
//
// Its own file rather than kit.tsx because it fetches (kit is presentation
// only), and rather than living in one of its two consumers because the other
// would then import a page — which is how a list row and a detail drawer come
// to offer different formats for the same artifact.
import { useEffect, useRef, useState } from 'react';
import { Icon } from '../../components/ui';
import { downloadFormatsFor } from './kit';
import { downloadArtifact, type CBOMArtifact, type DownloadFormat } from './queries';

/**
 * A single button when the artifact offers one format, a menu when it offers
 * more.
 *
 * Which formats it offers depends on the artifact's KIND (see
 * downloadFormatsFor). An always-visible OCSF item would 400 for three kinds
 * out of four, and the fastest way to teach someone a feature is broken is to
 * let them click something that never works.
 */
export function DownloadControl({ artifact, compact }: { artifact: CBOMArtifact; compact?: boolean }) {
  const formats = downloadFormatsFor(artifact.artifact_kind);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<DownloadFormat | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const ref = useRef<HTMLDivElement>(null);

  // Close on any outside click. Without it the menu survives interaction with
  // the rest of the page, which reads as a stuck overlay.
  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);

  const run = async (format: DownloadFormat) => {
    setErr(null);
    setBusy(format);
    setOpen(false);
    try {
      await downloadArtifact(artifact, format);
    } catch (e) {
      // Surfaced, not swallowed: a download that silently does nothing is
      // indistinguishable from a browser blocking the save.
      setErr(e instanceof Error ? e.message : 'Download failed');
    } finally {
      setBusy(null);
    }
  };

  if (formats.length === 1) {
    const only = formats[0];
    return (
      <span style={{ display: 'inline-flex', flexDirection: 'column', alignItems: 'flex-end', gap: 3 }}>
        <button
          className={compact ? 'ui-btn sm' : 'ui-btn sm accent'}
          title={only.hint}
          onClick={(e) => { e.stopPropagation(); void run(only.format); }}
          disabled={busy !== null}
        >
          <Icon name="download" size={13} />{compact ? null : only.label}
        </button>
        {err && <span style={{ fontSize: 11, color: 'var(--danger-text)' }}>{err}</span>}
      </span>
    );
  }

  return (
    <div ref={ref} style={{ position: 'relative' }} onClick={(e) => e.stopPropagation()}>
      <button
        className={compact ? 'ui-btn sm' : 'ui-btn sm accent'}
        title="Download"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        disabled={busy !== null}
      >
        <Icon name="download" size={13} />{compact ? null : 'Download'}<Icon name="chevron-down" size={12} />
      </button>
      {open && (
        <div role="menu" className="panel" style={{ position: 'absolute', right: 0, top: 'calc(100% + 5px)', zIndex: 30, minWidth: 272, borderRadius: 11, padding: 5, boxShadow: 'var(--app-shadow)' }}>
          {formats.map((f) => (
            <button
              key={f.format}
              role="menuitem"
              onClick={() => void run(f.format)}
              style={{ display: 'block', width: '100%', textAlign: 'left', padding: '8px 10px', borderRadius: 8, border: 'none', background: 'transparent', cursor: 'pointer' }}
            >
              <span style={{ display: 'block', fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>{f.label}</span>
              <span style={{ display: 'block', fontSize: 11, color: 'var(--app-t3)', lineHeight: 1.45, marginTop: 2 }}>{f.hint}</span>
            </button>
          ))}
        </div>
      )}
      {err && <div style={{ position: 'absolute', right: 0, top: 'calc(100% + 5px)', fontSize: 11, color: 'var(--danger-text)', whiteSpace: 'nowrap' }}>{err}</div>}
    </div>
  );
}
