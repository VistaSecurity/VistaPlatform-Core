// Platform Settings — Legal. Lets a platform admin author and version the
// tenant-facing legal documents (Terms of Service, Privacy Policy). Publishing
// creates a NEW immutable version server-side (the previous version is demoted,
// never mutated), so prior acceptances stay pinned to the exact accepted text.
// Backed by admin-service /admin/legal/* (RBAC-gated platform.settings). The
// acceptance ledger is a cross-tenant audit read.
import { useMemo, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { FileText, CheckCircle, XCircle, History, ClipboardCheck } from 'lucide-react';
import { clients } from '../../lib/clients';
import { usePlatformEdition } from '../../lib/edition';

type DocType = 'terms_of_service' | 'privacy_policy';

const DOC_TABS: { key: DocType; label: string }[] = [
  { key: 'terms_of_service', label: 'Terms of Service' },
  { key: 'privacy_policy', label: 'Privacy Policy' },
];

const DOCS_KEY = ['platform', 'settings', 'legal'] as const;
const ACCEPT_KEY = ['platform', 'settings', 'legal', 'acceptances'] as const;

interface LegalDoc {
  id: string;
  doc_type: string;
  version: number;
  title: string;
  body: string;
  content_hash: string;
  is_current: boolean;
  effective_date: string;
  published_at: string;
}
interface LegalVersion {
  doc_type: string;
  version: number;
  title: string;
  is_current: boolean;
  published_at: string;
}
interface AcceptanceRow {
  tenant_id: string;
  tenant_name: string;
  user_id: string;
  user_email: string;
  doc_type: string;
  version: number;
  accepted_at: string;
  accepted_ip?: string | null;
}

function useLegalDocuments() {
  return useQuery({
    queryKey: DOCS_KEY,
    queryFn: async () => {
      const { data, error } = await clients.admin.GET('/admin/legal/documents', {});
      if (error || !data) throw new Error('Failed to load legal documents');
      return {
        documents: (data.documents ?? []) as LegalDoc[],
        history: (data.history ?? []) as LegalVersion[],
      };
    },
    staleTime: 30_000,
  });
}

// Split edition: authoring /admin/legal/documents is Core, but the ledger
// (/admin/legal/acceptances) is a CROSS-TENANT read served by
// admin-service/ee/msp, so a Core build 404s it. Authoring stays visible; only
// the ledger disappears.
function useAcceptances(docType: DocType, enabled: boolean) {
  return useQuery({
    queryKey: [...ACCEPT_KEY, docType],
    enabled,
    queryFn: async () => {
      const { data, error } = await clients.admin.GET('/admin/legal/acceptances', {
        params: { query: { doc_type: docType, limit: 100 } },
      });
      if (error || !data) throw new Error('Failed to load acceptances');
      return (data.acceptances ?? []) as AcceptanceRow[];
    },
    staleTime: 30_000,
  });
}

function Toast({ msg, ok, onDone }: { msg: string; ok: boolean; onDone: () => void }) {
  return (
    <div onClick={onDone} style={{
      position: 'fixed', bottom: 24, right: 24, zIndex: 9999,
      background: ok ? 'rgba(34,197,94,.15)' : 'rgba(239,68,68,.15)',
      border: `1px solid ${ok ? 'rgba(34,197,94,.4)' : 'rgba(239,68,68,.4)'}`,
      borderRadius: 'var(--r-btn)', padding: '10px 16px',
      display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer',
      color: 'var(--op-t1)', fontSize: 13, maxWidth: 360,
    }}>
      {ok ? <CheckCircle size={15} color="var(--ok)" /> : <XCircle size={15} color="var(--danger)" />}
      {msg}
    </div>
  );
}

const inputStyle: React.CSSProperties = {
  background: 'var(--op-input-bg, rgba(255,255,255,.05))', border: '1px solid var(--op-border)',
  borderRadius: 'var(--r-btn)', padding: '8px 11px', color: 'var(--op-t1)', fontSize: 13,
  outline: 'none', width: '100%', boxSizing: 'border-box', fontFamily: 'inherit',
};

export function SettingsLegalPage() {
  const { data, isLoading } = useLegalDocuments();
  const qc = useQueryClient();
  const [tab, setTab] = useState<DocType>('terms_of_service');
  const [draft, setDraft] = useState<{ title: string; body: string } | null>(null);
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null);

  const showToast = (msg: string, ok: boolean) => { setToast({ msg, ok }); setTimeout(() => setToast(null), 4000); };

  const current = useMemo(() => data?.documents.find((d) => d.doc_type === tab), [data, tab]);
  const history = useMemo(() => (data?.history ?? []).filter((h) => h.doc_type === tab), [data, tab]);
  const showAcceptances = usePlatformEdition().has('msp');
  const acceptancesQ = useAcceptances(tab, showAcceptances);

  // Draft is seeded from the current version but tracked separately so switching
  // tabs resets it. title/body fall back to the current doc when the draft is null.
  const title = draft?.title ?? current?.title ?? '';
  const body = draft?.body ?? current?.body ?? '';
  const dirty = draft !== null && (draft.title !== (current?.title ?? '') || draft.body !== (current?.body ?? ''));

  const publish = useMutation({
    mutationFn: async () => {
      const { error } = await clients.admin.POST('/admin/legal/documents', {
        body: { doc_type: tab, title: title.trim(), body },
      });
      if (error) throw new Error((error as { error?: string })?.error ?? 'Publish failed');
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: DOCS_KEY });
      qc.invalidateQueries({ queryKey: [...ACCEPT_KEY, tab] });
      setDraft(null);
      showToast('New version published. Existing tenants will be re-prompted to accept.', true);
    },
    onError: (e) => showToast((e as Error).message, false),
  });

  const switchTab = (t: DocType) => { setTab(t); setDraft(null); };

  return (
    <div className="op-fade" style={{ padding: 24, maxWidth: 900 }}>
      <div className="op-panel" style={{ padding: '20px 22px', display: 'flex', flexDirection: 'column', gap: 18 }}>
        {/* header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, borderBottom: '1px solid var(--op-border)', paddingBottom: 16 }}>
          <div style={{ width: 34, height: 34, borderRadius: 'var(--r-btn)', background: 'color-mix(in srgb, var(--accent) 12%, transparent)', display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 'none' }}>
            <FileText size={16} style={{ color: 'var(--op-accent)' }} />
          </div>
          <div>
            <div style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 15, color: 'var(--op-t1)' }}>Legal Documents</div>
            <div style={{ fontSize: 12, color: 'var(--op-t3)', marginTop: 2 }}>
              Author the Terms of Service and Privacy Policy tenants accept at signup. Publishing creates a new version and re-prompts existing tenants.
            </div>
          </div>
        </div>

        {/* doc-type tabs */}
        <div style={{ display: 'flex', gap: 8 }}>
          {DOC_TABS.map((t) => (
            <button key={t.key} className={`op-btn ${tab === t.key ? '' : 'ghost'} sm`} onClick={() => switchTab(t.key)}>
              {t.label}
            </button>
          ))}
        </div>

        {isLoading ? (
          <div style={{ color: 'var(--op-t3)', fontSize: 13 }}>Loading…</div>
        ) : (
          <>
            <div style={{ fontSize: 12, color: 'var(--op-t3)' }}>
              {current
                ? <>Current: <strong style={{ color: 'var(--op-t2)' }}>v{current.version}</strong> · published {new Date(current.published_at).toLocaleString()}</>
                : <>No version published yet — publishing creates v1.</>}
            </div>

            {/* editor */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--op-t2)' }}>Title</label>
              <input value={title} onChange={(e) => setDraft({ title: e.target.value, body })} style={inputStyle} placeholder="Terms of Service" />
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--op-t2)' }}>
                Body <span style={{ color: 'var(--op-t3)', fontWeight: 400 }}>(Markdown-style headings: <span className="mono"># H1</span>, <span className="mono">## H2</span>)</span>
              </label>
              <textarea
                value={body}
                onChange={(e) => setDraft({ title, body: e.target.value })}
                rows={18}
                style={{ ...inputStyle, height: 'auto', resize: 'vertical', lineHeight: 1.55, fontFamily: 'var(--font-mono, monospace)' }}
                placeholder="# Terms of Service&#10;&#10;Your document text…"
              />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <button className="op-btn" onClick={() => publish.mutate()} disabled={publish.isPending || !title.trim() || !body.trim() || (current != null && !dirty)}>
                {publish.isPending ? 'Publishing…' : current ? 'Publish new version' : 'Publish v1'}
              </button>
              {current && !dirty && <span style={{ fontSize: 12, color: 'var(--op-t3)' }}>Edit the title or body to publish a new version.</span>}
              {dirty && <span style={{ fontSize: 12, color: 'var(--op-accent)' }}>Unsaved changes — publishing creates v{(current?.version ?? 0) + 1}.</span>}
            </div>

            {/* version history */}
            <div style={{ borderTop: '1px solid var(--op-border)', paddingTop: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: 11, fontWeight: 700, letterSpacing: '.1em', textTransform: 'uppercase', color: 'var(--op-t3)', marginBottom: 10 }}>
                <History size={13} /> Version history
              </div>
              {history.length === 0 ? (
                <div style={{ fontSize: 12.5, color: 'var(--op-t3)' }}>No versions yet.</div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {history.map((h) => (
                    <div key={h.version} style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12.5, color: 'var(--op-t2)', padding: '4px 0' }}>
                      <span className="mono" style={{ minWidth: 34 }}>v{h.version}</span>
                      {h.is_current && <span style={{ fontSize: 9.5, fontWeight: 700, letterSpacing: '.08em', textTransform: 'uppercase', color: 'var(--op-accent)', background: 'color-mix(in srgb, var(--accent) 12%, transparent)', borderRadius: 4, padding: '1px 5px' }}>Current</span>}
                      <span style={{ color: 'var(--op-t3)' }}>{new Date(h.published_at).toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* acceptance ledger — MSP only (cross-tenant read) */}
            {showAcceptances && (
            <div style={{ borderTop: '1px solid var(--op-border)', paddingTop: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: 11, fontWeight: 700, letterSpacing: '.1em', textTransform: 'uppercase', color: 'var(--op-t3)', marginBottom: 10 }}>
                <ClipboardCheck size={13} /> Acceptance audit — most recent 100
              </div>
              {acceptancesQ.isLoading ? (
                <div style={{ fontSize: 12.5, color: 'var(--op-t3)' }}>Loading…</div>
              ) : (acceptancesQ.data ?? []).length === 0 ? (
                <div style={{ fontSize: 12.5, color: 'var(--op-t3)' }}>No acceptances recorded yet.</div>
              ) : (
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                    <thead>
                      <tr style={{ textAlign: 'left', color: 'var(--op-t3)' }}>
                        <th style={thStyle}>Tenant</th>
                        <th style={thStyle}>User</th>
                        <th style={thStyle}>Version</th>
                        <th style={thStyle}>Accepted</th>
                        <th style={thStyle}>IP</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(acceptancesQ.data ?? []).map((a, i) => (
                        <tr key={i} style={{ borderTop: '1px solid var(--op-border)', color: 'var(--op-t2)' }}>
                          <td style={tdStyle}>{a.tenant_name || a.tenant_id.slice(0, 8)}</td>
                          <td style={tdStyle}>{a.user_email || a.user_id.slice(0, 8)}</td>
                          <td style={tdStyle}><span className="mono">v{a.version}</span></td>
                          <td style={tdStyle}>{new Date(a.accepted_at).toLocaleString()}</td>
                          <td style={tdStyle}><span className="mono" style={{ color: 'var(--op-t3)' }}>{a.accepted_ip || '—'}</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
            )}
          </>
        )}
      </div>

      {toast && <Toast msg={toast.msg} ok={toast.ok} onDone={() => setToast(null)} />}
    </div>
  );
}

const thStyle: React.CSSProperties = { padding: '6px 10px 8px 0', fontWeight: 600, whiteSpace: 'nowrap' };
const tdStyle: React.CSSProperties = { padding: '7px 10px 7px 0', whiteSpace: 'nowrap' };
