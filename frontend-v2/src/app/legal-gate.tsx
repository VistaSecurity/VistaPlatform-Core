// Post-login re-acceptance gate. When a platform admin publishes a NEW version
// of a legal document, existing users are prompted to re-accept it before they
// continue. Mounted inside RequireAuth so it wraps the whole authenticated app;
// invisible (renders children only) when the user is already up to date, which
// is the common case (new signups accept at signup).
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { clients } from '../lib/clients';
import { LegalLinks } from '../components/legal-links';

const PENDING_KEY = ['legal', 'pending'];

// B-29: a server-side failure (e.g. a schema regression on legal_documents)
// must NOT resolve as "nothing pending" — this gate is the only place pending
// re-acceptance is enforced. Throwing routes it into isError, which `blocked`
// already treats as fail-closed below. Extracted so the throw is directly
// unit-testable without mounting the component.
export async function fetchLegalPending() {
  const { data, error } = await clients.auth.GET('/auth/legal/pending', {});
  if (error || !data) throw new Error('Failed to check legal acceptance status');
  return data.documents ?? [];
}

export function LegalGate({ children }: { children: React.ReactNode }) {
  const qc = useQueryClient();

  const pendingQ = useQuery({
    queryKey: PENDING_KEY,
    queryFn: fetchLegalPending,
    // Session-scoped: no need to refetch aggressively.
    staleTime: 5 * 60 * 1000,
  });

  const accept = useMutation({
    mutationFn: async () => {
      const { error } = await clients.auth.POST('/auth/legal/accept', { body: { accepted: true } });
      if (error) throw new Error('Could not record your acceptance. Please try again.');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: PENDING_KEY }),
  });

  const pending = pendingQ.data ?? [];
  const mustAccept = !pendingQ.isLoading && !pendingQ.isError && pending.length > 0;
  const blocked = pendingQ.isLoading || pendingQ.isError || mustAccept;

  return (
    <>
      {!blocked && children}
      {blocked && (
        <div style={scrim} role="dialog" aria-modal="true">
          <div style={modal}>
            {pendingQ.isLoading ? (
              <>
                <div style={{ fontFamily: 'var(--font-head, inherit)', fontSize: 18, fontWeight: 700, color: 'var(--app-t1, #F1F1F2)' }}>
                  Checking legal terms…
                </div>
                <p style={{ fontSize: 13.5, lineHeight: 1.55, color: 'var(--app-t2, rgba(255,255,255,.72))', margin: '10px 0 0' }}>
                  Verifying your acceptance status before continuing.
                </p>
              </>
            ) : pendingQ.isError ? (
              <>
                <div style={{ fontFamily: 'var(--font-head, inherit)', fontSize: 18, fontWeight: 700, color: 'var(--app-t1, #F1F1F2)' }}>
                  Couldn't verify legal terms
                </div>
                <p style={{ fontSize: 13.5, lineHeight: 1.55, color: 'var(--app-t2, rgba(255,255,255,.72))', margin: '10px 0 18px' }}>
                  We couldn't confirm whether you need to accept updated terms. Please try again.
                </p>
                <button type="button" onClick={() => pendingQ.refetch()} style={acceptBtn}>
                  Try again
                </button>
              </>
            ) : (
              <>
                <div style={{ fontFamily: 'var(--font-head, inherit)', fontSize: 18, fontWeight: 700, color: 'var(--app-t1, #F1F1F2)' }}>
                  Updated legal terms
                </div>
                <p style={{ fontSize: 13.5, lineHeight: 1.55, color: 'var(--app-t2, rgba(255,255,255,.72))', margin: '10px 0 18px' }}>
                  We've updated the <LegalLinks docs={pending} />. Please review and accept to continue using Vista.
                </p>
                {accept.isError && (
                  <div style={{ fontSize: 12.5, color: 'var(--danger-soft)', marginBottom: 12 }}>{(accept.error as Error).message}</div>
                )}
                <button type="button" onClick={() => accept.mutate()} disabled={accept.isPending} style={acceptBtn}>
                  {accept.isPending ? 'Recording…' : 'I agree and accept'}
                </button>
                <div style={{ fontSize: 11.5, color: 'var(--app-t3, rgba(255,255,255,.45))', marginTop: 12, textAlign: 'center' }}>
                  You must accept to continue. Contact your administrator with questions.
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </>
  );
}

const scrim: React.CSSProperties = {
  position: 'fixed', inset: 0, background: 'rgba(4,6,10,.72)', backdropFilter: 'blur(3px)',
  display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999, padding: 20,
};
const modal: React.CSSProperties = {
  width: '100%', maxWidth: 440, background: 'var(--app-panel, #14171f)', border: '1px solid rgba(255,255,255,.1)',
  borderRadius: 16, padding: '26px 26px 22px', boxShadow: '0 24px 70px rgba(0,0,0,.5)',
};
const acceptBtn: React.CSSProperties = {
  width: '100%', height: 46, border: 'none', borderRadius: 40, cursor: 'pointer',
  background: 'var(--accent-gradient)', color: 'var(--accent-fg)', fontFamily: 'var(--font-body)', fontWeight: 700, fontSize: 14,
};
