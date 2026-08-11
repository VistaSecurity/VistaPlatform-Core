// Public invitation accept page. Reached from the emailed accept link
// (?token=...), outside RequireAuth. Looks the invitation up, then offers the
// methods the tenant allows — a password and/or "Continue with <provider>".
// Password posts to /auth/invitations/accept (which signs the user in); SSO
// navigates to the provider's authorize endpoint carrying the invitation token,
// which the callback consumes to bind the identity to the invited account.
// Works identically for Google and Microsoft.
import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { Icon } from '../components/ui';
import { clients } from '../lib/clients';

const ACCENT = 'var(--accent-gradient)';

function providerLabel(provider: string): string {
  switch (provider) {
    case 'google': return 'Google';
    case 'microsoft': return 'Microsoft';
    case 'azure': return 'Azure AD';
    default: return provider.charAt(0).toUpperCase() + provider.slice(1);
  }
}

type SsoProvider = { provider: string; provider_name: string };

export function AcceptInvitePage() {
  const token = useMemo(() => new URLSearchParams(window.location.search).get('token') ?? '', []);
  const [phase, setPhase] = useState<'loading' | 'ready' | 'invalid'>('loading');
  const [errMsg, setErrMsg] = useState<string | null>(null);
  const [email, setEmail] = useState('');
  const [tenantName, setTenantName] = useState('');
  const [allowPassword, setAllowPassword] = useState(true);
  const [providers, setProviders] = useState<SsoProvider[]>([]);
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  useEffect(() => {
    if (!token) { setPhase('invalid'); setErrMsg('This invitation link is missing its token.'); return; }
    (async () => {
      const { data, error, response } = await clients.auth.GET('/auth/invitations/lookup', { params: { query: { token } } });
      if (error || !data || !response.ok) {
        setPhase('invalid');
        setErrMsg(messageFrom(error, 'This invitation is no longer valid.'));
        return;
      }
      setEmail(data.email ?? '');
      setTenantName(data.tenant_name ?? '');
      setAllowPassword(data.allow_password ?? true);
      setProviders((data.sso_providers ?? []) as SsoProvider[]);
      setPhase('ready');
    })();
  }, [token]);

  const startSso = (p: SsoProvider) => {
    window.location.href = `/api/v1/auth-service/auth/sso/${encodeURIComponent(p.provider_name)}/authorize`
      + `?invitation_token=${encodeURIComponent(token)}`;
  };

  const acceptWithPassword = async (e: FormEvent) => {
    e.preventDefault();
    setFormError(null);
    setSubmitting(true);
    try {
      const { error, response } = await clients.auth.POST('/auth/invitations/accept', { body: { token, password } });
      if (error || !response.ok) throw new Error(messageFrom(error, 'Could not accept the invitation.'));
      window.location.replace('/dashboard');
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Could not accept the invitation.');
      setSubmitting(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'radial-gradient(120% 90% at 30% 20%, #15110a 0%, #0A0A0A 55%)', fontFamily: 'var(--font-body)', padding: 24 }}>
      <div style={{ width: '100%', maxWidth: 400 }}>
        <div style={{ width: 64, height: 64, margin: '0 auto 20px', borderRadius: 18, background: phase === 'invalid' ? 'color-mix(in srgb, var(--danger) 14%, transparent)' : ACCENT, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Icon name={phase === 'invalid' ? 'shield-x' : 'mail-check'} size={32} style={{ color: phase === 'invalid' ? 'var(--danger-text)' : '#0A0A0A' }} />
        </div>

        {phase === 'loading' && (
          <p style={{ textAlign: 'center', color: 'rgba(255,255,255,.6)', fontSize: 14 }}>
            <Icon name="loader" size={16} style={{ animation: 'spin 1.1s linear infinite', verticalAlign: 'middle', marginRight: 8 }} />
            Checking your invitation…
          </p>
        )}

        {phase === 'invalid' && (
          <div style={{ textAlign: 'center' }}>
            <h1 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 22, color: '#F4F3F0' }}>Invitation unavailable</h1>
            <p style={{ margin: '10px 0 22px', fontSize: 13.5, color: 'rgba(255,255,255,.55)', lineHeight: 1.6 }}>{errMsg}</p>
            <a href="/login" style={{ color: 'var(--accent-light)', textDecoration: 'none', fontWeight: 600, fontSize: 14 }}>Go to sign in</a>
          </div>
        )}

        {phase === 'ready' && (
          <>
            <h1 style={{ margin: 0, textAlign: 'center', fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 23, letterSpacing: '-.02em', color: '#F4F3F0' }}>
              Join {tenantName || 'your team'} on Vista
            </h1>
            <p style={{ margin: '8px 0 22px', textAlign: 'center', fontSize: 13.5, color: 'rgba(255,255,255,.5)', lineHeight: 1.5 }}>
              Accepting as <strong style={{ color: 'rgba(255,255,255,.8)' }}>{email}</strong>. Choose how you'll sign in.
            </p>

            {providers.map((p) => (
              <button key={p.provider_name} type="button" onClick={() => startSso(p)} style={ssoBtnStyle}>
                <Icon name="key-round" size={16} style={{ color: 'rgba(255,215,115,.85)' }} />
                Continue with {providerLabel(p.provider)}
              </button>
            ))}

            {allowPassword && providers.length > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, margin: '16px 0 14px' }}>
                <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,.09)' }} />
                <span style={{ fontSize: 11, letterSpacing: '.14em', textTransform: 'uppercase', color: 'rgba(255,255,255,.34)' }}>or set a password</span>
                <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,.09)' }} />
              </div>
            )}

            {allowPassword && (
              <form onSubmit={acceptWithPassword} style={{ display: 'flex', flexDirection: 'column', gap: 11 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, height: 48, padding: '0 14px', borderRadius: 12, background: 'rgba(255,255,255,.045)', border: '1px solid rgba(255,255,255,.11)' }}>
                  <Icon name="lock" size={17} style={{ color: 'rgba(255,255,255,.42)', flex: 'none' }} />
                  <input type={showPw ? 'text' : 'password'} value={password} onChange={(e) => setPassword(e.target.value)} required placeholder="Create a password" autoComplete="new-password"
                    style={{ flex: 1, minWidth: 0, border: 'none', background: 'transparent', outline: 'none', fontFamily: 'var(--font-body)', fontSize: 14, color: '#F1F1F2' }} />
                  <button type="button" onClick={() => setShowPw((v) => !v)} style={{ border: 'none', background: 'transparent', cursor: 'pointer', display: 'flex', padding: 0 }}>
                    <Icon name={showPw ? 'eye-off' : 'eye'} size={16} style={{ color: 'rgba(255,255,255,.42)' }} />
                  </button>
                </div>
                {formError && (
                  <div style={{ fontSize: 12.5, color: 'var(--danger-soft)', background: 'color-mix(in srgb, var(--danger) 12%, transparent)', border: '1px solid color-mix(in srgb, var(--danger) 28%, transparent)', borderRadius: 10, padding: '9px 12px' }}>{formError}</div>
                )}
                <button type="submit" disabled={submitting} style={{ width: '100%', height: 50, marginTop: 4, border: 'none', borderRadius: 40, cursor: submitting ? 'default' : 'pointer', background: ACCENT, color: 'var(--accent-fg)', fontFamily: 'var(--font-body)', fontWeight: 700, fontSize: 15, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 9, opacity: submitting ? 0.7 : 1 }}>
                  <Icon name="shield-check" size={17} />{submitting ? 'Creating account…' : 'Create account & sign in'}
                </button>
              </form>
            )}
          </>
        )}
        <style>{'@keyframes spin { to { transform: rotate(360deg); } }'}</style>
      </div>
    </div>
  );
}

function messageFrom(error: unknown, fallback: string): string {
  if (error && typeof error === 'object' && 'error' in error) return String((error as { error: unknown }).error);
  return fallback;
}

const ssoBtnStyle: React.CSSProperties = {
  width: '100%',
  height: 48,
  marginBottom: 8,
  borderRadius: 40,
  border: '1px solid rgba(255,255,255,.14)',
  background: 'rgba(255,255,255,.045)',
  color: '#F1F1F2',
  cursor: 'pointer',
  fontFamily: 'var(--font-body)',
  fontWeight: 600,
  fontSize: 14,
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'center',
  gap: 9,
};
