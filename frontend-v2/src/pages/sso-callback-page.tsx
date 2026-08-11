// SSO callback landing — the route the auth-service redirects the browser to
// after a successful OIDC callback (it has already set the httpOnly session
// cookies). This page does NOT read tokens from the URL (the new UI is
// cookie-based, unlike the old web-ui): it just lands, then hard-navigates into
// the app so the AuthProvider re-initializes and re-fetches /auth/me with the
// freshly-set cookies. On an `?error=` it shows a failure with a way back.
//
// Public route (mounted outside RequireAuth): at landing time the SPA's auth
// state hasn't re-initialized yet, so RequireAuth would otherwise bounce here
// to /login before the cookies are picked up.
import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import { Icon } from '../components/ui';

const ACCENT = 'var(--accent-gradient)';

export function SsoCallbackPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const error = params.get('error') || params.get('error_description');
  const [phase, setPhase] = useState<'working' | 'error'>(error ? 'error' : 'working');

  useEffect(() => {
    if (error) { setPhase('error'); return; }
    // Cookies are already set by the backend redirect. A hard navigation
    // remounts the app → AuthProvider init → GET /auth/me with the new session.
    // If the session didn't actually take, RequireAuth lands the user on /login.
    const t = setTimeout(() => { window.location.replace('/dashboard'); }, 350);
    return () => clearTimeout(t);
  }, [error]);

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'radial-gradient(120% 90% at 30% 20%, #15110a 0%, #0A0A0A 55%)', fontFamily: 'var(--font-body)', padding: 24 }}>
      <div style={{ width: '100%', maxWidth: 420, textAlign: 'center' }}>
        <div style={{ width: 72, height: 72, margin: '0 auto 22px', borderRadius: 20, background: phase === 'error' ? 'color-mix(in srgb, var(--danger) 14%, transparent)' : ACCENT, display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: phase === 'error' ? 'none' : '0 12px 32px color-mix(in srgb, var(--accent) 30%, transparent)' }}>
          <Icon name={phase === 'error' ? 'shield-x' : 'shield-check'} size={36} style={{ color: phase === 'error' ? 'var(--danger-text)' : '#0A0A0A' }} />
        </div>

        {phase === 'working' ? (
          <>
            <h1 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 22, letterSpacing: '-.02em', color: '#F4F3F0' }}>Completing sign-in…</h1>
            <p style={{ margin: '9px 0 0', fontSize: 13.5, color: 'rgba(255,255,255,.5)', lineHeight: 1.55 }}>Setting up your secure session.</p>
            <div style={{ marginTop: 22, display: 'inline-flex', alignItems: 'center', gap: 9, color: 'rgba(255,215,115,.8)', fontSize: 12.5 }}>
              <Icon name="loader" size={15} style={{ animation: 'spin 1.1s linear infinite' }} />Redirecting to your console
            </div>
            <style>{'@keyframes spin { to { transform: rotate(360deg); } }'}</style>
          </>
        ) : (
          <>
            <h1 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 22, letterSpacing: '-.02em', color: '#F4F3F0' }}>SSO sign-in failed</h1>
            <p style={{ margin: '9px 0 0', fontSize: 13, color: 'rgba(255,255,255,.55)', lineHeight: 1.6 }}>
              {error || 'We couldn’t complete single sign-on. Please try again, or sign in with your email and password.'}
            </p>
            <button
              onClick={() => navigate('/login', { replace: true })}
              style={{ marginTop: 24, height: 46, padding: '0 26px', border: 'none', borderRadius: 40, cursor: 'pointer', background: ACCENT, color: 'var(--accent-fg)', fontFamily: 'var(--font-body)', fontWeight: 700, fontSize: 14, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 9, boxShadow: '0 6px 22px color-mix(in srgb, var(--accent) 28%, transparent)' }}
            >
              <Icon name="arrow-left" size={16} />Return to sign-in
            </button>
          </>
        )}
      </div>
    </div>
  );
}
