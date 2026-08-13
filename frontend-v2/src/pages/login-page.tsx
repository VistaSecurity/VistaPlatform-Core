import { useEffect, useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router';
import { useAuth } from '@vistasecurity/primitives/auth';
import { Icon } from '../components/ui';
import { clients } from '../lib/clients';
import { usePlatformBranding, BrandLogo } from '../app/platform-branding';

// An SSO sign-in option discovered for the typed email via POST /auth/methods.
type SsoOption = { provider: string; providerName: string; tenantId: string };

// Pretty label for the "Continue with …" button from the provider type.
function providerLabel(provider: string): string {
  switch (provider) {
    case 'google': return 'Google';
    case 'microsoft': return 'Microsoft';
    case 'azure': return 'Azure AD';
    default: return provider.charAt(0).toUpperCase() + provider.slice(1);
  }
}

// Returns the ?next= value if it is a safe internal OAuth path, null otherwise.
// Prevents open-redirect: only auth-service /oauth/ paths are allowed.
function safeNextURL(): string | null {
  const next = new URLSearchParams(window.location.search).get('next');
  if (!next) return null;
  try {
    const u = new URL(next, window.location.origin);
    if (u.origin !== window.location.origin) return null;
    if (!u.pathname.startsWith('/api/v1/auth-service/oauth/')) return null;
    return next;
  } catch {
    return null;
  }
}

// Vista sign-in — the mock's "Vault" concept (Logins.jsx, split-screen): a
// left brand stage + right form panel. Always dark (a premium pre-app screen),
// independent of the in-app theme. The functional spine — controlled inputs →
// useAuth().login → error/loading → redirect — is preserved from the original.
// SSO is email-first: "Continue with single sign-on" POSTs the email to
// /auth/methods, and if the user's tenant has an enabled OIDC provider, the
// browser navigates to the provider's authorize endpoint (a top-level redirect,
// which then bounces to Google/Microsoft and back to /auth/sso/callback).
// forgot-password is still omitted until that flow exists.

const ACCENT = 'var(--accent-gradient)';

export function LoginPage() {
  const { login, isLoginLoading, isAuthenticated, isInitializing } = useAuth();
  const navigate = useNavigate();
  // Email-first, progressive: ask for email, then show only the methods that
  // apply (SSO buttons and/or a password field). Avoids two competing CTAs.
  const [step, setStep] = useState<'email' | 'choose'>('email');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  // Arriving via the session-expiry redirect (?reason=session-expired, set by
  // the 401 handler in main.tsx) explains WHY the user is back at sign-in.
  const [error, setError] = useState<string | null>(() =>
    new URLSearchParams(window.location.search).get('reason') === 'session-expired'
      ? 'Your session has expired. Please sign in again.'
      : null,
  );
  const [busy, setBusy] = useState(false);
  const [ssoOptions, setSsoOptions] = useState<SsoOption[]>([]);
  // Provider types (e.g. "google") this email signed up with via Vista's shared
  // social-signup app — distinct from a tenant's own SSO above.
  const [platformProviders, setPlatformProviders] = useState<string[]>([]);
  const [passwordAllowed, setPasswordAllowed] = useState(true);

  const nextURL = safeNextURL();

  // Top-level navigation to the provider's OIDC authorize endpoint. A real
  // browser redirect (not fetch): authorize 302s to the IdP, which returns to
  // /api/v1/auth-service/auth/sso/<provider>/callback → /auth/sso/callback.
  const startSso = (opt: SsoOption) => {
    window.location.href = `/api/v1/auth-service/auth/sso/${encodeURIComponent(opt.providerName)}/authorize`
      + `?tenant_id=${encodeURIComponent(opt.tenantId)}`;
  };

  // Returning social-signup user: log back in via Vista's shared platform app.
  const startPlatformSso = (provider: string) => {
    window.location.href = `/api/v1/auth-service/auth/sso/platform/${encodeURIComponent(provider)}/authorize?flow=login`;
  };

  // Step 1 → 2: discover how this email can sign in.
  const continueEmail = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.trim())) {
      setError('Enter a valid work email to continue.');
      return;
    }
    setBusy(true);
    try {
      const { data, error: apiErr } = await clients.auth.POST('/auth/methods', { body: { email: email.trim() } });
      if (apiErr || !data) throw new Error('Could not check sign-in options. Please try again.');
      const tenantId = data.tenant_id ?? '';
      const options: SsoOption[] = (data.methods ?? [])
        .filter((m) => m.type === 'sso' && m.enabled && m.provider_name && tenantId)
        .map((m) => ({ provider: m.provider ?? 'sso', providerName: m.provider_name as string, tenantId }));
      const hasPassword = (data.methods ?? []).some((m) => m.type === 'password');
      const platformProvs = (data.methods ?? [])
        .filter((m) => m.type === 'platform_sso' && m.enabled && m.provider)
        .map((m) => m.provider as string);
      // One option and no password → go straight to the IdP, no extra click.
      if (options.length === 1 && platformProvs.length === 0 && !hasPassword) { startSso(options[0]); return; }
      if (options.length === 0 && platformProvs.length === 1 && !hasPassword) { startPlatformSso(platformProvs[0]); return; }
      setSsoOptions(options);
      setPlatformProviders(platformProvs);
      // Show the password field unless the only way in is SSO. (An unknown email
      // still falls through to a password field, which fails as before.)
      setPasswordAllowed(hasPassword || options.length === 0);
      setStep('choose');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not check sign-in options.');
    } finally {
      setBusy(false);
    }
  };

  const passwordSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await login(email.trim(), password);
      if (nextURL) window.location.href = nextURL;
      else navigate('/dashboard', { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sign-in failed');
    }
  };

  const backToEmail = () => { setStep('email'); setPassword(''); setError(null); setSsoOptions([]); setPlatformProviders([]); };

  useEffect(() => {
    if (!isInitializing && isAuthenticated) {
      if (nextURL) {
        window.location.href = nextURL;
      } else {
        navigate('/dashboard', { replace: true });
      }
    }
  }, [isInitializing, isAuthenticated, navigate, nextURL]);

  return (
    <div style={{ minHeight: '100vh', display: 'flex', background: '#0A0A0A', fontFamily: 'var(--font-body)', overflow: 'hidden' }}>
      {/* ---- left brand stage (hidden below 900px) ---- */}
      <div className="login-brand" style={{ position: 'relative', flex: '1 1 57%', overflow: 'hidden', background: 'radial-gradient(120% 90% at 30% 20%, #15110a 0%, #0A0A0A 55%)', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', padding: '52px 56px' }}>
        <Glow style={{ width: 620, height: 620, left: -120, top: -160, opacity: 0.6 }} />
        <Glow style={{ width: 420, height: 420, right: -60, bottom: -120, opacity: 0.3 }} />
        {/* concentric arcs */}
        <svg width="760" height="760" style={{ position: 'absolute', left: '50%', top: '50%', transform: 'translate(-50%,-48%)', opacity: 0.14, pointerEvents: 'none' }}>
          {[180, 270, 360].map((r, i) => <circle key={i} cx="380" cy="380" r={r} fill="none" stroke="url(#vg)" strokeWidth="1.2" />)}
          <defs><linearGradient id="vg" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stopColor="var(--accent-light)" /><stop offset="100%" stopColor="var(--accent-deep)" stopOpacity="0" /></linearGradient></defs>
        </svg>

        <Wordmark />

        <div style={{ position: 'relative', display: 'flex', flexDirection: 'column', alignItems: 'flex-start' }}>
          <div style={{ position: 'relative', width: 150, height: 150, marginBottom: 26 }}>
            <Glow style={{ inset: '-40%', opacity: 0.9 }} />
            <div style={{ position: 'relative', width: 150, height: 150, borderRadius: 36, background: ACCENT, display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 18px 40px rgba(0,0,0,.6)' }}>
              <Icon name="shield" size={78} style={{ color: '#0A0A0A' }} />
            </div>
          </div>
          <h2 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 800, fontSize: 42, lineHeight: 1.05, letterSpacing: '-.03em', color: '#F6F4EF', maxWidth: 500 }}>
            The Gold Standard<br />of Cryptographic<br />Observability.
          </h2>
          <p style={{ margin: '16px 0 0', fontSize: 15, lineHeight: 1.6, color: 'rgba(255,255,255,.6)', maxWidth: 420 }}>
            Discover, inventory, and grade every cryptographic asset across your network — with precision, discretion, and power.
          </p>
        </div>
      </div>

      {/* ---- right form panel ---- */}
      <div style={{ flex: '1 1 43%', minWidth: 0, background: '#0E0E10', borderLeft: '1px solid rgba(255,255,255,.06)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '40px 32px' }}>
        <div style={{ width: '100%', maxWidth: 380 }}>
          {/* wordmark shows here only when the brand stage is hidden */}
          <div className="login-form-word" style={{ marginBottom: 22, display: 'none' }}><Wordmark small /></div>

          <div style={{ fontFamily: 'var(--font-label)', fontWeight: 700, fontSize: 11, letterSpacing: '.16em', textTransform: 'uppercase', color: 'var(--accent-light)', marginBottom: 9 }}>Welcome back</div>
          <h1 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 27, letterSpacing: '-.02em', color: '#F4F3F0' }}>Sign in to your console</h1>
          <p style={{ margin: '7px 0 22px', fontSize: 13.5, color: 'rgba(255,255,255,.5)', lineHeight: 1.5 }}>Secure access to your cryptographic estate.</p>

          {step === 'email' ? (
            <form onSubmit={continueEmail} style={{ display: 'flex', flexDirection: 'column', gap: 11 }}>
              <LoginField icon="mail">
                <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoFocus required placeholder="Work email" style={inputStyle} />
              </LoginField>
              {error && <ErrorBox>{error}</ErrorBox>}
              <button type="submit" disabled={busy} style={primaryBtn(busy)}>
                <Icon name={busy ? 'loader' : 'arrow-right'} size={17} style={busy ? { animation: 'spin 1.1s linear infinite' } : undefined} />
                {busy ? 'Checking…' : 'Continue'}
              </button>
            </form>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 11 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 2 }}>
                <span style={{ fontSize: 12.5, color: 'rgba(255,255,255,.55)', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  Signing in as <strong style={{ color: 'rgba(255,255,255,.85)' }}>{email.trim()}</strong>
                </span>
                <button type="button" onClick={backToEmail} style={{ border: 'none', background: 'transparent', color: 'var(--accent-light)', cursor: 'pointer', fontSize: 12.5, fontWeight: 600, padding: 0, flex: 'none' }}>Change</button>
              </div>

              {ssoOptions.map((opt) => (
                <button key={opt.providerName} type="button" onClick={() => startSso(opt)} style={ssoBtnStyle}>
                  <Icon name="key-round" size={16} style={{ color: 'rgba(255,215,115,.85)' }} />
                  Continue with {providerLabel(opt.provider)}
                </button>
              ))}
              {platformProviders.map((p) => (
                <button key={`platform-${p}`} type="button" onClick={() => startPlatformSso(p)} style={ssoBtnStyle}>
                  <Icon name="key-round" size={16} style={{ color: 'rgba(255,215,115,.85)' }} />
                  Continue with {providerLabel(p)}
                </button>
              ))}

              {passwordAllowed && (ssoOptions.length > 0 || platformProviders.length > 0) && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, margin: '6px 0' }}>
                  <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,.09)' }} />
                  <span style={{ fontSize: 11, letterSpacing: '.12em', textTransform: 'uppercase', color: 'rgba(255,255,255,.34)' }}>or use your password</span>
                  <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,.09)' }} />
                </div>
              )}

              {passwordAllowed && (
                <form onSubmit={passwordSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 11 }}>
                  <LoginField icon="lock" trailing={
                    <button type="button" onClick={() => setShowPw((v) => !v)} title={showPw ? 'Hide password' : 'Show password'} style={{ border: 'none', background: 'transparent', cursor: 'pointer', display: 'flex', padding: 0 }}>
                      <Icon name={showPw ? 'eye-off' : 'eye'} size={16} style={{ color: 'rgba(255,255,255,.42)' }} />
                    </button>
                  }>
                    <input type={showPw ? 'text' : 'password'} value={password} onChange={(e) => setPassword(e.target.value)} autoFocus required placeholder="Password" style={inputStyle} />
                  </LoginField>
                  {error && <ErrorBox>{error}</ErrorBox>}
                  <button type="submit" disabled={isLoginLoading} style={primaryBtn(isLoginLoading)}>
                    <Icon name="shield-check" size={17} />{isLoginLoading ? 'Signing in…' : 'Sign in securely'}
                  </button>
                </form>
              )}
              {!passwordAllowed && error && <ErrorBox>{error}</ErrorBox>}
            </div>
          )}
          <style>{'@keyframes spin { to { transform: rotate(360deg); } }'}</style>

          <p style={{ margin: '22px 0 0', fontSize: 13, color: 'rgba(255,255,255,.5)', textAlign: 'center' }}>
            New to Vista? <a href="/signup" style={{ color: 'var(--accent-light)', textDecoration: 'none', fontWeight: 600 }}>Create an account</a>
          </p>
          <p style={{ margin: '12px 0 0', fontSize: 11.5, color: 'rgba(255,255,255,.36)', textAlign: 'center', lineHeight: 1.6 }}>
            Protected by Vista. Invited by your team? Use the link in your email.
          </p>
        </div>
      </div>

      {/* responsive: collapse the split below 900px */}
      <style>{`
        @media (max-width: 900px) {
          .login-brand { display: none !important; }
          .login-form-word { display: block !important; }
        }
      `}</style>
    </div>
  );
}

function Glow({ style }: { style: React.CSSProperties }) {
  return <div style={{ position: 'absolute', borderRadius: '50%', background: 'var(--accent-glow)', pointerEvents: 'none', mixBlendMode: 'screen', ...style }} />;
}

function Wordmark({ small }: { small?: boolean }) {
  const size = small ? 24 : 28;
  const { name, loginLogoUrl } = usePlatformBranding();
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
      <BrandLogo
        url={loginLogoUrl} size={size + 8} radius={9} shadow="0 0 18px color-mix(in srgb, var(--accent) 50%, transparent)" alt={name}
        fallback={
          <div style={{ width: size + 8, height: size + 8, borderRadius: 9, background: ACCENT, display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 0 18px color-mix(in srgb, var(--accent) 50%, transparent)', flex: 'none' }}>
            <Icon name="shield" size={Math.round(size * 0.62)} style={{ color: '#0A0A0A' }} />
          </div>
        }
      />
      <div style={{ lineHeight: 1 }}>
        <div className="wordmark accent-text" style={{ fontSize: size, fontWeight: 900, letterSpacing: '.2em' }}>{name}</div>
        <div style={{ fontSize: Math.round(size * 0.3), letterSpacing: '.32em', textTransform: 'uppercase', color: 'rgba(255,255,255,.4)', marginTop: 4 }}>Console</div>
      </div>
    </div>
  );
}

function LoginField({ icon, trailing, children }: { icon: string; trailing?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, height: 48, padding: '0 14px', borderRadius: 12, background: 'rgba(255,255,255,.045)', border: '1px solid rgba(255,255,255,.11)' }}>
      <Icon name={icon} size={17} style={{ color: 'rgba(255,255,255,.42)', flex: 'none' }} />
      {children}
      {trailing}
    </div>
  );
}

function ErrorBox({ children }: { children: React.ReactNode }) {
  return <div style={{ fontSize: 12.5, color: 'var(--danger-soft)', background: 'color-mix(in srgb, var(--danger) 12%, transparent)', border: '1px solid color-mix(in srgb, var(--danger) 28%, transparent)', borderRadius: 10, padding: '9px 12px' }}>{children}</div>;
}

function primaryBtn(disabled: boolean): React.CSSProperties {
  return {
    width: '100%', height: 50, marginTop: 4, border: 'none', borderRadius: 40,
    cursor: disabled ? 'default' : 'pointer', background: ACCENT, color: 'var(--accent-fg)',
    fontFamily: 'var(--font-body)', fontWeight: 700, fontSize: 15, letterSpacing: '-.01em',
    display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 9,
    boxShadow: '0 6px 22px color-mix(in srgb, var(--accent) 28%, transparent), inset 0 1px 0 rgba(255,255,255,.35)',
    opacity: disabled ? 0.7 : 1,
  };
}

const inputStyle: React.CSSProperties = {
  flex: 1,
  minWidth: 0,
  border: 'none',
  background: 'transparent',
  outline: 'none',
  fontFamily: 'var(--font-body)',
  fontSize: 14,
  color: '#F1F1F2',
};

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
