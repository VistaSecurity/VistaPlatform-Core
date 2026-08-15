import { useEffect, useState, type FormEvent } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import {
  Shield, ShieldAlert, KeyRound, Mail, Lock, Eye, EyeOff,
  Check, LogIn,
} from 'lucide-react';
import { usePlatformAuth } from '@vistasecurity/primitives/platform-auth';
import { usePlatformBranding, BrandLogo } from '../app/platform-branding';
import { StatusDot } from '../components/ui/primitives';
import { staffProviderLabel, startStaffSso, useStaffSsoProviders } from '../lib/staff-sso';
// Maps a callback ?error= to an operator-facing message.
const SSO_ERRORS: Record<string, string> = {
  no_admin_account: 'No admin account is linked to that identity. Ask an administrator to add you, then try again.',
  sso_state: 'Sign-in could not be verified. Please try again.',
  sso_no_email: 'The identity provider did not return an email address.',
  sso_unavailable: 'That single sign-on option is not available right now.',
  sso_exchange: 'Single sign-on failed during the provider handshake. Please try again.',
};

// VISTA Operations sign-in — the design kit's SSO-first / passkey two-pane
// screen ("VISTA Operations Login.html"), ported faithfully. Layout classes
// (.login-wrap/.login-stage/.login-form/.lf-input/.sso-btn) live in
// styles/operator.css; tokens resolve from the global data-theme/accent/geo on
// <html>. Always dark, operator-grade (deliberately NOT the Console's split).
//
// The CREDENTIALS path is the real, working spine — controlled inputs →
// usePlatformAuth().login → error/loading → redirect, backed by
// @vistasecurity/primitives/platform-auth. The kit's SSO/passkey buttons are
// design surface with no backend yet (clicking explains that and points at
// credentials); "Trust this device" is likewise not wired. "Forgot password?"
// IS wired — it links to /forgot-password (POST /auth/forgot-password), which is
// also the accept path for platform-admin invites (/reset-password?token=…).
export function LoginPage() {
  const { login, isLoginLoading, isAuthenticated, isInitializing } = usePlatformAuth();
  const { name, loginLogoUrl } = usePlatformBranding();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [show, setShow] = useState(false);
  const [trustDevice, setTrustDevice] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [params] = useSearchParams();

  // Staff-login providers. Empty unless an admin_login IdP is configured;
  // the cosmetic Okta/passkey buttons are replaced by these real ones.
  const providersQ = useStaffSsoProviders();
  const ssoProviders = providersQ.data ?? [];

  // Surface a failed SSO round-trip (?error= from the callback redirect) or a
  // session-expiry redirect (?reason= from the 401 handler in main.tsx).
  useEffect(() => {
    const e = params.get('error');
    if (e) setError(SSO_ERRORS[e] ?? 'Single sign-on failed. Please try again or use credentials.');
    else if (params.get('reason') === 'session-expired') setError('Your session has expired. Please sign in again.');
    else if (params.get('reason') === 'signed-out') setError('You have been signed out. Please sign in again.');
  }, [params]);

  useEffect(() => {
    if (!isInitializing && isAuthenticated) navigate('/overview', { replace: true });
  }, [isInitializing, isAuthenticated, navigate]);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await login(email, password);
      navigate('/overview', { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sign-in failed');
    }
  };

  return (
    <div className="login-wrap">
      {/* ===== brand / status stage ===== */}
      <div className="login-stage">
        <div className="glow" style={{ width: 560, height: 560, left: -140, top: -180, background: 'radial-gradient(circle, color-mix(in srgb, var(--accent-deep) 30%, transparent) 0%, color-mix(in srgb, var(--accent-deep) 0%, transparent) 70%)', opacity: 0.7 }} />
        <div className="glow" style={{ width: 420, height: 420, right: -80, bottom: -120, background: 'radial-gradient(circle, color-mix(in srgb, var(--accent) 30%, transparent) 0%, transparent 70%)', opacity: 0.55 }} />
        <svg width="720" height="720" style={{ position: 'absolute', left: '46%', top: '52%', transform: 'translate(-50%,-50%)', opacity: 0.12 }}>
          {[170, 250, 330, 410].map((r, i) => <circle key={i} cx="360" cy="360" r={r} fill="none" stroke="url(#og)" strokeWidth="1" />)}
          <defs><radialGradient id="og"><stop offset="0%" stopColor="var(--accent-light)" /><stop offset="100%" stopColor="var(--info)" stopOpacity="0" /></radialGradient></defs>
        </svg>

        {/* lockup */}
        <div style={{ position: 'relative', display: 'flex', alignItems: 'center', gap: 13 }}>
          <BrandLogo
            url={loginLogoUrl} size={38} radius="var(--r-md)" shadow="0 0 18px color-mix(in srgb, var(--accent) 50%, transparent)" alt={name}
            fallback={
              <span style={{ width: 38, height: 38, borderRadius: 'var(--r-md)', background: 'var(--accent-gradient)', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 0 18px color-mix(in srgb, var(--accent) 50%, transparent)', flex: 'none' }}>
                <Shield size={21} style={{ color: '#0A0A0A' }} />
              </span>
            }
          />
          <div style={{ lineHeight: 1 }}>
            <div className="wordmark accent-text" style={{ fontSize: 21 }}>{name}</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginTop: 5 }}>
              <span style={{ fontSize: 10, letterSpacing: '.22em', textTransform: 'uppercase', color: 'rgba(255,255,255,.5)', fontWeight: 600 }}>Operations</span>
              <span style={{ fontSize: 8, fontWeight: 700, letterSpacing: '.1em', color: 'var(--warn-light)', background: 'color-mix(in srgb, var(--accent) 16%, transparent)', border: '1px solid color-mix(in srgb, var(--accent) 30%, transparent)', borderRadius: 4, padding: '1px 5px', textTransform: 'uppercase' }}>Internal</span>
            </div>
          </div>
        </div>

        {/* headline + status board */}
        <div style={{ position: 'relative', maxWidth: 460 }}>
          <h1 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 800, fontSize: 42, lineHeight: 1.05, letterSpacing: '-.03em', color: '#F4F6FA' }}>Platform control.</h1>
          <p style={{ margin: '15px 0 0', fontSize: 15, lineHeight: 1.6, color: 'rgba(255,255,255,.58)', maxWidth: 400 }}>
            Operate the VISTA platform end to end — tenants, the discovery fleet, revenue, and the catalog that grades every customer's crypto.
          </p>
          <div style={{ marginTop: 28, padding: '16px 18px 6px', borderRadius: 'var(--r-lg)', background: 'rgba(255,255,255,.035)', border: '1px solid rgba(255,255,255,.09)', backdropFilter: 'blur(20px)', maxWidth: 360 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: 4 }}>
              <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: '.13em', textTransform: 'uppercase', color: 'rgba(255,255,255,.4)' }}>Platform status</span>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11.5, fontWeight: 600, color: 'var(--ok)' }}><StatusDot status="operational" size={7} />Operational</span>
            </div>
            <StatusRow label="Fleet online" value="86%" />
            <StatusRow label="Active tenants" value="11" />
            <StatusRow label="Recurring revenue" value="$387k" color="var(--accent-light)" />
          </div>
        </div>
      </div>

      {/* ===== auth form ===== */}
      <div className="login-form">
        <div style={{ width: '100%', maxWidth: 380 }}>
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 22 }}>
            <span className="op-chip" style={{ cursor: 'default' }}>
              <span style={{ width: 6, height: 6, borderRadius: 50, background: 'var(--danger)' }} />production
              <span style={{ color: 'var(--op-t3)' }}>·</span><span className="mono">us-east-1</span>
            </span>
          </div>

          <div className="op-eyebrow" style={{ color: 'var(--op-accent-text)', marginBottom: 9 }}>Operator sign-in</div>
          <h2 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 26, letterSpacing: '-.02em', color: 'var(--op-t1)' }}>Access the control plane</h2>
          <p style={{ margin: '7px 0 24px', fontSize: 13.5, color: 'var(--op-t3)', lineHeight: 1.5 }}>{ssoProviders.length > 0 ? 'Sign in with your company account, or use credentials.' : 'Sign in to operate the platform.'}</p>

          {ssoProviders.map((p, i) => (
            <button key={p.provider_type} type="button" className={i === 0 ? 'sso-btn primary' : 'sso-btn'} style={i > 0 ? { marginTop: 10 } : undefined} onClick={() => startStaffSso(p.provider_type)}>
              <KeyRound size={17} />Continue with {staffProviderLabel(p.provider_type)}
            </button>
          ))}

          {ssoProviders.length > 0 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, margin: '20px 0' }}>
              <div style={{ flex: 1, height: 1, background: 'var(--op-border)' }} />
              <span style={{ fontSize: 10.5, color: 'var(--op-t3)', letterSpacing: '.1em' }}>OR USE CREDENTIALS</span>
              <div style={{ flex: 1, height: 1, background: 'var(--op-border)' }} />
            </div>
          )}

          <form onSubmit={onSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 11 }}>
            <div className="lf-input">
              <Mail size={16} style={{ color: 'var(--op-t3)', flex: 'none' }} />
              <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" placeholder="Work email" required />
            </div>
            <div className="lf-input">
              <Lock size={16} style={{ color: 'var(--op-t3)', flex: 'none' }} />
              <input type={show ? 'text' : 'password'} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" placeholder="Password" required />
              {show
                ? <EyeOff size={16} style={{ color: 'var(--op-t3)', cursor: 'pointer', flex: 'none' }} onClick={() => setShow(false)} />
                : <Eye size={16} style={{ color: 'var(--op-t3)', cursor: 'pointer', flex: 'none' }} onClick={() => setShow(true)} />}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 1 }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12.5, color: 'var(--op-t3)', cursor: 'pointer' }}>
                <input type="checkbox" checked={trustDevice} onChange={(e) => setTrustDevice(e.target.checked)} style={{ position: 'absolute', opacity: 0, width: 0, height: 0 }} />
                <span style={{ width: 16, height: 16, borderRadius: 4, background: trustDevice ? 'var(--op-accent)' : 'var(--op-panel2)', border: trustDevice ? 'none' : '1px solid var(--op-border2)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center' }}>
                  {trustDevice && <Check size={11} style={{ color: 'var(--op-on-accent)' }} />}
                </span>
                Trust this device
              </label>
              <a href="/forgot-password" style={{ fontSize: 12.5, color: 'var(--op-accent-text)', textDecoration: 'none' }}>Forgot password?</a>
            </div>

            {error && <div style={{ fontSize: 12.5, color: 'var(--danger-text)', marginTop: 2 }}>{error}</div>}

            <button type="submit" className="op-btn" disabled={isLoginLoading} style={{ width: '100%', height: 44, justifyContent: 'center', marginTop: 16, fontSize: 14 }}>
              <LogIn size={16} />{isLoginLoading ? 'Signing in…' : 'Sign in'}
            </button>
          </form>

          <div style={{ display: 'flex', gap: 9, marginTop: 22, padding: '11px 13px', borderRadius: 'var(--r-md)', background: 'var(--op-panel2)', border: '1px solid var(--op-border)' }}>
            <ShieldAlert size={15} style={{ color: 'var(--op-t3)', flex: 'none', marginTop: 1 }} />
            <span style={{ fontSize: 11.5, color: 'var(--op-t3)', lineHeight: 1.5 }}>
              Authorized personnel only. Every session is recorded to the platform audit log.
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

function StatusRow({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 0', borderTop: '1px solid rgba(255,255,255,.07)' }}>
      <span style={{ fontSize: 12.5, color: 'rgba(255,255,255,.55)', flex: 1 }}>{label}</span>
      <span className="op-num" style={{ fontSize: 13.5, fontWeight: 700, color: color || '#fff' }}>{value}</span>
    </div>
  );
}
