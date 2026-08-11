// Shared two-pane shell for the public operator auth pages that aren't the full
// login screen — password reset (from an invite/reset email link) and the
// forgot-password request. Reuses the login screen's .login-wrap/.login-stage/
// .login-form layout and platform branding so these pages match the operator
// look, without duplicating the login stage's elaborate status board.
import type { ReactNode } from 'react';
import { Shield } from 'lucide-react';
import { usePlatformBranding, BrandLogo } from '../app/platform-branding';

export function AuthShell({
  eyebrow, title, subtitle, children,
}: {
  eyebrow: string;
  title: string;
  subtitle: string;
  children: ReactNode;
}) {
  const { name, loginLogoUrl } = usePlatformBranding();

  return (
    <div className="login-wrap">
      {/* ===== brand stage (condensed) ===== */}
      <div className="login-stage">
        <div className="glow" style={{ width: 560, height: 560, left: -140, top: -180, background: 'radial-gradient(circle, color-mix(in srgb, var(--accent-deep) 30%, transparent) 0%, color-mix(in srgb, var(--accent-deep) 0%, transparent) 70%)', opacity: 0.7 }} />
        <div className="glow" style={{ width: 420, height: 420, right: -80, bottom: -120, background: 'radial-gradient(circle, color-mix(in srgb, var(--accent) 30%, transparent) 0%, transparent 70%)', opacity: 0.55 }} />
        <svg width="720" height="720" style={{ position: 'absolute', left: '46%', top: '52%', transform: 'translate(-50%,-50%)', opacity: 0.12 }}>
          {[170, 250, 330, 410].map((r, i) => <circle key={i} cx="360" cy="360" r={r} fill="none" stroke="url(#og-auth)" strokeWidth="1" />)}
          <defs><radialGradient id="og-auth"><stop offset="0%" stopColor="var(--accent-light)" /><stop offset="100%" stopColor="var(--info)" stopOpacity="0" /></radialGradient></defs>
        </svg>

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

        <div style={{ position: 'relative', maxWidth: 460 }}>
          <h1 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 800, fontSize: 42, lineHeight: 1.05, letterSpacing: '-.03em', color: '#F4F6FA' }}>Platform control.</h1>
          <p style={{ margin: '15px 0 0', fontSize: 15, lineHeight: 1.6, color: 'rgba(255,255,255,.58)', maxWidth: 400 }}>
            Secure access to the {name} control plane — for authorized platform operators only.
          </p>
        </div>
      </div>

      {/* ===== form pane ===== */}
      <div className="login-form">
        <div style={{ width: '100%', maxWidth: 380 }}>
          <div className="op-eyebrow" style={{ color: 'var(--op-accent-text)', marginBottom: 9 }}>{eyebrow}</div>
          <h2 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 26, letterSpacing: '-.02em', color: 'var(--op-t1)' }}>{title}</h2>
          <p style={{ margin: '7px 0 24px', fontSize: 13.5, color: 'var(--op-t3)', lineHeight: 1.5 }}>{subtitle}</p>
          {children}
        </div>
      </div>
    </div>
  );
}

export function AuthBackToLogin() {
  return (
    <div style={{ marginTop: 20, textAlign: 'center' }}>
      <a href="/login" style={{ fontSize: 12.5, color: 'var(--op-accent-text)', textDecoration: 'none' }}>Back to sign-in</a>
    </div>
  );
}
