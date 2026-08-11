// Shared chrome for the pre-app auth screens (complete-profile, reset-password).
// Matches the login page's dark premium aesthetic without coupling to it — a
// centered card on the dark radial stage with the VISTA wordmark. Always dark,
// independent of the in-app theme.
import { type ReactNode } from 'react';
import { Icon } from '../components/ui';
import { usePlatformBranding, BrandLogo } from '../app/platform-branding';

const ACCENT = 'var(--accent-gradient)';

export function AuthShell({ icon, eyebrow, title, subtitle, children, footer }: {
  icon: string;
  eyebrow?: string;
  title: string;
  subtitle?: string;
  children: ReactNode;
  footer?: ReactNode;
}) {
  const { name, loginLogoUrl } = usePlatformBranding();
  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'radial-gradient(120% 90% at 30% 20%, #15110a 0%, #0A0A0A 55%)', fontFamily: 'var(--font-body)', padding: 24 }}>
      <div style={{ width: '100%', maxWidth: 408 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 11, marginBottom: 26 }}>
          <BrandLogo
            url={loginLogoUrl} size={34} radius={9} shadow="0 0 18px color-mix(in srgb, var(--accent) 50%, transparent)" alt={name}
            fallback={
              <div style={{ width: 34, height: 34, borderRadius: 9, background: ACCENT, display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 'none', boxShadow: '0 0 18px color-mix(in srgb, var(--accent) 50%, transparent)' }}>
                <Icon name="shield" size={19} style={{ color: '#0A0A0A' }} />
              </div>
            }
          />
          <div style={{ lineHeight: 1 }}>
            <div className="wordmark accent-text" style={{ fontSize: 21, fontWeight: 900, letterSpacing: '.2em' }}>{name}</div>
            <div style={{ fontSize: 9, letterSpacing: '.32em', textTransform: 'uppercase', color: 'rgba(255,255,255,.4)', marginTop: 4 }}>Console</div>
          </div>
        </div>

        <div style={{ background: '#0E0E10', border: '1px solid rgba(255,255,255,.08)', borderRadius: 18, padding: '28px 26px' }}>
          <div style={{ width: 46, height: 46, borderRadius: 12, background: 'color-mix(in srgb, var(--accent) 14%, transparent)', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 16, color: 'var(--accent-light)' }}>
            <Icon name={icon} size={23} />
          </div>
          {eyebrow && <div style={{ fontFamily: 'var(--font-label)', fontWeight: 700, fontSize: 10.5, letterSpacing: '.16em', textTransform: 'uppercase', color: 'var(--accent-light)', marginBottom: 8 }}>{eyebrow}</div>}
          <h1 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 24, letterSpacing: '-.02em', color: '#F4F3F0' }}>{title}</h1>
          {subtitle && <p style={{ margin: '8px 0 20px', fontSize: 13.5, color: 'rgba(255,255,255,.5)', lineHeight: 1.55 }}>{subtitle}</p>}
          <div style={{ marginTop: subtitle ? 0 : 18 }}>{children}</div>
        </div>

        {footer && <div style={{ marginTop: 18, textAlign: 'center', fontSize: 12.5, color: 'rgba(255,255,255,.4)' }}>{footer}</div>}
      </div>
    </div>
  );
}

export const authInputStyle: React.CSSProperties = {
  width: '100%', height: 46, padding: '0 14px', borderRadius: 11,
  background: 'rgba(255,255,255,.045)', border: '1px solid rgba(255,255,255,.11)',
  outline: 'none', fontFamily: 'var(--font-body)', fontSize: 14, color: '#F1F1F2',
};

export function AuthLabel({ children }: { children: ReactNode }) {
  return <div style={{ fontSize: 12, fontWeight: 600, color: 'rgba(255,255,255,.62)', marginBottom: 6 }}>{children}</div>;
}

export function AuthSubmit({ disabled, children }: { disabled?: boolean; children: ReactNode }) {
  return (
    <button type="submit" disabled={disabled} style={{
      width: '100%', height: 48, marginTop: 6, border: 'none', borderRadius: 40, cursor: disabled ? 'default' : 'pointer',
      background: 'var(--accent-gradient)', color: 'var(--accent-fg)', fontFamily: 'var(--font-body)', fontWeight: 700, fontSize: 14.5,
      display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 9,
      boxShadow: '0 6px 22px color-mix(in srgb, var(--accent) 28%, transparent), inset 0 1px 0 rgba(255,255,255,.35)', opacity: disabled ? 0.6 : 1,
    }}>{children}</button>
  );
}

export function AuthError({ children }: { children: ReactNode }) {
  return <div style={{ fontSize: 12.5, color: 'var(--danger-soft)', background: 'color-mix(in srgb, var(--danger) 12%, transparent)', border: '1px solid color-mix(in srgb, var(--danger) 28%, transparent)', borderRadius: 10, padding: '9px 12px', marginBottom: 12 }}>{children}</div>;
}
