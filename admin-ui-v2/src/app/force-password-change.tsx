import { useState, type FormEvent } from 'react';
import { Lock, Eye, EyeOff, KeyRound, ShieldAlert } from 'lucide-react';
import { usePlatformAuth } from '@vistasecurity/primitives/platform-auth';
import { usePlatformBranding, BrandLogo } from './platform-branding';

// Mandatory change-password interstitial. Rendered by RequireAuth when the
// signed-in operator carries `force_password_change` (temp password on first
// login, or an admin-forced reset). It blocks every other route — the app tree
// is not mounted until the flag clears — so the credential-hygiene gate the flag
// exists to enforce is actually enforced. changePassword() refetches /me on
// success, which flips forcePasswordChange false and lets RequireAuth proceed.
export function ForcePasswordChange() {
  const { changePassword, logout } = usePlatformAuth();
  const { name, loginLogoUrl } = usePlatformBranding();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [show, setShow] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (next.length < 8) { setError('New password must be at least 8 characters.'); return; }
    if (next !== confirm) { setError('The new password and confirmation do not match.'); return; }
    if (next === current) { setError('Choose a password different from your current one.'); return; }
    setBusy(true);
    try {
      await changePassword(current, next, confirm);
      // On success the primitive refetches /me; forcePasswordChange flips false
      // and RequireAuth mounts the app. No navigation needed here.
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not change password');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--op-bg)', padding: 24 }}>
      <div style={{ width: '100%', maxWidth: 400 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 11, marginBottom: 22 }}>
          <BrandLogo
            url={loginLogoUrl} size={34} radius="var(--r-md)" alt={name}
            fallback={
              <span style={{ width: 34, height: 34, borderRadius: 'var(--r-md)', background: 'var(--accent-gradient)', display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 'none' }}>
                <KeyRound size={18} style={{ color: '#0A0A0A' }} />
              </span>
            }
          />
          <div className="wordmark accent-text" style={{ fontSize: 18 }}>{name}</div>
        </div>

        <div className="op-eyebrow" style={{ color: 'var(--op-accent-text)', marginBottom: 9 }}>Security required</div>
        <h2 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 24, letterSpacing: '-.02em', color: 'var(--op-t1)' }}>Set a new password</h2>
        <p style={{ margin: '7px 0 22px', fontSize: 13.5, color: 'var(--op-t3)', lineHeight: 1.5 }}>
          Your account requires a password change before you can continue.
        </p>

        <form onSubmit={onSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 11 }}>
          <div className="lf-input">
            <Lock size={16} style={{ color: 'var(--op-t3)', flex: 'none' }} />
            <input type={show ? 'text' : 'password'} value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" placeholder="Current password" required />
          </div>
          <div className="lf-input">
            <Lock size={16} style={{ color: 'var(--op-t3)', flex: 'none' }} />
            <input type={show ? 'text' : 'password'} value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" placeholder="New password" required />
            {show
              ? <EyeOff size={16} style={{ color: 'var(--op-t3)', cursor: 'pointer', flex: 'none' }} onClick={() => setShow(false)} />
              : <Eye size={16} style={{ color: 'var(--op-t3)', cursor: 'pointer', flex: 'none' }} onClick={() => setShow(true)} />}
          </div>
          <div className="lf-input">
            <Lock size={16} style={{ color: 'var(--op-t3)', flex: 'none' }} />
            <input type={show ? 'text' : 'password'} value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" placeholder="Confirm new password" required />
          </div>

          {error && <div style={{ fontSize: 12.5, color: 'var(--danger-text)', marginTop: 2 }}>{error}</div>}

          <button type="submit" className="op-btn" disabled={busy} style={{ width: '100%', height: 44, justifyContent: 'center', marginTop: 6, fontSize: 14 }}>
            <KeyRound size={16} />{busy ? 'Updating…' : 'Update password'}
          </button>
        </form>

        <div style={{ display: 'flex', gap: 9, marginTop: 20, padding: '11px 13px', borderRadius: 'var(--r-md)', background: 'var(--op-panel2)', border: '1px solid var(--op-border)' }}>
          <ShieldAlert size={15} style={{ color: 'var(--op-t3)', flex: 'none', marginTop: 1 }} />
          <span style={{ fontSize: 11.5, color: 'var(--op-t3)', lineHeight: 1.5 }}>
            Not you, or signed in by mistake? <span onClick={() => logout()} style={{ color: 'var(--op-accent-text)', fontWeight: 600, cursor: 'pointer' }}>Sign out</span>.
          </span>
        </div>
      </div>
    </div>
  );
}
