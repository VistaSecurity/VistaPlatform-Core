// Public password-set landing for platform operators. This is where the
// InvitePlatformUser email link ({AdminUIBase}/reset-password?token=…) AND the
// forgot-password / admin-initiated reset links land — the token is the same
// mechanism for both, so one page serves invite acceptance and reset. Before
// this page existed the link dead-ended at /login (RequireAuth bounce) and
// invited admins could never set a password. Mounted OUTSIDE RequireAuth.
// Posts to admin-service POST /auth/reset-password { token, new_password, confirm_password }.
//
// When an admin_login SSO provider is configured, the page also offers
// "Continue with …": invited platform_users rows are created active, so
// the staff-SSO email-match gate already accepts them — setting a password is
// optional in that case. The reset token simply expires unused.
import { useState, type FormEvent } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import { useMutation } from '@tanstack/react-query';
import { Lock, Eye, EyeOff, ShieldCheck, ShieldX, BadgeCheck, ArrowRight, KeyRound } from 'lucide-react';
import { clients } from '../lib/clients';
import { staffProviderLabel, startStaffSso, useStaffSsoProviders } from '../lib/staff-sso';
import { AuthShell, AuthBackToLogin } from './auth-shell';

export function ResetPasswordPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const token = params.get('token') || '';

  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [show, setShow] = useState(false);
  const [done, setDone] = useState(false);

  const providersQ = useStaffSsoProviders();
  const ssoProviders = providersQ.data ?? [];

  const pwTooShort = password.length > 0 && password.length < 8;
  const mismatch = confirm.length > 0 && confirm !== password;
  const valid = !!token && password.length >= 8 && confirm === password;

  const submit = useMutation({
    mutationFn: async () => {
      const { data, error, response } = await clients.admin.POST('/auth/reset-password', {
        body: { token, new_password: password, confirm_password: confirm },
      });
      if (!response.ok || error || !data) {
        throw new Error((error as { error?: string } | undefined)?.error || 'Could not set your password. This link may have expired — request a new one from the sign-in page.');
      }
      return data;
    },
    onSuccess: () => setDone(true),
  });

  const onSubmit = (e: FormEvent) => { e.preventDefault(); if (valid) submit.mutate(); };

  if (!token) {
    return (
      <AuthShell eyebrow="Account access" title="Invalid link" subtitle="This link is missing its token or has already been used. Request a new one from the sign-in page.">
        <button type="button" className="op-btn primary" onClick={() => navigate('/login', { replace: true })} style={{ width: '100%', height: 44, justifyContent: 'center', fontSize: 14 }}>
          <ShieldX size={16} />Back to sign-in
        </button>
      </AuthShell>
    );
  }

  if (done) {
    return (
      <AuthShell eyebrow="Account access" title="Password set" subtitle="Your password has been set. Sign in with your new password to access the control plane.">
        <button type="button" className="op-btn primary" onClick={() => navigate('/login', { replace: true })} style={{ width: '100%', height: 44, justifyContent: 'center', fontSize: 14 }}>
          <BadgeCheck size={16} />Continue to sign-in<ArrowRight size={15} />
        </button>
      </AuthShell>
    );
  }

  return (
    <AuthShell
      eyebrow="Account access"
      title="Set your password"
      subtitle={ssoProviders.length > 0
        ? 'Sign in with your company account — or choose a password to finish setting up your operator account.'
        : 'Choose a password to finish setting up your operator account.'}
    >
      {ssoProviders.map((p, i) => (
        <button key={p.provider_type} type="button" className={i === 0 ? 'sso-btn primary' : 'sso-btn'} style={i > 0 ? { marginTop: 10 } : undefined} onClick={() => startStaffSso(p.provider_type)}>
          <KeyRound size={17} />Continue with {staffProviderLabel(p.provider_type)}
        </button>
      ))}

      {ssoProviders.length > 0 && (
        <>
          <div style={{ fontSize: 12, color: 'var(--op-t3)', marginTop: 10, lineHeight: 1.5 }}>
            Use the company account that matches your invited email address — no password needed.
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, margin: '18px 0' }}>
            <div style={{ flex: 1, height: 1, background: 'var(--op-border)' }} />
            <span style={{ fontSize: 10.5, color: 'var(--op-t3)', letterSpacing: '.1em' }}>OR SET A PASSWORD</span>
            <div style={{ flex: 1, height: 1, background: 'var(--op-border)' }} />
          </div>
        </>
      )}

      <form onSubmit={onSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 11 }}>
        <div className="lf-input" style={pwTooShort ? { borderColor: 'color-mix(in srgb, var(--danger) 50%, transparent)' } : undefined}>
          <Lock size={16} style={{ color: 'var(--op-t3)', flex: 'none' }} />
          <input type={show ? 'text' : 'password'} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" placeholder="New password (min 8 characters)" required autoFocus />
          {show
            ? <EyeOff size={16} style={{ color: 'var(--op-t3)', cursor: 'pointer', flex: 'none' }} onClick={() => setShow(false)} />
            : <Eye size={16} style={{ color: 'var(--op-t3)', cursor: 'pointer', flex: 'none' }} onClick={() => setShow(true)} />}
        </div>
        <div className="lf-input" style={mismatch ? { borderColor: 'color-mix(in srgb, var(--danger) 50%, transparent)' } : undefined}>
          <Lock size={16} style={{ color: 'var(--op-t3)', flex: 'none' }} />
          <input type={show ? 'text' : 'password'} value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" placeholder="Confirm new password" required />
        </div>

        {pwTooShort && <div style={{ fontSize: 12, color: 'var(--danger-soft)' }}>Use at least 8 characters.</div>}
        {mismatch && <div style={{ fontSize: 12, color: 'var(--danger-soft)' }}>Passwords don’t match.</div>}
        {submit.isError && <div style={{ fontSize: 12.5, color: 'var(--danger-text)' }}>{(submit.error as Error).message}</div>}

        <button type="submit" className="op-btn primary" disabled={!valid || submit.isPending} style={{ width: '100%', height: 44, justifyContent: 'center', marginTop: 6, fontSize: 14 }}>
          <ShieldCheck size={16} />{submit.isPending ? 'Setting password…' : 'Set password'}
        </button>
      </form>
      <AuthBackToLogin />
    </AuthShell>
  );
}
