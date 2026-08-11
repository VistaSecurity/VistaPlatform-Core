// Password-reset landing — the page a reset email link lands on (previously
// dead-ended at /login). Reads the reset token from the URL and posts a new
// password to the contracted POST /auth/reset-password. On success the
// user signs in with the new password. Public route — mounted outside RequireAuth.
import { useState, type FormEvent } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import { useMutation } from '@tanstack/react-query';
import { clients } from '../lib/clients';
import { Icon } from '../components/ui';
import { AuthShell, AuthLabel, AuthSubmit, AuthError, authInputStyle } from './auth-shell';

export function ResetPasswordPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const token = params.get('token') || '';

  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [done, setDone] = useState(false);

  const pwTooShort = password.length > 0 && password.length < 8;
  const mismatch = confirm.length > 0 && confirm !== password;
  const valid = !!token && password.length >= 8 && confirm === password;

  const submit = useMutation({
    mutationFn: async () => {
      // The contract carries both `password` and `new_password` (min 8); send the
      // chosen new password as both.
      const { data, error, response } = await clients.auth.POST('/auth/reset-password', {
        body: { token, password, new_password: password },
      });
      if (!response.ok || error || !data) throw new Error((error as { error?: string } | undefined)?.error || 'Could not reset your password. The link may have expired.');
      return data;
    },
    onSuccess: () => setDone(true),
  });

  const onSubmit = (e: FormEvent) => { e.preventDefault(); if (valid) submit.mutate(); };

  if (!token) {
    return (
      <AuthShell icon="shield-x" eyebrow="Password reset" title="Invalid reset link" subtitle="This password-reset link is missing its token or has already been used. Request a new one from the sign-in page."
        footer={<a href="/login" style={{ color: 'var(--accent-light)', textDecoration: 'none' }}>Back to sign-in</a>}>
        <button onClick={() => navigate('/login', { replace: true })} style={{ width: '100%', height: 48, border: 'none', borderRadius: 40, cursor: 'pointer', background: 'var(--accent-gradient)', color: 'var(--accent-fg)', fontWeight: 700, fontSize: 14.5, fontFamily: 'var(--font-body)' }}>Back to sign-in</button>
      </AuthShell>
    );
  }

  if (done) {
    return (
      <AuthShell icon="badge-check" eyebrow="Password reset" title="Password updated" subtitle="Your password has been changed. Sign in with your new password.">
        <button onClick={() => navigate('/login', { replace: true })} style={{ width: '100%', height: 48, border: 'none', borderRadius: 40, cursor: 'pointer', background: 'var(--accent-gradient)', color: 'var(--accent-fg)', fontWeight: 700, fontSize: 14.5, fontFamily: 'var(--font-body)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 9 }}>
          <Icon name="arrow-right" size={17} />Continue to sign-in
        </button>
      </AuthShell>
    );
  }

  return (
    <AuthShell icon="lock" eyebrow="Password reset" title="Choose a new password" subtitle="Set a new password for your account."
      footer={<a href="/login" style={{ color: 'var(--accent-light)', textDecoration: 'none' }}>Back to sign-in</a>}>
      <form onSubmit={onSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 13 }}>
        {submit.isError && <AuthError>{(submit.error as Error).message}</AuthError>}
        <div>
          <AuthLabel>New password</AuthLabel>
          <div style={{ position: 'relative' }}>
            <input type={showPw ? 'text' : 'password'} value={password} onChange={(e) => setPassword(e.target.value)} required autoFocus autoComplete="new-password"
              placeholder="At least 8 characters" style={{ ...authInputStyle, paddingRight: 44, borderColor: pwTooShort ? 'color-mix(in srgb, var(--danger) 50%, transparent)' : authInputStyle.border as string }} />
            <button type="button" onClick={() => setShowPw((v) => !v)} title={showPw ? 'Hide' : 'Show'} style={{ position: 'absolute', right: 12, top: 13, border: 'none', background: 'transparent', cursor: 'pointer', padding: 0 }}>
              <Icon name={showPw ? 'eye-off' : 'eye'} size={16} style={{ color: 'rgba(255,255,255,.42)' }} />
            </button>
          </div>
          {pwTooShort && <div style={{ fontSize: 11, color: 'var(--danger-soft)', marginTop: 5 }}>Use at least 8 characters.</div>}
        </div>
        <div>
          <AuthLabel>Confirm new password</AuthLabel>
          <input type={showPw ? 'text' : 'password'} value={confirm} onChange={(e) => setConfirm(e.target.value)} required autoComplete="new-password"
            style={{ ...authInputStyle, borderColor: mismatch ? 'color-mix(in srgb, var(--danger) 50%, transparent)' : authInputStyle.border as string }} />
          {mismatch && <div style={{ fontSize: 11, color: 'var(--danger-soft)', marginTop: 5 }}>Passwords don’t match.</div>}
        </div>
        <AuthSubmit disabled={!valid || submit.isPending}>
          <Icon name="shield-check" size={17} />{submit.isPending ? 'Updating…' : 'Reset password'}
        </AuthSubmit>
      </form>
    </AuthShell>
  );
}
