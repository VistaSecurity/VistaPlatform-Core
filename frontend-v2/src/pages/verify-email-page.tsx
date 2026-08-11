// Public email-verification landing — the target of the link in the verification
// email. Reads ?token=, calls POST /auth/verify-email, and routes to sign-in on
// success. On an invalid/expired token it offers a resend (by email). Public
// route — mounted outside RequireAuth.
// Spec: docsv4/internal/developer/standards/features/signup-entry.md
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import { useMutation } from '@tanstack/react-query';
import { clients } from '../lib/clients';
import { Icon } from '../components/ui';
import { AuthShell, AuthLabel, AuthSubmit, AuthError, authInputStyle } from './auth-shell';

export function VerifyEmailPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const token = params.get('token') || '';
  const [resendEmail, setResendEmail] = useState('');
  const ran = useRef(false);

  const verify = useMutation({
    mutationFn: async () => {
      const { data, error } = await clients.auth.POST('/auth/verify-email', { params: { query: { token } } });
      if (error || !data) throw new Error((error as { error?: string } | undefined)?.error || 'This verification link is invalid or has expired.');
      return data;
    },
  });

  const resend = useMutation({
    mutationFn: async () => {
      const { error } = await clients.auth.POST('/auth/resend-verification', { body: { email: resendEmail.trim() } });
      if (error) throw new Error('Could not resend the email.');
    },
  });

  // Verify once on mount (guard against StrictMode double-invoke).
  useEffect(() => {
    if (token && !ran.current) {
      ran.current = true;
      verify.mutate();
    }
  }, [token, verify]);

  if (!token) {
    return (
      <AuthShell icon="circle-alert" eyebrow="Verification" title="Invalid link"
        subtitle="This link is missing its verification token. Use the link from your verification email."
        footer={<a href="/login" style={{ color: 'var(--accent-light)', textDecoration: 'none' }}>Back to sign in</a>}>
        <span />
      </AuthShell>
    );
  }

  if (verify.isPending || verify.isIdle) {
    return (
      <AuthShell icon="shield-check" eyebrow="Verification" title="Verifying your email…" subtitle="One moment while we confirm your link.">
        <span />
      </AuthShell>
    );
  }

  if (verify.isSuccess) {
    return (
      <AuthShell icon="badge-check" eyebrow="Verified" title="Email verified"
        subtitle="Your account is active. Sign in to enter the console.">
        <button type="button" onClick={() => navigate('/login', { replace: true })} style={primaryBtn}>
          <Icon name="arrow-right" size={17} />Continue to sign-in
        </button>
      </AuthShell>
    );
  }

  // error / expired → offer resend
  const onResend = (e: FormEvent) => { e.preventDefault(); if (resendEmail.trim()) resend.mutate(); };
  return (
    <AuthShell icon="circle-alert" eyebrow="Verification" title="Link invalid or expired"
      subtitle="This verification link can't be used. Enter your email and we'll send a fresh one."
      footer={<a href="/login" style={{ color: 'var(--accent-light)', textDecoration: 'none' }}>Back to sign in</a>}>
      {resend.isSuccess ? (
        <div style={{ fontSize: 13, color: 'var(--ok)' }}>If that email is unverified, a new verification link is on its way.</div>
      ) : (
        <form onSubmit={onResend} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {resend.isError && <AuthError>{(resend.error as Error).message}</AuthError>}
          <div>
            <AuthLabel>Work email</AuthLabel>
            <input type="email" value={resendEmail} onChange={(e) => setResendEmail(e.target.value)} required autoFocus
              placeholder="you@company.com" style={authInputStyle} />
          </div>
          <AuthSubmit disabled={!resendEmail.trim() || resend.isPending}>
            <Icon name="mail" size={16} />{resend.isPending ? 'Sending…' : 'Resend verification email'}
          </AuthSubmit>
        </form>
      )}
    </AuthShell>
  );
}

const primaryBtn: React.CSSProperties = {
  width: '100%', height: 48, border: 'none', borderRadius: 40, cursor: 'pointer',
  background: 'var(--accent-gradient)', color: 'var(--accent-fg)', fontFamily: 'var(--font-body)', fontWeight: 700, fontSize: 14.5,
  display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 9,
};
