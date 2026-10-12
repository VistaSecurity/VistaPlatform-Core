// Forgot-password — public page reached from the sign-in screen's "Forgot
// password?" link. Takes an email and posts it to the contracted
// POST /auth/forgot-password. The server answers the same 200 for known and
// unknown addresses, so the page shows ONE fixed sentence on success and never
// echoes anything the server says about the address (no account enumeration).
// A failed request (rate limit, outage) is NOT masked as success: it shows an
// error so the user knows to retry.
import { useState, type FormEvent } from 'react';
import { Link, useSearchParams } from 'react-router';
import { useMutation } from '@tanstack/react-query';
import { clients } from '../lib/clients';
import { Icon } from '../components/ui';
import { AuthShell, AuthLabel, AuthSubmit, AuthError, authInputStyle } from './auth-shell';
import { unwrap } from '../lib/api-result';

export const FORGOT_PASSWORD_NEUTRAL_MESSAGE = 'If that address has an account, we sent a reset link.';

const backToSignIn = (
  <Link to="/login" style={{ color: 'var(--accent-light)', textDecoration: 'none' }}>Back to sign-in</Link>
);

export function ForgotPasswordPage() {
  const [params] = useSearchParams();
  const [email, setEmail] = useState(params.get('email') ?? '');
  const [sent, setSent] = useState(false);

  const submit = useMutation({
    mutationFn: async () => {
      unwrap(await clients.auth.POST('/auth/forgot-password', { body: { email: email.trim() } }),
        'Could not send the reset link. Please try again.', { requireData: true });
    },
    onSuccess: () => setSent(true),
  });

  const onSubmit = (e: FormEvent) => { e.preventDefault(); if (email.trim() && !submit.isPending) submit.mutate(); };

  if (sent) {
    return (
      <AuthShell icon="mail" eyebrow="Password reset" title="Check your email" subtitle={FORGOT_PASSWORD_NEUTRAL_MESSAGE} footer={backToSignIn}>
        <div style={{ fontSize: 13, color: 'rgba(255,255,255,.55)', lineHeight: 1.5 }}>
          The link expires after a short time. If nothing arrives, check your spam folder or try again.
        </div>
      </AuthShell>
    );
  }

  return (
    <AuthShell icon="lock" eyebrow="Password reset" title="Forgot your password?" subtitle="Enter your work email and we will send you a link to choose a new one." footer={backToSignIn}>
      <form onSubmit={onSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 13 }}>
        {submit.isError && <AuthError>{(submit.error as Error).message}</AuthError>}
        <div>
          <AuthLabel>Work email</AuthLabel>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus autoComplete="email" style={authInputStyle} />
        </div>
        <AuthSubmit disabled={!email.trim() || submit.isPending}>
          <Icon name="mail" size={17} />{submit.isPending ? 'Sending…' : 'Send reset link'}
        </AuthSubmit>
      </form>
    </AuthShell>
  );
}
