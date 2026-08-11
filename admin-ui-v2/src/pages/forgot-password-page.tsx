// Public forgot-password request for platform operators. Emails a time-limited
// reset link (which lands on /reset-password) if the address maps to an active
// platform user. The backend always returns 200 with a generic acknowledgement
// (no account enumeration), so this page shows the same confirmation regardless.
// Mounted OUTSIDE RequireAuth. Posts to admin-service POST /auth/forgot-password { email }.
import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router';
import { useMutation } from '@tanstack/react-query';
import { Mail, Send, MailCheck } from 'lucide-react';
import { clients } from '../lib/clients';
import { AuthShell, AuthBackToLogin } from './auth-shell';

export function ForgotPasswordPage() {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [sent, setSent] = useState(false);

  const submit = useMutation({
    mutationFn: async () => {
      // Anti-enumeration: treat any non-network outcome as success (the backend
      // returns 200 whether or not the address matched).
      await clients.admin.POST('/auth/forgot-password', { body: { email } });
    },
    onSuccess: () => setSent(true),
  });

  const onSubmit = (e: FormEvent) => { e.preventDefault(); if (email) submit.mutate(); };

  if (sent) {
    return (
      <AuthShell eyebrow="Account access" title="Check your email" subtitle={`If an operator account exists for ${email}, a password-reset link is on its way. The link expires in one hour.`}>
        <button type="button" className="op-btn primary" onClick={() => navigate('/login', { replace: true })} style={{ width: '100%', height: 44, justifyContent: 'center', fontSize: 14 }}>
          <MailCheck size={16} />Back to sign-in
        </button>
      </AuthShell>
    );
  }

  return (
    <AuthShell eyebrow="Account access" title="Reset your password" subtitle="Enter your work email and we'll send you a link to set a new password.">
      <form onSubmit={onSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 11 }}>
        <div className="lf-input">
          <Mail size={16} style={{ color: 'var(--op-t3)', flex: 'none' }} />
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" placeholder="Work email" required autoFocus />
        </div>

        {submit.isError && <div style={{ fontSize: 12.5, color: 'var(--danger-text)' }}>Something went wrong. Please try again.</div>}

        <button type="submit" className="op-btn primary" disabled={!email || submit.isPending} style={{ width: '100%', height: 44, justifyContent: 'center', marginTop: 6, fontSize: 14 }}>
          <Send size={16} />{submit.isPending ? 'Sending…' : 'Send reset link'}
        </button>
      </form>
      <AuthBackToLogin />
    </AuthShell>
  );
}
