// Public self-service signup — the front door. A cold visitor creates their
// organization + founder (tenant_admin) account via POST /auth/register/complete
// (which also bootstraps the trial and sends a verification email). Email
// verification is required, so on success we show a "check your email" state
// rather than routing to sign-in. Public route — mounted outside RequireAuth.
// Spec: docsv4/internal/developer/standards/features/signup-entry.md
import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router';
import { useMutation, useQuery } from '@tanstack/react-query';
import { clients } from '../lib/clients';
import { Icon } from '../components/ui';
import { AuthShell, AuthLabel, AuthSubmit, AuthError, authInputStyle } from './auth-shell';
import { LegalLinks } from '../components/legal-links';

function socialLabel(t: string) {
  return t === 'google' ? 'Google' : t === 'microsoft' ? 'Microsoft' : t;
}

// Start social signup with one of Vista's platform OAuth apps. Top-level
// navigation: the platform authorize endpoint 302s to the IdP, whose callback
// stashes a pending registration and lands the user on the org-name step.
function startSocialSignup(providerType: string) {
  window.location.href = `/api/v1/auth-service/auth/sso/platform/${encodeURIComponent(providerType)}/authorize`;
}

export function SignupPage() {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [orgName, setOrgName] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [done, setDone] = useState(false);
  const [acceptedLegal, setAcceptedLegal] = useState(false);

  // Current legal documents (Terms of Service / Privacy Policy). Public endpoint.
  // When any are published, acceptance is required to sign up (also enforced
  // server-side); when none are, the checkbox is not shown.
  const legalQ = useQuery({
    queryKey: ['signup', 'legal'],
    queryFn: async () => {
      const { data } = await clients.auth.GET('/auth/legal/current', {});
      return data?.documents ?? [];
    },
  });
  const legalDocs = legalQ.data ?? [];
  const legalRequired = legalDocs.length > 0;

  // Vista's configured social-signup providers (Google/Microsoft). Empty unless
  // a platform admin has configured one in admin → Settings → Identity Providers.
  //
  // Edition note: /platform/sso-providers lives in auth-service/ee/sso, so a
  // Core build does not mount it. This page is UNAUTHENTICATED, so the tenant
  // feature map is not available to gate on — but the degrade is already correct
  // (no data ⇒ no social buttons ⇒ password signup only, which is exactly the
  // Core product). `retry: false` keeps that from costing two console 404s.
  const providersQ = useQuery({
    queryKey: ['signup', 'social-providers'],
    retry: false,
    queryFn: async () => {
      const { data } = await clients.auth.GET('/platform/sso-providers', {});
      return data?.providers ?? [];
    },
  });
  const socialProviders = providersQ.data ?? [];

  // Platform admins can close self-service sign-up (admin → Settings →
  // Access). Enforcement is server-side on the register endpoints; this only
  // controls what the page renders. Fail open while loading/on error.
  const signupConfigQ = useQuery({
    queryKey: ['signup', 'config'],
    queryFn: async () => {
      const { data } = await clients.auth.GET('/platform/config', {});
      return data ?? null;
    },
  });
  const signupDisabled = signupConfigQ.data?.signup_enabled === false;

  const pwTooShort = password.length > 0 && password.length < 8;
  const mismatch = confirm.length > 0 && confirm !== password;
  // Org name is required: the backend creates a new tenant from it (signup is a
  // founder flow, not an invite-accept).
  const valid = !!email.trim() && !!firstName.trim() && !!lastName.trim() && !!orgName.trim() && password.length >= 8 && confirm === password && (!legalRequired || acceptedLegal);

  const submit = useMutation({
    mutationFn: async () => {
      const { data, error } = await clients.auth.POST('/auth/register/complete', {
        body: {
          email: email.trim(),
          password,
          first_name: firstName.trim(),
          last_name: lastName.trim(),
          tenant_name: orgName.trim(),
          accepted_legal: acceptedLegal,
        },
      });
      if (error || !data) throw new Error((error as { error?: string } | undefined)?.error || 'Could not create your account.');
      return data;
    },
    onSuccess: () => setDone(true),
  });

  const resend = useMutation({
    mutationFn: async () => {
      const { error } = await clients.auth.POST('/auth/resend-verification', { body: { email: email.trim() } });
      if (error) throw new Error('Could not resend the email.');
    },
  });

  const onSubmit = (e: FormEvent) => { e.preventDefault(); if (valid) submit.mutate(); };

  if (signupDisabled) {
    return (
      <AuthShell icon="shield" eyebrow="Sign-up unavailable" title="Sign-up is disabled"
        subtitle="Self-service sign-up is turned off on this platform. Contact your platform operator or your organization's administrator for an invitation."
        footer={<>Already have an account? <a href="/login" style={{ color: 'var(--accent-light)', textDecoration: 'none' }}>Sign in</a></>}>
        <button type="button" onClick={() => navigate('/login', { replace: true })} style={primaryBtn}>
          <Icon name="arrow-right" size={17} />Go to sign-in
        </button>
      </AuthShell>
    );
  }

  if (done) {
    return (
      <AuthShell icon="mail" eyebrow="Almost there" title="Check your email"
        subtitle={`We sent a verification link to ${email}. Click it to activate your account, then sign in.`}
        footer={<>Already verified? <a href="/login" style={{ color: 'var(--accent-light)', textDecoration: 'none' }}>Sign in</a></>}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 11 }}>
          {resend.isSuccess && <div style={{ fontSize: 12.5, color: 'var(--ok)' }}>Verification email resent.</div>}
          <button type="button" onClick={() => resend.mutate()} disabled={resend.isPending} style={ghostBtn}>
            {resend.isPending ? 'Resending…' : "Didn't get it? Resend email"}
          </button>
          <button type="button" onClick={() => navigate('/login', { replace: true })} style={primaryBtn}>
            <Icon name="arrow-right" size={17} />Continue to sign-in
          </button>
        </div>
      </AuthShell>
    );
  }

  return (
    <AuthShell icon="user-plus" eyebrow="Create your account" title="Start with Vista"
      subtitle="Create your organization and admin account. We'll email you a link to verify."
      footer={<>Already have an account? <a href="/login" style={{ color: 'var(--accent-light)', textDecoration: 'none' }}>Sign in</a></>}>
      {socialProviders.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 9, marginBottom: 16 }}>
          {socialProviders.map((p) => (
            <button key={p.id} type="button" onClick={() => startSocialSignup(p.provider_type)} style={socialBtn}>
              <Icon name="key-round" size={16} style={{ color: 'rgba(255,215,115,.85)' }} />
              Sign up with {socialLabel(p.provider_type)}
            </button>
          ))}
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, margin: '8px 0 0' }}>
            <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,.09)' }} />
            <span style={{ fontSize: 11, letterSpacing: '.14em', textTransform: 'uppercase', color: 'rgba(255,255,255,.34)' }}>or with email</span>
            <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,.09)' }} />
          </div>
        </div>
      )}

      <form onSubmit={onSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 13 }}>
        {submit.isError && <AuthError>{(submit.error as Error).message}</AuthError>}

        <div>
          <AuthLabel>Work email</AuthLabel>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus
            placeholder="you@company.com" style={authInputStyle} />
        </div>
        <div style={{ display: 'flex', gap: 11 }}>
          <div style={{ flex: 1 }}><AuthLabel>First name</AuthLabel><input value={firstName} onChange={(e) => setFirstName(e.target.value)} required style={authInputStyle} /></div>
          <div style={{ flex: 1 }}><AuthLabel>Last name</AuthLabel><input value={lastName} onChange={(e) => setLastName(e.target.value)} required style={authInputStyle} /></div>
        </div>
        <div>
          <AuthLabel>Organization</AuthLabel>
          <input value={orgName} onChange={(e) => setOrgName(e.target.value)} required placeholder="Acme Corp" style={authInputStyle} />
        </div>
        <div>
          <AuthLabel>Password</AuthLabel>
          <div style={{ position: 'relative' }}>
            <input type={showPw ? 'text' : 'password'} value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete="new-password"
              placeholder="At least 8 characters" style={{ ...authInputStyle, paddingRight: 44, borderColor: pwTooShort ? 'color-mix(in srgb, var(--danger) 50%, transparent)' : authInputStyle.border as string }} />
            <button type="button" onClick={() => setShowPw((v) => !v)} title={showPw ? 'Hide' : 'Show'} style={{ position: 'absolute', right: 12, top: 13, border: 'none', background: 'transparent', cursor: 'pointer', padding: 0 }}>
              <Icon name={showPw ? 'eye-off' : 'eye'} size={16} style={{ color: 'rgba(255,255,255,.42)' }} />
            </button>
          </div>
          {pwTooShort && <div style={{ fontSize: 11, color: 'var(--danger-soft)', marginTop: 5 }}>Use at least 8 characters.</div>}
        </div>
        <div>
          <AuthLabel>Confirm password</AuthLabel>
          <input type={showPw ? 'text' : 'password'} value={confirm} onChange={(e) => setConfirm(e.target.value)} required autoComplete="new-password"
            style={{ ...authInputStyle, borderColor: mismatch ? 'color-mix(in srgb, var(--danger) 50%, transparent)' : authInputStyle.border as string }} />
          {mismatch && <div style={{ fontSize: 11, color: 'var(--danger-soft)', marginTop: 5 }}>Passwords don’t match.</div>}
        </div>

        {legalRequired && (
          <label style={{ display: 'flex', alignItems: 'flex-start', gap: 9, fontSize: 12.5, color: 'rgba(255,255,255,.7)', lineHeight: 1.45, cursor: 'pointer' }}>
            <input type="checkbox" checked={acceptedLegal} onChange={(e) => setAcceptedLegal(e.target.checked)}
              style={{ marginTop: 2, accentColor: 'var(--warn)', width: 15, height: 15, flexShrink: 0, cursor: 'pointer' }} />
            <span>
              I agree to the <LegalLinks docs={legalDocs} />.
            </span>
          </label>
        )}

        <AuthSubmit disabled={!valid || submit.isPending}>
          <Icon name="shield-check" size={17} />{submit.isPending ? 'Creating account…' : 'Create account'}
        </AuthSubmit>
      </form>
    </AuthShell>
  );
}

const primaryBtn: React.CSSProperties = {
  width: '100%', height: 48, border: 'none', borderRadius: 40, cursor: 'pointer',
  background: 'var(--accent-gradient)', color: 'var(--accent-fg)', fontFamily: 'var(--font-body)', fontWeight: 700, fontSize: 14.5,
  display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 9,
};
const ghostBtn: React.CSSProperties = {
  width: '100%', height: 44, borderRadius: 40, cursor: 'pointer', background: 'transparent',
  border: '1px solid rgba(255,255,255,.16)', color: 'rgba(255,255,255,.75)', fontFamily: 'var(--font-body)', fontSize: 13,
};
const socialBtn: React.CSSProperties = {
  width: '100%', height: 46, borderRadius: 40, cursor: 'pointer', background: 'rgba(255,255,255,.045)',
  border: '1px solid rgba(255,255,255,.14)', color: '#F1F1F2', fontFamily: 'var(--font-body)', fontWeight: 600, fontSize: 14,
  display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 9,
};
