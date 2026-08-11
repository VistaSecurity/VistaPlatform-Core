// Invite-accept / complete-profile landing — the page an invited / signing-up
// user's email link lands on (previously dead-ended at /login). Collects name +
// password (+ optional organization) and posts the contracted
// CompleteRegistrationRequest to POST /auth/register/complete (/). The
// email and an optional subscription tier are pre-filled from the link's query
// params. On success the account exists but no session is established
// (RegisterResponse carries no tokens), so we route to /login with a success
// state. Public route — mounted outside RequireAuth.
import { useState, type FormEvent } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import { useMutation, useQuery } from '@tanstack/react-query';
import { clients } from '../lib/clients';
import { Icon } from '../components/ui';
import { AuthShell, AuthLabel, AuthSubmit, AuthError, authInputStyle } from './auth-shell';
import { LegalLinks } from '../components/legal-links';

export function CompleteProfilePage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const prefillEmail = params.get('email') || '';
  const tierId = params.get('tier_id') || undefined;
  // Social-signup completion: the IdP already verified identity; the user
  // only names their organization, then we create the tenant + founder.
  const ssoToken = params.get('sso_token') || '';

  const [email, setEmail] = useState(prefillEmail);
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [orgName, setOrgName] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [done, setDone] = useState(false);
  const [acceptedLegal, setAcceptedLegal] = useState(false);

  // Current legal documents — acceptance is required (and server-enforced) on
  // both the invite/complete and social-signup paths when any are published.
  const legalQ = useQuery({
    queryKey: ['complete-profile', 'legal'],
    queryFn: async () => {
      const { data } = await clients.auth.GET('/auth/legal/current', {});
      return data?.documents ?? [];
    },
  });
  const legalDocs = legalQ.data ?? [];
  const legalRequired = legalDocs.length > 0;

  const pwTooShort = password.length > 0 && password.length < 8;
  const mismatch = confirm.length > 0 && confirm !== password;
  const valid = !!email.trim() && !!firstName.trim() && !!lastName.trim() && password.length >= 8 && confirm === password && (!legalRequired || acceptedLegal);

  const submit = useMutation({
    mutationFn: async () => {
      const { data, error } = await clients.auth.POST('/auth/register/complete', {
        body: {
          email: email.trim(),
          password,
          first_name: firstName.trim(),
          last_name: lastName.trim(),
          tenant_name: orgName.trim() || undefined,
          subscription_tier_id: tierId,
          accepted_legal: acceptedLegal,
        },
      });
      if (error || !data) throw new Error((error as { error?: string } | undefined)?.error || 'Could not complete registration. The link may have expired.');
      return data;
    },
    onSuccess: () => setDone(true),
  });

  const onSubmit = (e: FormEvent) => { e.preventDefault(); if (valid) submit.mutate(); };

  // --- social-signup completion (sso_token present): org name only ---
  const [ssoNeedsVerify, setSsoNeedsVerify] = useState(false);
  const ssoSubmit = useMutation({
    mutationFn: async () => {
      const { data, error, response } = await clients.auth.POST('/auth/sso/platform/register/complete', {
        body: { sso_token: ssoToken, tenant_name: orgName.trim(), accepted_legal: acceptedLegal },
      });
      if (error || !response.ok || !data) throw new Error((error as { error?: string } | undefined)?.error || 'Could not finish setup. Please try signing up again.');
      return data;
    },
    // Microsoft (unverified email): show a check-your-email state instead of
    // entering the app. Google (verified) lands straight in the dashboard.
    onSuccess: (data) => { if (data?.requires_verification) setSsoNeedsVerify(true); else window.location.replace('/dashboard'); },
  });

  if (ssoToken && ssoNeedsVerify) {
    return (
      <AuthShell icon="mail" eyebrow="Almost there" title="Check your email"
        subtitle={`Your organization is set up. We sent a verification link to ${email || 'your email'} — click it to activate your account, then sign in.`}>
        <button onClick={() => navigate('/login', { replace: true })} style={{ width: '100%', height: 48, border: 'none', borderRadius: 40, cursor: 'pointer', background: 'var(--accent-gradient)', color: 'var(--accent-fg)', fontFamily: 'var(--font-body)', fontWeight: 700, fontSize: 14.5, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 9 }}>
          <Icon name="arrow-right" size={17} />Continue to sign-in
        </button>
      </AuthShell>
    );
  }

  if (ssoToken) {
    return (
      <AuthShell icon="user-plus" eyebrow="One last step" title="Name your organization"
        subtitle="You're verified. Tell us your organization name and we'll set up your console."
        footer={<>Wrong account? <a href="/login" style={{ color: 'var(--accent-light)', textDecoration: 'none' }}>Sign in</a></>}>
        <form onSubmit={(e) => { e.preventDefault(); if (orgName.trim().length >= 2 && (!legalRequired || acceptedLegal)) ssoSubmit.mutate(); }} style={{ display: 'flex', flexDirection: 'column', gap: 13 }}>
          {ssoSubmit.isError && <AuthError>{(ssoSubmit.error as Error).message}</AuthError>}
          <div>
            <AuthLabel>Organization</AuthLabel>
            <input value={orgName} onChange={(e) => setOrgName(e.target.value)} required autoFocus placeholder="Acme Corp" style={authInputStyle} />
          </div>
          {legalRequired && <LegalConsent docs={legalDocs} checked={acceptedLegal} onChange={setAcceptedLegal} />}
          <AuthSubmit disabled={orgName.trim().length < 2 || (legalRequired && !acceptedLegal) || ssoSubmit.isPending}>
            <Icon name="arrow-right" size={17} />{ssoSubmit.isPending ? 'Setting up…' : 'Finish setup'}
          </AuthSubmit>
        </form>
      </AuthShell>
    );
  }

  if (done) {
    return (
      <AuthShell icon="badge-check" eyebrow="Welcome" title="Your account is ready" subtitle="Sign in with your email and the password you just set to enter the console.">
        <button onClick={() => navigate('/login', { replace: true })} style={{ width: '100%', height: 48, border: 'none', borderRadius: 40, cursor: 'pointer', background: 'var(--accent-gradient)', color: 'var(--accent-fg)', fontFamily: 'var(--font-body)', fontWeight: 700, fontSize: 14.5, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 9 }}>
          <Icon name="arrow-right" size={17} />Continue to sign-in
        </button>
      </AuthShell>
    );
  }

  return (
    <AuthShell icon="user-plus" eyebrow="Complete your registration" title="Set up your account" subtitle="A few details and a password, and your console is ready."
      footer={<>Already have an account? <a href="/login" style={{ color: 'var(--accent-light)', textDecoration: 'none' }}>Sign in</a></>}>
      <form onSubmit={onSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 13 }}>
        {submit.isError && <AuthError>{(submit.error as Error).message}</AuthError>}

        <div>
          <AuthLabel>Work email</AuthLabel>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required readOnly={!!prefillEmail}
            placeholder="you@company.com" style={{ ...authInputStyle, opacity: prefillEmail ? 0.75 : 1 }} />
        </div>
        <div style={{ display: 'flex', gap: 11 }}>
          <div style={{ flex: 1 }}><AuthLabel>First name</AuthLabel><input value={firstName} onChange={(e) => setFirstName(e.target.value)} required autoFocus={!!prefillEmail} style={authInputStyle} /></div>
          <div style={{ flex: 1 }}><AuthLabel>Last name</AuthLabel><input value={lastName} onChange={(e) => setLastName(e.target.value)} required style={authInputStyle} /></div>
        </div>
        <div>
          <AuthLabel>Organization <span style={{ color: 'rgba(255,255,255,.3)' }}>(optional)</span></AuthLabel>
          <input value={orgName} onChange={(e) => setOrgName(e.target.value)} placeholder="Acme Corp" style={authInputStyle} />
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

        {legalRequired && <LegalConsent docs={legalDocs} checked={acceptedLegal} onChange={setAcceptedLegal} />}

        <AuthSubmit disabled={!valid || submit.isPending}>
          <Icon name="shield-check" size={17} />{submit.isPending ? 'Creating account…' : 'Create account'}
        </AuthSubmit>
      </form>
    </AuthShell>
  );
}

// Shared consent checkbox for the two registration forms on this page.
function LegalConsent({ docs, checked, onChange }: { docs: { doc_type: string; title: string }[]; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label style={{ display: 'flex', alignItems: 'flex-start', gap: 9, fontSize: 12.5, color: 'rgba(255,255,255,.7)', lineHeight: 1.45, cursor: 'pointer' }}>
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)}
        style={{ marginTop: 2, accentColor: 'var(--warn)', width: 15, height: 15, flexShrink: 0, cursor: 'pointer' }} />
      <span>I agree to the <LegalLinks docs={docs} />.</span>
    </label>
  );
}
