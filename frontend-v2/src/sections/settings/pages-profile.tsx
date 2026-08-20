// My Profile pages (Personal, Security, Notifications) — ported from the
// mock's settings/profile.jsx, mock data swapped for the live session user
// (useAuth) and notification preferences (GET/PUT, same categories/delivery/
// frequency shape web-ui persists). Password / MFA management need contract
// endpoints that don't exist yet, so those sections state that instead of
// rendering dead forms.
import { useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@vistasecurity/primitives/auth';
import { clients } from '../../lib/clients';
import { Icon } from '../../components/ui';
import { SPage, SSection, SCard, SRow, SInput, SAvatar, SDot, SToggle, SSelect, StateNote, STag, relTime, GREEN, AMBER } from './kit';
import { ExportMyDataButton } from './data-subject';
import type { SettingsNavItem } from './nav';

export function ProfilePersonalPage({ meta }: { meta: SettingsNavItem }) {
  const { user } = useAuth();
  const fileRef = useRef<HTMLInputElement>(null);

  const [firstName, setFirstName] = useState(user?.first_name ?? '');
  const [lastName, setLastName] = useState(user?.last_name ?? '');
  const [timezone, setTimezone] = useState(user?.timezone ?? '');

  const dirty =
    firstName !== (user?.first_name ?? '') ||
    lastName !== (user?.last_name ?? '') ||
    timezone !== (user?.timezone ?? '');

  const saveMutation = useMutation({
    mutationFn: async () => {
      const { error, response } = await clients.auth.PUT('/auth/me', {
        body: { first_name: firstName, last_name: lastName, timezone: timezone || undefined },
      });
      if (error || !response.ok) throw new Error('Failed to save profile');
    },
  });

  // Displayed avatar: starts from the session user, switches to a local object-URL
  // preview the instant a file is picked (so the user sees it took), then to the
  // server-persisted URL once the upload returns.
  const [avatarSrc, setAvatarSrc] = useState<string | null>(user?.avatar_url ?? null);

  const avatarMutation = useMutation({
    mutationFn: async (file: File) => {
      const fd = new FormData();
      fd.append('avatar', file);
      const { data, error, response } = await clients.auth.POST('/auth/upload-avatar', {
        body: { avatar: file } as never,
        bodySerializer: () => fd,
      });
      if (error || !response.ok) throw new Error('Failed to upload avatar');
      return (data as { avatar_url: string }).avatar_url;
    },
    onSuccess: (url) => setAvatarSrc(url),
  });

  const name = user ? `${user.first_name} ${user.last_name}` : '';

  return (
    <SPage
      eyebrow="My Profile" title="Personal" job={meta.job}
      actions={
        <button
          className="ui-btn sm accent"
          disabled={!dirty || saveMutation.isPending}
          onClick={() => saveMutation.mutate()}
        >
          <Icon name="check" size={14} />{saveMutation.isPending ? 'Saving…' : 'Save changes'}
        </button>
      }
    >
      {(saveMutation.isError || saveMutation.isSuccess) && (
        <p style={{ fontSize: 12, color: saveMutation.isSuccess ? GREEN : 'var(--danger-text)', marginBottom: 10 }}>
          <Icon name={saveMutation.isSuccess ? 'check' : 'alert-triangle'} size={13} style={{ verticalAlign: '-2px', marginRight: 5 }} />
          {saveMutation.isSuccess ? 'Profile saved. Changes to your name will appear after reloading.' : 'Failed to save — try again.'}
        </p>
      )}
      <SCard>
        <SRow label="Photo">
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            {avatarSrc
              ? <img src={avatarSrc} alt="Avatar" style={{ width: 52, height: 52, borderRadius: '50%', objectFit: 'cover', border: '2px solid var(--app-border2)' }} />
              : <SAvatar name={name} size={52} />}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <button
                className="ui-btn sm"
                onClick={() => fileRef.current?.click()}
                disabled={avatarMutation.isPending}
              >
                {avatarMutation.isPending ? 'Uploading…' : 'Upload photo'}
              </button>
              {avatarMutation.isError && (
                <span style={{ fontSize: 11.5, color: 'var(--danger-text)' }}>Upload failed — try again.</span>
              )}
              {avatarMutation.isSuccess && (
                <span style={{ fontSize: 11.5, color: GREEN }}>Photo updated.</span>
              )}
            </div>
            <input
              ref={fileRef}
              type="file"
              accept="image/*"
              style={{ display: 'none' }}
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) {
                  setAvatarSrc(URL.createObjectURL(file)); // instant local preview
                  avatarMutation.mutate(file);
                }
                e.target.value = '';
              }}
            />
          </div>
        </SRow>
        <SRow label="First name">
          <SInput key={`fn-${user?.id}`} value={firstName} width={200} onChange={setFirstName} />
        </SRow>
        <SRow label="Last name">
          <SInput key={`ln-${user?.id}`} value={lastName} width={200} onChange={setLastName} />
        </SRow>
        <SRow label="Email" hint="Changing your email requires confirming a link sent to the new address.">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span className="mono" style={{ fontSize: 12.5, color: 'var(--app-t2)' }}>{user?.email ?? '—'}</span>
            {user?.email_verified
              ? <STag color={GREEN}>Verified</STag>
              : <STag color={AMBER}>Unverified</STag>}
          </div>
        </SRow>
        <SRow label="Role" hint="Assigned by your organization's admins under Settings → Members.">
          <STag>{user?.role ?? '—'}</STag>
        </SRow>
        <SRow label="Timezone" last>
          <SInput key={`tz-${user?.id}`} value={timezone} width={220} placeholder="e.g. America/New_York" onChange={setTimezone} />
        </SRow>
      </SCard>

      {/* Data subject access, self-service (#1461). Sits on your own profile
          because the most common version of this request is your own. */}
      <SSection title="Your data">
        <SCard>
          <SRow label="Export" hint="Everything this platform holds about you, as a file you can keep." last>
            <ExportMyDataButton />
          </SRow>
        </SCard>
      </SSection>
    </SPage>
  );
}

export function ProfileSecurityPage({ meta }: { meta: SettingsNavItem }) {
  const { user } = useAuth();
  const memberSince = user?.created_at
    ? new Date(user.created_at).toLocaleDateString(undefined, { year: 'numeric', month: 'long' })
    : '—';

  const [currentPw, setCurrentPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [localError, setLocalError] = useState<string | null>(null);

  const pwMutation = useMutation({
    mutationFn: async () => {
      const { error, response } = await clients.auth.POST('/auth/change-password', {
        body: { current_password: currentPw, new_password: newPw },
      });
      if (!response.ok) {
        const body = error as { error?: string } | null;
        throw new Error(body?.error ?? 'Failed to change password');
      }
    },
    onSuccess: () => {
      setCurrentPw('');
      setNewPw('');
      setConfirmPw('');
      setLocalError(null);
    },
    onError: (err: Error) => {
      setLocalError(err.message);
    },
  });

  const handleChangePw = () => {
    setLocalError(null);
    if (newPw.length < 8) { setLocalError('New password must be at least 8 characters.'); return; }
    if (newPw !== confirmPw) { setLocalError('Passwords do not match.'); return; }
    pwMutation.mutate();
  };

  return (
    <SPage eyebrow="My Profile" title="Security" job={meta.job}>
      <SSection title="Password">
        <SCard>
          <SRow label="Last changed">
            <span style={{ fontSize: 12.5, color: 'var(--app-t3)' }}>
              {user?.password_changed_at ? relTime(user.password_changed_at) : 'Never changed'}
            </span>
          </SRow>
          <SRow label="Current password">
            <SInput key="cur-pw" type="password" value={currentPw} width={240} placeholder="Current password" onChange={setCurrentPw} />
          </SRow>
          <SRow label="New password" hint="Minimum 8 characters.">
            <SInput key="new-pw" type="password" value={newPw} width={240} placeholder="New password" onChange={setNewPw} />
          </SRow>
          <SRow label="Confirm new password" last>
            <SInput key="conf-pw" type="password" value={confirmPw} width={240} placeholder="Confirm new password" onChange={setConfirmPw} />
          </SRow>
        </SCard>
        {(localError || pwMutation.isSuccess) && (
          <p style={{ fontSize: 12, color: pwMutation.isSuccess ? GREEN : 'var(--danger-text)', marginTop: 8 }}>
            <Icon name={pwMutation.isSuccess ? 'check' : 'alert-triangle'} size={13} style={{ verticalAlign: '-2px', marginRight: 5 }} />
            {pwMutation.isSuccess ? 'Password changed successfully.' : localError}
          </p>
        )}
        <div style={{ marginTop: 12 }}>
          <button
            className="ui-btn sm accent"
            disabled={!currentPw || !newPw || !confirmPw || pwMutation.isPending}
            onClick={handleChangePw}
          >
            <Icon name="lock" size={14} />{pwMutation.isPending ? 'Changing…' : 'Change password'}
          </button>
        </div>
      </SSection>

      <SSection title="Multi-factor authentication">
        <SCard style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
          <span style={{ width: 40, height: 40, borderRadius: 10, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'color-mix(in srgb, var(--warn) 14%, transparent)', color: AMBER }}>
            <Icon name="smartphone" size={18} />
          </span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
              <span style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--app-t1)' }}>Authenticator app (TOTP)</span>
              <STag color={AMBER}>Spec'd</STag>
            </div>
            <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 2 }}>
              A second factor with backup codes is on the roadmap; enrollment will live here.
            </div>
          </div>
        </SCard>
      </SSection>

      <SSection title="Account status">
        <SCard>
          <SRow label="Account" hint={`Member since ${memberSince}.`}>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12.5, color: 'var(--app-t2)' }}>
              <SDot color={user?.is_active ? GREEN : 'var(--danger)'} />
              {user?.is_active ? 'Active' : 'Inactive'}
            </span>
          </SRow>
          <SRow label="Last sign-in" last>
            <span style={{ fontSize: 12.5, color: 'var(--app-t3)' }}>{relTime(user?.last_login_at)}</span>
          </SRow>
        </SCard>
      </SSection>
    </SPage>
  );
}

// Notification preference shape persisted by the platform (mirrors web-ui's
// notifications-context): per-category opt-ins, delivery transports, and an
// overall frequency. Unknown keys in the stored map are carried through.
const PREF_CATEGORIES = [
  { key: 'security', label: 'Security findings & alerts' },
  { key: 'sensors', label: 'Sensors & discovery' },
  { key: 'billing', label: 'Billing & subscription' },
  { key: 'system', label: 'System & maintenance' },
  { key: 'reports', label: 'CBOM & compliance evidence' },
  { key: 'users', label: 'Members & access changes' },
] as const;
const PREF_DELIVERY = [
  { key: 'inApp', label: 'In-app' },
  { key: 'email', label: 'Email' },
] as const;

type PrefMap = Record<string, unknown>;
function boolAt(prefs: PrefMap | null, group: string, key: string, fallback = true): boolean {
  const g = prefs?.[group];
  if (g && typeof g === 'object' && key in (g as Record<string, unknown>)) {
    return Boolean((g as Record<string, unknown>)[key]);
  }
  return fallback;
}

export function ProfileNotificationsPage({ meta }: { meta: SettingsNavItem }) {
  const queryClient = useQueryClient();
  // Local edits layered over the stored map; null = untouched.
  const [edits, setEdits] = useState<PrefMap | null>(null);

  const { data, isLoading, isError } = useQuery({
    queryKey: ['profile', 'notification-prefs'],
    queryFn: async () => {
      const { data, error, response } = await clients.auth.GET('/auth/me/preferences/notifications', {});
      if (error || !response.ok || !data) throw new Error('Failed to load notification preferences');
      return (data.preferences ?? {}) as PrefMap;
    },
  });

  const stored = data ?? null;
  const view: PrefMap = { ...(stored ?? {}), ...(edits ?? {}) };
  const setGroupKey = (group: string, key: string, value: unknown) => {
    setEdits((e) => {
      const base: PrefMap = { ...(stored ?? {}), ...(e ?? {}) };
      const g = { ...((base[group] as Record<string, unknown>) ?? {}) };
      g[key] = value;
      return { ...base, [group]: g };
    });
  };

  const mutation = useMutation({
    mutationFn: async () => {
      const { error, response } = await clients.auth.PUT('/auth/me/preferences/notifications', {
        body: view as Record<string, never>,
      });
      if (error || !response.ok) throw new Error('Failed to save preferences');
    },
    onSuccess: () => {
      setEdits(null);
      queryClient.invalidateQueries({ queryKey: ['profile', 'notification-prefs'] });
    },
  });

  if (isLoading || isError) {
    return (
      <SPage eyebrow="My Profile" title="Notifications" job={meta.job}>
        <SCard>
          {isError
            ? <StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load preferences" message="Your notification preferences failed to load." />
            : <StateNote icon="loader" tone="var(--app-t3)" title="Loading preferences…" message="Fetching your notification preferences." />}
        </SCard>
      </SPage>
    );
  }

  const frequency = typeof view.frequency === 'string' ? view.frequency : 'immediate';

  return (
    <SPage
      eyebrow="My Profile" title="Notifications" job={meta.job}
      actions={
        <button className="ui-btn sm accent" disabled={!edits || mutation.isPending} onClick={() => mutation.mutate()}>
          <Icon name="check" size={14} />{mutation.isPending ? 'Saving…' : 'Save changes'}
        </button>
      }
    >
      <SSection title="What you're notified about">
        <SCard>
          {PREF_CATEGORIES.map((c, i) => (
            <SRow key={c.key} label={c.label} last={i === PREF_CATEGORIES.length - 1}>
              <SToggle
                key={`${c.key}-${boolAt(view as PrefMap, 'categories', c.key)}`}
                on={boolAt(view, 'categories', c.key)}
                onChange={(v) => setGroupKey('categories', c.key, v)}
              />
            </SRow>
          ))}
        </SCard>
      </SSection>
      <SSection title="How it reaches you">
        <SCard>
          {PREF_DELIVERY.map((d, i) => (
            <SRow key={d.key} label={d.label} last={i === PREF_DELIVERY.length - 1}>
              <SToggle
                key={`${d.key}-${boolAt(view, 'delivery', d.key)}`}
                on={boolAt(view, 'delivery', d.key)}
                onChange={(v) => setGroupKey('delivery', d.key, v)}
              />
            </SRow>
          ))}
          <SRow label="Frequency" hint="Immediate, or batched into digests." last>
            <SSelect
              key={frequency}
              value={frequency}
              options={[['immediate', 'Immediate'], ['hourly', 'Hourly digest'], ['daily', 'Daily digest']]}
              width={160}
              onChange={(v) => setEdits((e) => ({ ...(stored ?? {}), ...(e ?? {}), frequency: v }))}
            />
          </SRow>
        </SCard>
      </SSection>
      <p style={{ fontSize: 12, color: mutation.isError ? 'var(--danger-text)' : 'var(--app-t3)', marginTop: 13, lineHeight: 1.55 }}>
        <Icon name="info" size={13} style={{ verticalAlign: '-2px', marginRight: 5 }} />
        {mutation.isError
          ? 'Saving preferences failed — try again.'
          : <>You choose <em>what</em> and <em>how often</em>; the actual channels (Slack, email, PagerDuty) are configured for the org under Settings → Integrations.</>}
      </p>
    </SPage>
  );
}
