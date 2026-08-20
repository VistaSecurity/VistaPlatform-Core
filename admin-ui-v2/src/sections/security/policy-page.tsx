// VISTA Operations — Security ▸ Policy. Platform-wide authentication & security policy,
// GET/PUT against admin-service /admin/settings via the typed client. Ported from
// _legacy/admin-ui security-settings-page.tsx into the v2 op-* design.
//
// OVERLAP NOTE: /admin/settings is also written by the platform Settings section
// (Email Delivery). updatePlatformSettings takes PlatformSettingsInput ("only provided
// fields are persisted") — a partial merge — so this page sends ONLY the security keys
// it owns and leaves email_config / other keys untouched. See queries.ts.
import { useEffect, useMemo, useState } from 'react';
import toast from 'react-hot-toast';
import { ShieldCheck, Save, RotateCcw, Lock } from 'lucide-react';
import { usePlatformPermissions, PLATFORM_PERMISSIONS } from '@vistasecurity/primitives/platform-auth';
import { usePlatformSettings, useUpdateSecuritySettings, errMsg } from './queries';

// The security-owned subset of PlatformSettings this page edits.
//
// EVERY field here is enforced. That was not previously true: the four numeric
// fields persisted and redisplayed while auth-service kept its hardcoded
// 5 attempts / 15 minutes / 8 characters, and a "Maintenance mode" toggle
// round-tripped as a constant false that no service read even in principle.
// If you add a field, wire its consumer in the same change — a control that
// saves and does nothing is worse than no control, because the operator
// believes it.
//
// (Maintenance mode is gone rather than persisted: a real one is a request gate
// across every service with an operator bypass. Storing the flag alone would
// only have made the false belief durable.)
interface SecurityForm {
  password_min_length: number;
  session_timeout_minutes: number;
  max_login_attempts: number;
  lockout_duration_minutes: number;
  registration_enabled: boolean;
  email_verification_required: boolean;
  admin_email_verification_required: boolean;
}

const NUMERIC_FIELDS: { key: keyof SecurityForm; label: string; desc: string; min: number; max: number }[] = [
  { key: 'password_min_length', label: 'Minimum password length', desc: 'Minimum length for every new or changed password, tenant and platform. Cannot go below 8 — the built-in floor.', min: 8, max: 72 },
  { key: 'session_timeout_minutes', label: 'Session timeout (minutes)', desc: 'How long a session survives without activity before sign-in is required again.', min: 5, max: 129600 },
  { key: 'max_login_attempts', label: 'Maximum login attempts', desc: 'Consecutive failed sign-ins before the account is locked. Applies to tenant users and platform admins alike.', min: 1, max: 100 },
  { key: 'lockout_duration_minutes', label: 'Lockout duration (minutes)', desc: 'How long a locked account stays locked.', min: 1, max: 10080 },
];

const TOGGLE_FIELDS: { key: keyof SecurityForm; label: string; desc: string }[] = [
  { key: 'registration_enabled', label: 'Registration enabled', desc: 'Allow new tenant registrations.' },
  { key: 'email_verification_required', label: 'Tenant email verification required', desc: 'Require email verification for new tenant users.' },
  { key: 'admin_email_verification_required', label: 'Admin email verification required', desc: 'Require email verification for new platform admins.' },
];

function fromSettings(s: Partial<Record<keyof SecurityForm, number | boolean | null>>): SecurityForm {
  return {
    password_min_length: Number(s.password_min_length ?? 0),
    session_timeout_minutes: Number(s.session_timeout_minutes ?? 0),
    max_login_attempts: Number(s.max_login_attempts ?? 0),
    lockout_duration_minutes: Number(s.lockout_duration_minutes ?? 0),
    registration_enabled: !!s.registration_enabled,
    email_verification_required: !!s.email_verification_required,
    admin_email_verification_required: !!s.admin_email_verification_required,
  };
}

const numStyle: React.CSSProperties = {
  height: 34, width: 140, borderRadius: 'var(--r-btn)', border: '1px solid var(--op-border2)',
  background: 'var(--op-panel2)', color: 'var(--op-t1)', padding: '0 11px', fontSize: 13, outline: 'none',
};

export function SecurityPolicyPage() {
  const { data: settings, isLoading, isError, refetch } = usePlatformSettings();
  const save = useUpdateSecuritySettings();
  // Editing security policy requires platform.security.manage. An operator with
  // only platform.security (view) — e.g. platform_admin — sees the policy
  // read-only. The admin-service enforces this server-side too.
  const { hasPermission } = usePlatformPermissions();
  const canManage = hasPermission(PLATFORM_PERMISSIONS.platform.securityManage);

  const baseline = useMemo<SecurityForm | null>(() => (settings ? fromSettings(settings as any) : null), [settings]);
  const [form, setForm] = useState<SecurityForm | null>(null);

  useEffect(() => { if (baseline) setForm(baseline); }, [baseline]);

  const current = form ?? baseline;
  const dirty = !!(form && baseline && JSON.stringify(form) !== JSON.stringify(baseline));

  const set = (patch: Partial<SecurityForm>) => current && setForm({ ...current, ...patch });

  const handleSave = async () => {
    if (!current) return;
    try {
      // Send ONLY the security-owned keys (partial merge — leaves email_config etc. alone).
      await save.mutateAsync({ ...current });
      toast.success('Security policy saved.');
    } catch (e) {
      toast.error(errMsg(e, 'Failed to save security policy'));
    }
  };

  return (
    <div className="op-fade" style={{ padding: '20px 24px 40px', maxWidth: 820 }}>
      <div className="op-panel" style={{ overflow: 'hidden' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 11, padding: '14px 18px', borderBottom: '1px solid var(--op-border)' }}>
          <span style={{ width: 32, height: 32, borderRadius: 'var(--r-btn)', background: 'color-mix(in srgb, var(--accent) 12%, transparent)', display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 'none' }}><ShieldCheck size={16} style={{ color: 'var(--op-accent)' }} /></span>
          <div style={{ flex: 1 }}>
            <div style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 15, color: 'var(--op-t1)' }}>Authentication & security</div>
            <div style={{ fontSize: 12, color: 'var(--op-t3)', marginTop: 2 }}>Platform-wide authentication policy and access controls.</div>
          </div>
          {!canManage && (
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11.5, color: 'var(--op-t3)' }}><Lock size={12} />Read-only</span>
          )}
          {dirty && canManage && (
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="op-btn ghost sm" onClick={() => baseline && setForm(baseline)} disabled={save.isPending}><RotateCcw size={13} />Reset</button>
              <button className="op-btn primary sm" onClick={handleSave} disabled={save.isPending}><Save size={13} />{save.isPending ? 'Saving…' : 'Save changes'}</button>
            </div>
          )}
        </div>

        {isLoading && <div style={{ padding: 40, color: 'var(--op-t3)', fontSize: 13 }}>Loading policy…</div>}
        {isError && !isLoading && (
          <div style={{ padding: 40, color: 'var(--op-t3)', fontSize: 13, textAlign: 'center' }}>Couldn't load settings. <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => refetch()}>Retry</button></div>
        )}

        {current && !isLoading && !isError && (
          <div style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: 20 }}>
            <div>
              <div className="op-eyebrow" style={{ marginBottom: 12 }}>Password & session</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                {NUMERIC_FIELDS.map((f) => (
                  <div key={f.key} style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--op-t1)' }}>{f.label}</div>
                      <div style={{ fontSize: 11.5, color: 'var(--op-t3)' }}>{f.desc}</div>
                    </div>
                    <input type="number" min={f.min} max={f.max} style={numStyle} value={String(current[f.key] as number)} onChange={(e) => set({ [f.key]: parseInt(e.target.value, 10) || 0 } as Partial<SecurityForm>)} />
                  </div>
                ))}
              </div>
            </div>

            <div style={{ borderTop: '1px solid var(--op-border)', paddingTop: 18 }}>
              <div className="op-eyebrow" style={{ marginBottom: 12 }}>Access & verification</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {TOGGLE_FIELDS.map((f) => (
                  <label key={f.key} style={{ display: 'flex', alignItems: 'center', gap: 16, cursor: 'pointer' }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--op-t1)' }}>{f.label}</div>
                      <div style={{ fontSize: 11.5, color: 'var(--op-t3)' }}>{f.desc}</div>
                    </div>
                    <input type="checkbox" checked={current[f.key] as boolean} onChange={(e) => set({ [f.key]: e.target.checked } as Partial<SecurityForm>)} style={{ width: 16, height: 16 }} />
                  </label>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
      <div style={{ fontSize: 11.5, color: 'var(--op-t3)', marginTop: 12 }}>
        These fields write the security-owned keys of the platform settings object and take effect on the next sign-in, password change or token refresh — existing sessions are not retroactively shortened. Email delivery settings live under the platform <strong>Settings</strong> section and are persisted independently (partial-merge save).
      </div>
    </div>
  );
}
