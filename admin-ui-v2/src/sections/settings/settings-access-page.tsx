// Platform Settings — Access & Sign-up (/). Two platform-wide gates on
// the tenant front door:
//   • registration_enabled — self-service sign-up at /signup. This is the ONLY
// tenant-onboarding path (admin tenant-create was removed in), so
//     turning it off closes the platform to new tenants entirely.
//   • email_verification_required — new users must click the emailed
//     verification link before first sign-in. Default ON; pre-flip accounts
//     were grandfathered server-side.
//   • block_personal_email_domains — reject consumer domains (gmail, outlook,
//     proton, ...) at sign-up. Default OFF, and that default is deliberate:
//     sign-up is the only way into a deployment, so on a self-hosted install
//     this list is the single front door and turning it on would tell the
//     operator to "use your work email address" on their own software. It is
//     an acquisition filter for a hosted offering, not a security control.
// Both live in platform_settings via GET/PUT /admin/settings; the PUT is a
// partial update (only the keys sent are upserted).
import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { DoorOpen, MailCheck, Building2, CheckCircle, XCircle } from 'lucide-react';
import { clients } from '../../lib/clients';

interface AccessSettings {
  registration_enabled: boolean;
  email_verification_required: boolean;
  block_personal_email_domains: boolean;
}

function useAccessSettings() {
  return useQuery({
    queryKey: ['platform', 'settings', 'access'],
    queryFn: async (): Promise<AccessSettings> => {
      const { data, error } = await clients.admin.GET('/admin/settings', {});
      if (error || !data) throw new Error('Failed to load settings');
      const s = data as any;
      return {
        registration_enabled: s.registration_enabled ?? true,
        email_verification_required: s.email_verification_required ?? true,
        // Mirrors the server default: auth.personalEmailBlocked fails open, so an
        // absent row must read as "not blocking" here too, or the toggle would
        // display a state the backend does not actually enforce.
        block_personal_email_domains: s.block_personal_email_domains ?? false,
      };
    },
    staleTime: 60_000,
  });
}

function useSaveAccessSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (patch: Partial<AccessSettings>) => {
      const { error } = await clients.admin.PUT('/admin/settings', { body: patch as any });
      if (error) throw new Error((error as any)?.error ?? 'Save failed');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['platform', 'settings', 'access'] }),
  });
}

// `warning` renders in the state that deserves attention. For most gates that is
// OFF (a door left open); for a restriction like the work-email rule it is ON.
// warnWhenOn flips which side the notice appears on.
function ToggleRow({ icon, title, description, warning, warnWhenOn, checked, disabled, onChange }: {
  icon: React.ReactNode; title: string; description: string; warning?: string;
  warnWhenOn?: boolean;
  checked: boolean; disabled: boolean; onChange: (v: boolean) => void;
}) {
  return (
    <div style={{ display: 'flex', gap: 14, alignItems: 'flex-start', padding: '16px 0', borderBottom: '1px solid var(--op-border)' }}>
      <div style={{ width: 34, height: 34, borderRadius: 'var(--r-btn)', background: 'color-mix(in srgb, var(--accent) 12%, transparent)', display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 'none' }}>
        {icon}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontWeight: 600, fontSize: 13.5, color: 'var(--op-t1)' }}>{title}</div>
        <div style={{ fontSize: 12, color: 'var(--op-t3)', marginTop: 3, lineHeight: 1.5 }}>{description}</div>
        {warning && (warnWhenOn ? checked : !checked) && (
          <div style={{ fontSize: 12, color: 'var(--warn)', marginTop: 6, lineHeight: 1.5 }}>{warning}</div>
        )}
      </div>
      <label style={{ display: 'inline-flex', alignItems: 'center', cursor: disabled ? 'default' : 'pointer', flex: 'none', marginTop: 4 }}>
        <input type="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)}
          style={{ position: 'absolute', opacity: 0, width: 0, height: 0 }} />
        <span style={{
          width: 38, height: 22, borderRadius: 22, position: 'relative', transition: 'background .15s',
          background: checked ? 'var(--op-accent, var(--accent))' : 'rgba(255,255,255,.14)',
          opacity: disabled ? 0.5 : 1,
        }}>
          <span style={{
            position: 'absolute', top: 3, left: checked ? 19 : 3, width: 16, height: 16, borderRadius: 16,
            background: '#fff', transition: 'left .15s',
          }} />
        </span>
      </label>
    </div>
  );
}

export function SettingsAccessPage() {
  const { data, isLoading } = useAccessSettings();
  const save = useSaveAccessSettings();
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null);

  const showToast = (msg: string, ok: boolean) => {
    setToast({ msg, ok });
    setTimeout(() => setToast(null), 4000);
  };

  const setKey = async (key: keyof AccessSettings, value: boolean) => {
    try {
      await save.mutateAsync({ [key]: value });
      showToast('Access settings saved.', true);
    } catch (e: any) {
      showToast(e.message, false);
    }
  };

  return (
    <div className="op-fade" style={{ padding: '24px', maxWidth: 780 }}>
      <div className="op-panel" style={{ padding: '20px 22px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, borderBottom: '1px solid var(--op-border)', paddingBottom: 16 }}>
          <div style={{ width: 34, height: 34, borderRadius: 'var(--r-btn)', background: 'color-mix(in srgb, var(--accent) 12%, transparent)', display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 'none' }}>
            <DoorOpen size={16} style={{ color: 'var(--op-accent)' }} />
          </div>
          <div>
            <div style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 15, color: 'var(--op-t1)' }}>Access &amp; Sign-up</div>
            <div style={{ fontSize: 12, color: 'var(--op-t3)', marginTop: 2 }}>
              Platform-wide gates on the tenant front door. Changes apply immediately.
            </div>
          </div>
        </div>

        {isLoading || !data ? (
          <div style={{ color: 'var(--op-t3)', fontSize: 13, paddingTop: 16 }}>Loading…</div>
        ) : (
          <>
            <ToggleRow
              icon={<DoorOpen size={16} style={{ color: 'var(--op-accent)' }} />}
              title="Self-service sign-up"
              description="Allow new organizations to create accounts at /signup (email or social). Sign-up is the only way tenants onboard."
              warning="Sign-up is closed — no new tenants can join this platform until it is re-enabled. Existing tenants and member invitations are unaffected."
              checked={data.registration_enabled}
              disabled={save.isPending}
              onChange={(v) => setKey('registration_enabled', v)}
            />
            <ToggleRow
              icon={<MailCheck size={16} style={{ color: 'var(--op-accent)' }} />}
              title="Require email verification"
              description="New users must click the emailed verification link before their first sign-in. Requires SMTP to be configured under Settings → Email. Tenant-level overrides, and invited or SSO users with a verified identity, are unaffected."
              warning="Verification is off — sign-ups activate immediately on unverified email addresses."
              checked={data.email_verification_required}
              disabled={save.isPending}
              onChange={(v) => setKey('email_verification_required', v)}
            />
            <ToggleRow
              icon={<Building2 size={16} style={{ color: 'var(--op-accent)' }} />}
              title="Require work email addresses"
              description="Reject consumer domains (gmail.com, outlook.com, proton.me and ~16 others) at sign-up. Useful when you run this as a hosted service and want to qualify inbound sign-ups. Leave this off for a self-hosted deployment — sign-up is the only way in, so it would block your own operators."
              warning="Personal email domains are rejected. Anyone signing up with a consumer address is told to use a work address instead."
              warnWhenOn
              checked={data.block_personal_email_domains}
              disabled={save.isPending}
              onChange={(v) => setKey('block_personal_email_domains', v)}
            />
          </>
        )}
      </div>

      {toast && (
        <div onClick={() => setToast(null)} style={{
          position: 'fixed', bottom: 24, right: 24, zIndex: 9999,
          background: toast.ok ? 'rgba(34,197,94,.15)' : 'rgba(239,68,68,.15)',
          border: `1px solid ${toast.ok ? 'rgba(34,197,94,.4)' : 'rgba(239,68,68,.4)'}`,
          borderRadius: 'var(--r-btn)', padding: '10px 16px',
          display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer',
          color: 'var(--op-t1)', fontSize: 13, maxWidth: 360,
        }}>
          {toast.ok ? <CheckCircle size={15} color="var(--ok)" /> : <XCircle size={15} color="var(--danger)" />}
          {toast.msg}
        </div>
      )}
    </div>
  );
}
