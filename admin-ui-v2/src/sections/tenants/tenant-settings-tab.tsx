// Tenants ▸ (a tenant) ▸ Settings — the per-tenant overrides a platform admin
// may set for one customer organization.
//
// WHY THIS FILE EXISTS. The backend for this (GET/PUT
// /admin/tenants/{id}/settings, `tenants.manage`) has been mounted since the
// admin-service MSP split, and auth-service has read both of its keys the whole
// time — but nothing has called it since the v1→v2 admin UI rebuild
// deleted the v1 tenant modal's Security tab without deleting the endpoint.
// That made it a textbook orphan under FEATURE_IMPLEMENTATION_FRAMEWORK.md:
// a wired backend layer with no consumer. This tab is the consumer.
//
// THE TRI-STATE IS THE WHOLE POINT. Both settings are three-valued — "follow
// the platform default", "override to required", "override to not required".
// A plain on/off toggle cannot express the first, and collapsing it would turn
// "this tenant has no opinion" into a silent override that stops tracking the
// platform setting. So the control is a three-way strip and "Platform default"
// is a real, selectable, default-selected state; choosing it OMITS the key from
// the request body, which is what the backend's jsonb merge reads as "leave
// this alone".
import { useMemo, useState } from 'react';
import toast from 'react-hot-toast';
import { Lock, RotateCcw, Save, SlidersHorizontal } from 'lucide-react';
import { PLATFORM_PERMISSIONS, usePlatformPermissions } from '@vistasecurity/primitives/platform-auth';
import { usePlatformSettings } from '../security/queries';
import { type TenantSettings, useTenantSettings, useUpdateTenantSettings } from './queries';

/** The three states an override can be in. `inherit` means "no override". */
export type Override = 'inherit' | 'on' | 'off';

export const toOverride = (v: boolean | undefined): Override => (v === undefined ? 'inherit' : v ? 'on' : 'off');

/** Form state → request body. `inherit` keys are OMITTED, never sent as null:
 *  absent is how the backend merge is told to leave a key alone. */
export function toSettings(form: Record<SettingKey, Override>): TenantSettings {
  const out: TenantSettings = {};
  if (form.email_verification_required !== 'inherit') {
    out.email_verification_required = form.email_verification_required === 'on';
  }
  if (form.onboarding_required !== 'inherit') {
    out.onboarding_required = form.onboarding_required === 'on';
  }
  return out;
}

export type SettingKey = 'email_verification_required' | 'onboarding_required';

type FieldSpec = {
  key: SettingKey;
  label: string;
  desc: string;
  onLabel: string;
  offLabel: string;
};

const FIELDS: FieldSpec[] = [
  {
    key: 'email_verification_required',
    label: 'Email verification',
    desc: 'Whether this tenant’s new users must click the emailed link before they can sign in.',
    onLabel: 'Required',
    offLabel: 'Not required',
  },
  {
    key: 'onboarding_required',
    label: 'Onboarding walkthrough',
    desc: 'Whether this tenant’s users are shown the guided setup banner. The tenant’s own admins can also change this for themselves.',
    onLabel: 'Required',
    offLabel: 'Not required',
  },
];

function OverrideStrip({
  value, onChange, disabled, defaultHint, onLabel, offLabel,
}: {
  value: Override;
  onChange: (v: Override) => void;
  disabled: boolean;
  defaultHint: string;
  onLabel: string;
  offLabel: string;
}) {
  const options: { v: Override; label: string }[] = [
    { v: 'inherit', label: defaultHint },
    { v: 'on', label: onLabel },
    { v: 'off', label: offLabel },
  ];
  return (
    <div role="group" style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
      {options.map((o) => (
        <button
          key={o.v}
          type="button"
          className={'op-chip' + (value === o.v ? ' active' : '')}
          aria-pressed={value === o.v}
          disabled={disabled}
          onClick={() => onChange(o.v)}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function TenantSettingsPanel({ tenantId }: { tenantId: string }) {
  const q = useTenantSettings(tenantId);
  const platform = usePlatformSettings();
  const save = useUpdateTenantSettings();
  // The endpoint requires `tenants.manage`. An operator with only tenants.read
  // sees the resolved state read-only rather than a hidden tab — same shape as
  // Security ▸ Policy, and the admin-service enforces it server-side anyway.
  const perms = usePlatformPermissions();
  const canManage = perms.hasPermission(PLATFORM_PERMISSIONS.tenants.manage);

  const baseline = useMemo<Record<SettingKey, Override> | null>(
    () => (q.data
      ? {
        email_verification_required: toOverride(q.data.settings.email_verification_required),
        onboarding_required: toOverride(q.data.settings.onboarding_required),
      }
      : null),
    [q.data],
  );
  // `form` is an OVERLAY, not a copy: null means "no local edits, render what
  // the server returned". That is why there is no effect syncing it to the
  // query result — a refetch (after a save, or a window refocus) changes
  // `baseline` and the unedited view follows it automatically, with no window
  // in which the tab shows a stale value it quietly re-saves.
  const [form, setForm] = useState<Record<SettingKey, Override> | null>(null);

  const current = form ?? baseline;
  const dirty = !!(form && baseline && JSON.stringify(form) !== JSON.stringify(baseline));

  // What "Platform default" actually resolves to right now, so the operator is
  // not choosing blind. Email verification has a real platform setting; the
  // onboarding default is auth-service's hardcoded "required" when the key is
  // unset, so it is stated as a constant rather than read from a setting that
  // does not exist.
  const platformEmailDefault = platform.data?.email_verification_required;
  const defaultHint = (key: SettingKey): string => {
    if (key === 'onboarding_required') return 'Platform default (required)';
    if (platformEmailDefault === undefined) return 'Platform default';
    return `Platform default (${platformEmailDefault ? 'required' : 'not required'})`;
  };

  const handleSave = async () => {
    if (!current) return;
    try {
      await save.mutateAsync({ id: tenantId, settings: toSettings(current), version: q.data?.version });
      setForm(null); // drop the overlay; the invalidated query supplies the saved state
      toast.success('Tenant settings saved.');
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to save tenant settings');
    }
  };

  return (
    <div style={{ padding: '16px 20px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 11, marginBottom: 14 }}>
        <span style={{ width: 30, height: 30, borderRadius: 'var(--r-btn)', background: 'color-mix(in srgb, var(--accent) 12%, transparent)', display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 'none' }}>
          <SlidersHorizontal size={15} style={{ color: 'var(--op-accent)' }} />
        </span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 14, color: 'var(--op-t1)' }}>Per-tenant overrides</div>
          <div style={{ fontSize: 11.5, color: 'var(--op-t3)', marginTop: 2 }}>
            Applies to this tenant only. Leave on the platform default unless this customer needs different behaviour.
          </div>
        </div>
        {!canManage && (
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11.5, color: 'var(--op-t3)', flex: 'none' }}>
            <Lock size={12} />Read-only
          </span>
        )}
      </div>

      {q.isLoading && <div style={{ padding: '24px 0', color: 'var(--op-t3)', fontSize: 12.5 }}>Loading settings…</div>}

      {q.isError && !q.isLoading && (
        <div style={{ padding: '24px 0', color: 'var(--op-t3)', fontSize: 12.5 }}>
          Couldn&rsquo;t load this tenant&rsquo;s settings.
          <button className="op-btn sm" style={{ marginLeft: 8 }} onClick={() => void q.refetch()}>Retry</button>
        </div>
      )}

      {current && !q.isLoading && !q.isError && (
        <>
          <div style={{ display: 'grid', gap: 14 }}>
            {FIELDS.map((f) => (
              <div key={f.key} style={{ background: 'var(--op-panel2)', border: '1px solid var(--op-border)', borderRadius: 'var(--r-sm)', padding: '12px 14px' }}>
                <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--op-t1)' }}>{f.label}</div>
                <div style={{ fontSize: 11.5, color: 'var(--op-t3)', margin: '3px 0 10px', lineHeight: 1.5 }}>{f.desc}</div>
                <OverrideStrip
                  value={current[f.key]}
                  onChange={(v) => setForm({ ...current, [f.key]: v })}
                  disabled={!canManage || save.isPending}
                  defaultHint={defaultHint(f.key)}
                  onLabel={f.onLabel}
                  offLabel={f.offLabel}
                />
              </div>
            ))}
          </div>

          {dirty && canManage && (
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16 }}>
              <button className="op-btn ghost sm" onClick={() => setForm(null)} disabled={save.isPending}>
                <RotateCcw size={13} />Reset
              </button>
              <button className="op-btn primary sm" onClick={() => void handleSave()} disabled={save.isPending}>
                <Save size={13} />{save.isPending ? 'Saving…' : 'Save changes'}
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
