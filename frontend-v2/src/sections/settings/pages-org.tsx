// Settings · Organization pages (Overview, Branding) — ported from the mock's
// settings/sectionF.jsx, mock data swapped for the live tenant (useAuth) and
// the typed branding / framework-license queries. Branding is editable
// (display name, colors, logo/favicon upload); org details (name / domain /
// billing email) save through PUT /tenant, gated by settings.update.
import { useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router';
import { useAuth } from '@vistasecurity/primitives/auth';
import { usePermissions, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { useFeature } from '@vistasecurity/primitives/features';
import { clients } from '../../lib/clients';
import { Icon } from '../../components/ui';
import { SPage, SSection, SCard, SRow, SInput, StateNote, STag, GREEN } from './kit';
import type { SettingsNavItem } from './nav';

export function OrgOverviewPage({ meta }: { meta: SettingsNavItem }) {
  const { tenant } = useAuth();
  const { hasPermission } = usePermissions();
  const canEdit = hasPermission(TENANT_PERMISSIONS.settings.update);
  // null = untouched; only touched fields are sent (PUT /tenant is partial).
  const [draft, setDraft] = useState<{ name: string | null; domain: string | null; billing_email: string | null }>({
    name: null, domain: null, billing_email: null,
  });
  const { data, isLoading, isError } = useQuery({
    queryKey: ['settings', 'framework-licenses'],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/frameworks/licenses', {});
      if (error || !data) throw new Error('Failed to load framework licenses');
      return data;
    },
  });
  const licenses = (data?.licenses ?? []).filter((l) => l.subscription_status === 'active');

  const mutation = useMutation({
    mutationFn: async () => {
      const { error, response } = await clients.auth.PUT('/tenant', {
        body: {
          ...(draft.name !== null ? { name: draft.name.trim() } : {}),
          ...(draft.domain !== null ? { domain: draft.domain.trim() } : {}),
          ...(draft.billing_email !== null ? { billing_email: draft.billing_email.trim() } : {}),
        },
      });
      if (error || !response.ok) throw new Error('Failed to save organization details');
    },
    onSuccess: () => setDraft({ name: null, domain: null, billing_email: null }),
  });

  const dirty = draft.name !== null || draft.domain !== null || draft.billing_email !== null;
  // Don't allow blanking the organization name.
  const valid = draft.name === null || draft.name.trim().length > 0;

  return (
    <SPage
      eyebrow="Organization" title="Overview" job={meta.job}
      actions={canEdit ? (
        <button className="ui-btn sm accent" disabled={!dirty || !valid || mutation.isPending} onClick={() => mutation.mutate()}>
          <Icon name="check" size={14} />{mutation.isPending ? 'Saving…' : 'Save changes'}
        </button>
      ) : undefined}
    >
      <SSection title="Organization details">
        <SCard>
          <SRow label="Organization name" hint="Shown across the console and on reports.">
            {canEdit
              ? <SInput key={tenant?.name} value={tenant?.name ?? ''} onChange={(v) => setDraft((d) => ({ ...d, name: v }))} />
              : <span style={{ fontSize: 12.5, color: 'var(--app-t2)' }}>{tenant?.name || '—'}</span>}
          </SRow>
          <SRow label="Primary domain" hint="Used to match SSO and invited users.">
            {canEdit
              ? <SInput key={tenant?.domain ?? 'no-domain'} value={tenant?.domain ?? ''} placeholder="Not set" onChange={(v) => setDraft((d) => ({ ...d, domain: v }))} />
              : <span style={{ fontSize: 12.5, color: 'var(--app-t2)' }}>{tenant?.domain || 'Not set'}</span>}
          </SRow>
          <SRow label="Billing email">
            {canEdit
              ? <SInput key={tenant?.billing_email} value={tenant?.billing_email ?? ''} width={280} onChange={(v) => setDraft((d) => ({ ...d, billing_email: v }))} />
              : <span style={{ fontSize: 12.5, color: 'var(--app-t2)' }}>{tenant?.billing_email || '—'}</span>}
          </SRow>
          <SRow label="Organization ID" hint="Reference this in support requests." last>
            <span className="mono" style={{ fontSize: 12.5, color: 'var(--app-t3)' }}>{tenant?.id ?? '—'}</span>
          </SRow>
        </SCard>
        {canEdit && (mutation.isError || mutation.isSuccess) && (
          <p style={{ fontSize: 12, color: mutation.isError ? 'var(--danger-text)' : 'var(--app-t3)', marginTop: 14, lineHeight: 1.55 }}>
            <Icon name={mutation.isError ? 'alert-triangle' : 'info'} size={13} style={{ verticalAlign: '-2px', marginRight: 5, color: mutation.isError ? 'var(--danger-text)' : GREEN }} />
            {mutation.isError
              ? 'Saving organization details failed — try again.'
              : 'Saved. Changes apply across the console after the next sign-in or refresh.'}
          </p>
        )}
      </SSection>

      <SSection
        title="Licensed frameworks"
        desc="Standing & control evaluation live in Risk & Compliance."
        action={<Link to="/settings/frameworks" className="ui-btn sm" style={{ textDecoration: 'none' }}><Icon name="scroll-text" size={14} />Manage</Link>}
      >
        {isError ? (
          <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load frameworks" message="The framework license list failed to load." /></SCard>
        ) : isLoading ? (
          <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading frameworks…" message="Fetching the tenant's active frameworks." /></SCard>
        ) : licenses.length === 0 ? (
          <SCard><StateNote icon="scroll-text" tone="var(--app-t3)" title="No active frameworks" message="Activate a compliance framework to see it here." /></SCard>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(220px,1fr))', gap: 12 }}>
            {licenses.map((l) => (
              <SCard key={l.id} pad={15} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <span style={{ width: 34, height: 34, borderRadius: 9, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--app-panel2)', border: '1px solid var(--app-border)', color: 'var(--accent)' }}>
                  <Icon name="shield-check" size={16} />
                </span>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--app-t1)', display: 'flex', alignItems: 'center', gap: 7 }}>
                    {l.platform_framework?.name ?? 'Framework'}
                    {l.is_default && <STag color="var(--accent)">Default</STag>}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--app-t3)' }}>
                    {l.platform_framework ? `${l.platform_framework.controls_count} controls` : l.subscription_status}
                  </div>
                </div>
              </SCard>
            ))}
          </div>
        )}
      </SSection>
    </SPage>
  );
}

function BrandingUpload({ kind, url, size, canEdit }: { kind: 'logo' | 'favicon'; url?: string; size: number; canEdit: boolean }) {
  const queryClient = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);
  const mutation = useMutation({
    mutationFn: async (file: File) => {
      const { error, response } = await clients.auth.POST('/tenant/branding/upload', {
        body: { type: kind, file: '' },
        bodySerializer: () => {
          const fd = new FormData();
          fd.append('type', kind);
          fd.append('file', file);
          return fd;
        },
      });
      if (error || !response.ok) throw new Error('Upload failed');
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['settings', 'branding'] }),
  });

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
      <div style={{ width: size, height: size, borderRadius: 12, border: '1.5px dashed var(--app-border2)', background: 'var(--app-panel2)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--app-t3)', overflow: 'hidden', flex: 'none' }}>
        {url ? <img src={url} alt="" style={{ maxWidth: '100%', maxHeight: '100%', objectFit: 'contain' }} /> : <Icon name="image-plus" size={20} />}
      </div>
      {canEdit && (
        <div>
          <input ref={fileRef} type="file" accept="image/png,image/svg+xml,image/jpeg" style={{ display: 'none' }}
            onChange={(e) => { const f = e.target.files?.[0]; if (f) mutation.mutate(f); e.target.value = ''; }} />
          <button className="ui-btn sm" disabled={mutation.isPending} onClick={() => fileRef.current?.click()}>
            <Icon name="upload" size={14} />{mutation.isPending ? 'Uploading…' : `Upload ${kind}`}
          </button>
          <div style={{ fontSize: 11, color: mutation.isError ? 'var(--danger-text)' : 'var(--app-t3)', marginTop: 6 }}>
            {mutation.isError ? 'Upload failed' : 'PNG or SVG, up to 2 MB'}
          </div>
        </div>
      )}
    </div>
  );
}

/** Row content shown in place of a white-label control the edition doesn't include. */
function WhiteLabelLock({ children }: { children: React.ReactNode }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 7, fontSize: 12, color: 'var(--app-t3)' }}>
      <Icon name="lock" size={13} style={{ color: 'var(--accent)', flex: 'none' }} />
      {children}
    </span>
  );
}

export function OrgBrandingPage({ meta }: { meta: SettingsNavItem }) {
  const queryClient = useQueryClient();
  const { hasPermission } = usePermissions();
  const canEdit = hasPermission(TENANT_PERMISSIONS.settings.update);
  // The white-label line is drawn on what the request CHANGES, matching the
  // backend gate (auth-service ui_config.go): the palette is Core — one org
  // styling itself — while replacing the product marks (logo, favicon, display
  // name) is Enterprise. `GET /tenant/branding` is Core and always runs, so
  // there is no query to skip here; a lapsed tenant keeps seeing its own marks.
  const whiteLabel = useFeature('custom_branding');
  const [name, setName] = useState<string | null>(null);
  const [colors, setColors] = useState<{ primary_color?: string; secondary_color?: string; accent_color?: string }>({});

  const { data, isLoading, isError } = useQuery({
    queryKey: ['settings', 'branding'],
    queryFn: async () => {
      const { data, error } = await clients.auth.GET('/tenant/branding', {});
      if (error || !data) throw new Error('Failed to load branding');
      return data.branding;
    },
  });

  const mutation = useMutation({
    mutationFn: async () => {
      // The Branding schema always carries the three colors — send the
      // current values merged with any edits, plus the name when touched.
      const { error, response } = await clients.auth.PUT('/tenant/branding', {
        body: {
          primary_color: colors.primary_color ?? data?.primary_color ?? '#000000',
          secondary_color: colors.secondary_color ?? data?.secondary_color ?? '#000000',
          accent_color: colors.accent_color ?? data?.accent_color ?? '#000000',
          // Never send company_name without the white-label entitlement: the
          // backend rejects the whole PUT when a gated field is present, which
          // would take the (Core) colour save down with it.
          ...(whiteLabel && name !== null ? { company_name: name.trim() } : {}),
        },
      });
      if (error || !response.ok) throw new Error('Failed to save branding');
    },
    onSuccess: () => {
      setName(null);
      setColors({});
      queryClient.invalidateQueries({ queryKey: ['settings', 'branding'] });
    },
  });

  if (isLoading || isError) {
    return (
      <SPage eyebrow="Organization" title="Branding" job={meta.job}>
        <SCard>
          {isError
            ? <StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load branding" message="The tenant branding failed to load." />
            : <StateNote icon="loader" tone="var(--app-t3)" title="Loading branding…" message="Fetching the tenant's branding configuration." />}
        </SCard>
      </SPage>
    );
  }

  const dirty = name !== null || Object.keys(colors).length > 0;
  const colorField = (key: 'primary_color' | 'secondary_color' | 'accent_color', label: string) => {
    const value = colors[key] ?? data?.[key] ?? '#000000';
    return (
      <div key={key} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 5 }}>
        <input
          type="color" value={value} disabled={!canEdit}
          onChange={(e) => setColors((c) => ({ ...c, [key]: e.target.value }))}
          title={`${label}: ${value}`}
          style={{ width: 30, height: 30, padding: 0, border: '1px solid var(--app-border2)', borderRadius: 7, background: 'var(--app-panel2)', cursor: canEdit ? 'pointer' : 'default' }}
        />
        <span className="mono" style={{ fontSize: 9.5, color: 'var(--app-t3)' }}>{label}</span>
      </div>
    );
  };

  return (
    <SPage
      eyebrow="Organization" title="Branding" job={meta.job}
      actions={canEdit ? (
        <button className="ui-btn sm accent" disabled={!dirty || mutation.isPending} onClick={() => mutation.mutate()}>
          <Icon name="check" size={14} />{mutation.isPending ? 'Saving…' : 'Save changes'}
        </button>
      ) : undefined}
    >
      <SCard>
        <SRow label="Logo" hint="Appears in the top-left of the console.">
          {whiteLabel
            ? <BrandingUpload kind="logo" url={data?.logo_url} size={64} canEdit={canEdit} />
            : <WhiteLabelLock>Replacing the product logo is an Enterprise feature.</WhiteLabelLock>}
        </SRow>
        <SRow label="Favicon" hint="Shown in the browser tab.">
          {whiteLabel
            ? <BrandingUpload kind="favicon" url={data?.favicon_url} size={44} canEdit={canEdit} />
            : <WhiteLabelLock>Replacing the product favicon is an Enterprise feature.</WhiteLabelLock>}
        </SRow>
        <SRow label="Display name" hint="White-labels the wordmark in the UI.">
          {!whiteLabel
            ? <WhiteLabelLock>{data?.company_name || 'Not set'} · white-labelling the wordmark is an Enterprise feature.</WhiteLabelLock>
            : canEdit
              ? <SInput key={data?.company_name ?? 'none'} value={data?.company_name ?? ''} placeholder="Not set" width={220} onChange={setName} />
              : <span style={{ fontSize: 12.5, color: 'var(--app-t2)' }}>{data?.company_name || 'Not set'}</span>}
        </SRow>
        <SRow label="Brand colors" hint="Used for highlights and primary actions." last>
          <div style={{ display: 'flex', gap: 12 }}>
            {colorField('primary_color', 'primary')}
            {colorField('secondary_color', 'secondary')}
            {colorField('accent_color', 'accent')}
          </div>
        </SRow>
      </SCard>
      <p style={{ fontSize: 12, color: mutation.isError ? 'var(--danger-text)' : 'var(--app-t3)', marginTop: 14, lineHeight: 1.55 }}>
        <Icon name="info" size={13} style={{ verticalAlign: '-2px', marginRight: 5, color: mutation.isError ? 'var(--danger-text)' : GREEN }} />
        {mutation.isError
          ? 'Saving branding failed — try again.'
          : whiteLabel
            ? 'Changes apply to the console after the next sign-in or refresh.'
            : 'Brand colours are included in every edition. Replacing the logo, favicon, and wordmark is part of Enterprise white-labelling.'}
      </p>
    </SPage>
  );
}
