// SSO identity-provider editing modals — create / configure / delete, with a
// group→role mappings editor. google/microsoft/azure are OAuth2/OIDC (client id
// + secret + auth/token URLs required). SAML is no longer offered for NEW
// providers (owner decision D2 — OIDC-only for v3; the backend rejects SAML
// provider creation). Legacy SAML providers stay viewable/editable.
// Client secrets are write-only: never echoed back, blank on edit = unchanged.
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAuth } from '@vistasecurity/primitives/auth';
import { usePermissions, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { Icon, Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import type { authServiceComponents as AuthC } from '@vistasecurity/api-contract';

type SSOProvider = AuthC['schemas']['SSOProvider'];
type GroupRoleMapping = AuthC['schemas']['GroupRoleMapping'];

// OIDC-only for new providers (D2). SAML types are intentionally absent from
// this picker; family detection still recognizes them so legacy SAML providers
// remain viewable/editable.
const PROVIDER_TYPES: Array<{ value: string; label: string; family: 'oauth' | 'saml' }> = [
  { value: 'google', label: 'Google', family: 'oauth' },
  { value: 'microsoft', label: 'Microsoft', family: 'oauth' },
  { value: 'azure', label: 'Azure AD', family: 'oauth' },
];
const SAML_TYPES = new Set(['saml', 'okta']);
export function providerFamily(type: string): 'oauth' | 'saml' {
  return SAML_TYPES.has(type) ? 'saml' : 'oauth';
}

// OIDC endpoint templates per provider so neither Google nor Microsoft is harder
// to configure (provider parity). Microsoft/Azure default to the multi-tenant
// `common` authority — an admin pins a single-tenant `…/{tenant-id}/…` if needed.
type OAuthEndpoints = { authUrl: string; tokenUrl: string; userinfoUrl: string; scopes: string };
const PROVIDER_DEFAULTS: Record<string, OAuthEndpoints> = {
  google: {
    authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    userinfoUrl: 'https://openidconnect.googleapis.com/v1/userinfo',
    scopes: 'openid email profile',
  },
  microsoft: {
    authUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    userinfoUrl: 'https://graph.microsoft.com/oidc/userinfo',
    scopes: 'openid email profile',
  },
  azure: {
    authUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    userinfoUrl: 'https://graph.microsoft.com/oidc/userinfo',
    scopes: 'openid email profile',
  },
};
// Every templated URL across providers — used to tell an untouched field (safe to
// re-prefill when switching provider) from one an admin has hand-edited.
const TEMPLATE_URLS = new Set(
  Object.values(PROVIDER_DEFAULTS).flatMap((d) => [d.authUrl, d.tokenUrl, d.userinfoUrl]),
);

function legacyMessage(error: unknown, fallback: string): string {
  if (error && typeof error === 'object' && 'error' in error) return String((error as { error: unknown }).error);
  return fallback;
}

type MappingDraft = { external_group_name: string; role_id: string };

// The role dropdown is populated from GET /tenant/{tenantId}/roles, which
// auth-service gates on users.manage — a stricter permission than the
// settings.update that opens this modal. Without it the request 403s and the
// select renders empty, which reads as "this tenant has no roles" and, on save,
// would blank the role_id of every existing mapping. So when the caller can't
// read roles we say so and show the existing mappings read-only rather than
// offering a control that cannot work.
function MappingsEditor({ mappings, onChange, roles, rolesReadable }: {
  mappings: MappingDraft[];
  onChange: (m: MappingDraft[]) => void;
  roles: Array<{ id: string; name: string }>;
  rolesReadable: boolean;
}) {
  if (!rolesReadable) {
    return (
      <div style={{ border: '1px solid var(--app-border)', borderRadius: 12, padding: '13px 14px', marginBottom: 15 }}>
        <div className="eyebrow-app" style={{ marginBottom: 10 }}>Group → role mapping</div>
        <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginBottom: mappings.length ? 10 : 0 }}>
          Editing group → role mappings needs the "Manage users" permission, which lists the
          tenant's roles. {mappings.length ? 'Existing mappings are shown below and are preserved on save.' : 'No mappings are configured.'}
        </div>
        {mappings.map((m, i) => (
          <div key={i} className="mono" style={{ fontSize: 11.5, color: 'var(--app-t2)', marginBottom: 4 }}>
            {m.external_group_name || '(unnamed group)'}
          </div>
        ))}
      </div>
    );
  }
  return (
    <div style={{ border: '1px solid var(--app-border)', borderRadius: 12, padding: '13px 14px', marginBottom: 15 }}>
      <div className="eyebrow-app" style={{ marginBottom: 10 }}>Group → role mapping</div>
      {mappings.length === 0 && (
        <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginBottom: 10 }}>
          No mappings — provisioned users get the provider's default role.
        </div>
      )}
      {mappings.map((m, i) => (
        <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
          <ModalInput
            value={m.external_group_name} placeholder="idp-group-name" className="mono" style={{ flex: 1.4 }}
            onChange={(e) => onChange(mappings.map((x, j) => (j === i ? { ...x, external_group_name: e.target.value } : x)))}
          />
          <ModalSelect
            value={m.role_id} style={{ flex: 1 }}
            onChange={(e) => onChange(mappings.map((x, j) => (j === i ? { ...x, role_id: e.target.value } : x)))}
          >
            {roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
          </ModalSelect>
          <button className="ui-btn sm ghost" title="Remove mapping" style={{ color: 'var(--danger-text)', flex: 'none' }}
            onClick={() => onChange(mappings.filter((_, j) => j !== i))}>
            <Icon name="x" size={14} />
          </button>
        </div>
      ))}
      <button className="ui-btn sm" disabled={!roles.length}
        onClick={() => onChange([...mappings, { external_group_name: '', role_id: roles[0]?.id ?? '' }])}>
        <Icon name="plus" size={13} />Add mapping
      </button>
    </div>
  );
}

export function SsoProviderModal({ provider, open, onClose }: { provider: SSOProvider | null; open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const { tenant } = useAuth();
  const isEdit = !!provider;

  const [type, setType] = useState(provider?.provider_type ?? 'google');
  const [name, setName] = useState(provider?.provider_name ?? '');
  const [enabled, setEnabled] = useState(provider?.is_enabled ?? true);
  const [isDefault, setIsDefault] = useState(provider?.is_default ?? false);
  const [autoProvision, setAutoProvision] = useState(provider?.auto_provision_users ?? true);
  const [domains, setDomains] = useState((provider?.allowed_domains ?? []).join(', '));
  const [groupsClaim, setGroupsClaim] = useState(provider?.groups_claim_name ?? '');
  const [mappings, setMappings] = useState<MappingDraft[]>(
    (provider?.group_role_mappings ?? []).map((m: GroupRoleMapping) => ({ external_group_name: m.external_group_name, role_id: m.role_id })),
  );
  // OAuth fields — secret is write-only (blank on edit = leave unchanged)
  const [clientId, setClientId] = useState(provider?.client_id ?? '');
  const [clientSecret, setClientSecret] = useState('');
  // On create, seed the OIDC URLs from the selected provider's template (Google by
  // default); on edit, keep the stored values. Switching provider re-prefills via
  // changeType() below.
  const initDefaults = PROVIDER_DEFAULTS[provider?.provider_type ?? 'google'];
  const [authUrl, setAuthUrl] = useState(provider?.auth_url ?? initDefaults?.authUrl ?? '');
  const [tokenUrl, setTokenUrl] = useState(provider?.token_url ?? initDefaults?.tokenUrl ?? '');
  const [userinfoUrl, setUserinfoUrl] = useState(provider?.userinfo_url ?? initDefaults?.userinfoUrl ?? '');
  const [scopes, setScopes] = useState(provider?.scopes ?? initDefaults?.scopes ?? '');
  // SAML fields
  const [entityId, setEntityId] = useState(provider?.saml_entity_id ?? '');
  const [ssoUrl, setSsoUrl] = useState(provider?.saml_sso_url ?? '');
  const [certificate, setCertificate] = useState('');

  const family = providerFamily(type);

  // Switch provider type and re-prefill the OIDC URLs from that provider's template,
  // but only for fields that are empty or still hold another provider's template
  // (never clobber a URL the admin hand-edited). Only reachable on create — the
  // provider select is disabled on edit.
  const changeType = (next: string) => {
    setType(next);
    const d = PROVIDER_DEFAULTS[next];
    if (!d) return;
    if (!authUrl.trim() || TEMPLATE_URLS.has(authUrl.trim())) setAuthUrl(d.authUrl);
    if (!tokenUrl.trim() || TEMPLATE_URLS.has(tokenUrl.trim())) setTokenUrl(d.tokenUrl);
    if (!userinfoUrl.trim() || TEMPLATE_URLS.has(userinfoUrl.trim())) setUserinfoUrl(d.userinfoUrl);
    if (!scopes.trim()) setScopes(d.scopes);
  };

  // Not destructured: `const { hasPermission } = usePermissions()` trips
  // @typescript-eslint/unbound-method and the lint job is a warning ratchet.
  const rolesReadable = usePermissions().hasPermission(TENANT_PERMISSIONS.users.manage);
  const rolesQ = useQuery({
    queryKey: ['settings', 'roles', tenant?.id],
    enabled: !!tenant?.id && open && rolesReadable,
    queryFn: async () => {
      const { data, error } = await clients.auth.GET('/tenant/{tenantId}/roles', { params: { path: { tenantId: tenant!.id } } });
      if (error || !data) throw new Error('Failed to load roles');
      return data;
    },
  });
  const roles = (rolesQ.data?.roles ?? []).map((r) => ({ id: r.id, name: r.name }));

  const valid = name.trim().length > 0 && (
    family === 'saml'
      ? entityId.trim().length > 0 && ssoUrl.trim().length > 0
      : clientId.trim().length > 0 && authUrl.trim().length > 0 && tokenUrl.trim().length > 0 && (isEdit || clientSecret.trim().length > 0)
  ) && mappings.every((m) => m.external_group_name.trim() && m.role_id);

  const mutation = useMutation({
    mutationFn: async () => {
      const common = {
        provider_name: name.trim(),
        is_enabled: enabled,
        is_default: isDefault,
        auto_provision_users: autoProvision,
        allowed_domains: domains.split(',').map((s) => s.trim()).filter(Boolean),
        groups_claim_name: groupsClaim.trim() || undefined,
        group_role_mappings: mappings.map((m) => ({ external_group_name: m.external_group_name.trim(), role_id: m.role_id })),
      };
      const oauthFields = family === 'oauth' ? {
        client_id: clientId.trim(),
        ...(clientSecret.trim() ? { client_secret: clientSecret.trim() } : {}),
        auth_url: authUrl.trim(),
        token_url: tokenUrl.trim(),
        userinfo_url: userinfoUrl.trim() || undefined,
        scopes: scopes.trim() || undefined,
      } : {};
      const samlFields = family === 'saml' ? {
        saml_entity_id: entityId.trim(),
        saml_sso_url: ssoUrl.trim(),
        ...(certificate.trim() ? { saml_certificate: certificate.trim() } : {}),
      } : {};

      if (isEdit) {
        const { error, response } = await clients.auth.PUT('/tenant/sso/providers/{id}', {
          params: { path: { id: provider.id } },
          body: { ...common, ...oauthFields, ...samlFields },
        });
        if (error || !response.ok) throw new Error(legacyMessage(error, 'Failed to update the provider'));
      } else {
        const { error, response } = await clients.auth.POST('/tenant/sso/providers', {
          body: { provider_type: type, ...common, ...oauthFields, ...samlFields },
        });
        if (error || !response.ok) throw new Error(legacyMessage(error, 'Failed to create the provider'));
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings', 'sso-providers'] });
      queryClient.invalidateQueries({ queryKey: ['settings', 'auth-policy'] });
      onClose();
    },
  });

  const toggleRow = (label: string, hint: string, value: boolean, set: (v: boolean) => void) => (
    <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 13 }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>{label}</div>
        <div style={{ fontSize: 11, color: 'var(--app-t3)' }}>{hint}</div>
      </div>
      <button onClick={() => set(!value)} aria-pressed={value}
        style={{ width: 38, height: 22, borderRadius: 40, border: 'none', cursor: 'pointer', padding: 0, background: value ? 'var(--accent-gradient)' : 'var(--app-track)', position: 'relative', flex: 'none', transition: 'background .18s' }}>
        <span style={{ position: 'absolute', top: 2, left: value ? 18 : 2, width: 18, height: 18, borderRadius: 50, background: '#fff', transition: 'left .18s', boxShadow: '0 1px 2px rgba(0,0,0,.3)' }} />
      </button>
    </div>
  );

  return (
    <Modal
      open={open}
      onClose={onClose}
      size="lg"
      icon="key-round"
      eyebrow="People & Access · Security & SSO"
      title={isEdit ? `Configure — ${provider.provider_name}` : 'Add identity provider'}
      description="Members authenticate against this provider; the org sign-in policy chooses whether it's optional or required."
      primary={
        <button className="ui-btn sm accent" disabled={!valid || mutation.isPending} onClick={() => mutation.mutate()}>
          {mutation.isPending ? 'Saving…' : isEdit ? 'Save changes' : 'Add provider'}
        </button>
      }
      secondary={<button className="ui-btn sm" onClick={onClose}>Cancel</button>}
      footerNote={mutation.isError ? <span style={{ color: 'var(--danger-text)' }}>{mutation.error instanceof Error ? mutation.error.message : 'Request failed'}</span> : undefined}
    >
      <div style={{ display: 'flex', gap: 14 }}>
        <div style={{ flex: 1 }}>
          <ModalField label="Provider" hint={isEdit ? (family === 'saml' ? 'SAML is deprecated — OIDC-only for new providers.' : 'The provider type cannot be changed.') : 'OIDC / OAuth2 providers.'}>
            <ModalSelect value={type} disabled={isEdit} onChange={(e) => changeType(e.target.value)}>
              {/* Show the legacy SAML type for an existing SAML provider so the
                  disabled select renders it (and isn't silently re-typed). */}
              {isEdit && provider && !PROVIDER_TYPES.some((t) => t.value === provider.provider_type) && (
                <option value={provider.provider_type}>{provider.provider_type} (legacy SAML)</option>
              )}
              {PROVIDER_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
            </ModalSelect>
          </ModalField>
        </div>
        <div style={{ flex: 1.4 }}>
          <ModalField label="Display name">
            <ModalInput value={name} data-autofocus placeholder="e.g. Okta · OIDC" onChange={(e) => setName(e.target.value)} />
          </ModalField>
        </div>
      </div>

      {family === 'oauth' ? (
        <>
          <div style={{ display: 'flex', gap: 14 }}>
            <div style={{ flex: 1 }}>
              <ModalField label="Client ID">
                <ModalInput value={clientId} className="mono" onChange={(e) => setClientId(e.target.value)} />
              </ModalField>
            </div>
            <div style={{ flex: 1 }}>
              <ModalField label="Client secret" hint={isEdit ? 'Leave blank to keep the stored secret.' : 'Stored encrypted; never shown again.'}>
                <ModalInput value={clientSecret} type="password" autoComplete="new-password" placeholder={isEdit ? '••••••••  (unchanged)' : ''} onChange={(e) => setClientSecret(e.target.value)} />
              </ModalField>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 14 }}>
            <div style={{ flex: 1 }}>
              <ModalField label="Authorization URL">
                <ModalInput value={authUrl} className="mono" placeholder="https://…/authorize" onChange={(e) => setAuthUrl(e.target.value)} />
              </ModalField>
            </div>
            <div style={{ flex: 1 }}>
              <ModalField label="Token URL">
                <ModalInput value={tokenUrl} className="mono" placeholder="https://…/token" onChange={(e) => setTokenUrl(e.target.value)} />
              </ModalField>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 14 }}>
            <div style={{ flex: 1 }}>
              <ModalField label="Userinfo URL" hint="Optional.">
                <ModalInput value={userinfoUrl} className="mono" onChange={(e) => setUserinfoUrl(e.target.value)} />
              </ModalField>
            </div>
            <div style={{ flex: 1 }}>
              <ModalField label="Scopes" hint="Space-separated; defaults apply when empty.">
                <ModalInput value={scopes} className="mono" placeholder="openid email profile" onChange={(e) => setScopes(e.target.value)} />
              </ModalField>
            </div>
          </div>
        </>
      ) : (
        <>
          <div style={{ display: 'flex', gap: 14 }}>
            <div style={{ flex: 1 }}>
              <ModalField label="Entity ID">
                <ModalInput value={entityId} className="mono" placeholder="urn:example:idp" onChange={(e) => setEntityId(e.target.value)} />
              </ModalField>
            </div>
            <div style={{ flex: 1 }}>
              <ModalField label="SSO URL">
                <ModalInput value={ssoUrl} className="mono" placeholder="https://…/sso/saml" onChange={(e) => setSsoUrl(e.target.value)} />
              </ModalField>
            </div>
          </div>
          <ModalField label="Signing certificate (PEM)" hint={isEdit ? 'Leave blank to keep the stored certificate.' : 'The IdP’s X.509 signing certificate.'}>
            <textarea
              value={certificate} rows={4} placeholder="-----BEGIN CERTIFICATE-----"
              onChange={(e) => setCertificate(e.target.value)}
              className="mono"
              style={{ width: '100%', padding: '9px 12px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 11.5, outline: 'none', resize: 'vertical' }}
            />
          </ModalField>
        </>
      )}

      <ModalField label="Allowed email domains" hint="Comma-separated; empty allows any domain.">
        <ModalInput value={domains} placeholder="globexcorp.com" onChange={(e) => setDomains(e.target.value)} />
      </ModalField>
      <ModalField label="Groups claim" hint="Token claim (or SAML attribute) carrying the user's groups; needed for role mapping.">
        <ModalInput value={groupsClaim} className="mono" placeholder="groups" onChange={(e) => setGroupsClaim(e.target.value)} />
      </ModalField>

      <MappingsEditor mappings={mappings} onChange={setMappings} roles={roles} rolesReadable={rolesReadable} />

      {toggleRow('Enabled', 'Members can sign in through this provider.', enabled, setEnabled)}
      {toggleRow('Default provider', 'Pre-selected on the sign-in page.', isDefault, setIsDefault)}
      {toggleRow('Auto-provision users', 'First sign-in creates the account with the mapped (or default) role.', autoProvision, setAutoProvision)}
    </Modal>
  );
}

export function SsoProviderDeleteModal({ provider, open, onClose }: { provider: SSOProvider | null; open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: async () => {
      if (!provider) return;
      const { error, response } = await clients.auth.DELETE('/tenant/sso/providers/{id}', { params: { path: { id: provider.id } } });
      if (error || !response.ok) throw new Error(legacyMessage(error, 'Failed to delete the provider'));
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings', 'sso-providers'] });
      queryClient.invalidateQueries({ queryKey: ['settings', 'auth-policy'] });
      onClose();
    },
  });
  return (
    <Modal
      open={open} onClose={onClose} size="sm" tone="danger" icon="alert-triangle" eyebrow="People & Access · Security & SSO"
      title={`Delete provider — ${provider?.provider_name ?? ''}`}
      description="Members lose this sign-in method immediately. If the org policy requires SSO and no other provider is enabled, password sign-in rules apply per the policy."
      primary={<button className="ui-btn sm" style={{ borderColor: 'color-mix(in srgb, var(--danger) 40%, transparent)', color: 'var(--danger-text)' }} disabled={mutation.isPending} onClick={() => mutation.mutate()}>{mutation.isPending ? 'Deleting…' : 'Delete provider'}</button>}
      secondary={<button className="ui-btn sm" onClick={onClose}>Cancel</button>}
      footerNote={mutation.isError ? <span style={{ color: 'var(--danger-text)' }}>{mutation.error instanceof Error ? mutation.error.message : 'Request failed'}</span> : undefined}
    />
  );
}
