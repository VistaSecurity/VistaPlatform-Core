// Platform Settings — Identity Providers. Configures VISTA'S OWN OAuth
// apps (Google / Microsoft) that power social signup ("Sign up with Google").
// This is platform-wide (one row per provider type), distinct from a tenant's
// own SSO (that's the tenant web-ui). CRUD over admin-service
// /admin/identity-providers; the client secret is write-only and never returned.
import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { KeyRound, Plus, Pencil, Trash2 } from 'lucide-react';
import toast from 'react-hot-toast';
import { clients } from '../../lib/clients';
import { Modal, ModalField, modalInputStyle } from '../../components/ui/modal';
import type { adminServiceComponents as AdminC } from '@vistasecurity/api-contract';

type Provider = AdminC['schemas']['PlatformIdentityProvider'];

const KEY = ['platform', 'identity-providers'] as const;

type Endpoints = { auth_url: string; token_url: string; userinfo_url: string; scopes: string };
const DEFAULTS: Record<string, Endpoints> = {
  google: {
    auth_url: 'https://accounts.google.com/o/oauth2/v2/auth',
    token_url: 'https://oauth2.googleapis.com/token',
    userinfo_url: 'https://openidconnect.googleapis.com/v1/userinfo',
    scopes: 'openid email profile',
  },
  microsoft: {
    auth_url: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    token_url: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    userinfo_url: 'https://graph.microsoft.com/oidc/userinfo',
    scopes: 'openid email profile',
  },
};

function providerLabel(t: string) {
  return t === 'google' ? 'Google' : t === 'microsoft' ? 'Microsoft' : t;
}

function purposeLabel(p: string) {
  return p === 'admin_login' ? 'Admin login' : 'Sign-up';
}

// The redirect URI to register in Google/Entra. It differs by purpose:
//  - admin_login (staff sign-in) callback is served by admin-service on THIS
//    (admin) host — so window.location.origin is correct as-is.
//  - signup (tenant founders) callback is served by auth-service on the tenant
//    web host — strip a leading `admin.` from the origin as a best-effort default.
function redirectURIFor(type: string, purpose: string) {
  const t = type || 'google';
  if (purpose === 'admin_login') {
    return `${window.location.origin}/api/v1/admin-service/admin/sso/${t}/callback`;
  }
  const webOrigin = window.location.origin.replace('://admin.', '://');
  return `${webOrigin}/api/v1/auth-service/auth/sso/platform/${t}/callback`;
}

export function SettingsIdentityProvidersPage() {
  const { data, isLoading, isError } = useQuery({
    queryKey: KEY,
    queryFn: async () => {
      const { data, error } = await clients.admin.GET('/admin/identity-providers', {});
      if (error || !data) throw new Error('Failed to load identity providers');
      return data.providers;
    },
  });
  const providers = data ?? [];
  const [editing, setEditing] = useState<Provider | 'new' | null>(null);

  return (
    <div className="op-fade" style={{ padding: 24, maxWidth: 820 }}>
      <div className="op-panel" style={{ padding: '20px 22px', display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
          <div>
            <div style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 16, color: 'var(--op-t1)', display: 'flex', alignItems: 'center', gap: 8 }}>
              <KeyRound size={18} /> Identity Providers
            </div>
            <div style={{ fontSize: 12.5, color: 'var(--op-t3)', marginTop: 4 }}>
              Vista's own Google / Microsoft OAuth apps that power "Sign up with Google/Microsoft" on the public sign-up page.
            </div>
          </div>
          <button className="op-btn" onClick={() => setEditing('new')} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, flex: 'none' }}>
            <Plus size={15} /> Add provider
          </button>
        </div>

        {isError ? (
          <div style={{ fontSize: 13, color: 'var(--danger)' }}>Couldn't load identity providers.</div>
        ) : isLoading ? (
          <div style={{ fontSize: 13, color: 'var(--op-t3)' }}>Loading…</div>
        ) : providers.length === 0 ? (
          <div style={{ fontSize: 13, color: 'var(--op-t3)', padding: '8px 0' }}>
            No identity providers configured. Add Google or Microsoft to enable social sign-up.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {providers.map((p) => (
              <div key={p.id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '11px 13px', borderRadius: 10, border: '1px solid var(--op-border)', background: 'var(--op-panel2)' }}>
                <KeyRound size={16} style={{ color: 'var(--op-accent-text)', flex: 'none' }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--op-t1)' }}>
                    {p.provider_name || providerLabel(p.provider_type)} · {providerLabel(p.provider_type)}
                    <span style={{ marginLeft: 8, fontSize: 10.5, fontWeight: 600, color: p.purpose === 'admin_login' ? '#7FB3FF' : 'var(--op-t3)', border: '1px solid var(--op-border)', borderRadius: 5, padding: '1px 6px' }}>{purposeLabel(p.purpose)}</span>
                  </div>
                  <div className="mono" style={{ fontSize: 11, color: 'var(--op-t3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.client_id}</div>
                </div>
                <span style={{ fontSize: 11.5, fontWeight: 600, color: p.is_enabled ? 'var(--ok)' : 'var(--op-t3)', flex: 'none' }}>
                  {p.is_enabled ? 'Enabled' : 'Disabled'}
                </span>
                <button className="op-btn ghost sm" title="Edit" onClick={() => setEditing(p)}><Pencil size={14} /></button>
              </div>
            ))}
          </div>
        )}
      </div>

      {editing && <IdpModal provider={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
    </div>
  );
}

function IdpModal({ provider, onClose }: { provider: Provider | null; onClose: () => void }) {
  const qc = useQueryClient();
  const isEdit = !!provider;
  const [type, setType] = useState<string>(provider?.provider_type ?? 'google');
  const [purpose, setPurpose] = useState<string>(provider?.purpose ?? 'signup');
  const [name, setName] = useState(provider?.provider_name ?? '');
  const [clientId, setClientId] = useState(provider?.client_id ?? '');
  const [clientSecret, setClientSecret] = useState('');
  const init = DEFAULTS[provider?.provider_type ?? 'google'];
  const [authUrl, setAuthUrl] = useState(provider?.auth_url ?? init?.auth_url ?? '');
  const [tokenUrl, setTokenUrl] = useState(provider?.token_url ?? init?.token_url ?? '');
  const [userinfoUrl, setUserinfoUrl] = useState(provider?.userinfo_url ?? init?.userinfo_url ?? '');
  const [scopes, setScopes] = useState(provider?.scopes ?? init?.scopes ?? '');
  const [enabled, setEnabled] = useState(provider?.is_enabled ?? true);

  const allTemplates = new Set(Object.values(DEFAULTS).flatMap((d) => [d.auth_url, d.token_url, d.userinfo_url]));
  const changeType = (next: string) => {
    setType(next);
    const d = DEFAULTS[next];
    if (!d) return;
    if (!authUrl.trim() || allTemplates.has(authUrl.trim())) setAuthUrl(d.auth_url);
    if (!tokenUrl.trim() || allTemplates.has(tokenUrl.trim())) setTokenUrl(d.token_url);
    if (!userinfoUrl.trim() || allTemplates.has(userinfoUrl.trim())) setUserinfoUrl(d.userinfo_url);
    if (!scopes.trim()) setScopes(d.scopes);
  };

  const body = () => ({
    provider_type: type as 'google' | 'microsoft',
    purpose: purpose as 'signup' | 'admin_login',
    provider_name: name.trim() || undefined,
    client_id: clientId.trim(),
    ...(clientSecret.trim() ? { client_secret: clientSecret.trim() } : {}),
    auth_url: authUrl.trim(),
    token_url: tokenUrl.trim(),
    userinfo_url: userinfoUrl.trim() || undefined,
    scopes: scopes.trim() || undefined,
    is_enabled: enabled,
  });

  const mutation = useMutation({
    mutationFn: async () => {
      if (isEdit) {
        const { error, response } = await clients.admin.PUT('/admin/identity-providers/{id}', { params: { path: { id: provider!.id } }, body: body() });
        if (error || !response.ok) throw new Error((error as { error?: string })?.error ?? 'Failed to save');
      } else {
        const { error, response } = await clients.admin.POST('/admin/identity-providers', { body: body() });
        if (error || !response.ok) throw new Error((error as { error?: string })?.error ?? 'Failed to create');
      }
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: KEY }); toast.success(isEdit ? 'Provider saved' : 'Provider created'); onClose(); },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Request failed'),
  });

  const del = useMutation({
    mutationFn: async () => {
      const { error, response } = await clients.admin.DELETE('/admin/identity-providers/{id}', { params: { path: { id: provider!.id } } });
      if (error || !response.ok) throw new Error('Failed to delete');
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: KEY }); toast.success('Provider deleted'); onClose(); },
    onError: () => toast.error('Failed to delete'),
  });

  const valid = clientId.trim() && authUrl.trim() && tokenUrl.trim() && (isEdit || clientSecret.trim());

  return (
    <Modal
      open
      onClose={onClose}
      title={isEdit ? `Edit ${providerLabel(type)} provider` : 'Add identity provider'}
      description="Vista's own OAuth app. Sign-up = tenant founders (web host); Admin login = staff into this console (admin host). Register the redirect URI below in the provider's console."
      size="md"
      primaryLabel={isEdit ? 'Save changes' : 'Add provider'}
      onPrimary={() => mutation.mutate()}
      primaryDisabled={!valid || mutation.isPending}
      primaryLoading={mutation.isPending}
    >
      <ModalField label="Used for">
        <select value={purpose} disabled={isEdit} onChange={(e) => setPurpose(e.target.value)} style={modalInputStyle}>
          <option value="signup">Sign-up (tenant founders)</option>
          <option value="admin_login">Admin login (Vista staff)</option>
        </select>
      </ModalField>
      <ModalField label="Provider">
        <select value={type} disabled={isEdit} onChange={(e) => changeType(e.target.value)} style={modalInputStyle}>
          <option value="google">Google</option>
          <option value="microsoft">Microsoft</option>
        </select>
      </ModalField>
      <ModalField label="Display name (optional)">
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder={providerLabel(type)} style={modalInputStyle} />
      </ModalField>
      <ModalField label="Redirect URI — register this in the provider's console">
        <input readOnly value={redirectURIFor(type, purpose)} onFocus={(e) => e.currentTarget.select()} className="mono" style={modalInputStyle} />
      </ModalField>
      <ModalField label="Client ID">
        <input value={clientId} onChange={(e) => setClientId(e.target.value)} className="mono" style={modalInputStyle} />
      </ModalField>
      <ModalField label={isEdit ? 'Client secret (blank = unchanged)' : 'Client secret'}>
        <input value={clientSecret} onChange={(e) => setClientSecret(e.target.value)} type="password" autoComplete="new-password" placeholder={isEdit ? '••••••••' : ''} style={modalInputStyle} />
      </ModalField>
      <ModalField label="Authorization URL">
        <input value={authUrl} onChange={(e) => setAuthUrl(e.target.value)} className="mono" style={modalInputStyle} />
      </ModalField>
      <ModalField label="Token URL">
        <input value={tokenUrl} onChange={(e) => setTokenUrl(e.target.value)} className="mono" style={modalInputStyle} />
      </ModalField>
      <ModalField label="Userinfo URL (optional)">
        <input value={userinfoUrl} onChange={(e) => setUserinfoUrl(e.target.value)} className="mono" style={modalInputStyle} />
      </ModalField>
      <ModalField label="Scopes">
        <input value={scopes} onChange={(e) => setScopes(e.target.value)} className="mono" placeholder="openid email profile" style={modalInputStyle} />
      </ModalField>
      <ModalField label="Status">
        <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--op-t2)', cursor: 'pointer' }}>
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled (shows the sign-up button)
        </label>
      </ModalField>
      {isEdit && (
        <button className="op-btn ghost sm" disabled={del.isPending} onClick={() => del.mutate()} style={{ color: 'var(--danger)', marginTop: 4, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
          <Trash2 size={14} /> Delete provider
        </button>
      )}
    </Modal>
  );
}
