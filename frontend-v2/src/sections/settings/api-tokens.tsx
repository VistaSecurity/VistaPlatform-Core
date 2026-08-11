// My Profile · API Tokens — personal access tokens for the read-only MCP
// surface. Wired to auth-service /api-tokens (list / create / revoke) through the
// typed client. The plaintext token is returned exactly once on create, so the
// modal switches to a copy-once panel and never shows the value again.
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { authServiceComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { copyToClipboard } from '../../lib/clipboard';
import { Icon, Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import { SPage, SCard, STable, STableRow, STag, SDot, StateNote, relTime, GREEN, AMBER, RED } from './kit';
import type { SettingsNavItem } from './nav';

type APIToken = authServiceComponents['schemas']['APIToken'];
type Perm = NonNullable<authServiceComponents['schemas']['APITokenCreateRequest']['permissions']>[number];

// The allowed read-only scope set + the server's default subset (see the
// createApiToken contract description). Labels keep the table/checkboxes terse.
const ALL_PERMS: Perm[] = ['assets.read', 'compliance.read', 'reports.read', 'discovery.read', 'sensors.read', 'settings.read'];
const DEFAULT_PERMS: Perm[] = ['assets.read', 'compliance.read', 'reports.read'];
const EXPIRY_OPTIONS = [30, 90, 180, 365];

type Status = 'active' | 'revoked' | 'expired';
function tokenStatus(t: APIToken): Status {
  if (t.revoked_at) return 'revoked';
  if (t.expires_at && new Date(t.expires_at).getTime() <= Date.now()) return 'expired';
  return 'active';
}
const STATUS_TONE: Record<Status, string> = { active: GREEN, expired: AMBER, revoked: RED };

function dateStr(iso?: string | null): string {
  return iso ? new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : '—';
}

export function ApiTokensPage({ meta }: { meta: SettingsNavItem }) {
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [confirmRevoke, setConfirmRevoke] = useState<APIToken | null>(null);

  const q = useQuery({
    queryKey: ['settings', 'api-tokens'],
    queryFn: async () => {
      const { data, error } = await clients.auth.GET('/api-tokens', {});
      if (error || !data) throw new Error('Failed to load API tokens');
      return data.tokens ?? [];
    },
  });

  const revoke = useMutation({
    mutationFn: async (id: string) => {
      const { error, response } = await clients.auth.DELETE('/api-tokens/{id}', { params: { path: { id } } });
      if (!response.ok || error) throw new Error('Failed to revoke token');
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['settings', 'api-tokens'] }),
    onSettled: () => setConfirmRevoke(null),
  });

  const tokens = q.data ?? [];
  const cols = [
    { label: 'Name' }, { label: 'Prefix', w: '120px' }, { label: 'Scopes' },
    { label: 'Created', w: '110px' }, { label: 'Expires', w: '110px' },
    { label: 'Last used', w: '110px' }, { label: 'Status', w: '92px' }, { label: '', w: '84px', align: 'right' as const },
  ];

  return (
    <SPage
      eyebrow="My Profile" title="API Tokens" job={meta.job}
      actions={<button className="ui-btn accent" onClick={() => setCreateOpen(true)}><Icon name="plus" size={14} />New token</button>}
    >
      {q.isError ? (
        <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load API tokens" message="The token list failed to load." /></SCard>
      ) : q.isLoading ? (
        <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading tokens…" message="Fetching your personal access tokens." /></SCard>
      ) : tokens.length === 0 ? (
        <SCard><StateNote icon="key-round" tone="var(--app-t3)" title="No API tokens" message="Create a token to authenticate the read-only MCP server or scripts with the scopes you grant." /></SCard>
      ) : (
        <STable cols={cols}>
          {tokens.map((t, i) => {
            const status = tokenStatus(t);
            return (
              <STableRow
                key={t.id}
                first={i === 0}
                cols={cols}
                cells={[
                  <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>{t.name}</span>,
                  <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>{t.token_prefix}…</span>,
                  <span style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                    {t.permissions.map((p) => <STag key={p}>{p.replace('.read', '')}</STag>)}
                  </span>,
                  <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t2)' }}>{dateStr(t.created_at)}</span>,
                  <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t2)' }}>{t.expires_at ? dateStr(t.expires_at) : 'Never'}</span>,
                  <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>{t.last_used_at ? relTime(t.last_used_at) : 'Never'}</span>,
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}><SDot color={STATUS_TONE[status]} /><span style={{ fontSize: 11.5, color: 'var(--app-t2)', textTransform: 'capitalize' }}>{status}</span></span>,
                  status === 'active'
                    ? <button className="ui-btn sm ghost" style={{ color: 'var(--danger-text)' }} title="Revoke token" onClick={() => setConfirmRevoke(t)}><Icon name="x" size={13} />Revoke</button>
                    : <span />,
                ]}
              />
            );
          })}
        </STable>
      )}

      <p style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 14, lineHeight: 1.55, maxWidth: 680 }}>
        Tokens carry a subset of read-only scopes and are owned by you. The full value is shown only once at creation — store it in a secret manager. Up to 25 active tokens per user.
      </p>

      <ConnectAISection />

      {createOpen && <CreateTokenModal open onClose={() => setCreateOpen(false)} />}

      {confirmRevoke && (
        <Modal
          open
          onClose={revoke.isPending ? undefined : () => setConfirmRevoke(null)}
          dismissible={!revoke.isPending}
          size="sm" tone="danger" icon="octagon-alert"
          eyebrow="API Tokens" title={`Revoke “${confirmRevoke.name}”?`}
          description="Any client using this token will immediately lose access. This cannot be undone."
          primary={<button className="ui-btn" style={{ background: 'var(--danger)', color: '#fff', borderColor: 'var(--danger)' }} disabled={revoke.isPending} onClick={() => revoke.mutate(confirmRevoke.id)}>{revoke.isPending ? 'Revoking…' : 'Revoke token'}</button>}
          secondary={<button className="ui-btn" onClick={() => setConfirmRevoke(null)} disabled={revoke.isPending}>Cancel</button>}
          footerNote={revoke.isError ? <span style={{ color: 'var(--danger-text)' }}>Revoke failed.</span> : undefined}
        />
      )}
    </SPage>
  );
}

// ---- connect AI section ---------------------------------------------------
function ConnectAISection() {
  const [copied, setCopied] = useState(false);
  const mcpURL = `${window.location.origin}/api/v1/mcp-service/mcp`;
  const copy = async () => {
    if (await copyToClipboard(mcpURL)) { setCopied(true); setTimeout(() => setCopied(false), 1800); }
  };
  return (
    <SCard style={{ marginTop: 20 }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14 }}>
        <div style={{ width: 36, height: 36, borderRadius: 10, background: 'color-mix(in srgb, var(--accent) 12%, transparent)', border: '1px solid color-mix(in srgb, var(--accent) 25%, transparent)', display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 'none' }}>
          <Icon name="bot" size={18} style={{ color: 'var(--accent)' }} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--app-t1)', marginBottom: 4 }}>Connect an AI assistant</div>
          <p style={{ fontSize: 12, color: 'var(--app-t2)', lineHeight: 1.6, margin: '0 0 12px' }}>
            Paste the URL below into Claude.ai, ChatGPT, Gemini, or any MCP-capable client under connector or tool settings.
            The AI client will open a Vista login page and ask you to approve read-only access — no token copy-paste required.
          </p>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <div className="mono" style={{ flex: 1, minWidth: 0, padding: '9px 12px', borderRadius: 9, background: 'var(--app-panel2)', border: '1px solid var(--app-border2)', fontSize: 11.5, color: 'var(--app-t2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{mcpURL}</div>
            <button className="ui-btn" onClick={copy} style={{ flex: 'none' }}>
              <Icon name={copied ? 'check' : 'copy'} size={14} />{copied ? 'Copied' : 'Copy URL'}
            </button>
          </div>
        </div>
      </div>
    </SCard>
  );
}

// ---- create modal (form → copy-once reveal) -------------------------------
function CreateTokenModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState('');
  const [perms, setPerms] = useState<Perm[]>(DEFAULT_PERMS);
  const [expiry, setExpiry] = useState(90);
  const [plaintext, setPlaintext] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const create = useMutation({
    mutationFn: async () => {
      const { data, error } = await clients.auth.POST('/api-tokens', {
        body: { name: name.trim(), permissions: perms, expires_in_days: expiry },
      });
      if (error || !data) throw new Error((error as { error?: string })?.error ?? 'Failed to create token');
      return data;
    },
    onSuccess: (data) => {
      setPlaintext(data.plaintext_token);
      qc.invalidateQueries({ queryKey: ['settings', 'api-tokens'] });
    },
  });

  const togglePerm = (p: Perm) => setPerms((s) => s.includes(p) ? s.filter((x) => x !== p) : [...s, p]);
  const copy = async () => {
    if (!plaintext) return;
    if (await copyToClipboard(plaintext)) { setCopied(true); setTimeout(() => setCopied(false), 1800); }
  };

  const revealed = plaintext != null;
  const valid = name.trim().length > 0 && perms.length > 0;
  const err = create.error instanceof Error ? create.error.message : null;

  return (
    <Modal
      open={open}
      onClose={create.isPending ? undefined : onClose}
      dismissible={!create.isPending && !revealed}
      size="md" tone="accent" icon="key-round"
      eyebrow="API Tokens"
      title={revealed ? 'Token created' : 'New API token'}
      description={revealed ? 'Copy your token now — it will never be shown again.' : 'Scopes are read-only. The token is owned by you and inherits no more than what you select.'}
      primary={revealed
        ? <button className="ui-btn accent" onClick={onClose}>Done</button>
        : <button className="ui-btn accent" disabled={!valid || create.isPending} onClick={() => create.mutate()}>{create.isPending ? 'Creating…' : 'Create token'}</button>}
      secondary={revealed ? undefined : <button className="ui-btn" onClick={onClose} disabled={create.isPending}>Cancel</button>}
      footerNote={err ? <span style={{ color: 'var(--danger-text)' }}>{err}</span> : revealed ? 'Store it in a secret manager.' : undefined}
    >
      {revealed ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 12px', borderRadius: 9, background: 'color-mix(in srgb, var(--warn) 10%, transparent)', border: '1px solid color-mix(in srgb, var(--warn) 30%, transparent)' }}>
            <Icon name="alert-triangle" size={15} style={{ color: 'var(--warn)', flex: 'none' }} />
            <span style={{ fontSize: 12, color: 'var(--app-t2)' }}>This is the only time the full token is shown.</span>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'stretch' }}>
            <div className="mono" style={{ flex: 1, minWidth: 0, padding: '11px 12px', borderRadius: 9, background: 'var(--app-panel2)', border: '1px solid var(--app-border2)', fontSize: 12, color: 'var(--app-t1)', wordBreak: 'break-all' }}>{plaintext}</div>
            <button className="ui-btn" onClick={copy} style={{ flex: 'none' }}><Icon name={copied ? 'check' : 'file-text'} size={14} />{copied ? 'Copied' : 'Copy'}</button>
          </div>
        </div>
      ) : (
        <>
          <ModalField label="Name" hint="A label so you can recognize this token later.">
            <ModalInput data-autofocus value={name} onChange={(e) => setName(e.target.value)} placeholder="Claude Code on my laptop" />
          </ModalField>
          <ModalField label="Scopes" hint="Read-only. At least one is required.">
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 7 }}>
              {ALL_PERMS.map((p) => {
                const on = perms.includes(p);
                return (
                  <button key={p} type="button" onClick={() => togglePerm(p)}
                    style={{ display: 'inline-flex', alignItems: 'center', gap: 6, height: 28, padding: '0 11px', borderRadius: 8, cursor: 'pointer', fontSize: 12, fontWeight: 600, border: `1px solid ${on ? 'var(--accent)' : 'var(--app-border2)'}`, background: on ? 'color-mix(in srgb, var(--accent) 12%, transparent)' : 'var(--app-panel2)', color: on ? 'var(--accent)' : 'var(--app-t2)' }}>
                    <Icon name={on ? 'check' : 'plus'} size={12} />{p}
                  </button>
                );
              })}
            </div>
          </ModalField>
          <ModalField label="Expires in">
            <ModalSelect value={String(expiry)} onChange={(e) => setExpiry(Number(e.target.value))}>
              {EXPIRY_OPTIONS.map((d) => <option key={d} value={d}>{d} days</option>)}
            </ModalSelect>
          </ModalField>
        </>
      )}
    </Modal>
  );
}
