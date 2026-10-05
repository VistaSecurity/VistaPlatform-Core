// Settings → AI assistant: the model provider row, and the form an organization
// connects its own with.
//
// Three people can have decided which model answers here, and the row has to
// say which one did: this organization (it connected a provider on this page),
// whoever runs the deployment (in the admin console, or at install), or nobody.
// Whether THIS organization may connect its own is a fourth fact with its own
// two "no"s — the plan, and the deployment — and each sends the reader
// somewhere different, so each has its own sentence.
//
// The logic that picks the sentence is pure and exported (`providerRowView`),
// so the test can drive every combination without rendering. The component
// renders what it returns.
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { AI_QUERY_KEY, type AIStatus } from '../../lib/ai-seams';
import { Icon } from '../../components/ui';
import { AMBER, GREEN, SCard, SInput, SRow, SSelect, STag, StateNote } from './kit';

/** Display names for the provider kinds. UI copy, so it lives here, not on the wire. */
export const PROVIDER_KIND_LABELS: Record<string, string> = {
  anthropic: 'Anthropic',
  openai_compat: 'OpenAI-compatible',
};

export function providerKindLabel(kind?: string): string {
  if (!kind) return '';
  return PROVIDER_KIND_LABELS[kind] ?? kind;
}

export type ProviderAction = 'connect' | 'change' | 'use-own';

export type ProviderRowView = {
  /** The row's value. */
  primary: string;
  /** Whose provider it is, when there is one. */
  tag?: { label: string; tone: string };
  /** The sentence under the label. */
  hint: string;
  /** Live, for the icon. */
  live: boolean;
  /** What the organization can do from here, if anything. */
  action: ProviderAction | null;
  /**
   * Set when the organization has a provider SAVED that is not the one in use —
   * its plan or the deployment stopped allowing it. The credential is still
   * stored, so the page says so and offers to remove it.
   */
  saved?: string;
};

/**
 * What the provider row says, for every combination the API can return.
 *
 * ORDER MATTERS in the same way it does for the seam rows: the edition is
 * checked first, because in a build with no model clients nothing else on the
 * row is the reader's to act on.
 */
export function providerRowView(status: AIStatus): ProviderRowView {
  const kinds = status.provider_kinds ?? [];
  const source = status.provider_source ?? (status.provider_configured ? 'deployment' : 'none');
  const mayConnect = Boolean(status.tenant_provider_allowed) && kinds.length > 0;
  const own = status.tenant_provider;

  if (!status.edition_linked) {
    return {
      primary: 'Not included in this edition',
      hint: 'Connecting a model provider is part of Vista Platform Enterprise.',
      live: false,
      action: null,
    };
  }

  const blockedHint =
    status.tenant_provider_blocked_by === 'plan'
      ? 'Your plan uses the provider this deployment supplies; connecting your own is not part of it.'
      : 'Set by whoever runs this deployment. Organizations cannot connect their own here.';

  // A provider this organization saved that is not the one answering.
  const saved =
    own && source !== 'tenant'
      ? `Your organization has ${providerKindLabel(own.kind)}${own.host ? ` at ${own.host}` : ''} saved, but it is not in use: ${
          status.tenant_provider_blocked_by === 'plan'
            ? 'your plan no longer includes connecting your own provider.'
            : 'whoever runs this deployment has switched that off.'
        }`
      : undefined;

  if (source === 'tenant' && own) {
    const where = own.host ? ` · ${own.host}` : '';
    const key = own.has_key ? (own.api_key_hint ? ` Key ending ${own.api_key_hint}.` : ' A key is saved.') : ' No key.';
    return {
      primary: `${providerKindLabel(own.kind)}${where}`,
      tag: { label: 'Connected by your organization', tone: GREEN },
      hint: `Your organization’s own provider answers for you.${key}`,
      live: status.provider_configured,
      action: mayConnect ? 'change' : null,
    };
  }

  if (source === 'deployment') {
    return {
      primary: status.provider_configured ? providerKindLabel(status.provider_name) : 'Configured, but not available',
      tag: { label: 'Provided by this deployment', tone: 'var(--accent)' },
      hint: mayConnect ? 'Whoever runs this deployment set this one. You can use your own instead.' : blockedHint,
      live: status.provider_configured,
      action: mayConnect ? 'use-own' : null,
      saved,
    };
  }

  return {
    primary: mayConnect ? 'None connected' : 'None configured',
    hint: mayConnect
      ? 'Connect a provider to turn on the capabilities marked “No provider” below.'
      : blockedHint,
    live: false,
    action: mayConnect ? 'connect' : null,
    saved,
  };
}

export const ACTION_LABELS: Record<ProviderAction, string> = {
  connect: 'Connect a provider',
  change: 'Change',
  'use-own': 'Use your own provider',
};

export type ProviderForm = { kind: string; baseUrl: string; model: string; apiKey: string };

/**
 * What the form refuses before asking the server. The server validates all of
 * this again — it is the authority, and it knows things the form does not (a
 * private address, a build without the client) — so this is only what can be
 * said without a round trip.
 */
export function validateProviderForm(form: ProviderForm, hasSavedKey: boolean): string | null {
  const url = form.baseUrl.trim();
  if (form.kind === 'openai_compat') {
    if (!url) return 'Enter the endpoint’s base URL.';
    if (!form.model.trim()) return 'Enter the model id your endpoint serves.';
  }
  if (url && !/^https?:\/\/[^\s/]+/i.test(url)) return 'The base URL must start with http:// or https:// and name a host.';
  if (form.kind === 'anthropic' && !form.apiKey.trim() && !hasSavedKey) return 'Enter the API key for this provider.';
  return null;
}

/**
 * The request body for save and for test.
 *
 * `api_key` is the part that needs care. A blank field with a key already saved
 * OMITS it, which the server reads as "keep the saved key" — and it will only
 * do that for the same provider and address, so a changed address comes back
 * asking for the key. A blank field with nothing saved sends "", which is how
 * an endpoint that needs no key (a local model) says so.
 */
export function providerRequestBody(form: ProviderForm, hasSavedKey: boolean) {
  const body: { kind: 'anthropic' | 'openai_compat'; base_url: string; model: string; api_key?: string } = {
    kind: form.kind as 'anthropic' | 'openai_compat',
    base_url: form.baseUrl.trim(),
    model: form.model.trim(),
  };
  const key = form.apiKey.trim();
  if (key || !hasSavedKey) body.api_key = key;
  return body;
}

function errorMessage(error: unknown, fallback: string): string {
  const msg = (error as { error?: unknown } | undefined)?.error;
  return typeof msg === 'string' && msg ? msg : fallback;
}

type TestResult = { ok: boolean; model_id?: string; latency_ms?: number; message?: string };

export function ProviderRow({ status }: { status: AIStatus }) {
  const qc = useQueryClient();
  const view = providerRowView(status);
  const [editing, setEditing] = useState(false);
  const [confirmDisconnect, setConfirmDisconnect] = useState(false);

  const disconnect = useMutation({
    mutationFn: async () => {
      const { data, error, response } = await clients.auth.DELETE('/tenant/ai/provider', {});
      if (!response.ok || error || !data) throw new Error(errorMessage(error, 'Couldn’t disconnect — try again.'));
      return data;
    },
    onSuccess: (next) => {
      qc.setQueryData(AI_QUERY_KEY, next);
      setConfirmDisconnect(false);
      setEditing(false);
    },
  });

  const tone = view.live ? GREEN : 'var(--app-t3)';
  const hasOwn = Boolean(status.tenant_provider);

  return (
    <>
      <SRow label="Model provider" hint={view.hint}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
          <Icon name={view.live ? 'plug-zap' : 'unplug'} size={14} style={{ color: tone }} />
          <span style={{ fontSize: 12.5, color: 'var(--app-t1)' }}>{view.primary}</span>
          {view.tag && <STag color={view.tag.tone}>{view.tag.label}</STag>}
        </div>
      </SRow>

      {status.provider_problem && (
        <div style={{ padding: '4px 0 12px' }}>
          <StateNote icon="alert-triangle" tone={AMBER} title="The provider is not answering" message={status.provider_problem} />
        </div>
      )}
      {view.saved && (
        <div style={{ padding: '4px 0 12px' }}>
          <StateNote icon="info" tone={AMBER} title="A saved provider is not in use" message={view.saved} />
        </div>
      )}

      <PermissionGate permission={TENANT_PERMISSIONS.settings.update} fallback={null}>
        {!editing && (view.action !== null || hasOwn) && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '2px 0 14px', flexWrap: 'wrap' }}>
            {view.action && (
              <button className={view.action === 'connect' ? 'ui-btn accent' : 'ui-btn'} onClick={() => setEditing(true)}>
                {ACTION_LABELS[view.action]}
              </button>
            )}
            {hasOwn && !confirmDisconnect && (
              <button className="ui-btn ghost" style={{ color: 'var(--danger-text)' }} onClick={() => setConfirmDisconnect(true)}>
                Disconnect
              </button>
            )}
            {hasOwn && confirmDisconnect && (
              <>
                <span style={{ fontSize: 12, color: 'var(--app-t2)' }}>
                  Remove your organization’s provider and its saved key?
                </span>
                <button
                  className="ui-btn"
                  style={{ background: 'var(--danger)', color: '#fff', borderColor: 'var(--danger)' }}
                  disabled={disconnect.isPending}
                  onClick={() => disconnect.mutate()}
                >
                  {disconnect.isPending ? 'Disconnecting…' : 'Disconnect'}
                </button>
                <button className="ui-btn" disabled={disconnect.isPending} onClick={() => setConfirmDisconnect(false)}>Cancel</button>
              </>
            )}
            {disconnect.isError && (
              <span style={{ fontSize: 12, color: 'var(--danger-text)' }}>{disconnect.error.message}</span>
            )}
          </div>
        )}
        {editing && <ProviderFormCard status={status} onDone={() => setEditing(false)} />}
      </PermissionGate>
    </>
  );
}

function ProviderFormCard({ status, onDone }: { status: AIStatus; onDone: () => void }) {
  const qc = useQueryClient();
  const kinds = status.provider_kinds ?? [];
  const own = status.tenant_provider;
  const hasSavedKey = Boolean(own?.has_key);

  const [form, setForm] = useState<ProviderForm>({
    kind: own?.kind && kinds.includes(own.kind) ? own.kind : (kinds[0] ?? 'anthropic'),
    baseUrl: '',
    model: own?.model ?? '',
    apiKey: '',
  });
  const [localError, setLocalError] = useState<string | null>(null);
  const [test, setTest] = useState<TestResult | null>(null);

  const set = (patch: Partial<ProviderForm>) => {
    setForm((f) => ({ ...f, ...patch }));
    setLocalError(null);
    setTest(null);
  };

  const save = useMutation({
    mutationFn: async () => {
      const { data, error, response } = await clients.auth.PUT('/tenant/ai/provider', {
        body: providerRequestBody(form, hasSavedKey),
      });
      if (!response.ok || error || !data) throw new Error(errorMessage(error, 'Couldn’t save the provider — try again.'));
      return data;
    },
    onSuccess: (next) => {
      qc.setQueryData(AI_QUERY_KEY, next);
      onDone();
    },
  });

  const runTest = useMutation({
    mutationFn: async (): Promise<TestResult> => {
      const { data, error, response } = await clients.auth.POST('/tenant/ai/provider/test', {
        body: providerRequestBody(form, hasSavedKey),
      });
      if (!response.ok || error || !data) throw new Error(errorMessage(error, 'Couldn’t run the test — try again.'));
      return data;
    },
    onSuccess: (result) => setTest(result),
  });

  const guard = (run: () => void) => () => {
    const problem = validateProviderForm(form, hasSavedKey);
    if (problem) {
      setLocalError(problem);
      return;
    }
    run();
  };

  const isCompat = form.kind === 'openai_compat';
  const busy = save.isPending || runTest.isPending;
  const serverError = save.isError ? save.error.message : runTest.isError ? runTest.error.message : null;

  return (
    <div style={{ padding: '2px 0 16px' }}>
      <SCard pad={16} style={{ background: 'var(--app-panel2)' }}>
        <SRow label="Provider" hint="Which kind of endpoint to talk to.">
          <SSelect
            value={form.kind}
            onChange={(kind) => set({ kind })}
            options={kinds.map((k) => [k, providerKindLabel(k)] as [string, string])}
            width={220}
          />
        </SRow>
        <SRow
          label="Base URL"
          hint={
            isCompat
              ? 'Your endpoint’s address, as far as its own documentation writes it — for example https://llm.example.com/v1.'
              : `Leave blank to use Anthropic’s public API.${own?.host ? ` Currently ${own.host}; enter the address again to keep it.` : ''}`
          }
        >
          <SInput value={form.baseUrl} onChange={(baseUrl) => set({ baseUrl })} placeholder={isCompat ? 'https://…' : 'Optional'} mono width={320} />
        </SRow>
        <SRow label="Model" hint={isCompat ? 'The model id your endpoint serves.' : 'Leave blank for the provider’s default.'}>
          <SInput value={form.model} onChange={(model) => set({ model })} placeholder={isCompat ? 'Required' : 'Optional'} mono width={320} />
        </SRow>
        <SRow
          label="API key"
          hint={
            hasSavedKey
              ? `Leave blank to keep the saved key${own?.api_key_hint ? ` (ending ${own.api_key_hint})` : ''}. A changed provider or address needs the key again.`
              : isCompat
                ? 'Leave blank if your endpoint needs none. Stored encrypted; never shown again.'
                : 'Stored encrypted; never shown again.'
          }
          last
        >
          <SInput value={form.apiKey} onChange={(apiKey) => set({ apiKey })} placeholder={hasSavedKey ? '••••••••' : ''} type="password" width={320} />
        </SRow>
      </SCard>

      {test && (
        <div style={{ marginTop: 10 }}>
          <StateNote
            icon={test.ok ? 'circle-check' : 'alert-triangle'}
            tone={test.ok ? GREEN : AMBER}
            title={test.ok ? 'Connection works' : 'Connection failed'}
            message={
              test.ok
                ? `Answered as ${test.model_id ?? 'the configured model'}${typeof test.latency_ms === 'number' ? ` in ${test.latency_ms} ms` : ''}. Nothing from your inventory was sent.`
                : (test.message ?? 'The provider did not answer.')
            }
          />
        </div>
      )}

      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 12, flexWrap: 'wrap' }}>
        <button className="ui-btn accent" disabled={busy} onClick={guard(() => save.mutate())}>
          {save.isPending ? 'Saving…' : 'Save'}
        </button>
        <button className="ui-btn" disabled={busy} onClick={guard(() => runTest.mutate())}>
          {runTest.isPending ? 'Testing…' : 'Test connection'}
        </button>
        <button className="ui-btn ghost" disabled={busy} onClick={onDone}>Cancel</button>
        {(localError ?? serverError) && (
          <span style={{ fontSize: 12, color: 'var(--danger-text)' }}>{localError ?? serverError}</span>
        )}
      </div>
    </div>
  );
}
