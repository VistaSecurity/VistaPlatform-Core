// Cloud integration write surface — restores the connect/edit/delete/test/discover
// controls the rebuild dropped from Discovery → Cloud. Wired through the typed
// device-interrogation-service client: POST /integrations (create),
// PUT /integrations/{id} (edit), DELETE /integrations/{id},
// POST /integrations/{id}/test, and POST /cloud/discover. Composes the shared
// Modal primitive, mirroring inventory/asset-form-modal.tsx. Every mutation
// invalidates ['discovery','integrations'] so the page re-reads live.
import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import type { deviceInterrogationComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';

export type CloudIntegration = deviceInterrogationComponents['schemas']['CloudIntegration'];

// integration_type IS the provider (aws / azure / gcp). The `provider` field on
// the wire is the category — the old web-ui sent the literal 'cloud' there.
const PROVIDERS = ['aws', 'azure', 'gcp'] as const;
type ProviderType = (typeof PROVIDERS)[number];

const PROVIDER_LABEL: Record<ProviderType, string> = { aws: 'AWS', azure: 'Azure', gcp: 'GCP' };

// Per-provider credential fields, mirroring the old web-ui
// CreateCloudIntegrationRequest.config shape exactly (cloud-integrations-api.ts).
// `secret` marks values rendered as password inputs and never pre-filled on edit
// (the API masks them in GET responses, so an empty value means "leave unchanged").
interface CredField { key: string; label: string; placeholder?: string; secret?: boolean; textarea?: boolean }

const PROVIDER_FIELDS: Record<ProviderType, CredField[]> = {
  aws: [
    { key: 'access_key_id', label: 'Access key ID', placeholder: 'AKIA…' },
    { key: 'secret_access_key', label: 'Secret access key', secret: true },
    { key: 'session_token', label: 'Session token', secret: true },
    { key: 'assume_role_arn', label: 'Assume role ARN', placeholder: 'arn:aws:iam::123456789012:role/…' },
    { key: 'external_id', label: 'External ID' },
  ],
  azure: [
    { key: 'tenant_id', label: 'Directory (tenant) ID' },
    { key: 'client_id', label: 'Application (client) ID' },
    { key: 'client_secret', label: 'Client secret', secret: true },
    { key: 'subscription_id', label: 'Subscription ID' },
  ],
  gcp: [
    { key: 'project_id', label: 'Project ID', placeholder: 'my-gcp-project' },
    { key: 'service_account_json', label: 'Service account JSON', secret: true, textarea: true },
  ],
};

// ---- Create / edit ---------------------------------------------------------

export function CloudIntegrationFormModal({ open, integration, onClose, onSaved }: {
  open: boolean;
  /** Present → edit mode; absent/null → create mode. */
  integration?: CloudIntegration | null;
  onClose: () => void;
  onSaved?: () => void;
}) {
  const isEdit = !!integration?.id;
  const qc = useQueryClient();

  const [providerType, setProviderType] = useState<ProviderType>('aws');
  const [name, setName] = useState('');
  const [accountId, setAccountId] = useState('');
  const [region, setRegion] = useState('');
  const [environment, setEnvironment] = useState('');
  const [description, setDescription] = useState('');
  const [isEnabled, setIsEnabled] = useState(true);
  const [cred, setCred] = useState<Record<string, string>>({});

  // (Re)hydrate from the target integration whenever it changes or modal reopens.
  // Credentials are masked in GET responses, so we never pre-fill secret inputs —
  // an empty secret on save means "leave the stored value unchanged".
  useEffect(() => {
    const t = (integration?.integration_type || 'aws').toLowerCase();
    setProviderType((PROVIDERS as readonly string[]).includes(t) ? (t as ProviderType) : 'aws');
    setName(integration?.integration_name ?? '');
    setAccountId(integration?.account_id ?? '');
    setRegion(integration?.region ?? '');
    setEnvironment(integration?.environment ?? '');
    setDescription(integration?.description ?? '');
    setIsEnabled(integration?.is_enabled ?? true);
    setCred({});
  }, [integration, open]);

  const fields = PROVIDER_FIELDS[providerType];

  // On create, at least one credential value is required; on edit, an all-empty
  // config means "don't touch credentials" (we omit config entirely below).
  const credEntries = useMemo(
    () => Object.entries(cred).filter(([, v]) => v.trim()),
    [cred],
  );
  const valid = !!name.trim() && (isEdit || credEntries.length > 0);

  const save = useMutation({
    mutationFn: async (): Promise<void> => {
      const config: Record<string, unknown> = {};
      credEntries.forEach(([k, v]) => { config[k] = v.trim(); });

      if (isEdit) {
        const body: deviceInterrogationComponents['schemas']['UpdateIntegrationRequest'] = {
          integration_name: name.trim(),
          account_id: accountId.trim() || undefined,
          region: region.trim() || undefined,
          environment: environment.trim() || undefined,
          description: description.trim() || undefined,
          is_enabled: isEnabled,
          // Only send config when the user actually entered new credentials —
          // the backend merges it into the existing decrypted config.
          ...(credEntries.length ? { config } : {}),
        };
        const { error } = await clients.devices.PUT('/integrations/{id}', {
          params: { path: { id: integration!.id } }, body,
        });
        if (error) throw new Error('Failed to update integration');
        return;
      }

      const body: deviceInterrogationComponents['schemas']['CreateIntegrationRequest'] = {
        integration_type: providerType,
        integration_name: name.trim(),
        provider: 'cloud',
        config,
        account_id: accountId.trim() || undefined,
        region: region.trim() || undefined,
        environment: environment.trim() || undefined,
        description: description.trim() || undefined,
        is_enabled: isEnabled,
      };
      const { data, error } = await clients.devices.POST('/integrations', { body });
      if (error || !data) throw new Error('Failed to create integration');
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['discovery', 'integrations'] });
      onSaved?.();
      onClose();
    },
  });

  const footerErr = save.isError ? (save.error as Error).message : null;

  return (
    <Modal
      open={open}
      onClose={save.isPending ? undefined : onClose}
      dismissible={!save.isPending}
      size="lg"
      tone="accent"
      icon={isEdit ? 'cloud' : 'plus'}
      eyebrow="Discovery"
      title={isEdit ? 'Edit cloud integration' : 'Connect cloud integration'}
      description={isEdit
        ? 'Update the connection. Leave credential fields blank to keep the stored secrets unchanged.'
        : 'Connect an AWS, Azure or GCP account to sync cloud assets into discovery.'}
      primary={
        <button className="ui-btn accent" disabled={!valid || save.isPending} onClick={() => save.mutate()}>
          {save.isPending ? 'Saving…' : isEdit ? 'Save changes' : 'Connect'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose} disabled={save.isPending}>Cancel</button>}
      footerNote={footerErr ? <span style={{ color: 'var(--danger-text)' }}>{footerErr}</span> : undefined}
    >
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 14px' }}>
        <ModalField label="Provider">
          <ModalSelect
            value={providerType}
            disabled={isEdit}
            onChange={(e) => { setProviderType(e.target.value as ProviderType); setCred({}); }}
          >
            {PROVIDERS.map((p) => <option key={p} value={p}>{PROVIDER_LABEL[p]}</option>)}
          </ModalSelect>
        </ModalField>
        <ModalField label="Name"><ModalInput data-autofocus value={name} onChange={(e) => setName(e.target.value)} placeholder="Production AWS" /></ModalField>
        <ModalField label="Account ID"><ModalInput value={accountId} onChange={(e) => setAccountId(e.target.value)} placeholder="123456789012" /></ModalField>
        <ModalField label="Region"><ModalInput value={region} onChange={(e) => setRegion(e.target.value)} placeholder="us-east-1" /></ModalField>
        <ModalField label="Environment"><ModalInput value={environment} onChange={(e) => setEnvironment(e.target.value)} placeholder="production" /></ModalField>
        <ModalField label="Description"><ModalInput value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Short description" /></ModalField>
      </div>

      <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '.04em', textTransform: 'uppercase', color: 'var(--app-t3)', margin: '4px 0 12px' }}>
        {PROVIDER_LABEL[providerType]} credentials
      </div>
      {fields.map((f) => (
        <ModalField key={f.key} label={f.label} hint={isEdit && f.secret ? 'Leave blank to keep the stored secret.' : undefined}>
          {f.textarea ? (
            <textarea
              value={cred[f.key] ?? ''}
              onChange={(e) => setCred({ ...cred, [f.key]: e.target.value })}
              rows={4}
              spellCheck={false}
              placeholder={isEdit && f.secret ? '••••••••' : f.placeholder}
              className="mono"
              style={{ width: '100%', padding: '10px 12px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12, outline: 'none', resize: 'vertical' }}
            />
          ) : (
            <ModalInput
              type={f.secret ? 'password' : 'text'}
              autoComplete={f.secret ? 'new-password' : undefined}
              value={cred[f.key] ?? ''}
              onChange={(e) => setCred({ ...cred, [f.key]: e.target.value })}
              placeholder={isEdit && f.secret ? '••••••••' : f.placeholder}
            />
          )}
        </ModalField>
      ))}

      <label style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 4, cursor: 'pointer', fontSize: 12.5, color: 'var(--app-t1)' }}>
        <input type="checkbox" checked={isEnabled} onChange={(e) => setIsEnabled(e.target.checked)} />
        Enabled — include this integration in cloud discovery syncs.
      </label>
    </Modal>
  );
}

// ---- Delete (danger confirm) ----------------------------------------------

export function CloudIntegrationDeleteModal({ open, integration, onClose, onDeleted }: {
  open: boolean;
  integration: CloudIntegration | null;
  onClose: () => void;
  onDeleted?: () => void;
}) {
  const qc = useQueryClient();
  const del = useMutation({
    mutationFn: async (): Promise<void> => {
      if (!integration) return;
      const { error } = await clients.devices.DELETE('/integrations/{id}', { params: { path: { id: integration.id } } });
      if (error) throw new Error('Failed to delete integration');
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['discovery', 'integrations'] });
      onDeleted?.();
      onClose();
    },
  });

  const footerErr = del.isError ? (del.error as Error).message : null;

  return (
    <Modal
      open={open}
      onClose={del.isPending ? undefined : onClose}
      dismissible={!del.isPending}
      size="sm"
      tone="danger"
      icon="circle-alert"
      eyebrow="Discovery"
      title="Remove cloud integration"
      description={integration
        ? `Remove “${integration.integration_name}”? Existing discovered assets are kept, but no further syncs will run from this connection.`
        : undefined}
      primary={
        <button className="ui-btn" style={{ background: 'var(--danger)', borderColor: 'var(--danger)', color: '#fff' }} disabled={del.isPending} onClick={() => del.mutate()}>
          {del.isPending ? 'Removing…' : 'Remove'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose} disabled={del.isPending}>Cancel</button>}
      footerNote={footerErr ? <span style={{ color: 'var(--danger-text)' }}>{footerErr}</span> : undefined}
    />
  );
}

// ---- Discover (ad-hoc run) -------------------------------------------------

type ProviderKey = 'aws' | 'azure' | 'gcp';

const RESOURCE_TYPES: Record<ProviderKey, { value: string; label: string; description: string }[]> = {
  aws: [
    { value: 'alb',         label: 'Application Load Balancer', description: 'ALBs with TLS listeners' },
    { value: 'elb',         label: 'Classic Load Balancer',     description: 'Classic ELBs with SSL' },
    { value: 'nlb',         label: 'Network Load Balancer',     description: 'NLBs with TLS listeners' },
    { value: 'api_gateway', label: 'API Gateway',               description: 'API Gateway endpoints' },
    { value: 'cloudfront',  label: 'CloudFront',                description: 'CloudFront distributions' },
  ],
  azure: [
    { value: 'application_gateway', label: 'Application Gateway', description: 'App Gateways with SSL policies' },
    { value: 'load_balancer',       label: 'Load Balancer',       description: 'Azure Load Balancers' },
  ],
  gcp: [
    { value: 'load_balancer', label: 'HTTPS Load Balancer', description: 'GCP HTTPS load balancers' },
    { value: 'ssl_proxy',     label: 'SSL Proxy',           description: 'GCP SSL proxy load balancers' },
  ],
};

const AWS_REGIONS = [
  'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
  'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
  'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2',
  'ap-south-1', 'sa-east-1', 'ca-central-1',
];

export function CloudIntegrationDiscoverModal({ open, integration, onClose, onStarted }: {
  open: boolean;
  integration: CloudIntegration | null;
  onClose: () => void;
  onStarted?: (jobId: string) => void;
}) {
  const qc = useQueryClient();
  const provider = ((integration?.integration_type ?? 'aws').toLowerCase()) as ProviderKey;
  const resourceTypes = RESOURCE_TYPES[provider] ?? RESOURCE_TYPES.aws;
  const defaultRegion = integration?.region ?? 'us-east-1';

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [regions, setRegions] = useState<Set<string>>(new Set([defaultRegion]));

  // Reset when the target integration changes.
  useEffect(() => {
    setSelected(new Set(resourceTypes.map((r) => r.value))); // pre-select all
    setRegions(new Set([integration?.region ?? 'us-east-1']));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [integration?.id, open]);

  const toggleType = (v: string) => {
    const s = new Set(selected);
    if (s.has(v)) s.delete(v); else s.add(v);
    setSelected(s);
  };

  const toggleRegion = (v: string) => {
    const s = new Set(regions);
    if (s.has(v)) s.delete(v); else s.add(v);
    setRegions(s);
  };

  const discover = useMutation({
    mutationFn: async (): Promise<deviceInterrogationComponents['schemas']['CloudDiscoverResponse']> => {
      if (!integration) throw new Error('No integration selected');
      const body: deviceInterrogationComponents['schemas']['CloudDiscoverRequest'] = {
        integration_id: integration.id,
        cloud_provider: provider,
        resource_types: Array.from(selected),
        ...(provider === 'aws' && regions.size > 0 ? { regions: Array.from(regions) } : {}),
      };
      const { data, error } = await clients.devices.POST('/cloud/discover', { body });
      if (error || !data) throw new Error('Failed to start discovery');
      return data;
    },
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ['discovery', 'jobs'] });
      onStarted?.(result.job_id ?? '');
      onClose();
    },
  });

  const canSubmit = selected.size > 0 && !discover.isPending;
  const footerErr = discover.isError ? (discover.error as Error).message : null;

  return (
    <Modal
      open={open}
      onClose={discover.isPending ? undefined : onClose}
      dismissible={!discover.isPending}
      size="md"
      tone="accent"
      icon="search"
      eyebrow="Discovery"
      title="Discover cloud resources"
      description={integration ? `${integration.integration_name} · ${provider.toUpperCase()}` : undefined}
      primary={
        <button className="ui-btn accent" disabled={!canSubmit} onClick={() => discover.mutate()}>
          {discover.isPending ? 'Starting…' : 'Start discovery'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose} disabled={discover.isPending}>Cancel</button>}
      footerNote={footerErr ? <span style={{ color: 'var(--danger-text)' }}>{footerErr}</span> : undefined}
    >
      {/* Resource types */}
      <div style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
          <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '.04em', textTransform: 'uppercase', color: 'var(--app-t3)' }}>
            Resource types
          </div>
          <button
            className="ui-btn sm ghost"
            style={{ fontSize: 11 }}
            onClick={() => setSelected(selected.size === resourceTypes.length ? new Set() : new Set(resourceTypes.map((r) => r.value)))}
          >
            {selected.size === resourceTypes.length ? 'Deselect all' : 'Select all'}
          </button>
        </div>
        <div style={{ display: 'grid', gap: 6 }}>
          {resourceTypes.map((rt) => (
            <label key={rt.value} style={{ display: 'flex', alignItems: 'flex-start', gap: 9, cursor: 'pointer', padding: '8px 10px', borderRadius: 8, border: `1px solid ${selected.has(rt.value) ? 'var(--accent)' : 'var(--app-border2)'}`, background: selected.has(rt.value) ? 'color-mix(in srgb, var(--accent) 8%, transparent)' : 'transparent' }}>
              <input type="checkbox" checked={selected.has(rt.value)} onChange={() => toggleType(rt.value)} style={{ marginTop: 2 }} />
              <span>
                <span style={{ display: 'block', fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>{rt.label}</span>
                <span style={{ display: 'block', fontSize: 11, color: 'var(--app-t3)' }}>{rt.description}</span>
              </span>
            </label>
          ))}
        </div>
        {selected.size === 0 && (
          <div style={{ fontSize: 11, color: 'var(--danger-text)', marginTop: 6 }}>Select at least one resource type.</div>
        )}
      </div>

      {/* Region selection — AWS only */}
      {provider === 'aws' && (
        <div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
            <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '.04em', textTransform: 'uppercase', color: 'var(--app-t3)' }}>
              Regions
            </div>
            <button
              className="ui-btn sm ghost"
              style={{ fontSize: 11 }}
              onClick={() => setRegions(regions.size === AWS_REGIONS.length ? new Set([defaultRegion]) : new Set(AWS_REGIONS))}
            >
              {regions.size === AWS_REGIONS.length ? 'Reset' : 'All regions'}
            </button>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {AWS_REGIONS.map((r) => (
              <button
                key={r}
                className={`ui-btn sm${regions.has(r) ? ' accent' : ' ghost'}`}
                style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}
                onClick={() => toggleRegion(r)}
              >
                {r}
              </button>
            ))}
          </div>
        </div>
      )}
    </Modal>
  );
}

// ---- Test connection -------------------------------------------------------

export function CloudIntegrationTestModal({ open, integration, onClose }: {
  open: boolean;
  integration: CloudIntegration | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const test = useMutation({
    mutationFn: async (): Promise<deviceInterrogationComponents['schemas']['TestConnectionResult']> => {
      if (!integration) throw new Error('No integration selected');
      const { data, error } = await clients.devices.POST('/integrations/{id}/test', { params: { path: { id: integration.id } } });
      if (error || !data) throw new Error('Connection test failed to run');
      return data;
    },
    // The test records last_tested_at + status server-side; re-read the list.
    onSettled: () => qc.invalidateQueries({ queryKey: ['discovery', 'integrations'] }),
  });

  // Kick the probe automatically when the modal opens; reset on close.
  useEffect(() => {
    if (open && integration) test.mutate();
    if (!open) test.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, integration?.id]);

  const result = test.data;
  const ok = result?.success === true;
  const tone: 'green' | 'danger' | 'blue' = test.isPending ? 'blue' : ok ? 'green' : 'danger';

  return (
    <Modal
      open={open}
      onClose={onClose}
      size="sm"
      tone={tone}
      icon={test.isPending ? 'loader' : ok ? 'check' : 'alert-triangle'}
      eyebrow="Discovery"
      title="Test connection"
      description={integration ? integration.integration_name : undefined}
      primary={<button className="ui-btn accent" disabled={test.isPending} onClick={() => test.mutate()}>{test.isPending ? 'Testing…' : 'Re-test'}</button>}
      secondary={<button className="ui-btn" onClick={onClose}>Close</button>}
    >
      <div style={{ fontSize: 13, lineHeight: 1.55, color: 'var(--app-t2)' }}>
        {test.isPending && 'Probing the provider with the stored credentials…'}
        {!test.isPending && test.isError && <span style={{ color: 'var(--danger-text)' }}>{(test.error as Error).message}</span>}
        {!test.isPending && result && (
          <span style={{ color: ok ? 'var(--ok)' : 'var(--danger-text)' }}>{result.message || (ok ? 'Connection succeeded.' : 'Connection failed.')}</span>
        )}
      </div>
    </Modal>
  );
}
