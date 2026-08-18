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
interface CredField {
  key: string;
  label: string;
  placeholder?: string;
  /** Rendered as a password input. */
  secret?: boolean;
  /** Masked by the API in GET responses → never pre-filled; blank on edit means "leave unchanged". Every `secret` field is also masked. */
  masked?: boolean;
  textarea?: boolean;
  required?: boolean;
  hint?: string;
}

/** True when a field's stored value can never be shown back to the user. */
const isMasked = (f: CredField) => f.secret === true || f.masked === true;

// AWS authenticates one of two ways, and the fields for one are noise (and
// misleading) in the other. `config.auth_mode` selects; ABSENT or empty means
// access_key, which is what every integration written before assume-role
// support carries (internal/cloud/aws/client.go AuthMode*).
export const AWS_AUTH_MODES = ['access_key', 'assume_role'] as const;
export type AwsAuthMode = (typeof AWS_AUTH_MODES)[number];

const AWS_AUTH_MODE_LABEL: Record<AwsAuthMode, string> = {
  access_key: 'Access key',
  assume_role: 'Assume role (STS)',
};

// external_id is SECRET (awsclient.SensitiveConfigKeys) — possession of it is
// half of the assume-role authorization decision, so it is encrypted at rest,
// masked in GET responses and never pre-filled here. assume_role_arn is
// deliberately NOT secret and IS displayed.
const AWS_FIELDS: Record<AwsAuthMode, CredField[]> = {
  access_key: [
    { key: 'access_key_id', label: 'Access key ID', placeholder: 'AKIA…', masked: true, required: true },
    { key: 'secret_access_key', label: 'Secret access key', secret: true, required: true },
    { key: 'session_token', label: 'Session token', secret: true, hint: 'Only for temporary STS credentials. Leave blank for a long-lived IAM user key.' },
  ],
  assume_role: [
    { key: 'assume_role_arn', label: 'Role ARN', placeholder: 'arn:aws:iam::123456789012:role/VistaDiscovery', required: true },
    { key: 'external_id', label: 'External ID', secret: true, hint: 'The shared secret named in your role’s trust policy. Optional, but AWS recommends it whenever a third party assumes the role.' },
    { key: 'role_session_name', label: 'Role session name', placeholder: 'vista-discovery', hint: 'Optional — appears in your CloudTrail records for this session.' },
    { key: 'access_key_id', label: 'Access key ID (optional)', placeholder: 'AKIA…', masked: true },
    { key: 'secret_access_key', label: 'Secret access key (optional)', secret: true, hint: 'Leave both key fields blank to assume the role from the platform’s own credentials instead of chaining from a static key.' },
  ],
};

const PROVIDER_FIELDS: Record<ProviderType, CredField[]> = {
  aws: AWS_FIELDS.access_key,
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
  const [authMode, setAuthMode] = useState<AwsAuthMode>('access_key');
  // The mode the integration was stored with, so an edit that ONLY flips the
  // mode still sends a config (there are no new credential values to trigger it).
  const [storedAuthMode, setStoredAuthMode] = useState<AwsAuthMode>('access_key');

  // (Re)hydrate from the target integration whenever it changes or modal reopens.
  // Credentials are masked in GET responses, so we never pre-fill masked inputs —
  // an empty masked value on save means "leave the stored value unchanged". The
  // non-masked config values (auth_mode, assume_role_arn, role_session_name) DO
  // come back in plaintext and are pre-filled, so editing another field cannot
  // silently blank them.
  useEffect(() => {
    const t = (integration?.integration_type || 'aws').toLowerCase();
    setProviderType((PROVIDERS as readonly string[]).includes(t) ? (t as ProviderType) : 'aws');
    setName(integration?.integration_name ?? '');
    setAccountId(integration?.account_id ?? '');
    setRegion(integration?.region ?? '');
    setEnvironment(integration?.environment ?? '');
    setDescription(integration?.description ?? '');
    setIsEnabled(integration?.is_enabled ?? true);

    const cfg = (integration?.config ?? {}) as Record<string, unknown>;
    const str = (k: string): string => (typeof cfg[k] === 'string' ? cfg[k] : '');
    // Absent/empty auth_mode means access_key — every row written before
    // assume-role support carries no auth_mode at all.
    const mode: AwsAuthMode = str('auth_mode') === 'assume_role' ? 'assume_role' : 'access_key';
    setAuthMode(mode);
    setStoredAuthMode(mode);
    setCred({
      ...(str('assume_role_arn') ? { assume_role_arn: str('assume_role_arn') } : {}),
      ...(str('role_session_name') ? { role_session_name: str('role_session_name') } : {}),
    });
  }, [integration, open]);

  const isAws = providerType === 'aws';
  const fields = isAws ? AWS_FIELDS[authMode] : PROVIDER_FIELDS[providerType];

  // Only the fields currently on screen are submitted — switching auth mode
  // therefore drops the other mode's values instead of quietly sending them.
  const credEntries = useMemo(() => {
    const visible = new Set(fields.map((f) => f.key));
    return Object.entries(cred).filter(([k, v]) => visible.has(k) && v.trim());
  }, [cred, fields]);

  // A required field is only enforced when its value is actually enterable:
  // on edit a masked field left blank means "keep the stored secret".
  const missingRequired = fields.filter(
    (f) => f.required && !(cred[f.key] ?? '').trim() && !(isEdit && isMasked(f)),
  );
  const modeChanged = isAws && isEdit && authMode !== storedAuthMode;
  const valid = !!name.trim()
    && missingRequired.length === 0
    && (isEdit || isAws || credEntries.length > 0);

  const save = useMutation({
    mutationFn: async (): Promise<void> => {
      const config: Record<string, unknown> = {};
      credEntries.forEach(([k, v]) => { config[k] = v.trim(); });
      // auth_mode rides with any AWS config write so the backend never has to
      // infer which credential shape it was handed.
      if (isAws) config.auth_mode = authMode;

      if (isEdit) {
        const body: deviceInterrogationComponents['schemas']['UpdateIntegrationRequest'] = {
          integration_name: name.trim(),
          account_id: accountId.trim() || undefined,
          region: region.trim() || undefined,
          environment: environment.trim() || undefined,
          description: description.trim() || undefined,
          is_enabled: isEnabled,
          // Only send config when the user actually entered new credentials or
          // switched auth mode — the backend merges it into the existing
          // decrypted config, so an omitted config leaves the secrets alone.
          ...(credEntries.length || modeChanged ? { config } : {}),
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
            onChange={(e) => { setProviderType(e.target.value as ProviderType); setCred({}); setAuthMode('access_key'); }}
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

      {/* AWS authenticates one of two ways; showing both field sets at once made
          assume-role look configurable when only the keys were ever read. */}
      {isAws && (
        <ModalField
          label="Authentication"
          hint={authMode === 'assume_role'
            ? 'We call sts:AssumeRole on the role below. Your role’s trust policy must allow this platform’s principal, and — if you set one — must require the same external ID.'
            : 'A long-lived IAM user access key, or a temporary STS key plus its session token.'}
        >
          <ModalSelect value={authMode} onChange={(e) => setAuthMode(e.target.value as AwsAuthMode)}>
            {AWS_AUTH_MODES.map((m) => <option key={m} value={m}>{AWS_AUTH_MODE_LABEL[m]}</option>)}
          </ModalSelect>
        </ModalField>
      )}

      {fields.map((f) => (
        <ModalField
          key={f.key}
          label={f.label}
          hint={[f.hint, isEdit && isMasked(f) ? 'Leave blank to keep the stored value.' : null].filter(Boolean).join(' ') || undefined}
        >
          {f.textarea ? (
            <textarea
              value={cred[f.key] ?? ''}
              onChange={(e) => setCred({ ...cred, [f.key]: e.target.value })}
              rows={4}
              spellCheck={false}
              placeholder={isEdit && isMasked(f) ? '••••••••' : f.placeholder}
              className="mono"
              style={{ width: '100%', padding: '10px 12px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 12, outline: 'none', resize: 'vertical' }}
            />
          ) : (
            <ModalInput
              type={f.secret ? 'password' : 'text'}
              autoComplete={f.secret ? 'new-password' : undefined}
              value={cred[f.key] ?? ''}
              onChange={(e) => setCred({ ...cred, [f.key]: e.target.value })}
              placeholder={isEdit && isMasked(f) ? '••••••••' : f.placeholder}
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

// `global: true` marks a resource type the AWS API lists account-wide rather
// than per region — S3 (ListBuckets) and CloudFront (ListDistributions). The
// backend calls those without the regions argument at all
// (cloud_discovery_service.go DiscoverAWSResources), so offering a region
// filter next to them would promise filtering that cannot happen.
export interface ResourceTypeOption {
  value: string;
  label: string;
  description: string;
  global?: boolean;
}

export const RESOURCE_TYPES: Record<ProviderKey, ResourceTypeOption[]> = {
  aws: [
    { value: 'alb',         label: 'Application Load Balancer', description: 'ALBs with TLS listeners — negotiated protocol, cipher suite and the served certificate chain.' },
    { value: 'elb',         label: 'Classic Load Balancer',     description: 'Classic ELBs with SSL listeners.' },
    { value: 'nlb',         label: 'Network Load Balancer',     description: 'NLBs with TLS listeners.' },
    { value: 'api_gateway', label: 'API Gateway',               description: 'API Gateway endpoints and their TLS configuration.' },
    { value: 'cloudfront',  label: 'CloudFront',                description: 'CloudFront distributions and their viewer TLS configuration.', global: true },
    { value: 'kms',         label: 'KMS keys',                  description: 'Customer-managed KMS keys — key spec, state, usage, rotation status and period, aliases and multi-Region. AWS-managed keys (aws/s3, aws/ebs …) are skipped.' },
    { value: 's3',          label: 'S3 bucket encryption',      description: 'Default at-rest encryption on every bucket — SSE-S3, SSE-KMS or DSSE-KMS, the KMS key in use, and whether S3 Bucket Keys are on.', global: true },
    { value: 'rds',         label: 'RDS instance encryption',   description: 'Storage encryption on each RDS instance — whether it is on, the KMS key, engine and version, Multi-AZ, and the Performance Insights key.' },
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

// The AWS commercial partition (aws). Enumerating regions from the account
// (ec2:DescribeRegions / the account API) is deliberately deferred — that would
// need an extra IAM grant and a round trip before the modal can render.
// NOTE: GovCloud (aws-us-gov) and China (aws-cn) are separate partitions with
// separate credentials and endpoints; they are not selectable here.
export const AWS_REGIONS = [
  // North America
  'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
  'ca-central-1', 'ca-west-1', 'mx-central-1',
  // South America
  'sa-east-1',
  // Europe
  'eu-west-1', 'eu-west-2', 'eu-west-3',
  'eu-central-1', 'eu-central-2',
  'eu-north-1', 'eu-south-1', 'eu-south-2',
  // Middle East / Africa
  'il-central-1', 'me-central-1', 'me-south-1', 'af-south-1',
  // Asia Pacific
  'ap-east-1', 'ap-south-1', 'ap-south-2',
  'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
  'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3',
  'ap-southeast-4', 'ap-southeast-5', 'ap-southeast-7',
];

/**
 * True when the selected resource types actually make a region list meaningful.
 * S3 and CloudFront are listed account-wide, so a run of only those types needs
 * no `regions` at all — sending one would imply a filter the API never applies.
 */
export function selectionNeedsRegions(provider: ProviderKey, selected: Iterable<string>): boolean {
  if (provider !== 'aws') return false;
  const sel = new Set(selected);
  return RESOURCE_TYPES.aws.some((rt) => sel.has(rt.value) && !rt.global);
}

/** True when the selection includes at least one account-wide (global) type. */
export function selectionHasGlobal(provider: ProviderKey, selected: Iterable<string>): boolean {
  const sel = new Set(selected);
  return (RESOURCE_TYPES[provider] ?? []).some((rt) => sel.has(rt.value) && rt.global);
}

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

  const needsRegions = selectionNeedsRegions(provider, selected);
  const hasGlobal = selectionHasGlobal(provider, selected);

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
        // Only send regions when a regional type is in play. For a global-only
        // run the field is meaningless, and omitting it keeps the request
        // honest rather than recording a filter that was never applied.
        ...(needsRegions && regions.size > 0 ? { regions: Array.from(regions) } : {}),
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

  const canSubmit = selected.size > 0 && (!needsRegions || regions.size > 0) && !discover.isPending;
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
                <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>
                  {rt.label}
                  {rt.global && (
                    <span
                      title="Listed account-wide — region selection does not apply to this type"
                      style={{ fontSize: 9.5, fontWeight: 700, letterSpacing: 0.3, textTransform: 'uppercase', padding: '1px 6px', borderRadius: 20, border: '1px solid var(--app-border)', color: 'var(--app-t3)', flex: 'none' }}
                    >
                      Global
                    </span>
                  )}
                </span>
                <span style={{ display: 'block', fontSize: 11, color: 'var(--app-t3)' }}>{rt.description}</span>
              </span>
            </label>
          ))}
        </div>
        {selected.size === 0 && (
          <div style={{ fontSize: 11, color: 'var(--danger-text)', marginTop: 6 }}>Select at least one resource type.</div>
        )}
      </div>

      {/* Region selection — AWS only, and only meaningful for the regional types.
          When every selected type is account-wide the picker is disabled rather
          than hidden, so the reason is visible instead of the control vanishing. */}
      {provider === 'aws' && (
        <div style={{ opacity: needsRegions ? 1 : 0.55 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
            <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '.04em', textTransform: 'uppercase', color: 'var(--app-t3)' }}>
              Regions
            </div>
            <button
              className="ui-btn sm ghost"
              style={{ fontSize: 11 }}
              disabled={!needsRegions}
              onClick={() => setRegions(regions.size === AWS_REGIONS.length ? new Set([defaultRegion]) : new Set(AWS_REGIONS))}
            >
              {regions.size === AWS_REGIONS.length ? 'Reset' : 'All regions'}
            </button>
          </div>
          <div style={{ fontSize: 11, color: 'var(--app-t3)', marginBottom: 8 }}>
            {!needsRegions
              ? 'The selected resource types are listed account-wide, so no region selection is needed.'
              : hasGlobal
                ? 'S3 and CloudFront are listed account-wide; these regions apply to the other selected types.'
                : 'Each selected region is scanned separately — every region you add costs another pass.'}
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {AWS_REGIONS.map((r) => (
              <button
                key={r}
                className={`ui-btn sm${regions.has(r) ? ' accent' : ' ghost'}`}
                style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}
                disabled={!needsRegions}
                onClick={() => toggleRegion(r)}
              >
                {r}
              </button>
            ))}
          </div>
          {needsRegions && regions.size === 0 && (
            <div style={{ fontSize: 11, color: 'var(--danger-text)', marginTop: 6 }}>Select at least one region.</div>
          )}
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
