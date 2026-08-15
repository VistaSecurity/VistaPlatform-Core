// Settings · Policies pages — Scopes (cbom-service), Compliance Frameworks
// (compliance-engine licenses + catalog), and Retention Policies (audit-service)
// ported from the mock's settings/sectionF.jsx. Predicate summaries are
// rendered from the typed Scope.predicate shape.
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { Icon } from '../../components/ui';
import { SPage, SSection, SCard, STable, STableRow, STag, SDot, SToggle, StateNote, GREEN, AMBER } from './kit';
import { coverageLine, formatScore, isUnscored } from '../findings/control-status';
import { ScopeEditModal, ScopeDeleteModal } from './scope-modals';
import { RetentionPolicyModal } from './policies-modals';
import type { SettingsNavItem } from './nav';
// cbom-service schemas are the root `components` export of the contract package.
import type { components as CbomComponents } from '@vistasecurity/api-contract';

type Predicate = CbomComponents['schemas']['Predicate'];
type PredicateClause = CbomComponents['schemas']['PredicateClause'];

function clausePhrase(c?: PredicateClause): string {
  if (!c) return '';
  const parts: string[] = [];
  const f = c as Record<string, unknown>;
  for (const [key, label] of [
    ['environment', 'env'], ['asset_type', 'type'], ['asset_ownership', 'ownership'],
    ['asset_status', 'status'], ['business_unit', 'BU'], ['location_region', 'region'],
    ['risk_level', 'risk'], ['tags_any_of', 'tags'],
  ] as const) {
    const v = f[key];
    if (Array.isArray(v) && v.length) parts.push(`${label} ∈ {${v.join(', ')}}`);
  }
  return parts.join(' · ');
}

function predicateSummary(p?: Predicate): string {
  if (!p || (!p.include && !p.exclude)) return 'All assets';
  const inc = clausePhrase(p.include);
  const exc = clausePhrase(p.exclude);
  return [inc && `include ${inc}`, exc && `exclude ${exc}`].filter(Boolean).join(' — ') || 'All assets';
}

type ScopeModalState =
  | { kind: 'closed' }
  | { kind: 'create' }
  | { kind: 'edit'; scope: NonNullable<CbomComponents['schemas']['Scope']> }
  | { kind: 'delete'; scope: NonNullable<CbomComponents['schemas']['Scope']> };

// Scope writes are gated on compliance.update, NOT settings.update: cbom-service
// mounts the scope handler behind RequireTenantPermission(compliance.update)
// (services/cbom-service/cmd/main.go). Gating on settings.update both invited a
// 403 (a role with settings.update but no compliance.update) and hid the
// controls from security_admin, which holds every compliance.* permission but no
// settings.update. Reads (GET /scopes, including the lazy default seed) are
// ungated, so the list still renders for anyone who can reach the page.
export function ScopesPage({ meta }: { meta: SettingsNavItem }) {
  const [modal, setModal] = useState<ScopeModalState>({ kind: 'closed' });
  const { data, isLoading, isError } = useQuery({
    queryKey: ['settings', 'scopes'],
    queryFn: async () => {
      const { data, error } = await clients.cbom.GET('/scopes', {});
      if (error || !data) throw new Error('Failed to load scopes');
      return data.scopes;
    },
  });
  const scopes = data ?? [];
  const close = () => setModal({ kind: 'closed' });

  return (
    <SPage
      eyebrow="Policies" title="Scopes" job={meta.job}
      actions={
        <PermissionGate permission={TENANT_PERMISSIONS.compliance.update}>
          <button className="ui-btn sm accent" onClick={() => setModal({ kind: 'create' })}><Icon name="plus" size={14} />New scope</button>
        </PermissionGate>
      }
    >
      {isError ? (
        <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load scopes" message="The scope list failed to load." /></SCard>
      ) : isLoading ? (
        <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading scopes…" message="Fetching the tenant's CBOM scopes." /></SCard>
      ) : scopes.length === 0 ? (
        <SCard><StateNote icon="crop" tone="var(--app-t3)" title="No scopes" message="No scopes are defined for this tenant yet." /></SCard>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 11 }}>
          {scopes.map((s) => (
            <SCard key={s.id} pad={17} style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
              <span style={{ width: 36, height: 36, borderRadius: 9, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--app-panel2)', border: '1px solid var(--app-border)', color: 'var(--accent)' }}>
                <Icon name="crop" size={16} />
              </span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--app-t1)' }}>{s.name}</span>
                  <STag>v{s.version}</STag>
                  {s.is_system && <STag color="var(--accent)">System</STag>}
                </div>
                <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 2, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {s.description || predicateSummary(s.predicate)} · used by CBOM
                </div>
              </div>
              <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)', flex: 'none' }} title={predicateSummary(s.predicate)}>
                {predicateSummary(s.predicate).length > 42 ? `${predicateSummary(s.predicate).slice(0, 42)}…` : predicateSummary(s.predicate)}
              </span>
              <PermissionGate permission={TENANT_PERMISSIONS.compliance.update}>
                <div style={{ display: 'flex', gap: 8, flex: 'none' }}>
                  <button className="ui-btn sm" onClick={() => setModal({ kind: 'edit', scope: s })}>Edit</button>
                  {!s.is_system && (
                    <button className="ui-btn sm ghost" style={{ color: 'var(--danger-text)' }} title="Delete scope" onClick={() => setModal({ kind: 'delete', scope: s })}>
                      <Icon name="x" size={14} />
                    </button>
                  )}
                </div>
              </PermissionGate>
            </SCard>
          ))}
        </div>
      )}
      <p style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 16 }}>
        Scopes are versioned — CBOM artifacts capture the scope id + version at generation time so every snapshot is reproducible. System scopes are editable but not deletable.
      </p>

      {(modal.kind === 'create' || modal.kind === 'edit') && (
        <ScopeEditModal
          key={modal.kind === 'edit' ? modal.scope.id : 'new'}
          scope={modal.kind === 'edit' ? modal.scope : null}
          open
          onClose={close}
        />
      )}
      {modal.kind === 'delete' && <ScopeDeleteModal scope={modal.scope} open onClose={close} />}
    </SPage>
  );
}

// Preview-score colour ramp — mirrors the posture FwRing thresholds. An
// unscored framework is muted, not coloured.
function fwScoreColor(pct: number | null | undefined): string {
  if (isUnscored(pct)) return 'var(--app-t3)';
  return pct! >= 85 ? 'var(--ok)' : pct! >= 70 ? 'var(--warn)' : pct! >= 50 ? 'var(--warn-strong)' : 'var(--danger)';
}

export function FrameworksPage({ meta }: { meta: SettingsNavItem }) {
  const queryClient = useQueryClient();
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionNote, setActionNote] = useState<string | null>(null);
  const { data, isLoading, isError } = useQuery({
    queryKey: ['settings', 'frameworks-available'],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/frameworks/available', {});
      if (error || !data) throw new Error('Failed to load frameworks');
      return data.frameworks;
    },
  });
  const frameworks = data ?? [];
  const licensed = frameworks.filter((f) => f.is_licensed);
  const available = frameworks.filter((f) => !f.is_licensed);

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ['settings', 'frameworks-available'] });
    queryClient.invalidateQueries({ queryKey: ['settings', 'framework-licenses'] });
  };
  const fail = (error: unknown, fallback: string) => {
    setActionError(error && typeof error === 'object' && 'error' in error ? String((error as { error: unknown }).error) : fallback);
  };

  const clear = () => { setActionError(null); setActionNote(null); };
  // Endpoints keep the legacy "subscribe" name (ADR-0014: schema unchanged); only the
  // user-facing vocabulary becomes "activate".
  const subscribe = useMutation({
    mutationFn: async (frameworkId: string) => {
      clear();
      const { error, response } = await clients.compliance.POST('/frameworks/subscribe', { body: { framework_id: frameworkId } });
      if (error || !response.ok) throw { error, fallback: 'Failed to activate' };
    },
    onSuccess: () => {
      refresh();
      setActionNote('Activated — evaluating it against your current inventory. Posture appears in Risk & Compliance shortly.');
    },
    onError: (e: { error?: unknown; fallback?: string }) => fail(e.error, e.fallback ?? 'Failed to activate'),
  });
  const unsubscribe = useMutation({
    mutationFn: async (frameworkId: string) => {
      clear();
      const { error, response } = await clients.compliance.DELETE('/frameworks/subscribe/{frameworkId}', { params: { path: { frameworkId } } });
      if (error || !response.ok) throw { error, fallback: 'Failed to deactivate' };
    },
    onSuccess: refresh,
    onError: (e: { error?: unknown; fallback?: string }) => fail(e.error, e.fallback ?? 'Failed to deactivate'),
  });
  const setDefault = useMutation({
    mutationFn: async (frameworkId: string) => {
      clear();
      const { error, response } = await clients.compliance.PUT('/frameworks/default', { body: { framework_id: frameworkId } });
      if (error || !response.ok) throw { error, fallback: 'Failed to set the default framework' };
    },
    onSuccess: refresh,
    onError: (e: { error?: unknown; fallback?: string }) => fail(e.error, e.fallback ?? 'Failed to set the default framework'),
  });
  const busy = subscribe.isPending || unsubscribe.isPending || setDefault.isPending;

  const card = (f: (typeof frameworks)[number]) => {
    const fw = f.platform_framework;
    const isActive = f.is_licensed;
    const previewUnscored = isUnscored(f.preview_score);
    const coverage = coverageLine({
      total: fw.controls_count,
      passing: f.controls_passing,
      failing: f.controls_failing,
      notAssessed: f.controls_not_assessed,
    });

    return (
      <SCard key={fw.id} pad={18} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {/* Top row: icon · name · score */}
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
          <span style={{ width: 38, height: 38, borderRadius: 10, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: isActive ? 'var(--accent-gradient)' : 'var(--app-panel2)', border: isActive ? 'none' : '1px solid var(--app-border)', color: isActive ? 'var(--accent-fg)' : 'var(--app-t3)' }}>
            <Icon name="shield-check" size={18} />
          </span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--app-t1)' }}>{fw.name}</span>
              {isActive && <STag color="var(--app-ok)">Active</STag>}
              {f.is_platform_default && <STag color="var(--accent)">Default</STag>}
            </div>
            <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 2 }}>
              {fw.controls_count} controls · v{fw.version}
            </div>
          </div>
          {/* The preview follows exactly the same rules as an activated
              framework's score (D4): a framework nothing could be evaluated
              against shows "—", so a preview can never flatter itself with a
              100% that nothing earned. The old `typeof === 'number'` guard hid
              the whole block on null, which read as "no opinion" rather than
              "we could not assess this". */}
          <div style={{ textAlign: 'center', flex: 'none' }} title={previewUnscored
            ? 'No control could be assessed against your current inventory, so there is no score to preview.'
            : `Compliance score against your current inventory${isActive ? '' : ' — preview before activating'}`}>
            <div className="mono" style={{ fontSize: 20, fontWeight: 800, lineHeight: 1, color: fwScoreColor(f.preview_score) }}>
              {formatScore(f.preview_score)}{!previewUnscored && '%'}
            </div>
            <div style={{ fontSize: 9, color: 'var(--app-t3)', marginTop: 2, textTransform: 'uppercase', letterSpacing: 0.4 }}>{isActive ? 'posture' : 'preview'}</div>
          </div>
        </div>

        {coverage && (
          <div style={{ fontSize: 11, color: 'var(--app-t3)', display: 'flex', alignItems: 'center', gap: 5 }}
            title="Controls that could not be evaluated — no measurement rule configured, nothing in scope, or the check failed — are excluded from the score entirely.">
            <Icon name="info" size={12} />
            {coverage}
          </div>
        )}

        {/* Bottom row: action buttons */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 8, paddingTop: 2, borderTop: '1px solid var(--app-border)' }}>
          {isActive ? (
            <>
              <Link to="/risk-compliance/posture" className="ui-btn sm" style={{ textDecoration: 'none' }}>
                <Icon name="bar-chart-2" size={13} />View posture
              </Link>
              {/* compliance.update, not .manage: compliance-engine gates
                  POST /frameworks/subscribe, DELETE /frameworks/subscribe/:id
                  and PUT /frameworks/default on ComplianceUpdate. */}
              <PermissionGate permission={TENANT_PERMISSIONS.compliance.update}>
                {!f.is_platform_default && (
                  <button className="ui-btn sm" disabled={busy} onClick={() => setDefault.mutate(fw.id)}>
                    Set default
                  </button>
                )}
                {!f.is_platform_default && (
                  <button
                    className="ui-btn sm ghost"
                    disabled={busy}
                    style={{ color: 'var(--danger-text)', borderColor: 'color-mix(in srgb, var(--danger-text) 27%, transparent)' }}
                    onClick={() => unsubscribe.mutate(fw.id)}
                  >
                    <Icon name="power" size={13} />Deactivate
                  </button>
                )}
                {f.is_platform_default && (
                  <span style={{ fontSize: 11, color: 'var(--app-t3)', fontStyle: 'italic' }}>Cannot deactivate default</span>
                )}
              </PermissionGate>
            </>
          ) : (
            <PermissionGate permission={TENANT_PERMISSIONS.compliance.update}>
              <button className="ui-btn sm accent" disabled={busy} onClick={() => subscribe.mutate(fw.id)}>
                {subscribe.isPending ? 'Activating…' : 'Activate'}
              </button>
            </PermissionGate>
          )}
        </div>
      </SCard>
    );
  };

  return (
    <SPage eyebrow="Policies" title="Compliance Frameworks" job={meta.job} maxWidth={1000}>
      {isError ? (
        <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load frameworks" message="The framework catalog failed to load." /></SCard>
      ) : isLoading ? (
        <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading frameworks…" message="Fetching your active frameworks and the published catalog." /></SCard>
      ) : (
        <>
          <SSection title="Activated">
            {licensed.length === 0 ? (
              <SCard><StateNote icon="scroll-text" tone="var(--app-t3)" title="Nothing activated yet" message="Activate a framework below to start evaluating your inventory against it." /></SCard>
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(300px,1fr))', gap: 14 }}>{licensed.map(card)}</div>
            )}
          </SSection>
          {available.length > 0 && (
            <SSection title="Available frameworks">
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(300px,1fr))', gap: 14 }}>{available.map(card)}</div>
            </SSection>
          )}
        </>
      )}
      {actionError && (
        <p style={{ fontSize: 12, color: 'var(--danger-text)', marginTop: 12 }}>
          <Icon name="alert-triangle" size={13} style={{ verticalAlign: '-2px', marginRight: 5 }} />{actionError}
        </p>
      )}
      {actionNote && !actionError && (
        <p style={{ fontSize: 12, color: 'var(--accent)', marginTop: 12 }}>
          <Icon name="check" size={13} style={{ verticalAlign: '-2px', marginRight: 5 }} />{actionNote}
        </p>
      )}
      <p style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 12 }}>
        Preview scores show how each framework rates your current inventory before you commit. Once activated, live results appear in Risk &amp; Compliance → Posture.
        Best Practices is free and permanent for every tenant. Enterprise tenants can build their own at <Link to="/settings/policies/custom-policies" style={{ color: 'var(--app-t2)' }}>Custom Policies</Link>.
      </p>
    </SPage>
  );
}

function days(n?: number | null): string {
  if (n == null) return '—';
  if (n % 365 === 0 && n >= 365) return `${n / 365} year${n >= 730 ? 's' : ''}`;
  return `${n} days`;
}

type RetentionPolicyRow = import('@vistasecurity/api-contract').auditServiceComponents['schemas']['RetentionPolicy'];

function RetentionActiveToggle({ policy }: { policy: RetentionPolicyRow }) {
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: async (on: boolean) => {
      const { error, response } = await clients.audit.PUT('/retention-policies/{id}', {
        params: { path: { id: policy.id } },
        body: {
          policy_name: policy.policy_name, event_type: policy.event_type ?? null,
          compliance_framework: policy.compliance_framework ?? null,
          hot_storage_days: policy.hot_storage_days, cold_storage_days: policy.cold_storage_days ?? null,
          total_retention_days: policy.total_retention_days, is_active: on,
        },
      });
      if (error || !response.ok) throw new Error('Failed to update the policy');
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['settings', 'retention-policies'] }),
  });
  return <SToggle key={`${policy.id}-${policy.is_active}`} on={policy.is_active} onChange={(v) => mutation.mutate(v)} />;
}

type RetentionModalState = { kind: 'closed' } | { kind: 'create' } | { kind: 'edit'; policy: RetentionPolicyRow };

export function RetentionPage({ meta }: { meta: SettingsNavItem }) {
  const [modal, setModal] = useState<RetentionModalState>({ kind: 'closed' });
  const { data, isLoading, isError } = useQuery({
    queryKey: ['settings', 'retention-policies'],
    queryFn: async () => {
      const { data, error } = await clients.audit.GET('/retention-policies', {});
      if (error || !data) throw new Error('Failed to load retention policies');
      return data.policies ?? [];
    },
  });
  const policies = data ?? [];
  const close = () => setModal({ kind: 'closed' });
  const cols = [
    { label: 'Policy', w: '1.4fr' }, { label: 'Hot storage', w: '120px' }, { label: 'Total retention', w: '140px' },
    { label: 'Active', w: '70px', align: 'right' as const }, { label: '', w: '50px', align: 'right' as const },
  ];

  // Every write gate below is audit.manage, not settings.update: audit-service
  // gates POST/PUT /retention-policies on audit.manage. The list GET is
  // ungated, so the page still loads read-only for anyone who can reach it —
  // only the write affordances follow the route's real requirement.
  return (
    <SPage
      eyebrow="Policies" title="Retention Policies" job={meta.job}
      actions={
        <PermissionGate permission={TENANT_PERMISSIONS.audit.manage}>
          <button className="ui-btn sm accent" onClick={() => setModal({ kind: 'create' })}><Icon name="plus" size={14} />Add policy</button>
        </PermissionGate>
      }
    >
      {isError ? (
        <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load retention policies" message="The retention policy list failed to load." /></SCard>
      ) : isLoading ? (
        <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading retention policies…" message="Fetching data-retention schedules." /></SCard>
      ) : policies.length === 0 ? (
        <SCard><StateNote icon="archive" tone="var(--app-t3)" title="No retention policies" message="No data-retention schedules are defined yet — defaults apply until one is added." /></SCard>
      ) : (
        <STable cols={cols}>
          {policies.map((p, i) => (
            <STableRow
              key={p.id}
              first={i === 0}
              cols={cols}
              cells={[
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--app-t1)' }}>{p.policy_name}</div>
                  <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>
                    {[p.event_type, p.compliance_framework].filter(Boolean).join(' · ') || 'all events'}
                  </div>
                </div>,
                <span style={{ fontSize: 12.5, color: 'var(--app-t2)' }}>{days(p.hot_storage_days)}</span>,
                <span style={{ fontSize: 12.5, color: 'var(--app-t2)' }}>{days(p.total_retention_days)}</span>,
                <PermissionGate permission={TENANT_PERMISSIONS.audit.manage} fallback={<span style={{ display: 'inline-flex', justifyContent: 'flex-end' }}><SDot color={p.is_active ? GREEN : AMBER} /></span>}>
                  <span style={{ display: 'inline-flex', justifyContent: 'flex-end' }}><RetentionActiveToggle policy={p} /></span>
                </PermissionGate>,
                <PermissionGate permission={TENANT_PERMISSIONS.audit.manage}>
                  <button className="ui-btn sm ghost" title="Edit policy" onClick={() => setModal({ kind: 'edit', policy: p })}><Icon name="settings" size={14} /></button>
                </PermissionGate>,
              ]}
            />
          ))}
        </STable>
      )}
      <p style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 13 }}>
        Pairs with the Audit log. Policies are deactivated rather than deleted; long-retention data is archived per the storage connection configured in Integrations.
      </p>

      {(modal.kind === 'create' || modal.kind === 'edit') && (
        <RetentionPolicyModal key={modal.kind === 'edit' ? modal.policy.id : 'new'} policy={modal.kind === 'edit' ? modal.policy : null} open onClose={close} />
      )}
    </SPage>
  );
}
