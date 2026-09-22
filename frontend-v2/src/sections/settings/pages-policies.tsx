// Settings · Policies pages — Scopes (cbom-service), Compliance Frameworks
// (compliance-engine licenses + catalog), ported from the mock's
// settings/sectionF.jsx.
//
// Retention Policies used to live here too. It was removed with the C4 fix:
// audit.retention_policies is platform-GLOBAL config with no tenant_id column,
// and its routes now require a platform identity, so a tenant-facing page could
// only 403. The surface lives in admin-ui-v2 -> Security -> Retention.
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { QueryChip } from '../inventory/query-editor';
import { clients } from '../../lib/clients';
import { frameworkPercentageColor, Icon } from '../../components/ui';
import { SPage, SSection, SCard, STag, StateNote } from './kit';
import { coverageLine, formatScore, isUnscored } from '../findings/control-status';
import { ScopeEditModal, ScopeDeleteModal } from './scope-modals';
import type { SettingsNavItem } from './nav';
// cbom-service schemas are the root `components` export of the contract package.
import type { components as CbomComponents } from '@vistasecurity/api-contract';

// A scope's boundary, for the row.
//
// It USED to reassemble a sentence from eight predicate fields — "include env ∈
// {production} · type ∈ {server}" — because the stored shape was JSON and had
// no human reading. A scope is a query string now, which already reads, so the
// row shows the query itself, through the shared `QueryChip` that picks out its
// field names using the real parser's spans.

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
                  {s.description || 'No description'} · used by CBOM
                </div>
              </div>
              {/* The scope's actual boundary, with its field names picked out.
                  It is not truncated: the query IS the scope, and a boundary a
                  reader can only see half of is a boundary they cannot check. */}
              <span style={{ flex: '0 1 320px', minWidth: 0, textAlign: 'right' }}>
                <QueryChip query={s.query} />
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
    void queryClient.invalidateQueries({ queryKey: ['settings', 'frameworks-available'] });
    void queryClient.invalidateQueries({ queryKey: ['settings', 'framework-licenses'] });
  };
  const fail = (error: unknown, fallback: string) => {
    setActionError(error && typeof error === 'object' && 'error' in error ? String(error.error) : fallback);
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
            <div className="mono" style={{ fontSize: 20, fontWeight: 800, lineHeight: 1, color: frameworkPercentageColor(f.preview_score) }}>
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
