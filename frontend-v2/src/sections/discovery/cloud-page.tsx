import { useState } from 'react';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../components/ui';
import { PageWrap, queryNote, relTime } from './kit';
import { useIntegrations, useJobs } from './queries';
import {
  CloudIntegrationFormModal,
  CloudIntegrationDeleteModal,
  CloudIntegrationTestModal,
  CloudIntegrationDiscoverModal,
  type CloudIntegration,
} from './cloud-modals';

// Discovery → Cloud — the mock's `discovery-cloud` provider cards, live from
// device-interrogation-service /integrations, grouped by provider like the
// mock (accounts = integrations per provider). "Assets" sums what that
// provider's sync jobs discovered (client-side join on the jobs cache).
//
// Write surface (this page was read-only): Connect (toolbar), and per-account
// Test / Edit / Remove. All write controls are RBAC-gated on discovery.manage.

function statusTone(s: string): string {
  if (s === 'connected') return 'var(--ok)';
  if (s === 'error') return 'var(--danger)';
  return 'var(--warn-strong)'; // pending / configured / degraded
}

export function CloudPage() {
  const q = useIntegrations();
  const jobsQ = useJobs();
  const integrations = q.data ?? [];
  const jobs = jobsQ.data?.jobs ?? [];

  // Write-modal state. `create` opens the form in create mode; the others carry
  // the targeted integration.
  const [createOpen, setCreateOpen] = useState(false);
  const [editTarget, setEditTarget] = useState<CloudIntegration | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<CloudIntegration | null>(null);
  const [testTarget, setTestTarget] = useState<CloudIntegration | null>(null);
  const [discoverTarget, setDiscoverTarget] = useState<CloudIntegration | null>(null);

  const note = queryNote(q, integrations.length === 0, {
    thing: 'cloud integrations',
    emptyTitle: 'No cloud connections',
    emptyMessage: 'Connect AWS, Azure or GCP accounts to sync cloud assets into discovery.',
  });

  // Group per provider, mock-style. integration_type is the provider (aws /
  // azure / gcp …); the `provider` field is the category (cloud / saas / custom).
  const byProvider = new Map<string, typeof integrations>();
  for (const i of integrations) {
    const p = (i.integration_type || i.provider || 'other').toUpperCase();
    byProvider.set(p, [...(byProvider.get(p) ?? []), i]);
  }

  return (
    <PageWrap title="Cloud" count={q.isLoading ? '' : integrations.length}>
      <PermissionGate permission={TENANT_PERMISSIONS.discovery.manage}>
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 14, marginTop: -42 }}>
          <button className="ui-btn accent sm" onClick={() => setCreateOpen(true)}>
            <Icon name="plus" size={13} />Connect integration
          </button>
        </div>
      </PermissionGate>

      {note ?? (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 14 }}>
          {[...byProvider.entries()].map(([provider, list]) => {
            const status = list.some((i) => i.status === 'connected') ? 'connected'
              : list.some((i) => i.status === 'error') ? 'error'
              : list[0]?.status || 'pending';
            const assets = jobs
              .filter((j) => (j.cloud_provider || '').toUpperCase() === provider)
              .reduce((n, j) => n + (j.assets_discovered ?? 0), 0);
            const tested = list.map((i) => i.last_tested_at).filter(Boolean).sort();
            const lastTested = tested[tested.length - 1];
            return (
              <div key={provider} className="panel" style={{ padding: 20 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
                  <span style={{ fontSize: 16, fontWeight: 700, fontFamily: 'var(--font-head)', color: 'var(--app-t1)' }}>{provider}</span>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5, fontWeight: 600, color: statusTone(status) }}>
                    <span style={{ width: 6, height: 6, borderRadius: 50, background: statusTone(status) }} />{status}
                  </span>
                </div>
                <div style={{ display: 'flex', gap: 22 }}>
                  <div>
                    <div className="mono" style={{ fontSize: 18, fontWeight: 700, color: 'var(--app-t1)' }}>{list.length}</div>
                    <div style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>{list.length === 1 ? 'account' : 'accounts'}</div>
                  </div>
                  <div>
                    <div className="mono" style={{ fontSize: 18, fontWeight: 700, color: 'var(--app-t1)' }}>{assets}</div>
                    <div style={{ fontSize: 10.5, color: 'var(--app-t3)' }}>assets</div>
                  </div>
                  <div style={{ flex: 1 }} />
                </div>
                <div style={{ fontSize: 10.5, color: 'var(--app-t3)', marginTop: 14 }}>
                  {lastTested ? `Last tested ${relTime(lastTested)}` : 'Not tested yet'}
                </div>

                {/* Per-account rows with write actions (gated). */}
                <PermissionGate permission={TENANT_PERMISSIONS.discovery.manage}>
                  <div style={{ marginTop: 14, paddingTop: 12, borderTop: '1px solid var(--app-border2)', display: 'grid', gap: 8 }}>
                    {list.map((i) => (
                      <div key={i.id} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ flex: 1, minWidth: 0, fontSize: 12, color: 'var(--app-t2)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          <span style={{ width: 6, height: 6, borderRadius: 50, background: statusTone(i.status), display: 'inline-block', marginRight: 6 }} />
                          {i.integration_name}
                        </span>
                        <button className="ui-btn sm ghost" title="Run discovery now" onClick={() => setDiscoverTarget(i)}><Icon name="play" size={13} /></button>
                        <button className="ui-btn sm ghost" title="Test connection" onClick={() => setTestTarget(i)}><Icon name="plug" size={13} /></button>
                        <button className="ui-btn sm ghost" title="Edit integration" onClick={() => setEditTarget(i)}><Icon name="sliders-horizontal" size={13} /></button>
                        <button className="ui-btn sm ghost" style={{ color: 'var(--danger-text)' }} title="Remove integration" onClick={() => setDeleteTarget(i)}><Icon name="x" size={13} /></button>
                      </div>
                    ))}
                  </div>
                </PermissionGate>
              </div>
            );
          })}
        </div>
      )}

      <CloudIntegrationFormModal open={createOpen} onClose={() => setCreateOpen(false)} />
      <CloudIntegrationFormModal open={!!editTarget} integration={editTarget} onClose={() => setEditTarget(null)} />
      <CloudIntegrationDeleteModal open={!!deleteTarget} integration={deleteTarget} onClose={() => setDeleteTarget(null)} />
      <CloudIntegrationTestModal open={!!testTarget} integration={testTarget} onClose={() => setTestTarget(null)} />
      <CloudIntegrationDiscoverModal
        open={!!discoverTarget}
        integration={discoverTarget}
        onClose={() => setDiscoverTarget(null)}
        onStarted={() => setDiscoverTarget(null)}
      />
    </PageWrap>
  );
}
