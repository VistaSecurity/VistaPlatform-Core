import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import type { complianceEngineComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { Icon, MiniBar, Pill } from '../../components/ui';
import { CreatePlanModal, PlanDetailDrawer } from './plan-detail';

type RemediationPlan = complianceEngineComponents['schemas']['RemediationPlan'];

// Remediation → Plans. Initiatives view wired to live compliance-engine
// (GET /plans). Plans is a fully-built backend capability (grouped findings +
// progress); this surfaces it on the new UI.

const TYPE_ICON: Record<string, string> = {
  pqc_migration: 'layers', framework: 'shield-check', remediation: 'wrench', custom: 'file-text',
};
const STATUS_COLOR: Record<string, string> = {
  active: 'var(--ok)', draft: 'var(--neutral)', completed: 'var(--info)', cancelled: 'var(--danger)',
};
const PRIORITY_COLOR: Record<string, string> = {
  critical: 'var(--danger)', high: 'var(--warn-strong)', medium: 'var(--warn)', low: 'var(--ok)',
};

function dueLabel(iso?: string | null): string | null {
  if (!iso) return null;
  const days = Math.round((new Date(iso).getTime() - Date.now()) / 86400000);
  if (days < 0) return `${-days}d overdue`;
  if (days === 0) return 'due today';
  return `due in ${days}d`;
}

export function PlansPage() {
  const [createOpen, setCreateOpen] = useState(false);
  const [selected, setSelected] = useState<RemediationPlan | null>(null);
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['remediation', 'plans'],
    queryFn: async () => {
      const { data, error } = await clients.compliance.GET('/plans', {});
      if (error || !data) throw new Error('Failed to load plans');
      return data;
    },
  });
  const plans = data?.plans ?? [];

  return (
    <div style={{ padding: '20px 26px 40px', height: '100%', overflow: 'auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
        <h2 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 16, color: 'var(--app-t1)' }}>Plans</h2>
        <span className="mono" style={{ fontSize: 12, color: 'var(--app-t3)' }}>{isLoading ? '' : plans.length}</span>
        <div style={{ flex: 1 }} />
        <PermissionGate permission={TENANT_PERMISSIONS.compliance.update}>
          <button className="ui-btn sm accent" onClick={() => setCreateOpen(true)}><Icon name="plus" size={14} />New plan</button>
        </PermissionGate>
      </div>

      {isError ? (
        <Note icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load plans" message={error instanceof Error ? error.message : 'Request failed'} />
      ) : isLoading ? (
        <Note icon="loader" tone="var(--app-t3)" title="Loading plans…" message="Fetching remediation initiatives." />
      ) : plans.length === 0 ? (
        <Note icon="layers" tone="var(--app-t3)" title="No plans yet" message="Group related findings into a remediation plan to track progress as one initiative." />
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: 16 }}>
          {plans.map((p) => {
            const progress = typeof p.progress === 'number' ? p.progress : 0;
            const resolved = p.resolved_count ?? 0;
            const total = p.item_count ?? 0;
            const due = dueLabel(p.target_date);
            return (
              <div key={p.id} className="panel row-hover" onClick={() => setSelected(p)} style={{ padding: 20, cursor: 'pointer' }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 13 }}>
                  <span style={{ width: 40, height: 40, borderRadius: 11, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--app-panel2)', border: '1px solid var(--app-border)', color: 'var(--accent)' }}>
                    <Icon name={TYPE_ICON[p.plan_type ?? ''] || 'wrench'} size={20} />
                  </span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 15, fontWeight: 700, fontFamily: 'var(--font-head)', color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{p.title || 'Untitled plan'}</div>
                    <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 2 }}>{total} item{total !== 1 ? 's' : ''}{due ? ' · ' + due : ''}</div>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <div className="mono accent-text" style={{ fontSize: 22, fontWeight: 800, lineHeight: 1 }}>{progress}%</div>
                    <div style={{ fontSize: 10, color: 'var(--app-t3)' }}>{resolved}/{total}</div>
                  </div>
                </div>
                <div style={{ margin: '15px 0 12px' }}><MiniBar pct={progress} color="var(--accent)" h={7} /></div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  {p.status && <Pill color={STATUS_COLOR[p.status] || 'var(--app-t2)'} style={{ fontSize: 11 }}>{p.status}</Pill>}
                  {p.priority && <Pill color={PRIORITY_COLOR[p.priority] || 'var(--app-t2)'} tone="outline" style={{ fontSize: 11 }}>{p.priority}</Pill>}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {createOpen && <CreatePlanModal open={createOpen} onClose={() => setCreateOpen(false)} />}
      {selected && <PlanDetailDrawer plan={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

function Note({ icon, tone, title, message }: { icon: string; tone: string; title: string; message: string }) {
  return (
    <div className="panel" style={{ padding: '56px 24px', textAlign: 'center', color: 'var(--app-t3)' }}>
      <Icon name={icon} size={26} style={{ color: tone, opacity: 0.8 }} />
      <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--app-t1)', marginTop: 12 }}>{title}</div>
      <div style={{ fontSize: 12.5, marginTop: 4 }}>{message}</div>
    </div>
  );
}
