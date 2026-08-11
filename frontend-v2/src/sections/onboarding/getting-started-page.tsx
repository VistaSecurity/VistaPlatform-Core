// Getting Started — the tenant onboarding checklist (Slice 1). Reached from the
// profile dropdown. Renders the seeded default workflow's steps with per-user
// status and deep-links each to the page that owns the action. Login nudge,
// per-user dismiss, and org-level disable are Slice 2.
// Spec: docsv4/internal/developer/standards/features/onboarding-wizard.md
import { useNavigate } from 'react-router';
import toast from 'react-hot-toast';
import { usePermissions, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../components/ui';
import { useOnboardingWorkflow, useCompleteStep, useOnboardingStatus, useDismissOnboarding, useSetOnboardingEnabled } from './queries';
import { stepMeta } from './step-meta';

export function GettingStartedPage() {
  const navigate = useNavigate();
  const { hasPermission, isLoading: permLoading } = usePermissions();
  const wf = useOnboardingWorkflow();
  const complete = useCompleteStep();
  const status = useOnboardingStatus();
  const dismiss = useDismissOnboarding();
  const setEnabled = useSetOnboardingEnabled();

  const canManageOrg = hasPermission(TENANT_PERMISSIONS.settings.update);
  const orgEnabled = status.data?.required ?? true;

  const onDismiss = () =>
    dismiss.mutate(undefined, {
      onSuccess: () => { toast.success('Setup guide hidden'); navigate('/dashboard'); },
      onError: (e) => toast.error(e instanceof Error ? e.message : 'Could not dismiss'),
    });

  const onToggleOrg = (enabled: boolean) =>
    setEnabled.mutate(enabled, {
      onSuccess: () => toast.success(enabled ? 'Onboarding enabled for your team' : 'Onboarding hidden for your team'),
      onError: () => toast.error('Could not update setting'),
    });

  const steps = wf.data?.steps ?? [];
  const completedCount = steps.filter((s) => s.status === 'completed').length;
  const allDone = steps.length > 0 && completedCount === steps.length;
  const pct = steps.length ? Math.round((completedCount / steps.length) * 100) : 0;

  const markDone = (id: string) =>
    complete.mutate(id, {
      onSuccess: () => toast.success('Step marked complete'),
      onError: (e) => toast.error(e instanceof Error ? e.message : 'Could not update step'),
    });

  return (
    <div style={{ padding: '20px 26px 40px', height: '100%', overflowY: 'auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 11, marginBottom: 6 }}>
        <Icon name="list-checks" size={19} />
        <h2 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 17, color: 'var(--app-t1)' }}>
          Getting started
        </h2>
      </div>
      <p style={{ margin: '0 0 20px', fontSize: 13, color: 'var(--app-t3)', maxWidth: 560 }}>
        A few steps make the platform far more useful — define where to look, then point an agent at it.
      </p>

      {wf.isLoading || permLoading ? (
        <SkeletonList />
      ) : wf.isError ? (
        <Card>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Icon name="circle-alert" size={16} />
            <span style={{ fontSize: 13, color: 'var(--app-t2)' }}>
              Setup steps aren’t available right now.
            </span>
            <button className="ui-btn sm ghost" style={{ marginLeft: 'auto' }} onClick={() => wf.refetch()}>
              Retry
            </button>
          </div>
        </Card>
      ) : steps.length === 0 ? (
        <Card>
          <span style={{ fontSize: 13, color: 'var(--app-t3)' }}>No setup steps are configured.</span>
        </Card>
      ) : (
        <div style={{ maxWidth: 640 }}>
          {/* Progress */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 18 }}>
            <div style={{ flex: 1, height: 7, borderRadius: 50, background: 'var(--app-border)', overflow: 'hidden' }}>
              <div style={{ width: `${pct}%`, height: '100%', borderRadius: 50, background: 'var(--accent-gradient)', transition: 'width .25s ease' }} />
            </div>
            <span className="mono" style={{ fontSize: 11.5, color: 'var(--app-t3)', flex: 'none' }}>
              {completedCount}/{steps.length}
            </span>
          </div>

          {allDone && (
            <Card style={{ borderColor: 'var(--app-border2)', marginBottom: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <Icon name="badge-check" size={17} />
                <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--app-t1)' }}>
                  You’re all set — your workspace is ready.
                </span>
              </div>
            </Card>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {steps.map((step) => {
              const meta = stepMeta(step.id);
              const done = step.status === 'completed';
              const canAct = !meta.permission || hasPermission(meta.permission);
              return (
                <Card key={step.id}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 13 }}>
                    <span
                      style={{
                        width: 34, height: 34, borderRadius: 9, flex: 'none',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        background: done ? 'var(--accent-gradient)' : 'var(--app-hover)',
                        color: done ? 'var(--accent-fg)' : 'var(--app-t3)',
                      }}
                    >
                      <Icon name={done ? 'badge-check' : meta.icon} size={16} />
                    </span>
                    <div style={{ minWidth: 0, flex: 1 }}>
                      <div style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--app-t1)' }}>{step.title}</div>
                      <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 1 }}>{step.description}</div>
                    </div>
                    <div style={{ flex: 'none', display: 'flex', alignItems: 'center', gap: 8 }}>
                      {done ? (
                        <span style={{ fontSize: 11.5, fontWeight: 600, color: 'var(--ok)' }}>Done</span>
                      ) : !canAct ? (
                        <span style={{ fontSize: 11, color: 'var(--app-t3)' }}>Ask an admin</span>
                      ) : (
                        <>
                          <button className="ui-btn sm ghost" disabled={complete.isPending} onClick={() => markDone(step.id)}>
                            Mark as done
                          </button>
                          <button className="ui-btn accent sm" onClick={() => navigate(meta.route)}>
                            Set up <Icon name="arrow-right" size={13} />
                          </button>
                        </>
                      )}
                    </div>
                  </div>
                </Card>
              );
            })}
          </div>

          {/* Footer: per-user dismiss + (tenant admin) org-wide toggle */}
          <div style={{ marginTop: 22, paddingTop: 16, borderTop: '1px solid var(--app-border)', display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
            <button className="ui-btn sm ghost" disabled={dismiss.isPending} onClick={onDismiss}>
              Dismiss setup guide
            </button>
            <span style={{ fontSize: 11, color: 'var(--app-t3)' }}>Hides the reminders for you; you can reopen this page anytime.</span>
            {canManageOrg && (
              <label style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--app-t2)', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={orgEnabled}
                  disabled={setEnabled.isPending || status.isLoading}
                  onChange={(e) => onToggleOrg(e.target.checked)}
                />
                Show onboarding to my team
              </label>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function Card({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
  return (
    <div
      style={{
        background: 'var(--app-panel)', border: '1px solid var(--app-border)',
        borderRadius: 12, padding: '14px 16px', ...style,
      }}
    >
      {children}
    </div>
  );
}

function SkeletonList() {
  return (
    <div style={{ maxWidth: 640, display: 'flex', flexDirection: 'column', gap: 10 }}>
      {[0, 1, 2].map((i) => (
        <div
          key={i}
          style={{ height: 62, borderRadius: 12, background: 'var(--app-panel)', border: '1px solid var(--app-border)', opacity: 0.6 }}
        />
      ))}
    </div>
  );
}
