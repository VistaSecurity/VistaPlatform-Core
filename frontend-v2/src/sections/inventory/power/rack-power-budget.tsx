// The rack page's Power card (DCIM BUILD_PLAN row 6.2; ADR-0010 D9): the
// rack's power budget — for each feed declared as serving it, the draw
// allocated on it against its available power (NetBox Rack.get_power_utilization),
// per leg on a three-phase feed, and the rack's total. A PDU collector's
// measured load is shown beside the declared figures, never in them.
//
// Bars use the Facilities dashboard's capacity colour (over 80 % / over 95 %,
// fillColor) — a proportion, not a risk band. States: loading, error (never
// "no budget"), empty (no feed declared, which is not "draws nothing"), the
// budget. A feed whose devices declare no draw reads "no draw declared", never
// 0 W. Reads need dcim.read (the page's gate); nothing here writes.
import type { ReactNode } from 'react';
import { SectionLabel } from '../../../components/ui';
import { CAPACITY_CRITICAL, CAPACITY_WARN, fillColor } from '../../dashboard/facilities-dashboard-metrics';
import { PanelEmpty, PanelError, PanelLoading } from '../dcim/substrate-states';
import { useRackPower, type RackPowerBudget, type RackPowerFeed, type RackPowerLeg } from './power-queries';

function Card({ children, testId }: { children: ReactNode; testId?: string }) {
  return <div data-testid={testId} style={{ border: '1px solid var(--app-border)', borderRadius: 12, background: 'var(--app-panel)', padding: 16, minWidth: 0 }}>{children}</div>;
}

const num = (n: number): string => n.toLocaleString();
const pct = (p: number): string => `${Number(p.toFixed(1))}%`;

/** One allocated / available bar. */
export function BudgetBar({ allocated, available, utilization, testId }: { allocated: number; available: number; utilization: number | null; testId?: string }) {
  const width = utilization == null ? 0 : Math.min(Math.max(utilization, 0), 100);
  const color = utilization == null ? 'var(--app-t3)' : fillColor(utilization);
  return (
    <span data-testid={testId} data-color={color} style={{ display: 'inline-flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
      <span aria-hidden style={{ width: 90, height: 6, borderRadius: 4, background: 'var(--app-panel2)', overflow: 'hidden', flex: 'none' }}>
        <span style={{ display: 'block', width: `${width}%`, height: '100%', background: color }} />
      </span>
      <span className="mono" style={{ fontSize: 11.5, color: utilization != null && utilization > CAPACITY_CRITICAL ? 'var(--danger-text)' : 'var(--app-t2)', whiteSpace: 'nowrap' }}>
        {num(allocated)} W / {num(available)} VA{utilization != null ? ` · ${pct(utilization)}` : ''}
      </span>
    </span>
  );
}

function FeedRow({ f }: { f: RackPowerFeed }) {
  const declared = f.recorded_count > 0;
  return (
    <div data-testid="rack-power-feed" style={{ padding: '6px 0', borderBottom: '1px solid var(--app-border)' }}>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, flexWrap: 'wrap', fontSize: 12.5 }}>
        <span style={{ fontWeight: 600, color: 'var(--app-t1)' }}>{f.power_panel_name}:{f.name}</span>
        {f.operational_status !== 'active' && <span style={{ fontSize: 11, color: 'var(--app-t3)' }}>{f.operational_status}</span>}
        <span style={{ fontSize: 11, color: 'var(--app-t3)' }}>
          {f.power_port ? `→ ${f.power_port.asset_name ?? 'asset'} ${f.power_port.name}` : 'not cabled'}
        </span>
      </div>
      <div style={{ marginTop: 3 }}>
        {declared
          ? <BudgetBar testId="rack-power-feed-bar" allocated={f.allocated_draw} available={f.available_power} utilization={f.utilization ?? null} />
          : <span data-testid="rack-power-feed-unrecorded" style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>
            {f.power_port ? 'No draw declared' : 'Nothing cabled to it'} · {num(f.available_power)} VA available
          </span>}
      </div>
      {f.legs.length > 0 && declared && (
        <div data-testid="rack-power-legs" style={{ display: 'flex', flexDirection: 'column', gap: 2, marginTop: 4, paddingLeft: 10 }}>
          {f.legs.map((l: RackPowerLeg) => (
            <div key={l.leg} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11.5, color: 'var(--app-t3)' }}>
              <span style={{ width: 38 }}>Leg {l.leg}</span>
              <BudgetBar allocated={l.allocated_draw} available={l.available_power} utilization={l.utilization ?? null} />
              {l.measured_draw != null && <span>{num(l.measured_draw)} W measured</span>}
            </div>
          ))}
        </div>
      )}
      {f.measured_draw != null && (
        <div data-testid="rack-power-feed-measured" style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 2 }}>
          {num(f.measured_draw)} W measured{f.measured_at ? ` at ${new Date(f.measured_at).toLocaleString()}` : ''}
        </div>
      )}
    </div>
  );
}

export function RackPowerBudgetBody({ budget }: { budget: RackPowerBudget }) {
  const declared = budget.feeds.some((f) => f.recorded_count > 0);
  return (
    <>
      <div data-testid="rack-power-budget-total" style={{ marginBottom: 4 }}>
        {declared
          ? <BudgetBar testId="rack-power-budget-bar" allocated={budget.allocated_draw} available={budget.available_power} utilization={budget.utilization ?? null} />
          : <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>No device on these feeds declares a draw · {num(budget.available_power)} VA available</span>}
      </div>
      <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginBottom: 4 }}>
        {budget.feed_count} feed{budget.feed_count === 1 ? '' : 's'}
        {budget.measured_draw != null ? ` · ${num(budget.measured_draw)} W measured` : ' · not measured'}
        {' · '}amber over {CAPACITY_WARN}%, red over {CAPACITY_CRITICAL}%
      </div>
      {budget.feeds.map((f) => <FeedRow key={f.id} f={f} />)}
    </>
  );
}

export function RackPowerBudgetCard({ rackId }: { rackId: string }) {
  const q = useRackPower(rackId);
  let body: ReactNode;
  if (q.isLoading) body = <PanelLoading label="Loading the power budget…" />;
  else if (q.isError || !q.data) body = <PanelError message={q.error instanceof Error ? q.error.message : "Couldn't load the rack's power budget."} onRetry={() => { void q.refetch(); }} />;
  else if (q.data.feed_count === 0) {
    body = <PanelEmpty icon="zap" title="No power budget" message="No power feed is declared as serving this rack, so there is nothing to budget its devices' draw against. Add feeds from the site's Power panels card." />;
  } else body = <RackPowerBudgetBody budget={q.data} />;
  return (
    <Card testId="rack-power-budget">
      <SectionLabel icon="zap">Power</SectionLabel>
      {body}
    </Card>
  );
}
