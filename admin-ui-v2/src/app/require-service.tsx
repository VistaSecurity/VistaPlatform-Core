import type { ReactNode } from 'react';
import { Package } from 'lucide-react';
import { useMaintenanceAvailability } from '../sections/maintenance/maintenance-queries';
import type { OptionalService } from './nav';

// Route-level OPTIONAL-SERVICE guard: the deep-link backstop for `serviceAllows`
// in the nav filter, as RequirePlatformEdition backs up `editionAllows`.
// A chart install can leave maintenance-service out (maintenance.enabled=false);
// its status route then 404s, the rail hides the section, and a bookmark lands
// here on a notice instead of a page whose every call fails.

const COPY: Record<OptionalService, { title: string; body: string }> = {
  maintenance: {
    title: 'Maintenance is not deployed in this install',
    body:
      'This install was deployed without the maintenance service (maintenance.enabled=false in the chart values), ' +
      'so versions, backups and updates are not managed from the console. Enable it and re-apply the chart to use this section.',
  },
};

export function RequireService({ service, children }: { service?: OptionalService; children: ReactNode }) {
  if (!service) return <>{children}</>;
  return <ServiceGate service={service}>{children}</ServiceGate>;
}

function ServiceGate({ service, children }: { service: OptionalService; children: ReactNode }) {
  const availability = useMaintenanceAvailability();
  if (availability === 'pending') {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--op-t3)', fontSize: 13 }}>
        Checking…
      </div>
    );
  }
  if (availability === 'absent') {
    const { title, body } = COPY[service];
    return (
      <div data-testid="service-absent" style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 40 }}>
        <div style={{ maxWidth: 520, display: 'flex', gap: 14, padding: '22px 24px', borderRadius: 'var(--r-lg)', background: 'var(--op-panel2)', border: '1px solid var(--op-border)' }}>
          <Package size={20} style={{ color: 'var(--op-t3)', flex: 'none', marginTop: 2 }} />
          <div>
            <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--op-t1)' }}>{title}</div>
            <div style={{ fontSize: 12.5, color: 'var(--op-t3)', marginTop: 4, lineHeight: 1.55 }}>{body}</div>
          </div>
        </div>
      </div>
    );
  }
  return <>{children}</>;
}
