// Infrastructure workspace hubs.  These are intentionally small directories,
// not another layer of configuration: they keep related operational records
// reachable from the primary rail without turning every catalogue table into a
// permanent rail row.
import { Link } from 'react-router';
import { Icon } from '../../components/ui';
import { SCard, SPage } from '../settings/kit';

interface HubItem {
  label: string;
  description: string;
  icon: string;
  to: string;
}

function Hub({ title, job, items }: { title: string; job: string; items: HubItem[] }) {
  return (
    <SPage eyebrow="Infrastructure" title={title} job={job} maxWidth={1040}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 12 }}>
        {items.map((item) => (
          <Link key={item.to} to={item.to} style={{ color: 'inherit', textDecoration: 'none' }}>
            <SCard style={{ height: '100%', display: 'flex', gap: 12, alignItems: 'flex-start' }}>
              <span style={{ width: 34, height: 34, borderRadius: 9, background: 'var(--app-panel2)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent)', flex: 'none' }}>
                <Icon name={item.icon} size={17} />
              </span>
              <span>
                <span style={{ display: 'block', fontSize: 13.5, fontWeight: 700, color: 'var(--app-t1)', marginBottom: 3 }}>{item.label}</span>
                <span style={{ display: 'block', fontSize: 12, lineHeight: 1.5, color: 'var(--app-t3)' }}>{item.description}</span>
              </span>
            </SCard>
          </Link>
        ))}
      </div>
    </SPage>
  );
}

export function InfrastructureOrganizationPage() {
  return <Hub title="Organization" job="Maintain the ownership and contact records attached to infrastructure throughout this tenant." items={[
    { label: 'Business Units', description: 'Departments, customers and cost centres that own infrastructure.', icon: 'building-2', to: '/inventory/manage/business-units' },
    { label: 'Contacts', description: 'People, teams and roles assigned to sites, racks and assets.', icon: 'users', to: '/inventory/manage/contacts' },
  ]} />;
}

export function InfrastructureCatalogPage() {
  return <Hub title="Device Catalog" job="Maintain the reusable models and metadata used to describe assets in this tenant." items={[
    { label: 'Device Types', description: 'Hardware models and their interface, port and bay templates.', icon: 'server', to: '/inventory/manage/device-types' },
    { label: 'Module Types', description: 'Line cards, network modules and power supplies installed in module bays.', icon: 'blocks', to: '/inventory/manage/module-types' },
    { label: 'Manufacturers', description: 'The makers associated with device and module types.', icon: 'factory', to: '/inventory/manage/manufacturers' },
    { label: 'Device Roles', description: 'The function each physical or virtual device performs.', icon: 'tag', to: '/inventory/manage/device-roles' },
    { label: 'Platforms (OS)', description: 'Operating-system and firmware families used by devices.', icon: 'cpu', to: '/inventory/manage/platforms' },
    { label: 'Config Contexts', description: 'Weighted configuration data applied to matching infrastructure.', icon: 'braces', to: '/inventory/manage/config-contexts' },
    { label: 'Spares & RMA', description: 'Spare parts in stock, installs from the shelf, and units out for RMA.', icon: 'package', to: '/inventory/manage/spares' },
  ]} />;
}
