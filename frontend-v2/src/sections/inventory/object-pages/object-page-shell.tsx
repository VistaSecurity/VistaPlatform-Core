// The shell every DCIM object page shares (DCIM gap 7): breadcrumb
// (Infrastructure › lens › object), header, the object's own body, then the
// substrate panels — Custom fields, Tags, Contacts, Images, Changes, Journal —
// for every kind. Copied from the site page's layout, not a new one.
import { useState, type ReactNode } from 'react';
import { Link, useLocation } from 'react-router';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { OBJECT_KIND_LABELS, type ObjectKind } from '@vistasecurity/primitives/dcim';
import { Icon, SectionLabel } from '../../../components/ui';
import { ObjectChanges } from '../dcim/object-changes';
import { ObjectContacts } from '../dcim/object-contacts';
import { ObjectImages } from '../dcim/object-images';
import { ObjectJournal } from '../dcim/object-journal';
import { ObjectTags } from '../dcim/object-tags';
import { PanelEmpty, PanelError, PanelLoading } from '../dcim/substrate-states';
import { OBJECT_PAGE_LENS, backTarget, type ObjectPageKind } from './object-links';

/** The permission that lets a person read each kind (same as its lens). */
export const OBJECT_PAGE_READ: Record<ObjectPageKind, string> = {
  prefix: TENANT_PERMISSIONS.ipam.read,
  vlan: TENANT_PERMISSIONS.ipam.read,
  circuit: TENANT_PERMISSIONS.circuits.read,
  cable: TENANT_PERMISSIONS.dcim.read,
  interface: TENANT_PERMISSIONS.dcim.read,
};

export function Card({ children, testId }: { children: ReactNode; testId?: string }) {
  return <div data-testid={testId} style={{ border: '1px solid var(--app-border)', borderRadius: 12, background: 'var(--app-panel)', padding: 16 }}>{children}</div>;
}

export type PageStatus = 'loading' | 'error' | 'not-found' | 'ready';

export interface ObjectPageShellProps {
  kind: ObjectPageKind;
  id: string | undefined;
  status: PageStatus;
  /** The object's name once loaded (breadcrumb tail and heading fallback). */
  title?: ReactNode;
  breadcrumbName?: string;
  eyebrow?: ReactNode;
  icon: string;
  badges?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  errorMessage?: string;
  onRetry?: () => void;
  /** Overrides the lens breadcrumb (an interface returns to its asset). */
  lens?: { label: string; href: string };
  /** The object's custom-fields editor, wired to its own update route. */
  customFields?: ReactNode;
  children?: ReactNode;
}

export function ObjectPageShell(p: ObjectPageShellProps) {
  const { kind } = p;
  const loc = useLocation();
  const lens = p.lens ?? OBJECT_PAGE_LENS[kind];
  const backHref = backTarget(loc.state, lens.href);
  const noun = OBJECT_KIND_LABELS[kind as ObjectKind].uiLabel;

  const crumbs = (
    <nav aria-label="Breadcrumb" data-testid="object-breadcrumb" style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12.5, color: 'var(--app-t3)', flexWrap: 'wrap' }}>
      <Link to={backHref} data-testid="object-back" style={{ display: 'inline-flex', alignItems: 'center', gap: 3, color: 'var(--app-t3)', textDecoration: 'none' }}>
        <Icon name="chevron-left" size={13} />Back
      </Link>
      <span aria-hidden="true">·</span>
      <Link to="/inventory" style={{ color: 'var(--app-t3)', textDecoration: 'none' }}>Infrastructure</Link>
      <span aria-hidden="true">›</span>
      <Link to={lens.href} data-testid="object-crumb-lens" style={{ color: 'var(--app-t3)', textDecoration: 'none' }}>{lens.label}</Link>
      <span aria-hidden="true">›</span>
      <span data-testid="object-crumb-name" style={{ color: 'var(--app-t2)' }}>{p.breadcrumbName ?? noun}</span>
    </nav>
  );

  let body: ReactNode;
  if (p.status === 'loading') body = <PanelLoading label={`Loading ${noun.toLowerCase()}…`} />;
  else if (p.status === 'not-found') {
    body = <PanelEmpty icon="search-x" title={`${noun} not found`} message={`This ${noun.toLowerCase()} no longer exists. It may have been deleted.`} />;
  } else if (p.status === 'error') body = <PanelError message={p.errorMessage ?? 'Request failed'} onRetry={p.onRetry} />;
  else {
    body = (
      <>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
            <Icon name={p.icon} size={14} style={{ color: 'var(--app-t3)' }} />
            <span className="eyebrow-app">{p.eyebrow ?? noun}</span>
            {p.badges}
            {p.actions && <span style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>{p.actions}</span>}
          </div>
          <h1 style={{ margin: '3px 0 2px', fontFamily: 'var(--font-head)', fontSize: 19, fontWeight: 700, color: 'var(--app-t1)' }}>{p.title}</h1>
          {p.subtitle && <div style={{ fontSize: 12.5, color: 'var(--app-t2)' }}>{p.subtitle}</div>}
        </div>
        <Card testId="object-body">{p.children}</Card>
        {p.id && <ObjectSubstrate kind={kind} id={p.id} customFields={p.customFields} />}
      </>
    );
  }

  return (
    <div data-testid={`object-page-${kind}`} style={{ padding: '14px 26px 40px', display: 'flex', flexDirection: 'column', gap: 16, overflowY: 'auto', height: '100%' }}>
      {crumbs}
      <PermissionGate
        permission={OBJECT_PAGE_READ[kind]}
        fallback={<PanelEmpty icon="lock" title={`You can't view this ${noun.toLowerCase()}`} message="Ask an organisation admin to grant your role the read permission for this part of the inventory." />}
      >
        {body}
      </PermissionGate>
    </div>
  );
}

/** Custom fields, Tags, Contacts, Images, Changes and Journal of any object. */
export function ObjectSubstrate({ kind, id, customFields }: { kind: ObjectKind; id: string; customFields?: ReactNode }) {
  const [tab, setTab] = useState<'changes' | 'journal'>('changes');
  return (
    <div data-testid="object-substrate" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 14, alignItems: 'start' }}>
        <Card testId="substrate-custom-fields">
          <SectionLabel icon="list-checks">Custom fields</SectionLabel>
          {customFields}
        </Card>
        <PermissionGate permission={TENANT_PERMISSIONS.dcim.read}>
          <Card testId="substrate-tags">
            <SectionLabel icon="tags">Tags</SectionLabel>
            <ObjectTags kind={kind} id={id} />
          </Card>
          <Card testId="substrate-contacts">
            <SectionLabel icon="users">Contacts</SectionLabel>
            <ObjectContacts kind={kind} id={id} />
          </Card>
          <Card testId="substrate-images">
            <SectionLabel icon="image-plus">Images</SectionLabel>
            <ObjectImages kind={kind} id={id} />
          </Card>
        </PermissionGate>
      </div>
      <Card testId="substrate-history">
        <div role="tablist" style={{ display: 'flex', gap: 4, borderBottom: '1px solid var(--app-border)' }}>
          {(['changes', 'journal'] as const).map((t) => (
            <button key={t} type="button" role="tab" aria-selected={tab === t} className="ui-btn ghost sm"
              style={{ borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent', borderRadius: 0 }} onClick={() => setTab(t)}>
              {t === 'changes' ? 'Changes' : 'Journal'}
            </button>
          ))}
        </div>
        <div style={{ marginTop: 8 }}>
          {tab === 'changes' ? <ObjectChanges kind={kind} id={id} /> : <ObjectJournal kind={kind} id={id} />}
        </div>
      </Card>
    </div>
  );
}
