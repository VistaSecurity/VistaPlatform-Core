// Settings & My Profile page routers — resolve the :page URL param against the
// nav registries, enforce the page's RBAC permission (primitives), and render
// the built page or the spec-pending fallback. Mirrors the mock's
// Settings.jsx/sectionF.jsx page-key dispatch with react-router params.
import { useParams } from 'react-router';
import { usePermissions } from '@vistasecurity/primitives/rbac';
import { useFeatures } from '@vistasecurity/primitives/features';
import { settingsPageMeta, profilePageMeta, type SettingsNavItem } from './nav';
import { SpecPendingPage, AccessNotice } from './spec-pending';
import { SPage, SCard, StateNote } from './kit';
import { OrgOverviewPage, OrgBrandingPage } from './pages-org';
import { MembersPage, RolesPage, SecuritySsoPage } from './pages-people';
import { ScopesPage, FrameworksPage, RetentionPage } from './pages-policies';
import { CustomPoliciesPage } from './pages-custom-policies';
import { BillingPage, UsagePage } from './pages-account';
import { IntegrationsPage, RoutingRulesPage, AlertRulesPage } from './pages-integrations';
import { NotificationHistoryPage } from './pages-notification-history';
import { AuditPage } from './pages-audit';
import { LocationsPage, NetworkSegmentsPage, AssetLifecyclePage } from './pages-infra';
import { ProfilePersonalPage, ProfileSecurityPage, ProfileNotificationsPage } from './pages-profile';
import { ApiTokensPage } from './api-tokens';
import { ProfileSessionsPage, ProfileConnectedPage } from './profile-sessions';

/**
 * Upgrade card for a page whose edition/entitlement gate is off. Rendered
 * instead of the page body so a deep link (or a bookmark from an Enterprise
 * deployment) never mounts a page that would 404 against a Core build.
 */
function EditionLock({ meta }: { meta: SettingsNavItem & { section?: string } }) {
  const lock = meta.lock;
  return (
    <SPage eyebrow={meta.section ?? 'Settings'} title={meta.label} job={meta.job} maxWidth={1000}>
      <SCard>
        <StateNote
          icon="lock"
          tone="var(--accent)"
          title={lock?.title ?? 'An Enterprise feature'}
          message={lock?.message ?? 'This capability is part of the Enterprise edition. Upgrade to enable it.'}
        />
      </SCard>
    </SPage>
  );
}

export function SettingsPage() {
  const { page = '' } = useParams();
  const meta = settingsPageMeta(page);
  const { hasPermission, isLoading } = usePermissions();
  // Fail CLOSED while flags resolve (defaultFeatures is all-off), same posture
  // as the permission gate below: never flash an Enterprise page body — and its
  // on-mount fetches — on a deployment that may not ship the routes.
  const { features, isLoading: featuresLoading } = useFeatures();

  // Fail CLOSED while permissions resolve: render nothing rather than flashing the
  // gated page body (and its on-mount data fetches) to a user who may lack access.
  // Mirrors PermissionGate, which returns null during isLoading.
  if (meta.permission && isLoading) {
    return null;
  }
  if (meta.permission && !hasPermission(meta.permission)) {
    return <AccessNotice meta={meta} />;
  }
  if (meta.feature) {
    if (featuresLoading) return null;
    if (!features[meta.feature]) return <EditionLock meta={meta} />;
  }

  switch (page) {
    case 'org-overview': return <OrgOverviewPage meta={meta} />;
    case 'org-branding': return <OrgBrandingPage meta={meta} />;
    case 'members': return <MembersPage meta={meta} />;
    case 'roles': return <RolesPage meta={meta} />;
    case 'security-sso': return <SecuritySsoPage meta={meta} />;
    case 'billing': return <BillingPage meta={meta} />;
    case 'usage': return <UsagePage meta={meta} />;
    case 'integrations': return <IntegrationsPage meta={meta} />;
    case 'routing': return <RoutingRulesPage meta={meta} />;
    case 'alert-rules': return <AlertRulesPage meta={meta} />;
    case 'notification-history': return <NotificationHistoryPage meta={meta} />;
    case 'frameworks': return <FrameworksPage meta={meta} />;
    case 'custom-policies': return <CustomPoliciesPage meta={meta} />;
    case 'retention': return <RetentionPage meta={meta} />;
    case 'scopes': return <ScopesPage meta={meta} />;
    case 'audit': return <AuditPage meta={meta} />;
    case 'locations': return <LocationsPage meta={meta} />;
    case 'segments': return <NetworkSegmentsPage meta={meta} />;
    case 'asset-lifecycle': return <AssetLifecyclePage meta={meta} />;
    default: return <SpecPendingPage meta={meta} />;
  }
}

export function ProfilePage() {
  const { page = '' } = useParams();
  const meta = profilePageMeta(page);

  switch (page) {
    case 'personal': return <ProfilePersonalPage meta={meta} />;
    case 'security': return <ProfileSecurityPage meta={meta} />;
    case 'notifications': return <ProfileNotificationsPage meta={meta} />;
    case 'api-tokens': return <ApiTokensPage meta={meta} />;
    case 'sessions': return <ProfileSessionsPage meta={meta} />;
    case 'connected': return <ProfileConnectedPage meta={meta} />;
    default: return <SpecPendingPage meta={meta} eyebrow="My Profile" />;
  }
}
