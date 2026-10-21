import { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import { AppShell } from './app/app-shell';
import { PlatformBrandingEffects } from './app/platform-branding';
import { RequireAuth } from './app/require-auth';
import { SectionPlaceholder } from './app/section-placeholder';
import { LoginPage } from './pages/login-page';
import { SsoCallbackPage } from './pages/sso-callback-page';
import { CompleteProfilePage } from './pages/complete-profile-page';
import { AcceptInvitePage } from './pages/accept-invite-page';
import { SignupPage } from './pages/signup-page';
import { VerifyEmailPage } from './pages/verify-email-page';
import { LegalPage } from './pages/legal-page';
import { ResetPasswordPage } from './pages/reset-password-page';
import { ForgotPasswordPage } from './pages/forgot-password-page';
import { AboutPage } from './pages/about-page';
import { InventoryPage } from './sections/inventory/inventory-page';
import { AssetPage } from './sections/inventory/asset-page';
import { ClusterPage } from './sections/inventory/virtualization/cluster-page';
import { SitePage } from './sections/inventory/sites/site-page';
import { RackPage } from './sections/inventory/racks/rack-page';
import { PrefixPage } from './sections/inventory/object-pages/prefix-page';
import { VlanPage } from './sections/inventory/object-pages/vlan-page';
import { CircuitPage } from './sections/inventory/object-pages/circuit-page';
import { CablePage } from './sections/inventory/object-pages/cable-page';
import { InterfacePage } from './sections/inventory/object-pages/interface-page';
import { InfrastructureCatalogPage, InfrastructureOrganizationPage } from './sections/inventory/workspace-hubs';
import { SensorsPage } from './sections/discovery/sensors-page';
import { PlansPage } from './sections/remediation/plans-page';
import { ProgressPage } from './sections/remediation/progress-page';
import { QueuePage } from './sections/remediation/queue-page';
import { AlertsPage } from './sections/remediation/alerts-page';
import { JobsPage } from './sections/discovery/jobs-page';
import { CommandCenterPage } from './sections/discovery/command-center';
import { DevicesPage } from './sections/discovery/devices-page';
import { ScansPage } from './sections/discovery/scans-page';
import { NEVER_SCANNED_HREF } from './sections/inventory/builtin-views';
import { NETWORKS_LENS_HREF } from './sections/inventory/lenses';
import { CloudPage } from './sections/discovery/cloud-page';
import { ApprovalsPage } from './sections/discovery/approvals-page';
import { ObservationsPage } from './sections/discovery/observations-page';
import { PcapPage } from './sections/discovery/pcap-page';
import { SbomPage } from './sections/discovery/sbom-page';
import { DashboardPage } from './sections/dashboard/dashboard-page';
import { AssetsDashboardPage } from './sections/dashboard/assets-dashboard';
import { ComplianceDashboardPage } from './sections/dashboard/compliance-dashboard';
import { PqcDashboardPage } from './sections/dashboard/pqc-dashboard';
import { FacilitiesDashboardPage } from './sections/dashboard/facilities-dashboard';
import { SettingsPage, WorkspacePage, ProfilePage } from './sections/settings/settings-page';
import { FindingsPage } from './sections/findings/findings-page';
import { PosturePage } from './sections/posture/posture-page';
import { CbomPage } from './sections/cbom/cbom-page';
import { ComparePage } from './sections/cbom/compare-page';
import { GettingStartedPage } from './sections/onboarding/getting-started-page';

// The full-screen map (ADR-0006 D4). Lazy for the same reason the lens is: it
// is the only thing that loads `@xyflow/react` and dagre, and it must not be in
// the bundle a user downloads to sign in.
const AssetMapFullscreen = lazy(
  () => import('./sections/inventory/map-lens').then((m) => ({ default: m.AssetMapFullscreen })),
);

// Public /login; everything else is gated by RequireAuth (which also mounts the
// PermissionProvider) and laid out in the AppShell. Section bodies are built
// from the mock next; routing + IA + auth gate are real.
export default function App() {
  return (
    <>
      <PlatformBrandingEffects />
      <Routes>
      <Route path="/login" element={<LoginPage />} />
      {/* Public SSO landing — the auth-service redirects here after a successful
          OIDC callback (cookies already set). Must be outside RequireAuth so it
          isn't bounced to /login before auth re-initializes. */}
      <Route path="/auth/sso/callback" element={<SsoCallbackPage />} />
      {/* Public onboarding landings — invited/signing-up users and password
          resets arrive here from email links (token in the URL). Outside
          RequireAuth so the unauthenticated link doesn't bounce to /login. */}
      <Route path="/register/complete" element={<CompleteProfilePage />} />
      {/* Social-signup org-name step — the platform SSO callback redirects here
          with ?sso_token= after the IdP verifies the founder (#895). */}
      <Route path="/register/complete-profile" element={<CompleteProfilePage />} />
      <Route path="/accept-invite" element={<AcceptInvitePage />} />
      <Route path="/forgot-password" element={<ForgotPasswordPage />} />
      <Route path="/reset-password" element={<ResetPasswordPage />} />
      {/* Public self-service signup front door + email-verification landing (#725). */}
      <Route path="/signup" element={<SignupPage />} />
      <Route path="/verify-email" element={<VerifyEmailPage />} />
      {/* Public legal documents (Terms of Service / Privacy Policy). */}
      <Route path="/legal/terms" element={<LegalPage kind="terms" />} />
      <Route path="/legal/privacy" element={<LegalPage kind="privacy" />} />

      <Route element={<RequireAuth />}>
        {/* The full-screen map (ADR-0006 D4). Inside the auth gate, OUTSIDE the
            AppShell: it is the same component as the `?lens=map` body, given
            the whole viewport with no rail competing with the canvas. Its Exit
            control returns to the lens carrying the depth and pending state, so
            leaving full screen is not a reset. */}
        <Route
          path="/inventory/map/:assetId"
          element={
            <Suspense
              fallback={
                // Not `null`: this route has no shell behind it, so an empty
                // fallback is a blank window for as long as the chunk takes.
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', fontSize: 13, color: 'var(--app-t3)', background: 'var(--app-bg)' }}>
                  Loading the map…
                </div>
              }
            >
              <AssetMapFullscreen />
            </Suspense>
          }
        />
        <Route element={<AppShell />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          {/* Five dashboards (DASHBOARDS in sections/dashboard/dashboards.ts).
              Overview keeps the bare path — it is the index redirect target and
              every existing bookmark. `dashboard-nav.test.ts` joins the registry
              against these routes and the rail, so a dashboard cannot be added
              in one place and forgotten in the others. */}
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/dashboard/assets" element={<AssetsDashboardPage />} />
          <Route path="/dashboard/compliance" element={<ComplianceDashboardPage />} />
          <Route path="/dashboard/pqc" element={<PqcDashboardPage />} />
          <Route path="/dashboard/facilities" element={<FacilitiesDashboardPage />} />
          <Route path="/dashboard/overview-next" element={<Navigate to="/dashboard" replace />} />
          <Route path="/about" element={<AboutPage />} />

          {/* Discovery */}
          <Route path="/discovery" element={<CommandCenterPage />} />
          <Route path="/discovery/sensors" element={<SensorsPage />} />
          <Route path="/discovery/jobs" element={<JobsPage />} />
          <Route path="/discovery/devices" element={<DevicesPage />} />
          <Route path="/discovery/scans" element={<ScansPage />} />
          {/* Discovery → Active Scan is folded into Inventory (#2272): its list is
              the "Never scanned" view of All assets, and scanning is the bulk
              bar's Scan. A bookmark lands on that view. */}
          <Route path="/discovery/active-scan" element={<Navigate to={NEVER_SCANNED_HREF} replace />} />
          <Route path="/discovery/approvals" element={<ApprovalsPage />} />
          <Route path="/discovery/observations" element={<ObservationsPage />} />
          {/* Job Logs was folded into Discovery Jobs; keep old links working. */}
          <Route path="/discovery/logs" element={<Navigate to="/discovery/jobs" replace />} />
          <Route path="/discovery/cloud" element={<CloudPage />} />
          <Route path="/discovery/pcap" element={<PcapPage />} />
          <Route path="/discovery/sbom" element={<SbomPage />} />

          {/* Inventory */}
          <Route path="/inventory" element={<InventoryPage />} />
          {/* The asset page (ADR-0006 D3). Two routes, one page: the bare path
              is Overview, so the URL a user copies off the first tab is the
              short one, and `/:tab` deep-links the rest. An unknown tab falls
              back to Overview rather than 404ing — a stale link should still
              show the asset. */}
          <Route path="/inventory/assets/:id" element={<AssetPage />} />
          <Route path="/inventory/assets/:id/:tab" element={<AssetPage />} />
          <Route path="/inventory/clusters/:id" element={<ClusterPage />} />
          {/* The site page (DCIM row 2.1); its nav home is the Sites lens. */}
          <Route path="/inventory/sites/:id" element={<SitePage />} />
          {/* The rack page (DCIM row 2.5); its nav home is the Racks lens. */}
          <Route path="/inventory/racks/:id" element={<RackPage />} />
          <Route path="/inventory/prefixes/:id" element={<PrefixPage />} />
          <Route path="/inventory/vlans/:id" element={<VlanPage />} />
          <Route path="/inventory/circuits/:id" element={<CircuitPage />} />
          <Route path="/inventory/cables/:id" element={<CablePage />} />
          <Route path="/inventory/interfaces/:id" element={<InterfacePage />} />
          {/* Operational DCIM records belong to the tenant workspace, not the
              Settings drawer.  The old /settings/:page URLs redirect here. */}
          <Route path="/inventory/manage/organization" element={<InfrastructureOrganizationPage />} />
          <Route path="/inventory/manage/catalog" element={<InfrastructureCatalogPage />} />
          <Route path="/inventory/manage/:page" element={<WorkspacePage />} />

          {/* Risk & Compliance */}
          <Route path="/risk-compliance/posture" element={<PosturePage />} />
          <Route path="/risk-compliance/findings" element={<FindingsPage />} />
          {/* CBOM — audit-grade compliance evidence (artifacts + comparison) */}
          <Route path="/risk-compliance/cbom" element={<CbomPage />} />
          <Route path="/risk-compliance/cbom/compare" element={<ComparePage />} />
          <Route path="/risk-compliance/scopes" element={<WorkspacePage page="scopes" />} />
          <Route path="/risk-compliance/audit" element={<WorkspacePage page="audit" />} />
          {/* Back-compat for the documented /cbom deep links */}
          <Route path="/cbom" element={<Navigate to="/risk-compliance/cbom" replace />} />
          <Route path="/cbom/compare" element={<Navigate to="/risk-compliance/cbom/compare" replace />} />

          {/* Remediation */}
          <Route path="/remediation/alerts" element={<AlertsPage />} />
          {/* Triage was an audit-rule alert inbox with no producer: its only
              data source returned a hardcoded empty list, so it read "Inbox
              zero" forever and its Acknowledge stored nothing. The capability
              it promised (work an alert, or turn it into a ticket) is the
              Alerts page, which has real state and an evidence trail — so the
              documented deep link lands there. */}
          <Route path="/remediation/triage" element={<Navigate to="/remediation/alerts" replace />} />
          <Route path="/remediation/queue" element={<QueuePage />} />
          <Route path="/remediation/plans" element={<PlansPage />} />
          <Route path="/remediation/progress" element={<ProgressPage />} />
          <Route path="/remediation/delivery" element={<WorkspacePage page="notification-history" />} />

          {/* Profile-dropdown surfaces */}
          <Route path="/getting-started" element={<GettingStartedPage />} />
          <Route path="/settings" element={<Navigate to="/settings/org-overview" replace />} />
          {/* Settings → Network Segments was retired with the table (DCIM row
              1.6): the tenant's networks are prefixes in Inventory → Networks,
              and an old bookmark lands there rather than on an unknown page. */}
          <Route path="/settings/segments" element={<Navigate to={NETWORKS_LENS_HREF} replace />} />
          <Route path="/settings/:page" element={<SettingsPage />} />
          <Route path="/profile" element={<Navigate to="/profile/personal" replace />} />
          <Route path="/profile/:page" element={<ProfilePage />} />

          <Route path="*" element={<SectionPlaceholder title="Not found" />} />
        </Route>
      </Route>
      </Routes>
    </>
  );
}
