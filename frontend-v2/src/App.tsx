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
import { AboutPage } from './pages/about-page';
import { InventoryPage } from './sections/inventory/inventory-page';
import { SensorsPage } from './sections/discovery/sensors-page';
import { PlansPage } from './sections/remediation/plans-page';
import { QueuePage } from './sections/remediation/queue-page';
import { AlertsPage } from './sections/remediation/alerts-page';
import { JobsPage } from './sections/discovery/jobs-page';
import { CommandCenterPage } from './sections/discovery/command-center';
import { LogsPage } from './sections/discovery/logs-page';
import { DevicesPage } from './sections/discovery/devices-page';
import { ScansPage } from './sections/discovery/scans-page';
import { ActiveScanPage } from './sections/discovery/active-scan-page';
import { CloudPage } from './sections/discovery/cloud-page';
import { ApprovalsPage } from './sections/discovery/approvals-page';
import { PcapPage } from './sections/discovery/pcap-page';
import { DashboardPage } from './sections/dashboard/dashboard-page';
import { SettingsPage, ProfilePage } from './sections/settings/settings-page';
import { FindingsPage } from './sections/findings/findings-page';
import { PosturePage } from './sections/posture/posture-page';
import { CbomPage } from './sections/cbom/cbom-page';
import { ComparePage } from './sections/cbom/compare-page';
import { GettingStartedPage } from './sections/onboarding/getting-started-page';

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
      <Route path="/reset-password" element={<ResetPasswordPage />} />
      {/* Public self-service signup front door + email-verification landing (#725). */}
      <Route path="/signup" element={<SignupPage />} />
      <Route path="/verify-email" element={<VerifyEmailPage />} />
      {/* Public legal documents (Terms of Service / Privacy Policy). */}
      <Route path="/legal/terms" element={<LegalPage kind="terms" />} />
      <Route path="/legal/privacy" element={<LegalPage kind="privacy" />} />

      <Route element={<RequireAuth />}>
        <Route element={<AppShell />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/about" element={<AboutPage />} />

          {/* Discovery */}
          <Route path="/discovery" element={<CommandCenterPage />} />
          <Route path="/discovery/sensors" element={<SensorsPage />} />
          <Route path="/discovery/jobs" element={<JobsPage />} />
          <Route path="/discovery/devices" element={<DevicesPage />} />
          <Route path="/discovery/scans" element={<ScansPage />} />
          <Route path="/discovery/active-scan" element={<ActiveScanPage />} />
          <Route path="/discovery/approvals" element={<ApprovalsPage />} />
          <Route path="/discovery/logs" element={<LogsPage />} />
          <Route path="/discovery/cloud" element={<CloudPage />} />
          <Route path="/discovery/pcap" element={<PcapPage />} />

          {/* Inventory */}
          <Route path="/inventory" element={<InventoryPage />} />

          {/* Risk & Compliance */}
          <Route path="/risk-compliance/posture" element={<PosturePage />} />
          <Route path="/risk-compliance/findings" element={<FindingsPage />} />
          {/* CBOM — audit-grade compliance evidence (artifacts + comparison) */}
          <Route path="/risk-compliance/cbom" element={<CbomPage />} />
          <Route path="/risk-compliance/cbom/compare" element={<ComparePage />} />
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

          {/* Profile-dropdown surfaces */}
          <Route path="/getting-started" element={<GettingStartedPage />} />
          <Route path="/settings" element={<Navigate to="/settings/org-overview" replace />} />
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
