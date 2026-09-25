import { Navigate, Route, Routes } from 'react-router';
import { AppShell } from './app/app-shell';
import { PlatformBrandingEffects } from './app/platform-branding';
import { RequireAuth } from './app/require-auth';
import { RequirePlatformPermission } from './app/require-permission';
import { RequireLicenseEdition, RequirePlatformEdition } from './app/require-edition';
import { SectionPlaceholder } from './app/section-placeholder';
import { LoginPage } from './pages/login-page';
import { ResetPasswordPage } from './pages/reset-password-page';
import { ForgotPasswordPage } from './pages/forgot-password-page';
import { SECTIONS } from './app/nav';
import { TenantsPage } from './sections/tenants/tenants-page';
import { StaffPage } from './sections/staff/staff-page';
import { SystemPage } from './sections/system/system-page';
import { CatalogPage } from './sections/catalog/catalog-page';
import { BillingPage } from './sections/billing/billing-page';
import { OverviewPage } from './sections/overview/overview-page';
import { PlansPage } from './sections/plans/plans-page';
import { FleetPage } from './sections/fleet/fleet-page';
import { JobsPage } from './sections/jobs/jobs-page';
import { SettingsPage } from './sections/settings/settings-page';
import { SecurityPage } from './sections/security/security-page';
import { SupportPage } from './sections/support/support-page';

// Sections with a real body built from the design kit. Everything else still
// renders the placeholder (naming the v1 page it supersedes) until built.
const BUILT: Record<string, React.ComponentType> = {
  overview: OverviewPage,
  tenants: TenantsPage,
  support: SupportPage,
  staff: StaffPage,
  system: SystemPage,
  catalog: CatalogPage,
  plans: PlansPage,
  billing: BillingPage,
  fleet: FleetPage,
  jobs: JobsPage,
  settings: SettingsPage,
  security: SecurityPage,
};

// Public /login; everything else is gated by RequireAuth and laid out in the
// AppShell. Routes are derived from the 10-section operator IA (src/app/nav.ts);
// each renders a placeholder naming the v1 page it supersedes until its section
// body is built from the design kit. Mirrors frontend-v2/src/App.tsx.
export default function App() {
  return (
    <>
      <PlatformBrandingEffects />
      <Routes>
      <Route path="/login" element={<LoginPage />} />
      {/* Public account-access landings — invited operators and password resets
          arrive here from email links (token in the URL). Outside RequireAuth so
          the unauthenticated link isn't bounced to /login. Mirrors frontend-v2. */}
      <Route path="/reset-password" element={<ResetPasswordPage />} />
      <Route path="/forgot-password" element={<ForgotPasswordPage />} />

      <Route element={<RequireAuth />}>
        <Route element={<AppShell />}>
          <Route index element={<Navigate to="/overview" replace />} />
          {SECTIONS.map((s) => {
            const Built = BUILT[s.id];
            // Sections with left-rail children own an internal <Routes> for their
            // sub-pages, so they mount on a wildcard path (/<id>/*). Childless
            // sections stay on the exact path.
            const path = s.children?.length ? `/${s.id}/*` : `/${s.id}`;
            const el = Built ? <Built /> : <SectionPlaceholder title={s.title} source={s.source} />;
            // Gate the route on the section's view permission so a deep link can't
            // bypass the nav filter. Sections without a permission are open to any
            // authenticated operator (e.g. Mission Control).
            const guarded = s.permission || s.anyOf?.length || s.allOf?.length
              ? <RequirePlatformPermission permission={s.permission} anyOf={s.anyOf} allOf={s.allOf}>{el}</RequirePlatformPermission>
              : el;
            // Second, independent gate: does this BUILD ship the section's
            // backend? A Core operator holds `tenants.read`, so the permission
            // guard above happily lets them into a section whose routes 404.
            // Pass-through when `s.edition` is undefined (Core sections).
            // Third gate: the install's LICENCE edition (Plans & Pricing and
            // Billing only on MSP). Pass-through when `s.license` is
            // undefined.
            return (
              <Route key={s.id} path={path} element={
                <RequirePlatformEdition capability={s.edition}>
                  <RequireLicenseEdition gate={s.license}>{guarded}</RequireLicenseEdition>
                </RequirePlatformEdition>
              } />
            );
          })}
          {/* Retired Comms section (owner decision 9, RC-20). Its maintenance
              form wrote a table nothing read; the one maintenance-window store
              is System → Alerts. Announcements are hidden until they can be
              delivered, so the rest of /comms has nowhere to go. */}
          <Route path="/comms/maintenance" element={<Navigate to="/system/alerts" replace />} />
          <Route path="/comms/*" element={<Navigate to="/overview" replace />} />
          <Route path="*" element={<SectionPlaceholder title="Not found" />} />
        </Route>
      </Route>
      </Routes>
    </>
  );
}
