// VISTA Operations — Settings (Platform group). Thin layout following the v2
// sub-nav pattern: sub-views live in the LEFT rail (see nav.ts children for
// `settings`), NOT as in-page tabs. This component renders an internal <Routes>
// mapping each child sub-path to a sub-page. The section mounts on /settings/*
// (App.tsx), so child paths here are relative.
//   • email         → SettingsEmailPage (platform SMTP config)
//   • access        → SettingsAccessPage (self-service sign-up + email verification gates)
//   • branding      → SettingsBrandingPage (white-label: product name + logos + favicon)
//   • legal         → SettingsLegalPage (Terms of Service / Privacy Policy authoring + acceptance audit)
//   • notifications → NotificationDeliveryPage (channels, rules, delivery history)
//   • license       → SettingsLicensePage (licence card, Enterprise data-retention cap)
import { Navigate, Route, Routes } from 'react-router';
import { SettingsEmailPage } from './settings-email-page';
import { SettingsAccessPage } from './settings-access-page';
import { SettingsBrandingPage } from './settings-branding-page';
import { SettingsIdentityProvidersPage } from './settings-identity-providers-page';
import { SettingsLegalPage } from './settings-legal-page';
import { NotificationDeliveryPage } from './notification-delivery-page';
import { SettingsLicensePage } from './settings-license-page';
import { RequireChildPermission } from '../../app/section-child';

export function SettingsPage() {
  return (
    <Routes>
      <Route index element={<SettingsEmailPage />} />
      <Route path="email" element={<SettingsEmailPage />} />
      <Route path="access" element={<SettingsAccessPage />} />
      <Route path="branding" element={<SettingsBrandingPage />} />
      <Route path="legal" element={<SettingsLegalPage />} />
      <Route path="identity-providers" element={<SettingsIdentityProvidersPage />} />
      <Route path="notifications" element={<RequireChildPermission section="settings" child="notifications"><NotificationDeliveryPage /></RequireChildPermission>} />
      <Route path="license" element={<SettingsLicensePage />} />
      <Route path="*" element={<Navigate to="/settings" replace />} />
    </Routes>
  );
}
