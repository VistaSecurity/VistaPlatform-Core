// VISTA Operations — System Health (Platform group). Thin layout following the v2
// sub-nav pattern: sub-views live in the LEFT rail (see nav.ts children for
// `system`), NOT as in-page tabs. This component renders an internal <Routes>
// mapping each child sub-path to a sub-page. The section mounts on /system/* (see
// App.tsx), so child paths here are relative. Reference: sections/security/security-page.tsx.
//
// Children (ids from nav.ts): services (index/default) · gateway · alerts.
// The fix lives in services-page.tsx (reads /admin/status, not /status/system).
import { Navigate, Route, Routes } from 'react-router';
import { ServicesPage } from './services-page';
import { GatewayPage } from './gateway-page';
import { AlertsPage } from './alerts-page';

export function SystemPage() {
  return (
    <Routes>
      <Route index element={<ServicesPage />} />
      <Route path="services" element={<ServicesPage />} />
      <Route path="gateway" element={<GatewayPage />} />
      <Route path="alerts" element={<AlertsPage />} />
      <Route path="*" element={<Navigate to="/system" replace />} />
    </Routes>
  );
}
