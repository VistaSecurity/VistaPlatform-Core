// VISTA Operations — Support (CS cockpit). The customer-success operator surface.
// Like every v2 section with sub-views, this is a thin layout: sub-navigation
// lives in the LEFT rail (see nav.ts children for `support`), and this component
// renders an internal <Routes> mapping each child sub-path to a sub-page. The
// section mounts on /support/* (App.tsx), so child paths here are relative. Do
// NOT add an in-page tab strip — the left rail is the navigation.
//   health        → Tenant Health (read)
//   impersonation → Impersonation (read-only session/history)
//   repair        → Job Repair (list + retry/cancel stuck discovery jobs)
import { Navigate, Route, Routes } from 'react-router';
import { TenantHealthPage } from './tenant-health-page';
import { ImpersonationPage } from './impersonation-page';
import { JobRepairPage } from './job-repair-page';

export function SupportPage() {
  return (
    <Routes>
      <Route index element={<TenantHealthPage />} />
      <Route path="health" element={<TenantHealthPage />} />
      <Route path="impersonation" element={<ImpersonationPage />} />
      <Route path="repair" element={<JobRepairPage />} />
      <Route path="*" element={<Navigate to="/support" replace />} />
    </Routes>
  );
}
