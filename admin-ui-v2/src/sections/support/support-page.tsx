// VISTA Operations — Support (CS cockpit). The customer-success operator surface.
// Like every v2 section with sub-views, this is a thin layout: sub-navigation
// lives in the LEFT rail (see nav.ts children for `support`), and this component
// renders an internal <Routes> mapping each child sub-path to a sub-page. The
// section mounts on /support/* (App.tsx), so child paths here are relative. Do
// NOT add an in-page tab strip — the left rail is the navigation.
//   health        → Tenant Health (read)
//   repair        → Job Repair (list + retry/cancel stuck discovery jobs)
// /support/impersonation is gone (owner decision 10): it falls through to the
// catch-all below like any unknown sub-path.
import { Navigate, Route, Routes } from 'react-router';
import { TenantHealthPage } from './tenant-health-page';
import { JobRepairPage } from './job-repair-page';
import { FirstPermittedChild, RequireChildPermission } from '../../app/section-child';

export function SupportPage() {
  return (
    <Routes>
      {/* Each sub-view is guarded on its nav entry's permission; the index
          lands on the first one this operator may open. */}
      <Route index element={<FirstPermittedChild section="support" />} />
      <Route path="health" element={<RequireChildPermission section="support" child="health"><TenantHealthPage /></RequireChildPermission>} />
      <Route path="repair" element={<RequireChildPermission section="support" child="repair"><JobRepairPage /></RequireChildPermission>} />
      <Route path="*" element={<Navigate to="/support" replace />} />
    </Routes>
  );
}
