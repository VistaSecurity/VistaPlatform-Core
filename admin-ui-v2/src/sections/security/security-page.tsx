// VISTA Operations — Security & Trust (Governance group). REFERENCE IMPLEMENTATION of
// the v2 sub-nav pattern: sub-views live in the LEFT rail (see nav.ts children for
// `security`), NOT as in-page tabs. This component is a thin layout that renders an
// internal <Routes> mapping each child sub-path to a sub-page. The section mounts on
// /security/* (App.tsx), so child paths here are relative.
//
// This section absorbed the dissolved Audit section (): the Activity Log,
// Retention, and SIEM Export sub-pages moved here from sections/audit/ (the cut Audit
// Alerts / Alert Rules / Compliance Reports views were dropped). Dashboard + Policy are
// wired to admin-service (/admin/security/*, /admin/settings) + auth-service; Activity /
// Retention / SIEM to audit-service — all via the typed @vistasecurity/api-contract
// client. Do NOT add a tab strip to the content area — the left rail is the navigation.
import { Navigate, Route, Routes } from 'react-router';
import { SecurityDashboardPage } from './dashboard-page';
import { SecurityPolicyPage } from './policy-page';
import { ActivityPage } from './activity-page';
import { RetentionPage } from './retention-page';
import { SiemPage } from './siem-page';

export function SecurityPage() {
  return (
    <Routes>
      <Route index element={<SecurityDashboardPage />} />
      <Route path="dashboard" element={<SecurityDashboardPage />} />
      <Route path="activity" element={<ActivityPage />} />
      <Route path="retention" element={<RetentionPage />} />
      <Route path="siem" element={<SiemPage />} />
      <Route path="policy" element={<SecurityPolicyPage />} />
      <Route path="*" element={<Navigate to="/security" replace />} />
    </Routes>
  );
}
