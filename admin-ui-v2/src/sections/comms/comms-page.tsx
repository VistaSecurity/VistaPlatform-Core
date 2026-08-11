// VISTA Operations — Comms (Platform group). Customer announcements + scheduled
// maintenance windows, both wired to admin-service (/admin/announcements,
// /admin/maintenance-windows) via the typed @vistasecurity/api-contract client.
// Follows the v2 sub-nav pattern: sub-views live in the LEFT rail (see nav.ts
// children for `comms`), NOT as in-page tabs. This component is a thin layout that
// renders an internal <Routes> mapping each child sub-path to a sub-page. The
// section mounts on /comms/* (App.tsx), so child paths here are relative.
import { Navigate, Route, Routes } from 'react-router';
import { AnnouncementsPage } from './announcements-page';
import { MaintenancePage } from './maintenance-page';

export function CommsPage() {
  return (
    <Routes>
      <Route index element={<AnnouncementsPage />} />
      <Route path="announcements" element={<AnnouncementsPage />} />
      <Route path="maintenance" element={<MaintenancePage />} />
      <Route path="*" element={<Navigate to="/comms" replace />} />
    </Routes>
  );
}
