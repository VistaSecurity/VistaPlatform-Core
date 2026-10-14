// VISTA Operations — Maintenance (Platform group). Thin layout following the v2
// sub-nav pattern: sub-views live in the LEFT rail (nav.ts children for
// `maintenance`), NOT as in-page tabs. The section mounts on /maintenance/*
// (App.tsx), so child paths here are relative. Reference:
// sections/system/system-page.tsx.
//
// Children (ids from nav.ts): about (index/default) · backups. Plus one
// route with no rail entry of its own: runs/:id, a run's progress page,
// reached from the Update dialog and from every Run history row (WP4).
import { Navigate, Route, Routes } from 'react-router';
import { AboutUpdatesPage } from './about-updates-page';
import { BackupsPage } from './backups-page';
import { RunProgressPage } from './run-progress';

export function MaintenancePage() {
  return (
    <Routes>
      <Route index element={<AboutUpdatesPage />} />
      <Route path="about" element={<AboutUpdatesPage />} />
      <Route path="backups" element={<BackupsPage />} />
      <Route path="runs/:id" element={<RunProgressPage />} />
      <Route path="*" element={<Navigate to="/maintenance" replace />} />
    </Routes>
  );
}
