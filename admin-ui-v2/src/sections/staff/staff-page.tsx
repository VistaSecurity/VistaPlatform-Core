// VISTA Operations — Staff & Access. Thin layout that renders the section's
// left-rail sub-pages via an internal <Routes>: Staff (index) + Roles. The sub-nav
// lives in the LEFT rail (see nav.ts children for `staff`), NOT as in-page tabs —
// same pattern as sections/security/security-page.tsx. Mounted on /staff/* (App.tsx).
import { Navigate, Route, Routes } from 'react-router';
import { StaffListPage } from './staff-list-page';
import { RolesPage } from './roles-page';

export function StaffPage() {
  return (
    <Routes>
      <Route index element={<StaffListPage />} />
      <Route path="staff" element={<StaffListPage />} />
      <Route path="roles" element={<RolesPage />} />
      <Route path="*" element={<Navigate to="/staff" replace />} />
    </Routes>
  );
}
