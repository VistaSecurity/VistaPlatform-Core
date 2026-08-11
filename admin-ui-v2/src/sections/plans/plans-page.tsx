// Plans & Pricing section (ADR-0004 ·). Left-rail children own their
// own routes (mirrors sections/security/security-page.tsx). Slice 1 ships the
// Entitlements catalog; Tiers (Slice 3) and Add-ons (Slice 6) are placeholders.
import { Navigate, Route, Routes } from 'react-router';
import { EntitlementsPage } from './entitlements-page';
import { TiersPage } from './tiers-page';
import { AddonsPage } from './addons-page';

export function PlansPage() {
  return (
    <Routes>
      <Route index element={<EntitlementsPage />} />
      <Route path="entitlements" element={<EntitlementsPage />} />
      <Route path="tiers" element={<TiersPage />} />
      <Route path="addons" element={<AddonsPage />} />
      <Route path="*" element={<Navigate to="/plans" replace />} />
    </Routes>
  );
}
