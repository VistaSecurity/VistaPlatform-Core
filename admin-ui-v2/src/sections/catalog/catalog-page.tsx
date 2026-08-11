// VISTA Operations — Catalog (Platform group). Thin layout that renders the
// left-rail sub-pages: sub-views live in the LEFT rail (see nav.ts children for
// `catalog`), NOT as in-page tabs. The section mounts on /catalog/* (see
// App.tsx), so child paths here are relative. Mirrors the reference
// security-page.tsx pattern.
//
// Children (ids from nav.ts):
//   • ratings    (index/default) — crypto severity-ratings registry (ADR-0003)
// • frameworks — compliance framework catalog ()
import { Navigate, Route, Routes } from 'react-router';
import { RatingsPage } from './ratings-page';
import { FrameworksPage } from './frameworks-page';

export function CatalogPage() {
  return (
    <Routes>
      <Route index element={<RatingsPage />} />
      <Route path="ratings" element={<RatingsPage />} />
      <Route path="frameworks" element={<FrameworksPage />} />
      <Route path="*" element={<Navigate to="/catalog" replace />} />
    </Routes>
  );
}
