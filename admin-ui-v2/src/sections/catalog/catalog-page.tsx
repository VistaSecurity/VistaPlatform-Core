// VISTA Operations — Catalog (Platform group). Thin layout that renders the
// left-rail sub-pages: sub-views live in the LEFT rail (see nav.ts children for
// `catalog`), NOT as in-page tabs. The section mounts on /catalog/* (see
// App.tsx), so child paths here are relative. Mirrors the reference
// security-page.tsx pattern.
//
// Children (ids from nav.ts):
//   • ratings         (index/default) — crypto severity-ratings registry (ADR-0003)
// • frameworks — compliance framework catalog ()
//   • eol             — end-of-life catalogue + its mirror feed (ADR-0005 D3),
//                       with three GRANDCHILDREN in the rail (ADR-0008 4.5b):
//                       eol/catalogue, eol/proposals, eol/gaps
//   • vulnerabilities — vulnerability catalogue + NVD/OSV feed status (ADR-0005 D3)
//   • classification-rules — the fingerprint rules behind class proposals (ADR-0004 D6)
//
// The last two are the point of ADR-0006 D7: crypto is ONE catalogue among
// several, and the non-crypto ones belong in the same place rather than in a
// section of their own.
import { Navigate, Route, Routes } from 'react-router';
import { RatingsPage } from './ratings-page';
import { FrameworksPage } from './frameworks-page';
import { EolPage } from './eol-page';
import { VulnerabilityPage } from './vulnerability-page';
import { ClassificationRulesPage } from './classification-rules-page';

export function CatalogPage() {
  return (
    <Routes>
      <Route index element={<RatingsPage />} />
      <Route path="ratings" element={<RatingsPage />} />
      <Route path="frameworks" element={<FrameworksPage />} />
      {/* End-of-life's three rail sub-views. Declared as flat two-segment
          relative paths rather than a nested layout so each grandchild is its
          own route react-router ranks above the catch-all below, and so the
          routing contract test can name every one of them. `eol` and
          `eol/catalogue` are the same view: the bare URL is what the parent
          rail entry links to, and nav.resolveActive resolves it to the first
          grandchild. */}
      <Route path="eol" element={<EolPage view="catalogue" />} />
      <Route path="eol/catalogue" element={<EolPage view="catalogue" />} />
      <Route path="eol/proposals" element={<EolPage view="proposals" />} />
      <Route path="eol/gaps" element={<EolPage view="gaps" />} />
      <Route path="vulnerabilities" element={<VulnerabilityPage />} />
      <Route path="classification-rules" element={<ClassificationRulesPage />} />
      <Route path="*" element={<Navigate to="/catalog" replace />} />
    </Routes>
  );
}
