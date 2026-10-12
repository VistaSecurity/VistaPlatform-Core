import { Suspense } from 'react';
import { Outlet } from 'react-router';

// The one Suspense boundary for the route-level code splitting in App.tsx.
// It sits inside AppShell's <Outlet/>, so the rail, topbar and palette stay
// painted while a section's chunk loads; only the page body shows the fallback.
export function SectionSuspense() {
  return (
    <Suspense
      fallback={
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 40, color: 'var(--op-t3)', fontSize: 13 }}>
          Loading…
        </div>
      }
    >
      <Outlet />
    </Suspense>
  );
}
