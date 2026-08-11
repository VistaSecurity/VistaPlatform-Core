// Risk & Compliance · POSTURE — view switch driven by `?tab=` (the rail's
// Posture sub-links set it, same pattern as the Findings/Inventory lenses):
//   · overview    — standing/trend/control-grid (posture-overview.tsx)
//   · frameworks  — read-only browse of published frameworks → controls →
//                   measurements in plain language (framework-browser.tsx)
//   · algorithms  — read-only browse of the algorithms source-of-truth table
//                   + our assessment (algorithm-reference.tsx)
// The two new views surface data that already exists, under Posture because
// both are exactly what produces the posture score. Reachable from the rail
// (Risk & Compliance → Posture → Overview / Frameworks / Algorithm Reference).
import { useSearchParams } from 'react-router';
import { PostureOverview } from './posture-overview';
import { FrameworkBrowser } from './framework-browser';
import { AlgorithmReference } from './algorithm-reference';

export function PosturePage() {
  const [params] = useSearchParams();
  const raw = params.get('tab');
  const tab = raw === 'frameworks' || raw === 'algorithms' ? raw : 'overview';

  if (tab === 'frameworks') return <FrameworkBrowser />;
  if (tab === 'algorithms') return <AlgorithmReference />;
  return <PostureOverview />;
}
