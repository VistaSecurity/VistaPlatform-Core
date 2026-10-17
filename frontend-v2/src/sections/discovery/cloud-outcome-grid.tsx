// The per-type, per-region outcome grid of a cloud discovery run
// (asset-inventory ADR-0009 D3): rows are resource types, columns the regions
// the run read (`global` for an account-wide call). Shown in the job detail
// and, compact, on the Discovery → Cloud account card.
import type { OutcomeTone, ResourceTypeOutcome } from './cloud-outcomes';
import { outcomeGrid } from './cloud-outcomes';

const TONE: Record<OutcomeTone, string> = {
  ok: 'var(--ok)',
  warn: 'var(--warn-strong)',
  danger: 'var(--danger-text)',
  muted: 'var(--app-t3)',
};

export function CloudOutcomeGrid({ types, compact = false }: { types: ResourceTypeOutcome[]; compact?: boolean }) {
  const grid = outcomeGrid(types);
  if (grid.regions.length === 0) {
    return <div style={{ fontSize: 11, color: 'var(--app-t3)' }}>This run reported no per-region outcome.</div>;
  }
  const fs = compact ? 10.5 : 11.5;
  return (
    <div style={{ overflowX: 'auto' }}>
      <table data-testid="cloud-outcome-grid" aria-label="Outcome by resource type and region" style={{ borderCollapse: 'collapse', fontSize: fs, width: '100%' }}>
        <thead>
          <tr>
            <th scope="col" style={{ textAlign: 'left', padding: '3px 8px 3px 0', color: 'var(--app-t3)', fontWeight: 600 }}>Type</th>
            {grid.regions.map((r) => (
              <th key={r} scope="col" className="mono" style={{ textAlign: 'right', padding: '3px 6px', color: 'var(--app-t3)', fontWeight: 600, whiteSpace: 'nowrap' }}>
                {r}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {grid.rows.map((row) => (
            <tr key={row.resourceType} style={{ borderTop: '1px solid var(--app-border)' }}>
              <th scope="row" style={{ textAlign: 'left', padding: '3px 8px 3px 0', fontWeight: 500, color: 'var(--app-t1)', whiteSpace: 'nowrap' }}>{row.label}</th>
              {grid.regions.map((r) => {
                const c = row.cells[r];
                return (
                  <td
                    key={r}
                    data-cell={`${row.resourceType}@${r}`}
                    data-status={c?.status ?? 'none'}
                    title={c?.title ?? 'not asked in this region'}
                    style={{ textAlign: 'right', padding: '3px 6px', color: c ? TONE[c.tone] : 'var(--app-t3)', fontWeight: c?.status === 'failed' ? 700 : 400 }}
                  >
                    {c ? c.text : '—'}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
