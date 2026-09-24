// Seeded-content ownership in the catalogue (decision 4, RC-12).
//
// Frameworks, controls, measurement rules and classification rules that Vista
// ships now belong to the platform admin once edited: upgrades keep the edit
// and, when Vista ships something new for that row, offer it instead of
// writing it. These two pieces show that on a row — where it came from, whether
// it has been changed here — and the one action the offer needs: accept.
import { ArrowDownToLine } from 'lucide-react';
import { Tag } from '../../components/ui/primitives';

export interface SeededState {
  content_origin?: 'vista' | 'custom';
  admin_modified?: boolean;
  update_available?: boolean;
  offered_update?: Record<string, unknown>;
}

/** "Vista" (shipped) or "Custom", plus "Modified" when a shipped row was edited here. */
export function SeededContentBadges({ row }: { row: SeededState }) {
  if (row.content_origin !== 'vista') {
    return row.content_origin === 'custom' ? <Tag color="var(--op-t3)">Custom</Tag> : null;
  }
  return (
    <>
      <Tag color="var(--info)">
        <span title="Shipped with Vista Platform">Vista</span>
      </Tag>
      {row.admin_modified && (
        <Tag color="var(--warn)">
          <span title="Edited here. Upgrades keep this version and offer later shipped changes instead of applying them.">Modified</span>
        </Tag>
      )}
    </>
  );
}

function show(v: unknown): string {
  if (v === null || v === undefined) return '(none)';
  if (typeof v === 'string') return v.length > 80 ? `${v.slice(0, 77)}…` : v;
  return JSON.stringify(v);
}

/** What an offer would change, one "field: current → shipped" line each. */
export function describeOffer(row: SeededState & Record<string, unknown>): string {
  const offer = row.offered_update ?? {};
  return Object.keys(offer)
    .sort()
    .map((k) => `${k.replace(/_/g, ' ')}: ${show(row[k])} → ${show(offer[k])}`)
    .join('\n');
}

/**
 * The "Update available" action. Rendered only while the row carries an offer;
 * its tooltip lists exactly what accepting writes, and so does the confirm
 * step before anything is written — the tooltip alone is not there on a
 * touch device, and accepting overwrites the admin's own values.
 */
export function AcceptUpdateButton({
  row, pending, onAccept, label,
}: {
  row: SeededState & Record<string, unknown>;
  pending: boolean;
  onAccept: () => void;
  label: string;
}) {
  if (!row.update_available) return null;
  return (
    <button
      className="op-btn sm"
      type="button"
      aria-label={`Accept the shipped update for ${label}`}
      title={`Vista ships an update for ${label}. Accepting writes:\n${describeOffer(row)}`}
      disabled={pending}
      onClick={() => {
        if (window.confirm(`Accept the shipped update for ${label}? This replaces your values:\n\n${describeOffer(row)}`)) onAccept();
      }}
      data-testid="accept-shipped-update"
    >
      <ArrowDownToLine size={12} />Update available
    </button>
  );
}
