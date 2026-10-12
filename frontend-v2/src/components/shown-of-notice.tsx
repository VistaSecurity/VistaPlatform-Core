/**
 * "Showing N of M" line for a list that is capped by its request page size.
 * Renders nothing when everything is shown, so a capped list never reads as the
 * whole set.
 */
export function ShownOfNotice({ shown, total, noun }: { shown: number; total: number; noun: string }) {
  if (total <= shown) return null;
  return (
    <div data-testid="shown-of-notice" role="note" style={{ fontSize: 12, color: 'var(--app-t3)', padding: '6px 0' }}>
      Showing <strong>{shown}</strong> of <strong>{total}</strong> {noun}.
    </div>
  );
}
