// <ChangeDiff id /> — the field-level diff of one recorded change (DCIM
// BUILD_PLAN row 5.2): a Field / Before / After table from GET /dcim/changes/{id}.
// Secrets were redacted when the change was recorded, so a changed secret is
// listed with the redaction marker on both sides: the person sees that it
// moved, never what it was.
import { useChangeDetail } from './substrate-queries';
import { PanelError, PanelLoading } from './substrate-states';

/** A JSON value as one line of text; null and absent read as an em dash. */
export function diffValueText(v: unknown): string {
  if (v === null || v === undefined) return '—';
  if (typeof v === 'string') return v === '' ? '(empty)' : v;
  return JSON.stringify(v);
}

const cell = { padding: '6px 8px', verticalAlign: 'top', wordBreak: 'break-word', fontSize: 12 } as const;

export function ChangeDiff({ id }: { id: string }) {
  const q = useChangeDetail(id);
  if (q.isLoading) return <PanelLoading label="Loading the diff…" />;
  if (q.isError) return <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />;
  const diff = q.data?.diff ?? [];
  if (diff.length === 0) return <div data-testid="change-diff-empty" style={{ fontSize: 12, color: 'var(--app-t3)', padding: '6px 0' }}>No field changed.</div>;
  return (
    <table data-testid="change-diff" style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed' }}>
      <thead>
        <tr style={{ textAlign: 'left', color: 'var(--app-t3)', fontSize: 11 }}>
          <th style={{ ...cell, width: '24%' }}>Field</th><th style={cell}>Before</th><th style={cell}>After</th>
        </tr>
      </thead>
      <tbody>
        {diff.map((d) => (
          <tr key={d.field} data-testid="change-diff-row" style={{ borderTop: '1px solid var(--app-border)' }}>
            <td className="mono" style={cell}>{d.field}</td>
            <td className="mono" data-testid="diff-before" style={{ ...cell, background: d.before === null || d.before === undefined ? undefined : 'color-mix(in srgb, var(--danger) 8%, transparent)' }}>{diffValueText(d.before)}</td>
            <td className="mono" data-testid="diff-after" style={{ ...cell, background: d.after === null || d.after === undefined ? undefined : 'color-mix(in srgb, var(--ok, var(--accent)) 10%, transparent)' }}>{diffValueText(d.after)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
