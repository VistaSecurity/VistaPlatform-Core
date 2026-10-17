// Settings -> Import (DCIM BUILD_PLAN row 2.7): pick an object kind, download
// its CSV template, drop a file, read the row-by-row plan (create / update /
// unchanged / error with the reason), then apply. Reading needs dcim.read; the
// Apply button needs the kind's own manage permission.
import { useRef, useState, type DragEvent } from 'react';
import { PermissionGate } from '@vistasecurity/primitives/rbac';
import { Icon } from '../../components/ui';
import { SPage, SCard, STable, STableRow, STag, StateNote } from './kit';
import type { SettingsNavItem } from './nav';
import { downloadTemplate, useBulkKinds, useBulkRun, type BulkPlan, type BulkRow } from './bulk-import-queries';

const ACTION_LABEL: Record<BulkRow['action'], string> = { create: 'Create', update: 'Update', unchanged: 'Unchanged', error: 'Error' };
const ACTION_COLOR: Record<BulkRow['action'], string> = {
  create: 'var(--ok)', update: 'var(--accent)', unchanged: 'var(--app-t3)', error: 'var(--danger-text)',
};

export function BulkImportPage({ meta }: { meta: SettingsNavItem }) {
  const kinds = useBulkKinds();
  const run = useBulkRun();
  const [kindKey, setKindKey] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [plan, setPlan] = useState<BulkPlan | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [templateError, setTemplateError] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);

  const list = kinds.data ?? [];
  const kind = list.find((k) => k.kind === kindKey) ?? list[0];

  const reset = () => { setFile(null); setPlan(null); run.reset(); if (input.current) input.current.value = ''; };
  const check = (f: File, k: string) => {
    setFile(f);
    setPlan(null);
    run.mutate({ kind: k, file: f, apply: false }, { onSuccess: setPlan });
  };
  const pick = (f: File | undefined) => { if (f && kind) check(f, kind.kind); };
  const onDrop = (e: DragEvent) => { e.preventDefault(); setDragOver(false); pick(e.dataTransfer.files[0]); };
  const apply = () => {
    if (file && kind) run.mutate({ kind: kind.kind, file, apply: true }, { onSuccess: setPlan });
  };
  const template = async () => {
    if (!kind) return;
    setTemplateError(null);
    try { await downloadTemplate(kind.kind); } catch (e) { setTemplateError(e instanceof Error ? e.message : 'The template could not be downloaded'); }
  };

  const pending = run.isPending;
  const applied = plan?.applied === true;
  const actionable = plan ? plan.summary.create + plan.summary.update : 0;

  return (
    <SPage eyebrow="Infrastructure" title="Import" job={meta.job}>
      {kinds.isError ? (
        <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load the importable kinds" message="The list of object kinds failed to load." /></SCard>
      ) : kinds.isLoading || !kind ? (
        <SCard><StateNote icon="loader" tone="var(--app-t3)" title="Loading…" message="Fetching the importable object kinds." /></SCard>
      ) : (
        <>
          <SCard>
            <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
              <label style={{ fontSize: 12.5, color: 'var(--app-t2)', display: 'flex', alignItems: 'center', gap: 8 }}>
                Import into
                <select aria-label="Object kind" data-testid="import-kind" value={kind.kind} disabled={pending}
                  onChange={(e) => { setKindKey(e.target.value); reset(); }}>
                  {list.map((k) => <option key={k.kind} value={k.kind}>{k.plural}</option>)}
                </select>
              </label>
              <button type="button" className="ui-btn sm" data-testid="import-template" onClick={() => { void template(); }}>
                <Icon name="download" size={13} />Download template
              </button>
              {templateError && <span role="alert" style={{ fontSize: 12, color: 'var(--danger-text)' }}>{templateError}</span>}
            </div>
            <div style={{ marginTop: 12, fontSize: 12, color: 'var(--app-t3)', lineHeight: 1.5 }}>
              Columns: {kind.columns.map((c, i) => (
                <span key={c.name}>{i > 0 && ', '}<span className="mono" style={{ color: c.required ? 'var(--app-t1)' : undefined }}>{c.name}{c.required ? '*' : ''}</span></span>
              ))}. A blank cell leaves a value alone; <span className="mono">-</span> clears it. Rows are matched to existing objects by name, not id.
            </div>
          </SCard>

          <div
            data-testid="import-drop" onDragOver={(e) => { e.preventDefault(); setDragOver(true); }} onDragLeave={() => setDragOver(false)} onDrop={onDrop}
            style={{ marginTop: 14, border: `1.5px dashed ${dragOver ? 'var(--accent)' : 'var(--app-border)'}`, borderRadius: 12, padding: 24, textAlign: 'center', color: 'var(--app-t2)' }}
          >
            <Icon name="file-up" size={20} />
            <div style={{ marginTop: 6, fontSize: 13 }}>{file ? file.name : 'Drop a CSV file here, or'}</div>
            <button type="button" className="ui-btn sm" style={{ marginTop: 8 }} disabled={pending} onClick={() => input.current?.click()}>
              {file ? 'Choose another file' : 'Choose a file'}
            </button>
            <input ref={input} type="file" accept=".csv,text/csv" aria-label="CSV file" data-testid="import-file" hidden onChange={(e) => pick(e.target.files?.[0])} />
          </div>

          <div style={{ marginTop: 14 }} aria-live="polite">
            {pending && (
              <SCard><StateNote icon="loader" tone="var(--app-t3)" title={applied || run.variables?.apply ? 'Importing…' : 'Checking the file…'} message="Reading every row against your inventory." /></SCard>
            )}
            {run.isError && !pending && (
              <SCard><StateNote icon="alert-triangle" tone="var(--danger-text)" title="The file was not accepted" message={run.error instanceof Error ? run.error.message : 'The request failed.'} /></SCard>
            )}
            {plan && !pending && (
              <PlanView plan={plan} kindLabel={kind.plural} previewNote={plan.preview}
                action={!applied && (
                  <PermissionGate permission={kind.permission}
                    fallback={<span data-testid="import-no-permission" style={{ fontSize: 12, color: 'var(--app-t3)' }}>Applying needs the <span className="mono">{kind.permission}</span> permission.</span>}>
                    <button type="button" className="ui-btn sm accent" data-testid="import-apply" disabled={actionable === 0} onClick={apply}>
                      {plan.summary.error > 0 ? `Apply ${actionable} valid ${actionable === 1 ? 'row' : 'rows'} (skip ${plan.summary.error})` : `Apply ${actionable} ${actionable === 1 ? 'row' : 'rows'}`}
                    </button>
                  </PermissionGate>
                )} />
            )}
          </div>
        </>
      )}
    </SPage>
  );
}

function PlanView({ plan, kindLabel, previewNote, action }: { plan: BulkPlan; kindLabel: string; previewNote: boolean; action: React.ReactNode }) {
  const s = plan.summary;
  const applied = plan.applied;
  const cols = [{ label: 'Line', w: '60px' }, { label: 'Result', w: '110px' }, { label: 'Row' }, { label: 'Detail' }];
  const nothing = s.create + s.update === 0 && s.error === 0;
  return (
    <div data-testid="import-plan">
      <SCard>
        <div style={{ display: 'flex', gap: 14, alignItems: 'center', flexWrap: 'wrap' }}>
          <strong style={{ fontSize: 13.5 }}>{applied ? `Imported ${kindLabel.toLowerCase()}` : 'Dry run — nothing has been written'}</strong>
          <span data-testid="import-summary" style={{ fontSize: 12.5, color: 'var(--app-t2)' }}>
            {s.create} {applied ? 'created' : 'to create'} · {s.update} {applied ? 'updated' : 'to update'} · {s.unchanged} unchanged · {s.error} {s.error === 1 ? 'error' : 'errors'}
          </span>
          <span style={{ marginLeft: 'auto' }}>{action}</span>
        </div>
        {previewNote && !applied && (
          <div style={{ marginTop: 8, fontSize: 12, color: 'var(--app-t3)' }}>
            This kind is checked for references and values here; the rules its own service applies show up per row when you apply.
          </div>
        )}
        {plan.unknown_columns && plan.unknown_columns.length > 0 && (
          <div style={{ marginTop: 8, fontSize: 12, color: 'var(--warn)' }}>Ignored columns: {plan.unknown_columns.join(', ')}</div>
        )}
      </SCard>
      {nothing ? (
        <div style={{ marginTop: 14 }}><SCard><StateNote icon="check" tone="var(--ok)" title="Nothing to change" message="Every row in the file already matches what is in your inventory." /></SCard></div>
      ) : (
        <div style={{ marginTop: 14 }}>
          <STable cols={cols}>
            {plan.rows.map((r, i) => (
              <STableRow key={r.row} first={i === 0} cols={cols} cells={[
                <span className="mono" style={{ fontSize: 12 }}>{r.row}</span>,
                <span data-testid="import-row-action" style={{ fontSize: 12, fontWeight: 600, color: ACTION_COLOR[r.action] }}>{ACTION_LABEL[r.action]}</span>,
                <span style={{ fontSize: 12.5 }}>{r.key === undefined || r.key === '' ? '—' : r.key}</span>,
                r.action === 'error'
                  ? <span data-testid="import-row-reason" style={{ fontSize: 12, color: 'var(--danger-text)' }}>{r.reason}</span>
                  : r.changed && r.changed.length > 0 ? <STag>{`changes ${r.changed.join(', ')}`}</STag> : <span />,
              ]} />
            ))}
          </STable>
        </div>
      )}
    </div>
  );
}
