// Import-from-spreadsheet wizard. Upload a CSV/XLSX, map its columns to
// asset or network-segment fields, validate client-side, then bulk-create via
// the inventory-service /bulk endpoints. Two targets share one wizard:
//   - "segments" → POST /network-segments/bulk  (scan targets)
//   - "assets"   → POST /infrastructure-assets/bulk  (CI records)
// Launched from the Discovery command center (both targets) and from
// Settings → Network Segments (locked to "segments").
import { useEffect, useMemo, useRef, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { Modal, ModalField, ModalSelect, Icon } from '../../components/ui';

type AssetInput = inventoryComponents['schemas']['AssetInput'];
type NetworkSegmentInput = inventoryComponents['schemas']['NetworkSegmentInput'];
type BulkImportResult = inventoryComponents['schemas']['BulkImportResult'];

export type ImportTarget = 'assets' | 'segments';

type Phase = 'type' | 'upload' | 'map' | 'preview' | 'result';

// A target field the wizard can populate from a spreadsheet column.
interface FieldSpec {
  key: string;
  label: string;
  required?: boolean; // must be satisfied by a mapped column OR (for enums) a default
  enumOptions?: string[]; // when set, the field is an enum with a default-value fallback
  guess: string[]; // lowercased header substrings used to auto-map
}

const ASSET_FIELDS: FieldSpec[] = [
  { key: 'hostname', label: 'Hostname', guess: ['hostname', 'host name', 'fqdn', 'host', 'name', 'server'] },
  { key: 'ip_address', label: 'IP address', guess: ['ip address', 'ip_addr', 'ipaddress', 'ip', 'address'] },
  { key: 'asset_type', label: 'Asset type', required: true, enumOptions: ['server', 'workstation', 'network_device', 'firewall', 'load_balancer', 'vm', 'container', 'database', 'application', 'other'], guess: ['asset type', 'type', 'category', 'kind'] },
  { key: 'environment', label: 'Environment', enumOptions: ['production', 'staging', 'development', 'test'], guess: ['environment', 'env', 'tier'] },
  { key: 'operating_system', label: 'Operating system', guess: ['operating system', 'os', 'platform'] },
  { key: 'business_unit', label: 'Business unit', guess: ['business unit', 'business_unit', 'bu', 'department', 'team', 'org'] },
  { key: 'owner_email', label: 'Owner email', guess: ['owner email', 'owner', 'email', 'contact'] },
  { key: 'description', label: 'Description', guess: ['description', 'notes', 'comment', 'desc'] },
];

const SEGMENT_FIELDS: FieldSpec[] = [
  { key: 'name', label: 'Name', required: true, guess: ['name', 'segment', 'label', 'description'] },
  { key: 'value', label: 'Value (CIDR / range / domain)', required: true, guess: ['value', 'cidr', 'subnet', 'range', 'network', 'address', 'ip'] },
  { key: 'segment_type', label: 'Segment type', required: true, enumOptions: ['cidr', 'ip_range', 'domain', 'cloud_vpc'], guess: ['segment type', 'segment_type', 'type'] },
  { key: 'network_type', label: 'Network type', required: true, enumOptions: ['private', 'public', 'vpn', 'cloud'], guess: ['network type', 'network_type', 'network', 'scope'] },
  { key: 'environment', label: 'Environment', required: true, enumOptions: ['production', 'staging', 'development', 'test'], guess: ['environment', 'env', 'tier'] },
  { key: 'business_unit', label: 'Business unit', guess: ['business unit', 'business_unit', 'bu', 'department', 'team'] },
  { key: 'owner_email', label: 'Owner email', guess: ['owner email', 'owner', 'email', 'contact'] },
  { key: 'description', label: 'Description', guess: ['description', 'notes', 'comment'] },
];

type Row = Record<string, unknown>;

function autoGuess(fields: FieldSpec[], columns: string[]): Record<string, string> {
  const map: Record<string, string> = {};
  const used = new Set<string>();
  for (const f of fields) {
    const hit = columns.find((c) => {
      if (used.has(c)) return false;
      const lc = c.trim().toLowerCase();
      return f.guess.some((g) => lc === g || lc.includes(g));
    });
    if (hit) {
      map[f.key] = hit;
      used.add(hit);
    } else {
      map[f.key] = '';
    }
  }
  return map;
}

function cellStr(v: unknown): string {
  if (v === null || v === undefined) return '';
  return String(v).trim();
}

const CIDR_RE = /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/;

// Build a typed input object for one spreadsheet row from the column mapping and
// enum defaults. Returns the object plus a per-row validation error (or null).
function buildAsset(row: Row, mapping: Record<string, string>, defaults: Record<string, string>): { input: AssetInput; error: string | null } {
  const get = (key: string) => {
    const col = mapping[key];
    const v = col ? cellStr(row[col]) : '';
    return v || defaults[key] || '';
  };
  const hostname = get('hostname');
  const ip = get('ip_address');
  const assetType = get('asset_type');
  const input: AssetInput = {
    asset_type: assetType,
    hostname: hostname || undefined,
    ip_address: ip || undefined,
    environment: get('environment') || undefined,
    operating_system: get('operating_system') || undefined,
    business_unit: get('business_unit') || undefined,
    owner_email: get('owner_email') || undefined,
    description: get('description') || undefined,
  };
  let error: string | null = null;
  if (!assetType) error = 'asset type is required';
  else if (!hostname && !ip) error = 'a hostname or IP is required';
  return { input, error };
}

function buildSegment(row: Row, mapping: Record<string, string>, defaults: Record<string, string>): { input: NetworkSegmentInput; error: string | null } {
  const get = (key: string) => {
    const col = mapping[key];
    const v = col ? cellStr(row[col]) : '';
    return v || defaults[key] || '';
  };
  const name = get('name');
  const value = get('value');
  const segType = get('segment_type');
  const netType = get('network_type');
  const env = get('environment');
  const input: NetworkSegmentInput = {
    name,
    value,
    segment_type: segType,
    network_type: netType,
    environment: env,
    business_unit: get('business_unit') || undefined,
    owner_email: get('owner_email') || undefined,
    description: get('description') || undefined,
  };
  let error: string | null = null;
  if (!name) error = 'name is required';
  else if (!value) error = 'value is required';
  else if (!segType || !netType || !env) error = 'segment type, network type and environment are required';
  else if (segType === 'cidr' && !CIDR_RE.test(value)) error = `"${value}" is not a valid CIDR`;
  else if (segType === 'ip_range' && !value.includes('-')) error = `"${value}" is not an IP range (expected start-end)`;
  return { input, error };
}

const TARGET_LABEL: Record<ImportTarget, string> = {
  assets: 'infrastructure assets',
  segments: 'network segments',
};

export function ImportSpreadsheetModal({
  open,
  onClose,
  lockedTarget,
}: {
  open: boolean;
  onClose: () => void;
  lockedTarget?: ImportTarget; // when set, skip the target-picker step
}) {
  const qc = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);

  const [phase, setPhase] = useState<Phase>(lockedTarget ? 'upload' : 'type');
  const [target, setTarget] = useState<ImportTarget>(lockedTarget ?? 'segments');
  const [fileName, setFileName] = useState('');
  const [columns, setColumns] = useState<string[]>([]);
  const [rows, setRows] = useState<Row[]>([]);
  const [mapping, setMapping] = useState<Record<string, string>>({});
  const [defaults, setDefaults] = useState<Record<string, string>>({});
  const [parseErr, setParseErr] = useState<string | null>(null);
  const [result, setResult] = useState<BulkImportResult | null>(null);

  const fields = target === 'assets' ? ASSET_FIELDS : SEGMENT_FIELDS;

  useEffect(() => {
    if (open) {
      setPhase(lockedTarget ? 'upload' : 'type');
      setTarget(lockedTarget ?? 'segments');
      setFileName('');
      setColumns([]);
      setRows([]);
      setMapping({});
      setDefaults({});
      setParseErr(null);
      setResult(null);
    }
  }, [open, lockedTarget]);

  // Seed enum defaults to the first option whenever the target changes.
  useEffect(() => {
    const d: Record<string, string> = {};
    for (const f of fields) if (f.enumOptions) d[f.key] = f.enumOptions[0];
    setDefaults(d);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target]);

  function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.currentTarget.files?.[0];
    if (!f) return;
    setFileName(f.name);
    setParseErr(null);
    const lower = f.name.toLowerCase();
    const finish = (cols: string[], data: Row[]) => {
      if (cols.length === 0 || data.length === 0) {
        setParseErr('No rows found. Make sure the first row is a header and there is at least one data row.');
        return;
      }
      setColumns(cols);
      setRows(data);
      setMapping(autoGuess(fields, cols));
      setPhase('map');
    };
    // Parsers are dynamically imported so the spreadsheet lib stays out of the
    // main bundle and only loads when a user actually imports a file.
    if (lower.endsWith('.csv')) {
      import('papaparse')
        .then(({ default: Papa }) => {
          Papa.parse<Row>(f, {
            header: true,
            skipEmptyLines: true,
            complete: (res) => finish((res.meta.fields ?? []).filter(Boolean), res.data as Row[]),
            error: (err: Error) => setParseErr(err.message || 'Failed to parse CSV'),
          });
        })
        .catch(() => setParseErr('Failed to load the CSV parser.'));
    } else if (lower.endsWith('.xlsx')) {
      // exceljs (maintained) replaced the unmaintained, vulnerable `xlsx`/SheetJS
      // (prototype-pollution + ReDoS on untrusted uploads, no npm fix). exceljs
      // reads OOXML (.xlsx) only — legacy .xls (BIFF) is no longer accepted.
      Promise.all([f.arrayBuffer(), import('exceljs')])
        .then(async ([buf, { default: ExcelJS }]) => {
          const wb = new ExcelJS.Workbook();
          await wb.xlsx.load(buf);
          const ws = wb.worksheets[0];
          if (!ws) { setParseErr('The workbook has no sheets.'); return; }
          // Header row = row 1; map each populated column index to its header name.
          const headers = new Map<number, string>();
          const cols: string[] = [];
          ws.getRow(1).eachCell({ includeEmpty: false }, (cell, colNumber) => {
            const name = cell.text.trim();
            if (name) { headers.set(colNumber, name); cols.push(name); }
          });
          const data: Row[] = [];
          ws.eachRow({ includeEmpty: false }, (row, rowNumber) => {
            if (rowNumber === 1) return; // skip header
            const obj: Row = {};
            let hasValue = false;
            for (const [colNumber, name] of headers) {
              // cell.text renders rich text / formula results / dates as strings,
              // avoiding "[object Object]" from raw cell.value objects.
              const text = row.getCell(colNumber).text;
              obj[name] = text;
              if (text.trim() !== '') hasValue = true;
            }
            if (hasValue) data.push(obj);
          });
          finish(cols, data);
        })
        .catch((err) => setParseErr(err instanceof Error ? err.message : 'Failed to parse spreadsheet'));
    } else {
      setParseErr('Unsupported file type. Upload a .csv or .xlsx file.');
    }
  }

  // Build + validate all rows for the preview/commit steps.
  const built = useMemo(() => {
    if (target === 'assets') {
      return rows.map((r) => buildAsset(r, mapping, defaults));
    }
    return rows.map((r) => buildSegment(r, mapping, defaults));
  }, [rows, mapping, defaults, target]);

  const validRows = built.filter((b) => !b.error);
  const invalidRows = built.filter((b) => b.error);

  // Required text fields (no enum default) must be mapped before mapping is complete.
  const unmappedRequired = fields.filter((f) => f.required && !f.enumOptions && !mapping[f.key]);
  const mapComplete = unmappedRequired.length === 0;

  const importM = useMutation({
    mutationFn: async () => {
      const payloadRows = validRows.map((b) => b.input);
      if (target === 'assets') {
        const { data, error } = await clients.inventory.POST('/infrastructure-assets/bulk', {
          body: { rows: payloadRows as AssetInput[] },
        });
        if (error || !data) throw new Error('Import failed');
        return data as BulkImportResult;
      }
      const { data, error } = await clients.inventory.POST('/network-segments/bulk', {
        body: { rows: payloadRows as NetworkSegmentInput[] },
      });
      if (error || !data) throw new Error('Import failed');
      return data as BulkImportResult;
    },
    onSuccess: (data) => {
      setResult(data);
      setPhase('result');
      toast.success(`Imported ${data.created} ${TARGET_LABEL[target]}`);
      qc.invalidateQueries({ queryKey: ['inventory'] });
      qc.invalidateQueries({ queryKey: ['settings', 'network-segments'] });
      qc.invalidateQueries({ queryKey: ['discovery'] });
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Import failed'),
  });

  // Active Scan handoff (): after an asset import, offer to scan the just-created
  // assets so their crypto gets cataloged (imported assets land crypto-empty + pending; the
  // scan approves + dispatches a TLS probe).
  const scanM = useMutation({
    mutationFn: async (ids: string[]) => {
      const { data, error } = await clients.inventory.POST('/infrastructure-assets/scan', { body: { asset_ids: ids } });
      if (error || !data) throw new Error('Failed to start scan');
      return data;
    },
    onSuccess: (d) => {
      toast.success(`Active scan started for ${d.count ?? ''} asset${(d.count ?? 2) === 1 ? '' : 's'}`);
      qc.invalidateQueries({ queryKey: ['inventory'] });
      qc.invalidateQueries({ queryKey: ['discovery'] });
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Scan failed'),
  });

  // ---- footer buttons per phase ----
  let primary: React.ReactNode = null;
  let secondary: React.ReactNode = null;
  const busy = importM.isPending;

  if (phase === 'type') {
    primary = <button className="ui-btn accent" onClick={() => setPhase('upload')}>Next</button>;
    secondary = <button className="ui-btn" onClick={onClose}>Cancel</button>;
  } else if (phase === 'upload') {
    primary = <button className="ui-btn accent" disabled={rows.length === 0} onClick={() => setPhase('map')}>Next</button>;
    secondary = <button className="ui-btn" onClick={lockedTarget ? onClose : () => setPhase('type')}>{lockedTarget ? 'Cancel' : 'Back'}</button>;
  } else if (phase === 'map') {
    primary = <button className="ui-btn accent" disabled={!mapComplete} onClick={() => setPhase('preview')}>Review</button>;
    secondary = <button className="ui-btn" onClick={() => setPhase('upload')}>Back</button>;
  } else if (phase === 'preview') {
    // The submit permission follows the target's route, not the wizard:
    // POST /infrastructure-assets/bulk is assets.create, POST
    // /network-segments/bulk is settings.update.
    primary = (
      <PermissionGate permission={target === 'assets' ? TENANT_PERMISSIONS.assets.create : TENANT_PERMISSIONS.settings.update}>
        <button className="ui-btn accent" disabled={validRows.length === 0 || busy} onClick={() => importM.mutate()}>
          {busy ? 'Importing…' : `Import ${validRows.length} ${validRows.length === 1 ? 'row' : 'rows'}`}
        </button>
      </PermissionGate>
    );
    secondary = <button className="ui-btn" onClick={() => setPhase('map')} disabled={busy}>Back</button>;
  } else if (phase === 'result') {
    primary = <button className="ui-btn accent" onClick={onClose}>Done</button>;
  }

  return (
    <Modal
      open={open}
      onClose={busy ? undefined : onClose}
      dismissible={!busy}
      size="lg"
      tone="accent"
      icon="upload"
      eyebrow={target === 'assets' ? 'Discovery · Import' : 'Network Segments · Import'}
      title="Import from spreadsheet"
      description={`Upload a CSV or Excel file and map its columns to create ${TARGET_LABEL[target]} in bulk.`}
      primary={primary}
      secondary={secondary}
      footerNote={parseErr ? <span style={{ color: 'var(--danger-text)' }}>{parseErr}</span> : undefined}
    >
      {phase === 'type' && (
        <div style={{ display: 'grid', gap: 10 }}>
          <TargetCard active={target === 'segments'} onClick={() => setTarget('segments')} icon="network"
            title="Network segments" desc="CIDRs, IP ranges or domains to scan for crypto assets." />
          <TargetCard active={target === 'assets'} onClick={() => setTarget('assets')} icon="server"
            title="Infrastructure assets" desc="Known servers / devices (hostname, IP, owner) as CI records." />
        </div>
      )}

      {phase === 'upload' && (
        <ModalField label="Spreadsheet file" hint="CSV or XLSX. The first row must be a header. Up to 1000 rows per import.">
          <input
            ref={fileRef}
            type="file"
            accept=".csv,.xlsx"
            onChange={onFile}
            style={{ width: '100%', padding: '9px 12px', borderRadius: 9, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 13 }}
          />
          {fileName && rows.length > 0 && (
            <div style={{ fontSize: 12, color: 'var(--app-t2)', marginTop: 8 }}>
              <Icon name="check" size={12} /> {fileName} — {rows.length} row{rows.length === 1 ? '' : 's'}, {columns.length} columns detected.
            </div>
          )}
        </ModalField>
      )}

      {phase === 'map' && (
        <div>
          <div style={{ fontSize: 12, color: 'var(--app-t3)', marginBottom: 12 }}>
            Map your spreadsheet columns to {TARGET_LABEL[target]} fields. Required fields are marked. Enum fields fall back to the chosen default when a column isn't mapped or a cell is blank.
          </div>
          <div style={{ display: 'grid', gap: 12 }}>
            {fields.map((f) => (
              <div key={f.key} style={{ display: 'grid', gridTemplateColumns: f.enumOptions ? '1fr 1fr' : '1fr', gap: 8, alignItems: 'end' }}>
                <ModalField label={`${f.label}${f.required ? ' *' : ''}`} hint={mapping[f.key] ? undefined : f.required && !f.enumOptions ? 'Map a column' : undefined}>
                  <ModalSelect value={mapping[f.key] || ''} onChange={(e) => setMapping((m) => ({ ...m, [f.key]: e.target.value }))}>
                    <option value="">— not mapped —</option>
                    {columns.map((c) => <option key={c} value={c}>{c}</option>)}
                  </ModalSelect>
                </ModalField>
                {f.enumOptions && (
                  <ModalField label={`Default ${f.label.toLowerCase()}`} hint="used when unmapped/blank">
                    <ModalSelect value={defaults[f.key] || f.enumOptions[0]} onChange={(e) => setDefaults((d) => ({ ...d, [f.key]: e.target.value }))}>
                      {f.enumOptions.map((o) => <option key={o} value={o}>{o}</option>)}
                    </ModalSelect>
                  </ModalField>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {phase === 'preview' && (
        <div>
          <div style={{ display: 'flex', gap: 16, marginBottom: 12 }}>
            <Stat label="Will import" value={validRows.length} tone="var(--ok)" />
            <Stat label="Skipped (invalid)" value={invalidRows.length} tone={invalidRows.length ? 'var(--warn-strong)' : 'var(--app-t3)'} />
            <Stat label="Total rows" value={rows.length} tone="var(--app-t2)" />
          </div>
          <PreviewTable target={target} built={built} />
          {invalidRows.length > 0 && (
            <div style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 8 }}>
              Invalid rows are skipped, not imported. Go Back to fix the mapping or your spreadsheet.
            </div>
          )}
        </div>
      )}

      {phase === 'result' && result && (
        <div>
          <div style={{ display: 'flex', gap: 16, marginBottom: 14 }}>
            <Stat label="Created" value={result.created} tone="var(--ok)" />
            <Stat label="Skipped" value={result.skipped} tone="var(--warn-strong)" />
            <Stat label="Failed" value={result.failed} tone={result.failed ? 'var(--danger)' : 'var(--app-t3)'} />
          </div>
          {(result.skipped > 0 || result.failed > 0) && (
            <ResultTable result={result} />
          )}
          {target === 'segments' && result.created > 0 && (
            <div style={{ fontSize: 12, color: 'var(--app-t2)', marginTop: 12 }}>
              <Icon name="radar" size={12} /> Next: run a discovery scan on these segments from the Command Center to find crypto assets.
            </div>
          )}
          {target === 'assets' && (() => {
            const ids = (result.results ?? []).filter((r) => r.status === 'created' && r.id).map((r) => r.id as string);
            if (ids.length === 0) return null;
            return (
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 14, padding: 12, borderRadius: 10, background: 'var(--app-panel2)' }}>
                <Icon name="radar" size={16} />
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--app-t1)' }}>Scan {ids.length} imported asset{ids.length === 1 ? '' : 's'} now?</div>
                  <div style={{ fontSize: 12, color: 'var(--app-t2)', marginTop: 2 }}>Imported assets have no cryptography yet. An Active Scan approves them and probes for certificates + cipher configs.</div>
                </div>
                <PermissionGate permission={TENANT_PERMISSIONS.assets.update}>
                  <button className="ui-btn sm accent" disabled={scanM.isPending} onClick={() => scanM.mutate(ids)}>
                    <Icon name="radar" size={13} />{scanM.isPending ? 'Starting…' : 'Scan now'}
                  </button>
                </PermissionGate>
              </div>
            );
          })()}
        </div>
      )}
    </Modal>
  );
}

// ---- small presentational helpers ----

function TargetCard({ active, onClick, icon, title, desc }: { active: boolean; onClick: () => void; icon: string; title: string; desc: string }) {
  return (
    <button
      onClick={onClick}
      className="panel"
      style={{
        display: 'flex', gap: 12, alignItems: 'flex-start', textAlign: 'left', padding: 14, borderRadius: 12, cursor: 'pointer',
        border: active ? '1px solid var(--accent)' : '1px solid var(--app-border2)',
        background: active ? 'var(--app-panel2)' : 'var(--app-panel)',
      }}
    >
      <Icon name={icon} size={18} />
      <div>
        <div style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--app-t1)' }}>{title}</div>
        <div style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 3 }}>{desc}</div>
      </div>
    </button>
  );
}

function Stat({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div>
      <div style={{ fontSize: 20, fontWeight: 700, color: tone }}>{value}</div>
      <div className="eyebrow-app">{label}</div>
    </div>
  );
}

function PreviewTable({ target, built }: { target: ImportTarget; built: { input: AssetInput | NetworkSegmentInput; error: string | null }[] }) {
  const shown = built.slice(0, 8);
  return (
    <div className="panel" style={{ borderRadius: 12, overflow: 'auto', maxHeight: 260 }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
        <thead>
          <tr style={{ position: 'sticky', top: 0, background: 'var(--app-panel)' }}>
            <th style={thStyle}>#</th>
            {target === 'assets' ? (
              <><th style={thStyle}>Hostname</th><th style={thStyle}>IP</th><th style={thStyle}>Type</th></>
            ) : (
              <><th style={thStyle}>Name</th><th style={thStyle}>Value</th><th style={thStyle}>Seg type</th></>
            )}
            <th style={thStyle}>Status</th>
          </tr>
        </thead>
        <tbody>
          {shown.map((b, i) => {
            const a = b.input as AssetInput;
            const s = b.input as NetworkSegmentInput;
            return (
              <tr key={i} style={{ borderTop: '1px solid var(--app-border)' }}>
                <td style={tdStyle}>{i + 1}</td>
                {target === 'assets' ? (
                  <><td style={tdStyle}>{a.hostname || '—'}</td><td style={tdStyle}>{a.ip_address || '—'}</td><td style={tdStyle}>{a.asset_type || '—'}</td></>
                ) : (
                  <><td style={tdStyle}>{s.name || '—'}</td><td style={tdStyle}>{s.value || '—'}</td><td style={tdStyle}>{s.segment_type || '—'}</td></>
                )}
                <td style={{ ...tdStyle, color: b.error ? 'var(--warn-strong)' : 'var(--ok)' }}>{b.error ? b.error : 'ok'}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {built.length > shown.length && (
        <div style={{ fontSize: 11, color: 'var(--app-t3)', padding: '6px 10px' }}>…and {built.length - shown.length} more rows.</div>
      )}
    </div>
  );
}

function ResultTable({ result }: { result: BulkImportResult }) {
  const notable = (result.results ?? []).filter((r) => r.status !== 'created').slice(0, 12);
  if (notable.length === 0) return null;
  return (
    <div className="panel" style={{ borderRadius: 12, overflow: 'auto', maxHeight: 220 }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
        <thead>
          <tr style={{ position: 'sticky', top: 0, background: 'var(--app-panel)' }}>
            <th style={thStyle}>Row</th><th style={thStyle}>Status</th><th style={thStyle}>Reason</th>
          </tr>
        </thead>
        <tbody>
          {notable.map((r, i) => (
            <tr key={i} style={{ borderTop: '1px solid var(--app-border)' }}>
              <td style={tdStyle}>{r.index + 1}</td>
              <td style={{ ...tdStyle, color: r.status === 'error' ? 'var(--danger)' : 'var(--warn-strong)' }}>{r.status.replace('_', ' ')}</td>
              <td style={tdStyle}>{r.reason || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const thStyle: React.CSSProperties = { textAlign: 'left', padding: '7px 10px', fontSize: 10.5, textTransform: 'uppercase', letterSpacing: 0.4, color: 'var(--app-t3)', fontWeight: 600 };
const tdStyle: React.CSSProperties = { padding: '6px 10px', color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 220 };
