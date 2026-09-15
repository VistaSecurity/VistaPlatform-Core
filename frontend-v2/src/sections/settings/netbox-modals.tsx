// Settings · Integrations — the NetBox connector (workstream 2.7).
//
// A NetBox is a network team's statement of what the network is MEANT to be.
// We pull it; we never write to it. The Drift modal says so on the page, not
// only in the docs — a read-only promise the product does not state is a
// promise the user has to take on trust.
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { clients } from '../../lib/clients';
import { Icon, Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import { SCard, STable, STableRow, STag, StateNote, SToggle, relTime, GREEN, AMBER, RED } from './kit';
import { ASSET_CLASSES, ASSET_CLASS_KEYS } from '@vistasecurity/primitives/assets';
import {
  NETBOX_CONNECTIONS_KEY,
  netboxDriftQuery,
  netboxRunsQuery,
  roleMappingRecord,
  roleMappingRows,
  runSummaryLine,
  runTone,
  type ConnectorRun,
  type NetBoxConnection,
  type RoleMappingRow,
} from './connectors-queries';

const SCHEDULES: Array<[string, string]> = [
  ['manual', 'Manual only'],
  ['hourly', 'Hourly'],
  ['daily', 'Daily'],
  ['weekly', 'Weekly'],
];

const ENVIRONMENTS: Array<[string, string]> = [
  ['production', 'Production'],
  ['staging', 'Staging'],
  ['development', 'Development'],
  ['test', 'Test'],
];

const TONE: Record<string, string> = { ok: GREEN, warn: AMBER, danger: RED, muted: 'var(--app-t3)' };

// The classes a NetBox device role may be mapped onto: the hardware subtree
// (a DCIM holds physical and virtual infrastructure) plus `unknown_host`, which
// is where an unrecognised role lands anyway and is a legitimate thing to say
// on purpose. Deliberately not every class — mapping a device role onto
// `business_service` or `object_storage` would be nonsense the server would
// accept, and a picker that offers nonsense invites it.
const MAPPABLE_CLASSES = ASSET_CLASS_KEYS
  .filter((k) => ASSET_CLASSES[k].path.startsWith('hardware') || k === 'unknown_host')
  .map((k) => [k, ASSET_CLASSES[k].label] as const);

export function statusTone(status?: string | null): string {
  return TONE[runTone(status ?? '')];
}

// ---------------------------------------------------------------------------
// Create / edit
// ---------------------------------------------------------------------------

export function NetBoxConnectionModal({
  connection, open, onClose,
}: { connection: NetBoxConnection | null; open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const isEdit = !!connection;

  const [name, setName] = useState(connection?.name ?? '');
  const [baseUrl, setBaseUrl] = useState(connection?.base_url ?? '');
  const [token, setToken] = useState('');
  const [schedule, setSchedule] = useState<NetBoxConnection['schedule']>(connection?.schedule ?? 'daily');
  const [environment, setEnvironment] = useState(connection?.options?.default_environment ?? 'production');
  // Defaults ON: a network source of truth is on-premises by construction, and
  // a default of off makes the common case fail on save with an error most
  // operators read as "this product cannot talk to my network".
  const [allowPrivate, setAllowPrivate] = useState(connection?.allow_private_endpoint ?? true);
  const [enabled, setEnabled] = useState(connection?.is_enabled ?? true);
  const [roleRows, setRoleRows] = useState<RoleMappingRow[]>(
    () => roleMappingRows(connection?.options?.role_class_overrides),
  );

  const setRow = (i: number, patch: Partial<RoleMappingRow>) =>
    setRoleRows((rows) => rows.map((r, n) => (n === i ? { ...r, ...patch } : r)));

  // On edit the token may be left blank — the server keeps the stored one. On
  // create it is required, because a NetBox connection without one can do
  // nothing at all.
  const valid = name.trim() !== '' && baseUrl.trim() !== '' && (isEdit || token.trim() !== '');

  const save = useMutation({
    mutationFn: async () => {
      const body = {
        name: name.trim(),
        base_url: baseUrl.trim(),
        ...(token.trim() ? { api_token: token.trim() } : {}),
        default_environment: environment,
        role_class_overrides: roleMappingRecord(roleRows),
        allow_private_endpoint: allowPrivate,
        is_enabled: enabled,
        schedule,
      };
      const res = isEdit
        ? await clients.inventory.PUT('/connectors/netbox/connections/{id}', {
            params: { path: { id: connection.id } }, body,
          })
        : await clients.inventory.POST('/connectors/netbox/connections', { body });
      if (res.error || !res.response.ok) {
        // The server's message is the useful one here — it says WHY a URL was
        // refused (http:// when a token is a bearer credential, a private
        // address without the opt-in). Swallowing it for a house-style string
        // would leave the user guessing.
        const detail = (res.error as { error?: string } | undefined)?.error;
        throw new Error(detail || 'Failed to save the NetBox connection');
      }
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: NETBOX_CONNECTIONS_KEY });
      void qc.invalidateQueries({ queryKey: ['settings', 'connector-catalogue'] });
      toast.success(isEdit ? 'NetBox connection updated' : 'NetBox connection added');
      onClose();
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Save failed'),
  });

  return (
    <Modal
      open={open}
      onClose={save.isPending ? undefined : onClose}
      dismissible={!save.isPending}
      size="lg"
      tone="accent"
      icon="plug"
      eyebrow="Settings · Integrations · NetBox"
      title={isEdit ? `Edit ${connection.name}` : 'Connect NetBox'}
      description="Pull sites, prefixes, VLANs, device types and devices from your NetBox. Vista never writes to NetBox — what it does not know about is shown as drift for your network team to act on there."
      primary={
        <button className="ui-btn accent" disabled={!valid || save.isPending} onClick={() => save.mutate()}>
          {save.isPending ? 'Saving…' : isEdit ? 'Save changes' : 'Connect'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose} disabled={save.isPending}>Cancel</button>}
      footerNote={
        save.isError
          ? <span style={{ color: 'var(--danger-text)' }}>{save.error.message}</span>
          : <span style={{ color: 'var(--app-t3)' }}>The token needs READ access only. Vista issues no write to NetBox.</span>
      }
    >
      <ModalField label="Name">
        <ModalInput data-autofocus value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Primary NetBox" />
      </ModalField>
      <ModalField label="NetBox URL">
        <ModalInput value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="https://netbox.internal.example.com" />
      </ModalField>
      <ModalField label={isEdit ? 'API token (leave blank to keep the current one)' : 'API token'}>
        <ModalInput type="password" value={token} onChange={(e) => setToken(e.target.value)}
          placeholder={isEdit && connection?.has_token ? '•••••••• stored' : ''} />
      </ModalField>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
        <ModalField label="Import schedule">
          <ModalSelect value={schedule} onChange={(e) => setSchedule(e.target.value as NetBoxConnection['schedule'])}>
            {SCHEDULES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </ModalSelect>
        </ModalField>
        <ModalField label="Environment for imported segments">
          <ModalSelect value={environment} onChange={(e) => setEnvironment(e.target.value)}>
            {ENVIRONMENTS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </ModalSelect>
        </ModalField>
      </div>
      <p style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: -6, marginBottom: 12 }}>
        NetBox has no environment field. A prefix tagged <code>production</code>, <code>staging</code>,{' '}
        <code>development</code> or <code>test</code> uses that tag; everything else uses the choice above.
      </p>

      {/*
        Device-role mapping. The run summary reports how many roles it could not
        map; without this editor that number has no remedy on the page, and the
        customer doc already tells the tenant they can extend the mapping.
      */}
      <ModalField label="Device-role mapping (optional)">
        <div style={{ display: 'grid', gap: 6 }}>
          {roleRows.map((row, i) => (
            <div key={i} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto', gap: 6, alignItems: 'center' }}>
              <ModalInput
                value={row.role}
                onChange={(e) => setRow(i, { role: e.target.value })}
                placeholder="NetBox role, e.g. edge-guard"
              />
              <ModalSelect value={row.classKey} onChange={(e) => setRow(i, { classKey: e.target.value })}>
                <option value="">Choose an asset class…</option>
                {MAPPABLE_CLASSES.map(([k, label]) => <option key={k} value={k}>{label}</option>)}
              </ModalSelect>
              <button
                type="button"
                className="ui-btn sm ghost"
                style={{ color: 'var(--danger-text)', flex: 'none' }}
                title="Remove mapping"
                aria-label={`Remove the mapping for ${row.role || 'this role'}`}
                onClick={() => setRoleRows((rows) => rows.filter((_, n) => n !== i))}
              >
                <Icon name="x" size={14} />
              </button>
            </div>
          ))}
          <button
            type="button"
            className="ui-btn sm"
            style={{ justifySelf: 'start' }}
            onClick={() => setRoleRows((rows) => [...rows, { role: '', classKey: '' }])}
          >
            <Icon name="plus" size={13} />Add a role mapping
          </button>
        </div>
      </ModalField>
      <p style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: -6, marginBottom: 12 }}>
        Roles Vista already recognises (switch, router, firewall, server…) need no entry. Add one
        where your NetBox uses a local name. A role that matches nothing is imported as
        <strong> Unknown host</strong> — never a nearest guess — and each import reports how many
        it could not map.
      </p>

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, padding: '10px 0' }}>
        <div>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--app-t1)' }}>NetBox is on our own network</div>
          <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>
            Required for a NetBox on a private (10.x, 172.16–31.x, 192.168.x) address. Loopback and
            cloud metadata addresses are never reachable, whatever this is set to.
          </div>
        </div>
        <SToggle on={allowPrivate} onChange={setAllowPrivate} />
      </div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, padding: '10px 0' }}>
        <div>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--app-t1)' }}>Enabled</div>
          <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>Scheduled imports only run while this is on.</div>
        </div>
        <SToggle on={enabled} onChange={setEnabled} />
      </div>
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

export function NetBoxDeleteModal({
  connection, open, onClose,
}: { connection: NetBoxConnection; open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const del = useMutation({
    mutationFn: async () => {
      const res = await clients.inventory.DELETE('/connectors/netbox/connections/{id}', {
        params: { path: { id: connection.id } },
      });
      if (res.error || !res.response.ok) throw new Error('Failed to remove the NetBox connection');
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: NETBOX_CONNECTIONS_KEY });
      toast.success('NetBox connection removed');
      onClose();
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Remove failed'),
  });

  return (
    <Modal
      open={open}
      onClose={del.isPending ? undefined : onClose}
      size="sm"
      tone="danger"
      icon="alert-triangle"
      eyebrow="Settings · Integrations · NetBox"
      title={`Remove ${connection.name}?`}
      description="Assets and network segments already imported are kept — this only stops future imports. Nothing is changed in NetBox."
      primary={
        <button className="ui-btn danger" disabled={del.isPending} onClick={() => del.mutate()}>
          {del.isPending ? 'Removing…' : 'Remove'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose} disabled={del.isPending}>Cancel</button>}
    />
  );
}

// ---------------------------------------------------------------------------
// Run history
// ---------------------------------------------------------------------------

export function NetBoxRunsModal({
  connection, open, onClose,
}: { connection: NetBoxConnection; open: boolean; onClose: () => void }) {
  const q = useQuery(netboxRunsQuery(connection.id));
  const runs = q.data ?? [];

  return (
    <Modal
      open={open}
      onClose={onClose}
      size="lg"
      icon="history"
      eyebrow="Settings · Integrations · NetBox"
      title={`Import history — ${connection.name}`}
      description="Every run records what it read and what it did with it. A run that imported nothing says so."
      secondary={<button className="ui-btn" onClick={onClose}>Close</button>}
    >
      {q.isLoading ? (
        <StateNote icon="loader" tone="var(--app-t3)" title="Loading…" message="Fetching the import history." />
      ) : q.isError ? (
        <StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't load the history" message="The import history failed to load." />
      ) : runs.length === 0 ? (
        <StateNote icon="history" tone="var(--app-t3)" title="No imports yet" message="Run an import to see its results here." />
      ) : (
        <STable cols={[{ label: 'When', w: '140px' }, { label: 'Trigger', w: '90px' }, { label: 'Result', w: '90px' }, { label: 'Summary' }]}>
          {runs.map((r: ConnectorRun, i: number) => (
            <STableRow
              key={r.id}
              first={i === 0}
              cols={[{ w: '140px' }, { w: '90px' }, { w: '90px' }, {}]}
              cells={[
                relTime(r.started_at),
                r.trigger_type,
                <STag key="s" color={statusTone(r.status)}>{r.status}</STag>,
                <div key="sum">
                  <div style={{ fontSize: 11.5, color: 'var(--app-t2)' }}>{runSummaryLine(r)}</div>
                  {r.errors.length > 0 && (
                    <div style={{ fontSize: 11, color: 'var(--danger-text)', marginTop: 3 }}>{r.errors[0]}</div>
                  )}
                </div>,
              ]}
            />
          ))}
        </STable>
      )}
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Drift
// ---------------------------------------------------------------------------

export function NetBoxDriftModal({
  connection, open, onClose,
}: { connection: NetBoxConnection; open: boolean; onClose: () => void }) {
  const q = useQuery(netboxDriftQuery(connection.id));
  const report = q.data;

  return (
    <Modal
      open={open}
      onClose={onClose}
      size="lg"
      icon="git-compare"
      eyebrow="Settings · Integrations · NetBox"
      title={`Drift — ${connection.name}`}
      description="Where NetBox and your inventory disagree. Read-only: Vista never writes to NetBox."
      secondary={<button className="ui-btn" onClick={onClose}>Close</button>}
    >
      {q.isLoading ? (
        <StateNote icon="loader" tone="var(--app-t3)" title="Comparing…" message="Reading NetBox and comparing it with your inventory." />
      ) : q.isError ? (
        <StateNote icon="alert-triangle" tone="var(--danger-text)" title="Couldn't compare" message="NetBox could not be read. Check the connection with Test." />
      ) : !report ? null : (
        <>
          <SCard pad={14} style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 12, color: 'var(--app-t2)' }}>
              <Icon name="info" size={13} style={{ verticalAlign: '-2px', marginRight: 6 }} />
              {report.note}
            </div>
          </SCard>

          <DriftList
            title={`In NetBox, not in your inventory (${report.missing_in_inventory_count})`}
            empty="Every NetBox device is in your inventory."
            rows={report.missing_in_inventory.map((d) => ({
              key: `nb-${d.netbox_id}`,
              primary: d.name,
              secondary: [d.role, d.site, d.ip_address || d.serial].filter(Boolean).join(' · '),
              href: d.url,
            }))}
          />
          <DriftList
            title={`In your inventory, not in NetBox (${report.missing_in_netbox_count})`}
            empty="Everything you hold is described in NetBox."
            rows={report.missing_in_netbox.map((a) => ({
              key: `as-${a.asset_id}`,
              primary: a.display_name || a.hostname || a.ip_address || a.asset_id,
              secondary: [a.class_key, a.asset_status, a.ip_address || a.serial].filter(Boolean).join(' · '),
            }))}
          />

          {report.truncated && (
            <p style={{ fontSize: 11.5, color: 'var(--app-t3)', marginTop: 10 }}>
              Only the first 200 of each are listed. The counts above are complete.
            </p>
          )}
        </>
      )}
    </Modal>
  );
}

function DriftList({ title, empty, rows }: {
  title: string;
  empty: string;
  rows: Array<{ key: string; primary: string; secondary: string; href?: string }>;
}) {
  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--app-t1)', marginBottom: 6 }}>{title}</div>
      {rows.length === 0 ? (
        <div style={{ fontSize: 11.5, color: 'var(--app-t3)' }}>{empty}</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          {rows.map((r) => (
            <div key={r.key} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, padding: '6px 10px', border: '1px solid var(--app-border)', borderRadius: 7 }}>
              <div style={{ minWidth: 0 }}>
                <div style={{ fontSize: 12.5, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.primary}</div>
                <div style={{ fontSize: 11, color: 'var(--app-t3)' }}>{r.secondary}</div>
              </div>
              {r.href && (
                <a className="ui-btn sm ghost" href={r.href} target="_blank" rel="noreferrer" style={{ flex: 'none' }}>
                  Open in NetBox
                </a>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Row actions
// ---------------------------------------------------------------------------

export function NetBoxTestButton({ connection }: { connection: NetBoxConnection }) {
  const m = useMutation({
    mutationFn: async () => {
      const { data, response } = await clients.inventory.POST('/connectors/netbox/connections/{id}/test', {
        params: { path: { id: connection.id } },
      });
      if (!response.ok || !data) throw new Error('Test failed to run');
      return data;
    },
    onSuccess: (d) => (d.success ? toast.success(d.message) : toast.error(d.message)),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Test failed'),
  });
  return (
    <button className="ui-btn sm ghost" disabled={m.isPending} title="Check the URL and token" onClick={() => m.mutate()}>
      {m.isPending ? 'Testing…' : 'Test'}
    </button>
  );
}

export function NetBoxRunButton({ connection }: { connection: NetBoxConnection }) {
  const qc = useQueryClient();
  const m = useMutation({
    mutationFn: async () => {
      const { data, response, error } = await clients.inventory.POST('/connectors/netbox/connections/{id}/run', {
        params: { path: { id: connection.id } },
      });
      if (!response.ok || !data) {
        throw new Error((error as { error?: string } | undefined)?.error || 'The import failed');
      }
      return data;
    },
    onSuccess: (run) => {
      void qc.invalidateQueries({ queryKey: NETBOX_CONNECTIONS_KEY });
      void qc.invalidateQueries({ queryKey: ['settings', 'netbox-runs', connection.id] });
      const line = runSummaryLine(run);
      if (run.status === 'success') toast.success(`Imported from NetBox — ${line}`);
      else toast.error(`Import finished with problems — ${line}`);
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'The import failed'),
  });
  return (
    <button className="ui-btn sm ghost" disabled={m.isPending} title="Pull from NetBox now" onClick={() => m.mutate()}>
      {m.isPending ? 'Importing…' : 'Import'}
    </button>
  );
}
