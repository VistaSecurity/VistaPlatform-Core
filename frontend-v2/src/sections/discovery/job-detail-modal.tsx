// Discovery → job detail: the execution log and discovered assets for one job
// run. Opened by clicking a row on Discovery Jobs or Job Logs.
//
// Before this existed, a job's outcome was one number in a table cell —
// "assets_discovered", parsed straight out of the raw stored payload. That
// number counted what the agent SENT, not what the platform kept, so a run that
// discovered 12 assets and materialized none of them still read as a success.
// The modal separates those two claims: what was found, and what survived
// processing. When they disagree, the errors that explain why are right here
// instead of only in a pod's stdout.
import type { deviceInterrogationComponents } from '@vistasecurity/api-contract';
import { Modal } from '../../components/ui';
import { jobMeta, relTime, durationFmt, shortId } from './kit';
import { useJobResults } from './queries';

type Job = deviceInterrogationComponents['schemas']['InterrogationJob'];
type ResultAsset = deviceInterrogationComponents['schemas']['JobResultAsset'];

const OK = 'var(--ok)';
const DANGER = 'var(--danger)';
const MUTED = 'var(--app-t3)';

/**
 * First value that is present AND non-empty.
 *
 * The API omits absent strings but the agent can send `""` for a field it
 * probed and found blank (an unnamed AP, a certificate with no subject DN), so
 * `??` is wrong here — it would pick the empty string and render nothing.
 */
function firstText(...vals: Array<string | null | undefined>): string | undefined {
  return vals.find((v): v is string => v !== null && v !== undefined && v !== '');
}

function Section({ title, right, children }: { title: string; right?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div style={{ marginTop: 18 }}>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 8 }}>
        <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: 0.4, textTransform: 'uppercase', color: MUTED }}>{title}</div>
        {right}
      </div>
      {children}
    </div>
  );
}

function Row({ label, value, mono, color }: { label: string; value?: React.ReactNode; mono?: boolean; color?: string }) {
  if (value === null || value === undefined || value === '') return null;
  return (
    <div style={{ display: 'flex', gap: 12, padding: '4px 0', fontSize: 12 }}>
      <span style={{ width: 150, flex: 'none', color: MUTED }}>{label}</span>
      <span className={mono ? 'mono' : undefined} style={{ color: color ?? 'var(--app-t1)', minWidth: 0, wordBreak: 'break-word' }}>{value}</span>
    </div>
  );
}

/** The headline counts, with "found" and "kept" deliberately side by side. */
function Counts({ total, withCrypto, materialized }: { total: number; withCrypto: number; materialized?: number }) {
  const shortfall = materialized !== undefined && materialized < total;
  const tiles: Array<{ label: string; value: React.ReactNode; color?: string; hint?: string }> = [
    { label: 'Discovered', value: total },
    { label: 'Crypto measured', value: withCrypto, hint: total - withCrypto > 0 ? `${total - withCrypto} listed only` : undefined },
  ];
  if (materialized !== undefined) {
    tiles.push({
      label: 'Into inventory',
      value: materialized,
      color: shortfall ? DANGER : OK,
      hint: shortfall ? `${total - materialized} did not materialize` : undefined,
    });
  }
  return (
    <div style={{ display: 'grid', gridTemplateColumns: `repeat(${tiles.length}, 1fr)`, gap: 10 }}>
      {tiles.map((t) => (
        <div key={t.label} className="panel" style={{ padding: '10px 12px', borderRadius: 10 }}>
          <div style={{ fontSize: 10.5, color: MUTED, textTransform: 'uppercase', letterSpacing: 0.3 }}>{t.label}</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: t.color ?? 'var(--app-t1)', lineHeight: 1.2 }}>{t.value}</div>
          {t.hint && <div style={{ fontSize: 10.5, color: t.color ?? MUTED }}>{t.hint}</div>}
        </div>
      ))}
    </div>
  );
}

function AssetCard({ a }: { a: ResultAsset }) {
  const name = firstText(a.hostname, a.ip_address) ?? 'Unnamed asset';
  const certs = a.certificates ?? [];
  const untrusted = a.cert_validation_status && a.cert_validation_status !== 'valid';

  return (
    <div style={{ padding: '10px 12px', borderTop: '1px solid var(--app-border)' }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--app-t1)' }}>{name}</span>
        {a.ip_address && a.hostname && <span className="mono" style={{ fontSize: 11, color: MUTED }}>{a.ip_address}</span>}
        {a.port ? <span className="mono" style={{ fontSize: 11, color: MUTED }}>:{a.port}</span> : null}
        {a.service_name && <span style={{ fontSize: 10.5, color: MUTED }}>· {a.service_name}</span>}
        {!a.crypto_observed && (
          // "Not measured" is not "nothing found" — say which one it is.
          <span
            title="Listed by the device's management API. No handshake was performed, so its crypto posture is unknown."
            style={{ fontSize: 10, padding: '1px 6px', borderRadius: 20, border: '1px solid var(--app-border)', color: MUTED }}
          >
            not probed
          </span>
        )}
      </div>

      {a.crypto_observed && (
        <div className="mono" style={{ fontSize: 11, color: MUTED, marginTop: 5, display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          {a.protocol_version && <span style={{ color: 'var(--app-t2)' }}>{a.protocol_version}</span>}
          {a.cipher_suite && <span>{a.cipher_suite}</span>}
          {a.key_exchange_algorithm && <span>{a.key_exchange_algorithm}</span>}
          {a.key_size ? <span>{a.key_size}-bit</span> : null}
        </div>
      )}

      {certs.map((c, i) => (
        <div key={firstText(c.fingerprint_sha256) ?? i} style={{ marginTop: 6, paddingLeft: 10, borderLeft: '2px solid var(--app-border)' }}>
          <div style={{ fontSize: 11.5, color: 'var(--app-t2)' }}>
            {firstText(c.subject_dn) ?? 'Certificate'}
            {c.self_signed && <span style={{ color: DANGER, marginLeft: 6, fontSize: 10.5 }}>self-signed</span>}
          </div>
          <div className="mono" style={{ fontSize: 10.5, color: MUTED }}>
            {[c.key_algorithm, c.key_size ? `${c.key_size}-bit` : null, c.signature_alg].filter(Boolean).join(' · ')}
          </div>
          {c.not_after && (
            <div className="mono" style={{ fontSize: 10.5, color: MUTED }}>expires {new Date(c.not_after).toLocaleDateString()}</div>
          )}
          {c.fingerprint_sha256 && (
            <div className="mono" style={{ fontSize: 10, color: MUTED, wordBreak: 'break-all' }}>{c.fingerprint_sha256}</div>
          )}
        </div>
      ))}

      {untrusted && (
        <div style={{ fontSize: 11, color: DANGER, marginTop: 5 }}>
          ✗ {a.cert_validation_status}
          {a.cert_validation_error ? ` — ${a.cert_validation_error}` : ''}
        </div>
      )}
    </div>
  );
}

export function JobDetailModal({ job, onClose }: { job: Job | null; onClose: () => void }) {
  const q = useJobResults(job?.id);
  if (!job) return null;

  const m = jobMeta(job.status);
  const res = q.data;
  const assets = res?.assets ?? [];
  const summary = res?.summary;
  const processing = (res?.processing ?? null) as null | {
    assets_received?: number;
    findings_created?: number;
    findings_failed?: number;
    discoveries_written?: number;
    discoveries_skipped?: number;
    fully_materialized?: boolean;
    errors?: Array<{ stage?: string; message?: string; count?: number }>;
  };
  const errors = processing?.errors ?? [];

  return (
    <Modal
      open
      onClose={onClose}
      size="lg"
      tone={job.status === 'failed' ? 'danger' : 'accent'}
      icon="radar"
      eyebrow={`Job ${shortId(job.id)}`}
      title={firstText(job.device_name, job.integration_name, job.job_type) ?? 'Interrogation job'}
      description={`${firstText(job.job_type) ?? 'job'} · ${m.l}`}
      secondary={<button className="ui-btn" onClick={onClose}>Close</button>}
    >
      <Section title="Execution">
        <Row label="Status" value={m.l} color={m.c} />
        <Row label="Target" value={firstText(job.device_name, job.integration_name)} />
        <Row label="Device type" value={firstText(job.device_type, job.cloud_provider)} mono />
        <Row label="Created" value={relTime(job.created_at)} />
        <Row label="Started" value={job.started_at ? relTime(job.started_at) : 'not started'} />
        <Row label="Completed" value={job.completed_at ? relTime(job.completed_at) : undefined} />
        <Row label="Duration" value={durationFmt(job.duration_seconds)} mono />
        <Row label="Job ID" value={job.id} mono />
        {job.error_message && <Row label="Error" value={job.error_message} color={DANGER} />}
      </Section>

      {q.isLoading && <div style={{ fontSize: 12, color: MUTED, marginTop: 16 }}>Loading results…</div>}
      {q.isError && <div style={{ fontSize: 12, color: DANGER, marginTop: 16 }}>Could not load this job's results.</div>}

      {res && (
        <>
          <Section title="Outcome">
            <Counts
              total={summary?.total_assets ?? 0}
              withCrypto={summary?.with_crypto ?? 0}
              materialized={summary?.materialized}
            />
            {processing && processing.fully_materialized === false && (
              <div style={{ marginTop: 10, padding: '8px 10px', borderRadius: 8, background: 'color-mix(in srgb, var(--danger) 10%, transparent)', border: '1px solid var(--danger)', fontSize: 11.5, color: 'var(--danger-text)' }}>
                Some assets did not reach inventory. The job itself ran, but processing its results
                failed — those assets will not appear in Approvals or Inventory.
              </div>
            )}
          </Section>

          {errors.length > 0 && (
            <Section title="Processing errors">
              <div className="panel" style={{ padding: 0, borderRadius: 10, overflow: 'hidden' }}>
                {errors.map((e, i) => (
                  <div key={i} style={{ padding: '8px 12px', borderTop: i ? '1px solid var(--app-border)' : 'none' }}>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                      <span className="mono" style={{ fontSize: 10.5, color: MUTED }}>{e.stage}</span>
                      {e.count && e.count > 1 ? (
                        <span style={{ fontSize: 10.5, color: MUTED }}>×{e.count}</span>
                      ) : null}
                    </div>
                    <div className="mono" style={{ fontSize: 11, color: 'var(--danger-text)', marginTop: 2, wordBreak: 'break-word' }}>{e.message}</div>
                  </div>
                ))}
              </div>
            </Section>
          )}

          {processing && (
            <Section title="Pipeline">
              <Row label="Assets received" value={processing.assets_received} mono />
              <Row label="Findings created" value={processing.findings_created} mono color={processing.findings_failed ? undefined : OK} />
              {processing.findings_failed ? <Row label="Findings failed" value={processing.findings_failed} mono color={DANGER} /> : null}
              <Row label="Queued for classification" value={processing.discoveries_written} mono />
              {processing.discoveries_skipped ? <Row label="Classification skipped" value={processing.discoveries_skipped} mono color={MUTED} /> : null}
            </Section>
          )}

          <Section title="Discovered assets" right={<span style={{ fontSize: 11, color: MUTED }}>{assets.length}</span>}>
            {assets.length === 0 ? (
              <div style={{ fontSize: 12, color: MUTED }}>This job recorded no assets.</div>
            ) : (
              <div className="panel" style={{ padding: 0, borderRadius: 10, overflow: 'hidden' }}>
                {assets.map((a, i) => <AssetCard key={`${a.hostname}-${a.ip_address}-${i}`} a={a} />)}
              </div>
            )}
          </Section>
        </>
      )}
    </Modal>
  );
}
