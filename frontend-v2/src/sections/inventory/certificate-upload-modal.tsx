// Upload a certificate — for tenants without sensors to populate their cert
// inventory by hand. Wired to the now-contracted POST /certificates/upload
// (/): multipart, field `certificate_file`, one or more PEM CERTIFICATE
// blocks (leaf first; chain allowed). The PEM is authoritative — the server
// extracts crypto fields via the shared x509 extractor. Two input modes (pick a
// file or paste PEM) both produce a File sent through the same endpoint.
import { useRef, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { clients } from '../../lib/clients';
import { Icon, Modal } from '../../components/ui';
import type { inventoryComponents } from '@vistasecurity/api-contract';

type Certificate = inventoryComponents['schemas']['Certificate'];

const ACCEPT = '.pem,.crt,.cer,.cert';
const MAX_BYTES = 1024 * 1024; // server reads up to a 1 MiB cap

type Ownership = 'internal' | 'third_party' | '';

export function CertificateUploadModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const inputRef = useRef<HTMLInputElement>(null);
  const [mode, setMode] = useState<'file' | 'paste'>('file');
  const [file, setFile] = useState<File | null>(null);
  const [pem, setPem] = useState('');
  const [dragOver, setDragOver] = useState(false);
  const [ownership, setOwnership] = useState<Ownership>('');
  const [created, setCreated] = useState<Certificate | null>(null);

  const upload = useMutation({
    mutationFn: async (): Promise<Certificate> => {
      // Build the File from whichever mode is active.
      const f = mode === 'file'
        ? file
        : new File([pem], 'pasted.pem', { type: 'application/x-pem-file' });
      if (!f) throw new Error('Choose a certificate file or paste a PEM.');
      if (f.size > MAX_BYTES) throw new Error('Certificate exceeds the 1 MiB limit.');
      // Typed multipart: the contract types the part ({ certificate_file: binary });
      // the serializer supplies the real FormData so the browser sets the boundary.
      const { data, error, response } = await clients.inventory.POST('/certificates/upload', {
        body: { certificate_file: '' },
        bodySerializer: () => {
          const fd = new FormData();
          fd.append('certificate_file', f);
          if (ownership) fd.append('ownership', ownership);
          return fd;
        },
      });
      if (!response.ok || error || !data) {
        throw new Error((error as { error?: string } | undefined)?.error || 'Upload failed — is this a valid PEM certificate?');
      }
      return data.certificate;
    },
    onSuccess: (cert) => {
      setCreated(cert);
      // New cert can surface in inventory lenses, the asset/cert drawers, and the
      // dashboard "expiring" widget.
      qc.invalidateQueries({ queryKey: ['inventory'] });
      qc.invalidateQueries({ queryKey: ['dashboard'] });
      qc.invalidateQueries({ queryKey: ['cert-detail'] });
    },
  });

  const pick = (files: FileList | null) => {
    const f = files?.[0];
    if (f) { setFile(f); setCreated(null); }
  };

  const reset = () => { setFile(null); setPem(''); setOwnership(''); setCreated(null); upload.reset(); };
  const close = () => { reset(); onClose(); };

  const hasInput = mode === 'file' ? !!file : pem.trim().length > 0;
  const err = upload.error instanceof Error ? upload.error.message : null;

  // ---- success view ----
  if (created) {
    const not = (created.not_after || '').slice(0, 10);
    return (
      <Modal
        open={open} onClose={close} size="md" tone="green" icon="badge-check"
        eyebrow="Inventory" title="Certificate uploaded"
        description="The PEM was parsed and added to your certificate inventory."
        primary={<button className="ui-btn accent" onClick={() => { reset(); }}>Upload another</button>}
        secondary={<button className="ui-btn" onClick={close}>Done</button>}
      >
        <div className="panel" style={{ padding: 14, borderRadius: 12, display: 'flex', flexDirection: 'column', gap: 8 }}>
          <Field k="Common name" v={created.common_name || created.subject_dn || '—'} />
          <Field k="Issuer" v={created.issuer_dn || '—'} />
          <Field k="Expires" v={not || '—'} mono />
          <Field k="Fingerprint" v={created.fingerprint_sha256} mono />
          {created.cert_ownership ? (
            <Field k="Ownership" v={created.cert_ownership === 'third_party' ? 'Third party' : 'Internal'} />
          ) : null}
        </div>
      </Modal>
    );
  }

  return (
    <Modal
      open={open}
      onClose={upload.isPending ? undefined : close}
      dismissible={!upload.isPending}
      size="md"
      tone="accent"
      icon="file-badge"
      eyebrow="Inventory"
      title="Upload certificate"
      description="Add an X.509 certificate by PEM. Useful when no sensor is deployed. The certificate is authoritative — crypto details are extracted from it server-side."
      primary={
        <button className="ui-btn accent" disabled={!hasInput || upload.isPending} onClick={() => upload.mutate()}>
          {upload.isPending ? 'Uploading…' : 'Upload'}
        </button>
      }
      secondary={<button className="ui-btn" onClick={close} disabled={upload.isPending}>Cancel</button>}
      footerNote={err ? <span style={{ color: 'var(--danger-text)' }}>{err}</span> : 'PEM (.pem/.crt/.cer); a chain (leaf first) is accepted. Max 1 MiB.'}
    >
      {/* mode toggle */}
      <div style={{ display: 'inline-flex', gap: 4, padding: 3, borderRadius: 9, background: 'var(--app-panel2)', border: '1px solid var(--app-border)', marginBottom: 14 }}>
        {(['file', 'paste'] as const).map((m) => (
          <button key={m} onClick={() => { setMode(m); upload.reset(); }}
            className={'chip' + (mode === m ? ' active' : '')} style={{ height: 26 }}>
            {m === 'file' ? 'Upload file' : 'Paste PEM'}
          </button>
        ))}
      </div>

      {mode === 'file' ? (
        <div
          onClick={() => inputRef.current?.click()}
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => { e.preventDefault(); setDragOver(false); pick(e.dataTransfer.files); }}
          style={{ border: `2px dashed ${dragOver ? 'var(--accent)' : 'var(--app-border2)'}`, borderRadius: 14, padding: '34px 20px', textAlign: 'center', cursor: 'pointer', background: 'var(--app-panel2)', transition: 'border-color .15s' }}
        >
          <input ref={inputRef} type="file" accept={ACCEPT} hidden onChange={(e) => pick(e.target.files)} />
          <span style={{ width: 46, height: 46, borderRadius: 12, margin: '0 auto 12px', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--app-panel)', border: '1px solid var(--app-border)', color: 'var(--accent)' }}>
            <Icon name={file ? 'file-text' : 'upload-cloud'} size={22} />
          </span>
          {file ? (
            <div style={{ fontSize: 13, color: 'var(--app-t1)', fontWeight: 600 }}>{file.name}<div className="mono" style={{ fontSize: 11, color: 'var(--app-t3)', fontWeight: 400, marginTop: 3 }}>{(file.size / 1024).toFixed(1)} KB · click to replace</div></div>
          ) : (
            <div style={{ fontSize: 13, color: 'var(--app-t2)' }}>Drop a PEM file here, or <span style={{ color: 'var(--accent)' }}>browse</span></div>
          )}
        </div>
      ) : (
        <textarea
          value={pem}
          onChange={(e) => setPem(e.target.value)}
          rows={8}
          spellCheck={false}
          placeholder={'-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----'}
          className="mono"
          style={{ width: '100%', padding: '11px 13px', borderRadius: 10, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)', color: 'var(--app-t1)', fontSize: 11.5, outline: 'none', resize: 'vertical', lineHeight: 1.45 }}
        />
      )}

      {/* ownership picker */}
      <div style={{ marginTop: 16 }}>
        <div style={{ fontSize: 12, color: 'var(--app-t3)', marginBottom: 7, fontWeight: 500 }}>
          Ownership <span style={{ fontWeight: 400, opacity: 0.7 }}>(optional — helps with filtering)</span>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          {([
            { value: '' as Ownership, label: 'Unset' },
            { value: 'internal' as Ownership, label: 'Internal' },
            { value: 'third_party' as Ownership, label: 'Third party' },
          ]).map(({ value, label }) => (
            <button
              key={value || 'unset'}
              onClick={() => setOwnership(value)}
              style={{
                flex: 1, padding: '7px 0', borderRadius: 8, fontSize: 12.5, fontWeight: 500,
                cursor: 'pointer', transition: 'all .12s',
                background: ownership === value ? 'var(--accent)' : 'var(--app-panel2)',
                color: ownership === value ? '#000' : 'var(--app-t2)',
                border: `1px solid ${ownership === value ? 'var(--accent)' : 'var(--app-border2)'}`,
              }}
            >
              {label}
            </button>
          ))}
        </div>
      </div>
    </Modal>
  );
}

function Field({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div style={{ display: 'flex', gap: 12, alignItems: 'baseline' }}>
      <span style={{ fontSize: 11.5, color: 'var(--app-t3)', width: 96, flex: 'none' }}>{k}</span>
      <span className={mono ? 'mono' : undefined} style={{ fontSize: 12.5, color: 'var(--app-t1)', flex: 1, minWidth: 0, wordBreak: mono ? 'break-all' : 'normal' }}>{v}</span>
    </div>
  );
}
