import { useRef, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { PermissionGate, TENANT_PERMISSIONS, usePermissions } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { Icon } from '../../components/ui';
import { PageWrap, jobMeta, relTime } from './kit';
import { usePcapJobs } from './queries';

// Discovery → PCAP Upload — the mock's `discovery-pcap` dropzone, wired to the
// live sensor-manager upload endpoint, plus the processing-job history below
// (the mock stops at the dropzone; the history makes the result observable).

function sizeFmt(bytes?: number | null): string {
  if (bytes == null) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

export function PcapPage() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);
  const qc = useQueryClient();
  const jobsQ = usePcapJobs();
  const jobs = jobsQ.data?.jobs ?? [];
  const canUpload = usePermissions().hasPermission(TENANT_PERMISSIONS.pcap.upload);

  const upload = useMutation({
    mutationFn: async (file: File) => {
      // Typed multipart: the contract types the part ({ file: binary }); the
      // serializer supplies the real FormData. Content-Type is left to the
      // browser so the boundary is set.
      const { data, error } = await clients.sensors.POST('/pcap/upload', {
        body: { file: '' },
        bodySerializer: () => {
          const fd = new FormData();
          fd.append('file', file);
          return fd;
        },
      });
      if (error || !data) throw new Error('Upload failed');
      return data;
    },
    onSuccess: () => toast.success('Capture uploaded — processing started'),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Upload failed'),
    onSettled: () => qc.invalidateQueries({ queryKey: ['discovery', 'pcap-jobs'] }),
  });

  const pick = (files: FileList | null) => {
    const f = files?.[0];
    if (!f) return;
    if (!/\.pcap(ng)?$/i.test(f.name)) {
      toast.error('Expected a .pcap or .pcapng file');
      return;
    }
    upload.mutate(f);
  };

  return (
    <PageWrap title="PCAP Upload">
      <div style={{ maxWidth: 620, margin: '0 auto' }}>
        <div
          onDragOver={(e) => { if (!canUpload) return; e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => { e.preventDefault(); setDragOver(false); if (canUpload) pick(e.dataTransfer.files); }}
          style={{ border: `2px dashed ${dragOver ? 'var(--accent)' : 'var(--app-border2)'}`, borderRadius: 16, padding: '48px 24px', textAlign: 'center', background: 'var(--app-panel)', transition: 'border-color .15s' }}
        >
          <span style={{ width: 52, height: 52, borderRadius: 13, margin: '0 auto 16px', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--app-panel2)', border: '1px solid var(--app-border)', color: 'var(--accent)' }}>
            <Icon name="upload-cloud" size={24} />
          </span>
          <h3 style={{ margin: '0 0 7px', fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 17, color: 'var(--app-t1)' }}>Upload a packet capture</h3>
          <p style={{ margin: '0 0 18px', fontSize: 13, color: 'var(--app-t3)', lineHeight: 1.5 }}>
            Drop a .pcap / .pcapng file to extract cryptographic configurations as a discovery input. Parsed handshakes feed straight into Inventory.
          </p>
          <PermissionGate
            permission={TENANT_PERMISSIONS.pcap.upload}
            fallback={<p style={{ margin: 0, fontSize: 12, color: 'var(--app-t3)' }}>You don't have permission to upload captures.</p>}
          >
            <button className="ui-btn accent" style={{ margin: '0 auto' }} disabled={upload.isPending} onClick={() => inputRef.current?.click()}>
              <Icon name="file-up" />{upload.isPending ? 'Uploading…' : 'Choose file'}
            </button>
            <input ref={inputRef} type="file" accept=".pcap,.pcapng" style={{ display: 'none' }} onChange={(e) => { pick(e.target.files); e.target.value = ''; }} />
          </PermissionGate>
        </div>

        {jobs.length > 0 && (
          <div className="panel" style={{ marginTop: 18, padding: 0, overflow: 'hidden', borderRadius: 14 }}>
            <div style={{ padding: '11px 18px', borderBottom: '1px solid var(--app-border2)' }}>
              <span className="eyebrow-app">Recent uploads</span>
            </div>
            {jobs.map((j, i) => {
              const m = jobMeta(j.status);
              return (
                <div key={j.id} style={{ padding: '11px 18px', borderTop: i ? '1px solid var(--app-border)' : 'none', display: 'flex', gap: 12, alignItems: 'center' }}>
                  <span style={{ width: 7, height: 7, borderRadius: 50, background: m.c, flex: 'none' }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div className="mono" style={{ fontSize: 12.5, color: 'var(--app-t1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{j.original_filename}</div>
                    <div className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)', marginTop: 2 }}>
                      {[sizeFmt(j.file_size_bytes), j.packet_count ? `${j.packet_count} packets` : null, `${j.discovery_count} discoveries`, relTime(j.created_at)].filter(Boolean).join(' · ')}
                    </div>
                    {j.error_message && <div className="mono" style={{ fontSize: 11, color: 'var(--danger-text)', marginTop: 2 }}>✗ {j.error_message}</div>}
                  </div>
                  <span style={{ fontSize: 11, color: m.c, flex: 'none' }}>{m.l}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </PageWrap>
  );
}
