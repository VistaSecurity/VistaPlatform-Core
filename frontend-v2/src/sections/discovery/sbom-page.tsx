import { useRef, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router';
import toast from 'react-hot-toast';
import { PermissionGate, TENANT_PERMISSIONS, usePermissions } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { Icon } from '../../components/ui';
import { PageWrap } from './kit';
import { useAssetsQuery } from '../inventory/asset-queries';
import { quoteValue } from '../inventory/facet-query';
import {
  assetNote, canUpload, filenameHint, summarise, uploadErrorMessage,
  type SbomResult, type SbomTarget,
} from './sbom-upload';

// Discovery → Sources → Upload SBOM (workstream 2.6b).
//
// It sits beside PCAP Upload under the Sources group, which is where the other
// "bring us a file" intake already lives. There is no Sources *page* — Sources
// is a nav group — so this is a page of its own rather than a card added to one.
//
// The card shows every state: nothing chosen, a target chosen, uploading, the
// counted result, the parser's warnings, and a refusal with the server's own
// message (which always names a remedy).

const cardStyle: React.CSSProperties = {
  background: 'var(--app-panel)',
  border: '1px solid var(--app-border2)',
  borderRadius: 14,
  padding: 18,
};

export function SbomPage() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);
  const [mode, setMode] = useState<'asset' | 'subject'>('asset');
  const [search, setSearch] = useState('');
  const [picked, setPicked] = useState<{ id: string; label: string } | null>(null);
  const [result, setResult] = useState<SbomResult | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const qc = useQueryClient();

  // The two targets need DIFFERENT permissions, because they do different
  // things: uploading against an existing asset changes what the inventory
  // says about it (assets.update), and uploading with no target CREATES an
  // application asset (assets.create). The routes are gated that way, so a
  // single gate here is wrong in both directions — it offers subject mode to
  // someone the server will answer 403, and hides the whole page from someone
  // who may legitimately use it.
  const perms = usePermissions();
  const requiredPermission = mode === 'subject'
    ? TENANT_PERMISSIONS.assets.create
    : TENANT_PERMISSIONS.assets.update;
  const canUploadHere = perms.hasPermission(requiredPermission);

  // The asset picker is the ordinary asset query, so it obeys the same default
  // scope (`status:monitoring`) every other list does. A pending asset is not
  // somewhere to file a bill of materials.
  // quoteValue, not JSON.stringify: they agree on backslash and double quote
  // and disagree on everything else, and a control character JSON escapes as
  // `\u0001` is a token the query lexer does not know — so the picker would
  // answer a parse error instead of "no matching assets". The software lens
  // makes the same point about its drill-through link.
  const searchQuery = search.trim() ? `display_name:${quoteValue(search.trim())}` : '';
  const assetsQ = useAssetsQuery(searchQuery, 1, mode === 'asset' && search.trim().length >= 2);

  const target: SbomTarget = mode === 'subject'
    ? { kind: 'subject' }
    : { kind: 'asset', assetId: picked?.id ?? '', label: picked?.label ?? '' };

  const upload = useMutation({
    mutationFn: async (file: File): Promise<SbomResult> => {
      // Typed multipart: the contract types the part ({ file: binary }); the
      // serializer supplies the real FormData. Content-Type is left to the
      // browser so the boundary is set.
      const body = { file: '' };
      const bodySerializer = () => {
        const fd = new FormData();
        fd.append('file', file);
        return fd;
      };
      if (target.kind === 'subject') {
        const { data, error } = await clients.inventory.POST('/sbom', { body, bodySerializer });
        if (error || !data) throw new Error(uploadErrorMessage(error));
        return data;
      }
      const { data, error } = await clients.inventory.POST('/infrastructure-assets/{id}/sbom', {
        params: { path: { id: target.assetId } },
        body,
        bodySerializer,
      });
      if (error || !data) throw new Error(uploadErrorMessage(error));
      return data;
    },
    onSuccess: (r) => {
      setResult(r);
      setFailure(null);
      toast.success(summarise(r));
    },
    onError: (e) => {
      setResult(null);
      setFailure(e instanceof Error ? e.message : 'Upload failed.');
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: ['asset-software'] });
      void qc.invalidateQueries({ queryKey: ['software-products'] });
      void qc.invalidateQueries({ queryKey: ['inventory'] });
      void qc.invalidateQueries({ queryKey: ['discovery', 'pending-assets'] });
    },
  });

  const pick = (files: FileList | null) => {
    const f = files?.[0];
    if (!f) return;
    if (!canUpload(target, f)) {
      toast.error('Choose the asset this document describes first.');
      return;
    }
    const hint = filenameHint(f.name);
    if (hint) toast(hint, { icon: '⚠️' });
    upload.mutate(f);
  };

  const ready = canUploadHere && canUpload(target, new File([], 'probe'));

  return (
    <PageWrap title="Upload SBOM">
      <div style={{ maxWidth: 720, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div style={cardStyle} data-testid="sbom-upload-card">
          <div style={{ display: 'flex', gap: 11, alignItems: 'flex-start', marginBottom: 14 }}>
            <span style={{ width: 38, height: 38, borderRadius: 10, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--app-panel2)', border: '1px solid var(--app-border)', color: 'var(--accent)', flex: 'none' }}>
              <Icon name="package" size={18} />
            </span>
            <div>
              <h3 style={{ margin: '0 0 4px', fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 15, color: 'var(--app-t1)' }}>
                Upload a bill of materials
              </h3>
              <p style={{ margin: 0, fontSize: 12.5, color: 'var(--app-t3)', lineHeight: 1.55 }}>
                CycloneDX JSON 1.4–1.7 or SPDX JSON 2.2/2.3, up to 32 MB. Its components become software
                inventory on the asset you choose. The format is read from inside the document, not from the
                filename.
              </p>
            </div>
          </div>

          {/* Target */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 9, marginBottom: 14 }}>
            <span className="eyebrow-app">Where does this document belong?</span>
            <label style={{ display: 'flex', gap: 8, alignItems: 'flex-start', fontSize: 12.5, color: 'var(--app-t2)', cursor: 'pointer' }}>
              <input type="radio" name="sbom-target" checked={mode === 'asset'} onChange={() => setMode('asset')} data-testid="sbom-target-asset" />
              <span>
                <strong style={{ color: 'var(--app-t1)' }}>An existing asset</strong> — the host, container or
                application this software runs on.
              </span>
            </label>
            <label style={{ display: 'flex', gap: 8, alignItems: 'flex-start', fontSize: 12.5, color: 'var(--app-t2)', cursor: 'pointer' }}>
              <input type="radio" name="sbom-target" checked={mode === 'subject'} onChange={() => setMode('subject')} data-testid="sbom-target-subject" />
              <span>
                <strong style={{ color: 'var(--app-t1)' }}>Create an application asset from the document</strong> —
                the artefact the document is about becomes an application, waiting for approval. Uploading the
                same artefact again lands on the same asset.
              </span>
            </label>
          </div>

          {mode === 'asset' && (
            <div style={{ marginBottom: 14 }}>
              <input
                className="ui-input"
                style={{ width: '100%' }}
                placeholder="Search assets by name…"
                value={picked ? picked.label : search}
                data-testid="sbom-asset-search"
                onChange={(e) => { setPicked(null); setSearch(e.target.value); }}
              />
              {!picked && search.trim().length >= 2 && (
                <div style={{ marginTop: 6, border: '1px solid var(--app-border)', borderRadius: 9, maxHeight: 190, overflowY: 'auto' }}>
                  {assetsQ.isLoading && <div style={{ padding: 10, fontSize: 12, color: 'var(--app-t3)' }}>Searching…</div>}
                  {!assetsQ.isLoading && (assetsQ.data?.assets.length ?? 0) === 0 && (
                    <div style={{ padding: 10, fontSize: 12, color: 'var(--app-t3)' }}>No matching assets.</div>
                  )}
                  {(assetsQ.data?.assets ?? []).map((a) => {
                    const label = a.display_name || a.hostname || a.primary_address || a.id;
                    return (
                      <button
                        key={a.id}
                        type="button"
                        className="ui-btn ghost"
                        style={{ display: 'block', width: '100%', textAlign: 'left', borderRadius: 0, border: 'none' }}
                        onClick={() => { setPicked({ id: a.id, label }); setSearch(label); }}
                      >
                        <span style={{ fontSize: 12.5, color: 'var(--app-t1)' }}>{label}</span>
                        <span className="mono" style={{ fontSize: 10.5, color: 'var(--app-t3)', marginLeft: 8 }}>{a.class_key}</span>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* Dropzone */}
          <div
            onDragOver={(e) => { if (!ready) return; e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => { e.preventDefault(); setDragOver(false); if (ready) pick(e.dataTransfer.files); }}
            style={{
              border: `2px dashed ${dragOver ? 'var(--accent)' : 'var(--app-border2)'}`,
              borderRadius: 12, padding: '30px 20px', textAlign: 'center',
              background: 'var(--app-panel2)', opacity: ready ? 1 : 0.55, transition: 'border-color .15s',
            }}
          >
            <PermissionGate
              permission={requiredPermission}
              fallback={<p style={{ margin: 0, fontSize: 12, color: 'var(--app-t3)' }}>{mode === 'subject'
                ? "You don't have permission to create assets. Choose an existing asset instead, or ask an administrator."
                : "You don't have permission to change asset inventory."}</p>}
            >
              <button
                className="ui-btn accent"
                style={{ margin: '0 auto' }}
                disabled={upload.isPending || !ready}
                data-testid="sbom-choose-file"
                onClick={() => inputRef.current?.click()}
              >
                <Icon name="file-up" />{upload.isPending ? 'Uploading…' : 'Choose a document'}
              </button>
              <input
                ref={inputRef}
                type="file"
                accept=".json,.cdx.json,.spdx.json,application/json"
                style={{ display: 'none' }}
                onChange={(e) => { pick(e.target.files); e.target.value = ''; }}
              />
              <p style={{ margin: '10px 0 0', fontSize: 11.5, color: 'var(--app-t3)' }}>
                {mode === 'asset' && !picked
                  ? 'Choose the asset this document describes first.'
                  : 'or drop it here'}
              </p>
            </PermissionGate>
          </div>

          <p style={{ margin: '12px 0 0', fontSize: 11.5, color: 'var(--app-t3)', lineHeight: 1.55 }}>
            <Icon name="info" size={11} style={{ verticalAlign: -1, marginRight: 4 }} />
            An upload <strong>replaces</strong> the imported software list for its asset: anything the new
            document does not list is marked <em>removed</em> rather than deleted, and a later document that
            lists it again brings it back. To combine two documents, merge them before uploading.
          </p>
        </div>

        {failure && (
          <div style={{ ...cardStyle, borderColor: 'var(--danger-border, var(--app-border2))' }} data-testid="sbom-failure">
            <div style={{ display: 'flex', gap: 9, alignItems: 'flex-start' }}>
              <Icon name="triangle-alert" size={15} style={{ color: 'var(--danger-text)', flex: 'none', marginTop: 2 }} />
              <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--app-t1)', marginBottom: 3 }}>That document was not ingested</div>
                <div style={{ fontSize: 12.5, color: 'var(--app-t2)', lineHeight: 1.55 }}>{failure}</div>
              </div>
            </div>
          </div>
        )}

        {result && <SbomResultCard result={result} />}
      </div>
    </PageWrap>
  );
}

/**
 * The result card.
 *
 * It reports what was ingested AGAINST what the document contained, plus every
 * warning the parser produced. A single "imported N components" is a number the
 * user cannot reconcile with their own build output; this is the sentence that
 * lets them.
 */
function SbomResultCard({ result }: { result: SbomResult }) {
  const note = assetNote(result);
  const warnings = result.warnings ?? [];
  return (
    <div style={cardStyle} data-testid="sbom-result">
      <div style={{ display: 'flex', gap: 9, alignItems: 'flex-start', marginBottom: 12 }}>
        <Icon name="circle-check" size={15} style={{ color: 'var(--ok-text, var(--accent))', flex: 'none', marginTop: 2 }} />
        <div>
          <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--app-t1)', marginBottom: 3 }}>{summarise(result)}</div>
          <div style={{ fontSize: 12.5, color: 'var(--app-t2)', lineHeight: 1.55 }}>{note.text}</div>
        </div>
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: warnings.length ? 12 : 0 }}>
        <Stat label="Format" value={`${result.format} ${result.spec_version}`} />
        <Stat label="New products" value={String(result.products_created)} />
        <Stat label="Already known" value={String(result.products_matched)} />
        <Stat label="Installs added" value={String(result.installs_created)} />
        <Stat label="Marked removed" value={String(result.installs_removed)} />
        {result.dependency_edges_ignored > 0 && (
          <Stat
            label="Dependency edges not kept"
            value={String(result.dependency_edges_ignored)}
            hint="Edges between components are not relationships between assets, and the inventory has no home for them yet."
          />
        )}
      </div>

      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <Link className="ui-btn ghost" to={`/inventory/assets/${result.asset_id}/software`} data-testid="sbom-view-software">
          <Icon name="package" />View the software
        </Link>
        {note.needsApproval && (
          <Link className="ui-btn ghost" to="/discovery/approvals" data-testid="sbom-go-approvals">
            <Icon name="inbox" />Approve the new asset
          </Link>
        )}
      </div>

      {warnings.length > 0 && (
        <div style={{ marginTop: 13, paddingTop: 12, borderTop: '1px solid var(--app-border)' }}>
          <span className="eyebrow-app">What was skipped</span>
          <ul style={{ margin: '7px 0 0', padding: '0 0 0 17px', fontSize: 12, color: 'var(--app-t3)', lineHeight: 1.65 }}>
            {warnings.map((w, i) => <li key={i}>{w}</li>)}
          </ul>
        </div>
      )}
    </div>
  );
}

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div title={hint} style={{ border: '1px solid var(--app-border)', borderRadius: 9, padding: '7px 11px', minWidth: 96 }}>
      <div className="mono" style={{ fontSize: 14, color: 'var(--app-t1)' }}>{value}</div>
      <div style={{ fontSize: 10.5, color: 'var(--app-t3)', marginTop: 1 }}>{label}</div>
    </div>
  );
}
