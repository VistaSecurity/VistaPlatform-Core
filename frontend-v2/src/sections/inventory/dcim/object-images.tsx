// <ObjectImages kind id /> — the pictures attached to one object (DCIM BUILD_PLAN
// row 2.8): a grid of thumbnails, an upload (png, jpeg, webp, svg, at most
// 5 MB) and a delete per image, behind dcim.manage. For a device type pass
// `slot="front"` or `slot="rear"` and the upload also becomes the type's front
// or rear image (the one the rack elevation draws).
//
// A documented slot like <ObjectContacts>: the site page and the asset page
// mount it today; the rack page (row 2.5) and the device-type detail (row 2.2)
// mount it with their own kind and id.
import { useRef, useState } from 'react';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import type { ObjectKind } from '@vistasecurity/primitives/dcim';
import { Icon } from '../../../components/ui';
import { IMAGE_ACCEPT, MAX_IMAGE_BYTES, imageUrl, useDeleteImage, useObjectImages, useUploadImage, type ImageAttachment } from './contact-queries';
import { PanelEmpty, PanelError, PanelLoading } from './substrate-states';

function Thumb({ image, kind, id }: { image: ImageAttachment; kind: ObjectKind; id: string }) {
  const del = useDeleteImage(kind, id);
  const label = image.name ?? 'image';
  return (
    <figure data-testid="image-card" style={{ margin: 0, width: 150 }}>
      <a href={imageUrl(image.id)} target="_blank" rel="noreferrer" title={`${label} — ${image.width}×${image.height}`}>
        <img src={imageUrl(image.id)} alt={label} loading="lazy" style={{ width: 150, height: 100, objectFit: 'cover', borderRadius: 8, border: '1px solid var(--app-border2)', background: 'var(--app-panel2)' }} />
      </a>
      <figcaption style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11.5, color: 'var(--app-t3)', marginTop: 3 }}>
        <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{label}</span>
        <PermissionGate permission={TENANT_PERMISSIONS.dcim.manage}>
          <button type="button" className="ui-btn sm ghost" aria-label={`Delete ${label}`} disabled={del.isPending} onClick={() => del.mutate(image.id)}>
            <Icon name="trash-2" size={12} />
          </button>
        </PermissionGate>
      </figcaption>
    </figure>
  );
}

export function ObjectImages({ kind, id, slot }: { kind: ObjectKind; id: string; slot?: 'front' | 'rear' }) {
  const q = useObjectImages(kind, id);
  const upload = useUploadImage(kind, id);
  const input = useRef<HTMLInputElement>(null);
  const [err, setErr] = useState<string | null>(null);
  const rows = q.data ?? [];

  const pick = (files: FileList | null) => {
    const file = files?.[0];
    if (input.current) input.current.value = '';
    if (!file) return;
    setErr(null);
    if (file.size > MAX_IMAGE_BYTES) {
      setErr('The image is larger than 5 MB.');
      return;
    }
    upload.mutate({ file, ...(slot ? { slot } : {}) }, { onError: (e) => setErr(e instanceof Error ? e.message : 'Upload failed') });
  };

  return (
    <section data-testid="object-images" aria-label="Images">
      {q.isLoading && <PanelLoading label="Loading images…" />}
      {q.isError && <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />}
      {q.isSuccess && rows.length === 0 && (
        <PanelEmpty icon="image-plus" title="No images" message="Attach a photo or a diagram — PNG, JPEG, WebP or SVG, up to 5 MB." />
      )}
      {rows.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12 }}>
          {rows.map((r) => <Thumb key={r.id} image={r} kind={kind} id={id} />)}
        </div>
      )}
      {q.isSuccess && (
        <PermissionGate permission={TENANT_PERMISSIONS.dcim.manage}>
          <div style={{ marginTop: 8 }}>
            <input ref={input} type="file" accept={IMAGE_ACCEPT} aria-label="Image file" data-testid="image-file" style={{ display: 'none' }} onChange={(e) => pick(e.target.files)} />
            <button type="button" className="ui-btn sm" data-testid="upload-image" disabled={upload.isPending} onClick={() => input.current?.click()}>
              <Icon name="upload" size={12} />{upload.isPending ? 'Uploading…' : slot ? `Upload ${slot} image` : 'Upload image'}
            </button>
          </div>
        </PermissionGate>
      )}
      {err && <div role="alert" data-testid="image-error" style={{ marginTop: 6, fontSize: 12, color: 'var(--danger-text)' }}>{err}</div>}
    </section>
  );
}
