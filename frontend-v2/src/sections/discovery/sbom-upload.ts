// The Upload SBOM card's logic, kept out of the component so it can be tested
// without mounting React.
//
// Everything here is a decision the page makes ABOUT the user's document —
// which target it will be sent to, whether it looks like something the parser
// can read, and what the result actually says. A decision buried in JSX is a
// decision nobody re-reads.

/** Where an upload is aimed. */
export type SbomTarget =
  /** At an asset the user picked. */
  | { kind: 'asset'; assetId: string; label: string }
  /** At no asset: the document's subject creates or matches an application. */
  | { kind: 'subject' };

/**
 * Whether the page will let the upload start.
 *
 * The `asset` target needs an id, which is the only thing a client can get
 * wrong here. Everything else about the document — is it CycloneDX, is it SPDX,
 * is it JSON at all — is the SERVER's decision, deliberately: the parser detects
 * the format from the document's own declaration, and a client-side guess that
 * disagreed would refuse a file the platform can read.
 */
export function canUpload(target: SbomTarget, file: File | null): boolean {
  if (!file) return false;
  return target.kind === 'subject' || target.assetId.trim() !== '';
}

/**
 * A LOOK at the filename, used for a warning and never for a refusal.
 *
 * `.xml` is worth saying something about before a 25 MB upload, because
 * CycloneDX XML is a real format this platform does not parse and the round
 * trip to find that out is slow. It is still only a hint — the file is sent
 * either way, and the server decides.
 */
export function filenameHint(name: string): string | null {
  const n = name.toLowerCase();
  if (n.endsWith('.xml')) {
    return 'This looks like XML. Only CycloneDX JSON and SPDX JSON are parsed — re-export as JSON. Uploading anyway will tell you for certain.';
  }
  if (n.endsWith('.json') || n.endsWith('.cdx.json') || n.endsWith('.spdx.json')) return null;
  return 'Expected a .json bill of materials. The format is read from inside the document, so this may still work.';
}

/** The shape POST /sbom and POST /{id}/sbom both return. */
export interface SbomResult {
  upload_id: string;
  format: string;
  spec_version: string;
  asset_id: string;
  asset_name?: string;
  asset_created: boolean;
  asset_status: string;
  component_count: number;
  products_created: number;
  products_matched: number;
  installs_created: number;
  installs_updated: number;
  installs_removed: number;
  components_excluded: number;
  dependency_edges_ignored: number;
  warnings?: string[] | null;
}

/**
 * The headline sentence for a finished upload.
 *
 * It reports what was INGESTED against what the document CONTAINED, because
 * those differ for good reasons (excluded components, a subject that was also a
 * component, two components sharing one purl) and a single "imported 412
 * components" is a number the user cannot reconcile with their build output.
 * This is the same reason the API returns every count separately.
 */
export function summarise(r: SbomResult): string {
  const ingested = r.installs_created + r.installs_updated;
  const parts = [`${ingested} of ${r.component_count} components ingested`];
  if (r.components_excluded > 0) {
    parts.push(`${r.components_excluded} excluded by the document`);
  }
  if (r.installs_removed > 0) {
    parts.push(`${r.installs_removed} no longer listed`);
  }
  return `${parts.join(' · ')}.`;
}

/**
 * What the page says about the asset afterwards, and whether it should send the
 * reader to Approvals.
 *
 * A created asset is PENDING. Saying "created" and stopping would leave a user
 * looking for it in an inventory it is not in yet — the orphaned-layer failure
 * in miniature.
 */
export function assetNote(r: SbomResult): { text: string; needsApproval: boolean } {
  const name = r.asset_name || 'the application';
  if (!r.asset_created) {
    return { text: `Software recorded against ${name}.`, needsApproval: false };
  }
  if (r.asset_status === 'pending_approval') {
    return {
      text: `Created ${name} as an application asset, waiting for approval. Declared is not approved: an upload is a file arriving at an endpoint, so somebody admits it deliberately in Discovery → Approvals.`,
      needsApproval: true,
    };
  }
  return { text: `Created ${name} as an application asset.`, needsApproval: false };
}

/**
 * The server's message for a failed upload, or a fallback.
 *
 * The refusals this endpoint produces all name a remedy — "re-export as JSON",
 * "upload it against the asset it runs on", "43,000 components, limit 100,000" —
 * so showing the server's text is strictly better than any sentence written
 * here. The fallback exists only for a transport failure with no body.
 */
export function uploadErrorMessage(body: unknown): string {
  if (body && typeof body === 'object') {
    const b = body as { message?: unknown; error?: unknown };
    if (typeof b.message === 'string' && b.message.trim() !== '') return b.message;
    if (typeof b.error === 'string' && b.error.trim() !== '') return b.error;
  }
  return 'Upload failed.';
}
