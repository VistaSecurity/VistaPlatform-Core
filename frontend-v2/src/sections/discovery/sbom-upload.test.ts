// The Upload SBOM card's decisions, tested without mounting React.
import { describe, expect, it } from 'vitest';
import {
  assetNote, canUpload, filenameHint, summarise, uploadErrorMessage,
  type SbomResult, type SbomTarget,
} from './sbom-upload';

const file = new File(['{}'], 'bom.json');

function result(over: Partial<SbomResult> = {}): SbomResult {
  return {
    upload_id: 'u1', format: 'cyclonedx', spec_version: '1.6',
    asset_id: 'a1', asset_created: false, asset_status: 'monitoring',
    component_count: 10, products_created: 8, products_matched: 2,
    installs_created: 10, installs_updated: 0, installs_removed: 0,
    components_excluded: 0, dependency_edges_ignored: 0,
    ...over,
  };
}

describe('canUpload', () => {
  it('needs a chosen asset for the asset target', () => {
    const noAsset: SbomTarget = { kind: 'asset', assetId: '', label: '' };
    const withAsset: SbomTarget = { kind: 'asset', assetId: 'a1', label: 'web-01' };
    expect(canUpload(noAsset, file)).toBe(false);
    expect(canUpload(withAsset, file)).toBe(true);
  });

  it('needs no asset for the subject target — the document supplies it', () => {
    expect(canUpload({ kind: 'subject' }, file)).toBe(true);
  });

  it('needs a file either way', () => {
    expect(canUpload({ kind: 'subject' }, null)).toBe(false);
  });
});

describe('filenameHint', () => {
  it('warns about XML before a slow upload finds out', () => {
    const hint = filenameHint('bom.xml');
    expect(hint).toMatch(/XML/);
    expect(hint).toMatch(/re-export as JSON/);
  });

  it('says nothing about a JSON document', () => {
    expect(filenameHint('bom.json')).toBeNull();
    expect(filenameHint('app.cdx.json')).toBeNull();
    expect(filenameHint('APP.SPDX.JSON')).toBeNull();
  });

  it('is a HINT, never a refusal — the format is read from inside the document', () => {
    // An unfamiliar extension gets a note, and canUpload still allows it. A
    // client-side format guess that disagreed with the parser would refuse a
    // file the platform can read.
    expect(filenameHint('bom.txt')).toMatch(/may still work/);
    expect(canUpload({ kind: 'subject' }, new File(['{}'], 'bom.txt'))).toBe(true);
  });
});

describe('summarise', () => {
  it('reports what was ingested AGAINST what the document contained', () => {
    // "412 ingested" alone is a number the user cannot reconcile with their own
    // build output; the denominator is the point.
    expect(summarise(result({ component_count: 480, installs_created: 400, installs_updated: 12 })))
      .toBe('412 of 480 components ingested.');
  });

  it('names the excluded components rather than letting the gap go unexplained', () => {
    const s = summarise(result({ component_count: 480, installs_created: 412, components_excluded: 68 }));
    expect(s).toMatch(/68 excluded by the document/);
  });

  it('names removed installs, because the upload changed something it did not add', () => {
    expect(summarise(result({ installs_removed: 3 }))).toMatch(/3 no longer listed/);
  });

  it('says nothing about zero excluded or zero removed', () => {
    const s = summarise(result());
    expect(s).not.toMatch(/excluded/);
    expect(s).not.toMatch(/no longer listed/);
  });
});

describe('assetNote', () => {
  it('sends the reader to Approvals when a created asset is pending', () => {
    // Saying "created" and stopping would leave a user hunting for the asset in
    // an inventory it is not in yet.
    const note = assetNote(result({ asset_created: true, asset_status: 'pending_approval', asset_name: 'billing-api' }));
    expect(note.needsApproval).toBe(true);
    expect(note.text).toMatch(/billing-api/);
    expect(note.text).toMatch(/waiting for approval/);
    expect(note.text).toMatch(/Declared is not approved/);
  });

  it('does not send the reader anywhere when the asset already existed', () => {
    const note = assetNote(result({ asset_created: false, asset_name: 'web-01' }));
    expect(note.needsApproval).toBe(false);
    expect(note.text).toMatch(/web-01/);
    expect(note.text).not.toMatch(/approval/);
  });

  it('does not claim an approval is pending when the asset landed approved', () => {
    // The polarity that would otherwise be decorative: the branch has to read
    // the status, not just `asset_created`.
    const note = assetNote(result({ asset_created: true, asset_status: 'monitoring' }));
    expect(note.needsApproval).toBe(false);
  });
});

describe('uploadErrorMessage', () => {
  it('prefers the server message, which always names a remedy', () => {
    expect(uploadErrorMessage({ error: 'Could not read this document', message: 'this looks like XML; re-export as JSON' }))
      .toBe('this looks like XML; re-export as JSON');
  });

  it('falls back to the error string when there is no message', () => {
    expect(uploadErrorMessage({ error: 'Asset not found' })).toBe('Asset not found');
  });

  it('has a last resort for a transport failure with no body', () => {
    expect(uploadErrorMessage(undefined)).toBe('Upload failed.');
    expect(uploadErrorMessage({ message: '   ' })).toBe('Upload failed.');
  });
});
