// "Create ticket" on a finding, and the inventory link it carries.
//
// A ticket has four optional inventory columns — asset_id, certificate_id,
// crypto_implementation_id and finding_id — and until workstream 3.1 the
// compliance path filled `asset_id` unconditionally with the finding's own id.
// On live data three findings in four are about a certificate, so three tickets
// in four carried a certificate id in the column that means "asset".
//
// Nothing about that was visible: the ticket rendered an empty asset link, not
// an error, and the id was a perfectly well-formed UUID. So this pins the
// MAPPING — which column each subject kind writes — rather than any behaviour
// you could have seen on screen.
import { describe, expect, it } from 'vitest';
import { subjectLink } from './workflow';
import type { ComplianceFinding } from './model';

const SUBJECT = '0198fb2c-1111-2222-3333-444455556666';
const CONFIG_A = '0198fb2c-aaaa-2222-3333-444455556666';
const CONFIG_B = '0198fb2c-bbbb-2222-3333-444455556666';

function finding(subject_type: string, evidence?: unknown): ComplianceFinding {
  return { subject_type, subject_id: SUBJECT, evidence } as ComplianceFinding;
}

describe('subjectLink', () => {
  it('links an asset subject through asset_id', () => {
    expect(subjectLink(finding('asset'))).toEqual({ asset_id: SUBJECT });
  });

  it('links a certificate subject through certificate_id, NOT asset_id', () => {
    // The bug. `asset_id` here is the regression: it is what the code did
    // before, and it is indistinguishable from correct at the call site.
    const link = subjectLink(finding('certificate'));
    expect(link).toEqual({ certificate_id: SUBJECT });
    expect(link).not.toHaveProperty('asset_id');
  });

  it('gives a subject kind with no column NO link rather than a wrong one', () => {
    // `tickets` has no endpoint or key column. Falling back to asset_id
    // would put an endpoint id in the asset link — the same class of bug one
    // step along — and a ticket pointing at nothing is at least visibly empty.
    //
    // `crypto_configuration` is here for the same reason and a second one: no
    // producer emits it yet, so a link built from today's subject_id would be
    // built from an id nothing has ever written.
    for (const kind of ['endpoint', 'key', 'relationship', 'crypto_configuration', '']) {
      expect(subjectLink(finding(kind))).toEqual({});
    }
  });
});

describe('a software_install subject', () => {
  // What the `eol` and `vulnerability` producers write. There is no
  // `software_install_id` column on `tickets`, and "upgrade openssl" is work
  // somebody does ON a machine — so the ticket links the HOST, from the
  // asset_id both producers put in evidence beside the subject.
  const HOST = '0198fb2c-cccc-2222-3333-444455556666';

  it('links the host the package is installed on', () => {
    expect(subjectLink(finding('software_install', { asset_id: HOST }))).toEqual({ asset_id: HOST });
  });

  it('never puts the INSTALL id in the asset link', () => {
    // The regression this exists to catch: `asset_id: f.subject_id` is
    // well-formed, renders as an empty asset link rather than an error, and is
    // wrong for every software finding in the tenant.
    const link = subjectLink(finding('software_install', { asset_id: HOST }));
    expect(link.asset_id).not.toBe(SUBJECT);
  });

  it('contributes no link when evidence names no asset', () => {
    for (const evidence of [undefined, {}, { asset_id: '' }, { asset_id: 42 }, null]) {
      expect(subjectLink(finding('software_install', evidence))).toEqual({});
    }
  });
});

describe('the configuration a ticket points at', () => {
  // A configuration measurement's subject is the ASSET — that is what the
  // extractor selects and what the reconcile keys on — and the configurations
  // it was read from are in evidence. The ticket names one only when there IS
  // one; naming the first of several would be a guess presented as a fact.
  it('carries the configuration when evidence names exactly one', () => {
    expect(subjectLink(finding('asset', { crypto_implementation_ids: [CONFIG_A] }))).toEqual({
      asset_id: SUBJECT,
      crypto_implementation_id: CONFIG_A,
    });
  });

  it('carries NO configuration when evidence names several', () => {
    const link = subjectLink(finding('asset', { crypto_implementation_ids: [CONFIG_A, CONFIG_B] }));
    expect(link).toEqual({ asset_id: SUBJECT });
    expect(link).not.toHaveProperty('crypto_implementation_id');
  });

  it('survives evidence that is absent, empty, null or the wrong shape', () => {
    // Evidence is JSONB: it arrives as null when empty, and a producer that
    // has not shipped yet writes no such key at all. None of those is an error.
    for (const evidence of [
      undefined,
      null,
      {},
      { crypto_implementation_ids: [] },
      { crypto_implementation_ids: 'not-a-list' },
      { crypto_implementation_ids: [42] },
      { crypto_implementation_ids: [''] },
    ]) {
      expect(subjectLink(finding('asset', evidence))).toEqual({ asset_id: SUBJECT });
    }
  });

  it('never writes an asset id into the configuration column', () => {
    // The specific wrongness this whole change exists to remove: before
    // workstream 3.1 settled the subject question, a configuration measurement
    // was labelled `crypto_configuration` while carrying the ASSET's id, so a
    // ticket took an asset id in crypto_implementation_id.
    const link = subjectLink(finding('asset', { crypto_implementation_ids: [CONFIG_A] }));
    expect(link.crypto_implementation_id).not.toBe(SUBJECT);
  });
});
