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
import { FINDING_PRODUCERS } from '@vistasecurity/primitives/findings';
import { DEFAULT_SLA_DAYS } from '@vistasecurity/primitives/tickets';
import { bulkCryptoTicketBody, subjectLink, ticketBody } from './workflow';
import type { ComplianceFinding, CryptoRisk } from './model';

const SUBJECT = '0198fb2c-1111-2222-3333-444455556666';
const CONFIG_A = '0198fb2c-aaaa-2222-3333-444455556666';
const CONFIG_B = '0198fb2c-bbbb-2222-3333-444455556666';

function finding(subject_type: string, evidence?: unknown): ComplianceFinding {
  return { subject_type, subject_id: SUBJECT, evidence } as ComplianceFinding;
}

function cryptoRisk(severity: string | null, over: Record<string, unknown> = {}): CryptoRisk {
  return {
    id: CONFIG_A,
    tenant_id: 'tenant-1',
    asset_id: SUBJECT,
    crypto_implementation_id: CONFIG_A,
    severity,
    category: 'algorithm',
    issue_type: 'weak_hash',
    current_value: 'SHA-1',
    description: 'A weak hash was observed.',
    recommendation: 'Move to SHA-256.',
    detected_at: '2026-09-17T00:00:00Z',
    asset_hostname: 'edge.example.test',
    ...over,
  } as CryptoRisk;
}

describe('crypto ticket payloads', () => {
  it.each([
    ['critical', 'critical'],
    ['high', 'high'],
    ['medium', 'medium'],
    ['low', 'low'],
    ['info', 'low'],
    ['informational', 'low'],
  ])('bridges crypto severity %s onto the ticket scale as %s', (input, expected) => {
    const body = ticketBody({ kind: 'crypto', risk: cryptoRisk(input) });
    expect(body).toMatchObject({
      priority: expected,
      severity: expected,
      asset_id: SUBJECT,
      crypto_implementation_id: CONFIG_A,
    });
  });

  it.each([null, '', 'unknown'])('does not fabricate ticket severity or priority for %s', (severity) => {
    const body = ticketBody({ kind: 'crypto', risk: cryptoRisk(severity) });
    expect(body).not.toHaveProperty('priority');
    expect(body).not.toHaveProperty('severity');
    expect(body).toMatchObject({ crypto_implementation_id: CONFIG_A });
  });

  it('uses the same bridge for a bulk ticket and keeps the primary configuration link', () => {
    const primary = cryptoRisk(null);
    const high = cryptoRisk('high', { id: CONFIG_B, crypto_implementation_id: CONFIG_B });
    const bulk = bulkCryptoTicketBody(primary, [primary, high]);
    expect(bulk).toMatchObject({
      priority: 'high',
      severity: 'high',
      asset_id: SUBJECT,
      crypto_implementation_id: CONFIG_A,
    });
    expect(bulk.title).toContain('2 configurations');
    expect(bulk.description).toContain('Affected configurations (2)');
    expect(bulk.description).not.toContain('Affected assets');

    const unknownOnly = bulkCryptoTicketBody(primary, [primary]);
    expect(unknownOnly).not.toHaveProperty('priority');
    expect(unknownOnly).not.toHaveProperty('severity');
  });
});

// — the CATEGORY a finding becomes. Previously a three-way branch sent
// `vulnerability` and `compliance` to themselves and everything else to
// `remediation`, so four of the seven producers arrived indistinguishable. That
// was never asserted here, which is exactly how it went unnoticed: the ticket
// was created, the queue showed it, and only the category filter was useless.
describe('the category a finding becomes', () => {
  const withProducer = (producer: string, kind = 'x', severity = 'high'): ComplianceFinding =>
    ({ subject_type: 'asset', subject_id: SUBJECT, producer, kind, severity, summary: 's' }) as ComplianceFinding;

  it.each([
    ['compliance', 'control_noncompliant', 'compliance'],
    ['crypto', 'weak_configuration', 'crypto'],
    ['crypto', 'weak_certificate', 'crypto'],
    ['crypto', 'pqc_vulnerable', 'pqc'],
    ['eol', 'os_end_of_life', 'lifecycle'],
    ['vulnerability', 'known_vulnerability', 'vulnerability'],
    ['configuration', 'default_credentials_exposed', 'configuration'],
    ['hygiene', 'no_owner', 'inventory'],
    ['drift', 'new_issuer', 'drift'],
  ])('%s/%s -> %s', (producer, kind, expected) => {
    expect(ticketBody({ kind: 'compliance', finding: withProducer(producer, kind), fw: 'PCI', host: 'h' }).category)
      .toBe(expected);
  });

  it('never files anything under the retired catch-all', () => {
    // `remediation` is still legal in the DB for pre-split rows, and the
    // backend now rejects it on create -- so a producer still mapping to it
    // would 400 at the moment a user clicks "Create ticket".
    for (const p of FINDING_PRODUCERS) {
      const body = ticketBody({ kind: 'compliance', finding: withProducer(p.key), fw: 'PCI', host: 'h' });
      expect(body.category, `producer ${p.key}`).not.toBe('remediation');
    }
  });

  it('gives every producer a category of its own, not a shared bucket', () => {
    // The actual regression: four producers sharing one category. Allow the
    // deliberate crypto/pqc pairing, but nothing wider.
    const mapped = FINDING_PRODUCERS.map((p) =>
      ticketBody({ kind: 'compliance', finding: withProducer(p.key), fw: 'PCI', host: 'h' }).category);
    expect(new Set(mapped).size).toBe(FINDING_PRODUCERS.length);
  });
});

// Every ticket in the system had due_date = NULL before, so the queue's
// SLA cards read 0/0/100% permanently and the backend's overdue and due-soon
// notifications had no row they could ever fire on.
describe('the due date a created ticket carries', () => {
  const f = (severity: string): ComplianceFinding =>
    ({ subject_type: 'asset', subject_id: SUBJECT, producer: 'compliance', kind: 'control_noncompliant', severity, summary: 's' }) as ComplianceFinding;

  it('always sets one on a finding ticket', () => {
    const body = ticketBody({ kind: 'compliance', finding: f('high'), fw: 'PCI', host: 'h' });
    expect(body.due_date).toBeTruthy();
    expect(Number.isNaN(new Date(body.due_date!).getTime())).toBe(false);
  });

  it('always sets one on a crypto-risk ticket, single and bulk', () => {
    expect(ticketBody({ kind: 'crypto', risk: cryptoRisk('high') }).due_date).toBeTruthy();
    expect(bulkCryptoTicketBody(cryptoRisk('high'), [cryptoRisk('high')]).due_date).toBeTruthy();
  });

  it('gives a critical finding a nearer date than a low one', () => {
    const crit = new Date(ticketBody({ kind: 'compliance', finding: f('critical'), fw: 'P', host: 'h' }).due_date!);
    const low = new Date(ticketBody({ kind: 'compliance', finding: f('low'), fw: 'P', host: 'h' }).due_date!);
    expect(crit.getTime()).toBeLessThan(low.getTime());
  });

  it('dates an informational finding as low, matching the priority it is filed at', () => {
    const info = ticketBody({ kind: 'compliance', finding: f('informational'), fw: 'P', host: 'h' });
    expect(info.priority).toBe('low');
    const days = Math.round((new Date(info.due_date!).getTime() - Date.now()) / 86400000);
    expect(days).toBe(DEFAULT_SLA_DAYS.low);
  });
});

// A crypto risk is not a finding row -- it comes from the weak-crypto
// detector, whose `category` says what KIND of thing is weak.
describe('the category a crypto risk becomes', () => {
  it.each([
    ['certificate', 'certificate'],
    ['compliance', 'compliance'],
    ['algorithm', 'crypto'],
    ['protocol', 'crypto'],
    ['key_size', 'crypto'],
    ['something_new', 'crypto'],
  ])('detector category %s -> ticket category %s', (detector, expected) => {
    expect(ticketBody({ kind: 'crypto', risk: cryptoRisk('high', { category: detector }) }).category).toBe(expected);
    expect(bulkCryptoTicketBody(cryptoRisk('high', { category: detector }), [cryptoRisk('high')]).category).toBe(expected);
  });
});

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
