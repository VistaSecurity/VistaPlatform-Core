// What the Findings inspector reads out of a finding's evidence.
//
// `evidence` is the one column on `findings` with no pinned schema, because
// every producer puts something different in it. That makes these readers the
// place a malformed document turns into a blank panel instead of a white
// screen — so every case below has BOTH polarities: the shape the producer
// actually writes is read correctly, AND a wrong shape returns null / an empty
// list rather than throwing. A reader that returned null for everything would
// satisfy all the defensive cases on its own.
import { describe, expect, it } from 'vitest';
import {
  assessmentLimitations, assessmentLimitText, configurationEvidence, cryptoEvidence, cveCount, cveList, driftEvidence, eolEvidence,
  hygieneEvidence, isHttpURL, kindFeedsRisk, kindLabel, producerLabel, subjectAssetID,
} from './producer-evidence';
import type { ComplianceFinding } from './model';

const HOST = '0198fb2c-cccc-2222-3333-444455556666';
const INSTALL = '0198fb2c-dddd-2222-3333-444455556666';

function finding(over: Partial<ComplianceFinding>): ComplianceFinding {
  return { subject_type: 'software_install', subject_id: INSTALL, ...over } as ComplianceFinding;
}

describe('producerLabel', () => {
  it('uses the registry label, so the UI cannot invent a second name for a producer', () => {
    expect(producerLabel('eol')).toBe('End of life');
    expect(producerLabel('vulnerability')).toBe('Vulnerability');
    expect(producerLabel('compliance')).toBe('Compliance');
  });

  it('falls back to the key rather than to a blank', () => {
    // A producer shipped in the backend and not yet regenerated here must
    // render as SOMETHING. A blank chip is a producer the user cannot click.
    expect(producerLabel('a-producer-from-the-future')).toBe('a-producer-from-the-future');
    expect(producerLabel(undefined)).toBe('Unknown');
  });
});

describe('kindLabel', () => {
  it('renders a kind key as a sentence', () => {
    expect(kindLabel('software_end_of_life')).toBe('Software end of life');
    expect(kindLabel('known_vulnerability')).toBe('Known vulnerability');
  });

  it('never renders a blank for an unknown kind', () => {
    expect(kindLabel('a_kind_from_the_future')).toBe('A kind from the future');
    expect(kindLabel(undefined)).toBe('—');
  });
});

describe('kindFeedsRisk', () => {
  // Both polarities, because the registry is what decides whether a score
  // means anything, and a reader that always said false would hide every real
  // contribution while passing a "hygiene does not feed risk" assertion.
  it('reads the registry rather than guessing', () => {
    expect(kindFeedsRisk('known_vulnerability')).toBe(true);
    expect(kindFeedsRisk('os_end_of_life')).toBe(true);
    expect(kindFeedsRisk('control_noncompliant')).toBe(false);
    expect(kindFeedsRisk('no_owner')).toBe(false);
    expect(kindFeedsRisk('nonsense')).toBe(false);
  });
});

describe('isHttpURL', () => {
  it('accepts http and https', () => {
    expect(isHttpURL('https://endoflife.date/ubuntu')).toBe(true);
    expect(isHttpURL('http://example.internal/advisory')).toBe(true);
  });

  it('refuses every other scheme and every non-string', () => {
    // `href` is a URL context where escaping does nothing, so the scheme has
    // to be checked rather than the value escaped.
    for (const bad of ['javascript:alert(1)', 'data:text/html,<script>', 'file:///etc/passwd', 'not a url', '', 42, null, undefined, {}]) {
      expect(isHttpURL(bad)).toBe(false);
    }
  });
});

describe('eolEvidence', () => {
  const full = finding({
    producer: 'eol',
    kind: 'software_end_of_life',
    evidence: {
      catalogue_id: '11111111-1111-1111-1111-111111111111',
      catalogue_source_url: 'https://endoflife.date/openssl',
      catalogue_product: 'OpenSSL',
      catalogue_cycle: '1.1.1',
      eol_date: '2023-09-11',
      extended_support_date: '2024-09-11',
      days_remaining: -412,
      observed_version: '1.1.1w',
      asset_id: HOST,
    },
  });

  it('reads the catalogue row the producer cited', () => {
    expect(eolEvidence(full)).toEqual({
      product: 'OpenSSL',
      cycle: '1.1.1',
      eolDate: '2023-09-11',
      extendedSupportDate: '2024-09-11',
      daysRemaining: -412,
      observedVersion: '1.1.1w',
      catalogueId: '11111111-1111-1111-1111-111111111111',
      sourceUrl: 'https://endoflife.date/openssl',
    });
  });

  it('keeps the catalogue row id when the row carried no source URL', () => {
    // A catalogue row an operator hand-entered without a URL still cites
    // SOMETHING — the row. Dropping both would make an uncited claim look
    // identical to a cited one.
    const noURL = finding({ evidence: { ...(full.evidence as object), catalogue_source_url: '' } });
    const e = eolEvidence(noURL);
    expect(e?.sourceUrl).toBeNull();
    expect(e?.catalogueId).toBe('11111111-1111-1111-1111-111111111111');
  });

  it('refuses a non-http source URL', () => {
    const evil = finding({ evidence: { ...(full.evidence as object), catalogue_source_url: 'javascript:alert(1)' } });
    expect(eolEvidence(evil)?.sourceUrl).toBeNull();
  });

  it('returns null when nothing end-of-life-shaped is there', () => {
    // The inspector renders the generic block instead of a panel of dashes.
    expect(eolEvidence(finding({ evidence: {} }))).toBeNull();
    expect(eolEvidence(finding({ evidence: null }))).toBeNull();
    expect(eolEvidence(finding({ evidence: { cves: [] } }))).toBeNull();
    expect(eolEvidence({} as ComplianceFinding)).toBeNull();
  });

  it('treats a non-numeric days_remaining as absent rather than as zero', () => {
    // 0 days remaining means "end of life is today". A string coerced to 0
    // would say that about a finding that never claimed it.
    const odd = finding({ evidence: { ...(full.evidence as object), days_remaining: 'lots' } });
    expect(eolEvidence(odd)?.daysRemaining).toBeNull();
  });
});

describe('cveList', () => {
  const vuln = finding({
    producer: 'vulnerability',
    kind: 'known_vulnerability',
    evidence: {
      cve_count: 3,
      asset_id: HOST,
      cves: [
        { cve_id: 'CVE-2026-1000', cvss_score: 9.8, cvss_vector: 'AV:N/AC:L', matched_by: 'cpe', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1000' },
        { cve_id: 'CVE-2026-1001', cvss_score: 4.3, matched_by: 'purl', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1001' },
        { cve_id: 'CVE-2026-1002', cvss_scored: false, matched_by: 'purl', source_url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1002' },
      ],
    },
  });

  it('lists EVERY CVE, in the order the producer sorted them', () => {
    // One finding per install carries all of them — the identity index leaves
    // no column for a CVE id — so this list IS the finding. A drawer showing
    // only the headline would hide two of three here and eleven of twelve on
    // a real package.
    const out = cveList(vuln);
    expect(out.map((c) => c.id)).toEqual(['CVE-2026-1000', 'CVE-2026-1001', 'CVE-2026-1002']);
    expect(out[0].cvss).toBe(9.8);
    expect(out[0].vector).toBe('AV:N/AC:L');
    expect(out[0].matchedBy).toBe('cpe');
    expect(out[0].href).toBe('https://nvd.nist.gov/vuln/detail/CVE-2026-1000');
  });

  it('keeps "not scored" apart from zero', () => {
    // NVD has not graded every CVE. Rendering an ungraded one as 0.0 is the
    // three-valued collapse: "we could not grade this" shown as "harmless".
    const unscored = cveList(vuln)[2];
    expect(unscored.cvss).toBeNull();
    expect(unscored.scored).toBe(false);

    const scored = cveList(vuln)[1];
    expect(scored.scored).toBe(true);
    expect(scored.cvss).toBe(4.3);
  });

  it('honours an explicit unscored flag even if malformed evidence also carries a number', () => {
    const contradictory = finding({ evidence: { cves: [{ cve_id: 'CVE-2026-X', cvss_score: 9.9, cvss_scored: false }] } });
    expect(cveList(contradictory)[0]).toMatchObject({ cvss: null, scored: false });
  });

  it('treats a genuine CVSS 0.0 as SCORED', () => {
    // 0.0 is the CVSS "None" rating — somebody looked and said it scores
    // nothing. Distinct from nobody having looked.
    const zero = finding({ evidence: { cves: [{ cve_id: 'CVE-2026-0', cvss_score: 0 }] } });
    expect(cveList(zero)[0]).toMatchObject({ cvss: 0, scored: true });
  });

  it('refuses a non-http advisory link', () => {
    const evil = finding({ evidence: { cves: [{ cve_id: 'CVE-1', source_url: 'javascript:alert(1)' }] } });
    expect(cveList(evil)[0].href).toBeNull();
  });

  it('tolerates a malformed list without throwing', () => {
    for (const evidence of [{}, null, { cves: 'not-a-list' }, { cves: [] }, { cves: [null, 3, 'x'] }, { cves: [{ nothing: true }] }]) {
      expect(cveList(finding({ evidence }))).toEqual([]);
    }
    expect(cveList({} as ComplianceFinding)).toEqual([]);
  });

  it('counts from the producer when it stated one, and from the list otherwise', () => {
    expect(cveCount(vuln)).toBe(3);
    expect(cveCount(finding({ evidence: { cves: [{ cve_id: 'CVE-1' }] } }))).toBe(1);
    expect(cveCount(finding({ evidence: {} }))).toBe(0);
  });
});

describe('assessmentLimitations', () => {
  it('inspects every CVE so a scored worst entry cannot hide an unscored one', () => {
    const mixed = finding({
      producer: 'vulnerability',
      evidence: {
        worst_cvss_scored: true,
        cves: [
          { cve_id: 'CVE-2026-1', cvss_score: 9.8 },
          { cve_id: 'CVE-2026-2', cvss_scored: false },
        ],
      },
    });
    const limit = assessmentLimitations([mixed]);
    expect(limit).toEqual({ unscoredCves: 1, totalCves: 2, unscoredSummaries: 0, crypto: [] });
    expect(assessmentLimitText(limit!)).toBe('Assessment incomplete: 1 of 2 matching CVEs has no CVSS score.');
  });

  it('reports unscored-only CVEs and no limitation when every entry is scored', () => {
    expect(assessmentLimitations([finding({ producer: 'vulnerability', evidence: { cves: [
      { cve_id: 'CVE-2026-1', cvss_scored: false },
      { cve_id: 'CVE-2026-2', cvss_scored: false },
    ] } })])).toEqual({ unscoredCves: 2, totalCves: 2, unscoredSummaries: 0, crypto: [] });
    expect(assessmentLimitations([finding({ producer: 'vulnerability', evidence: { cves: [
      { cve_id: 'CVE-2026-3', cvss_score: 0 },
    ] } })])).toBeNull();
  });

  it('does not infer crypto completeness from resolved-only component evidence', () => {
    expect(assessmentLimitations([finding({
      producer: 'crypto',
      evidence: { linked_component_count: 1, components: [{ code: 'AES-256' }] },
    })])).toBeNull();
  });

  it('uses only explicit crypto limitations and preserves their details', () => {
    expect(assessmentLimitations([finding({
      producer: 'crypto',
      evidence: {
        linked_component_count: 1,
        components: [{ code: 'AES-256' }],
        reassessment_required: true,
        assessment_limitations: ['observed hash "mystery" has no resolved catalogue component'],
      },
    })])).toEqual({
      unscoredCves: 0,
      unscoredSummaries: 0,
      totalCves: 0,
      crypto: ['observed hash "mystery" has no resolved catalogue component'],
    });
  });
});

describe('subjectAssetID', () => {
  it('is the subject itself for an asset finding', () => {
    expect(subjectAssetID(finding({ subject_type: 'asset', subject_id: HOST }))).toBe(HOST);
  });

  it('is the host for a software_install finding, never the install', () => {
    const f = finding({ subject_type: 'software_install', subject_id: INSTALL, evidence: { asset_id: HOST } });
    expect(subjectAssetID(f)).toBe(HOST);
    expect(subjectAssetID(f)).not.toBe(INSTALL);
  });

  it('is null rather than a wrong id when evidence names no asset', () => {
    expect(subjectAssetID(finding({ subject_type: 'software_install', evidence: {} }))).toBeNull();
    expect(subjectAssetID(finding({ subject_type: 'certificate', evidence: null }))).toBeNull();
  });
});

describe('configurationEvidence', () => {
  const endpointFinding = finding({
    subject_type: 'endpoint',
    subject_id: '0198fb2c-eeee-2222-3333-444455556666',
    producer: 'configuration',
    kind: 'insecure_service_exposed',
    evidence: {
      rule_id: 'expose-redis',
      matched_by: 'port',
      matched: 'tcp/6379',
      service: 'Redis',
      why: 'Redis ships with no authentication.',
      port: 6379,
      transport: 'tcp',
      bound_local: null,
      asset_id: HOST,
    },
  });

  it('reads the rule, the signal and the citation', () => {
    const e = configurationEvidence(endpointFinding);
    expect(e).not.toBeNull();
    expect(e!.ruleId).toBe('expose-redis');
    expect(e!.matchedBy).toBe('port');
    expect(e!.matched).toBe('tcp/6379');
    expect(e!.service).toBe('Redis');
    expect(e!.port).toBe(6379);
  });

  // The three-valued one. A JSON null and a missing key both mean "nobody
  // established whether this socket is reachable", and reading either as
  // `false` would publish a measurement nobody took.
  it('keeps bound_local three-valued', () => {
    expect(configurationEvidence(endpointFinding)!.boundLocal).toBeNull();
    expect(configurationEvidence(finding({
      evidence: { rule_id: 'x', bound_local: false },
    }))!.boundLocal).toBe(false);
    expect(configurationEvidence(finding({
      evidence: { rule_id: 'x', bound_local: true },
    }))!.boundLocal).toBe(true);
    expect(configurationEvidence(finding({ evidence: { rule_id: 'x' } }))!.boundLocal).toBeNull();
  });

  it('reads the fact-derived management finding', () => {
    const e = configurationEvidence(finding({
      subject_type: 'asset',
      producer: 'configuration',
      kind: 'plaintext_management',
      evidence: { matched_by: 'fact', mgmt_protocol: 'snmpv2c', fact_source_ref: 'interrogation:42' },
    }));
    expect(e!.matchedBy).toBe('fact');
    expect(e!.mgmtProtocol).toBe('snmpv2c');
    expect(e!.factSourceRef).toBe('interrogation:42');
    expect(e!.ruleId).toBeNull();
  });

  it('rejects a signal it does not know rather than rendering the raw key', () => {
    const e = configurationEvidence(finding({ evidence: { rule_id: 'x', matched_by: 'vibes' } }));
    expect(e!.matchedBy).toBeNull();
  });

  it('returns null on anything that is not configuration-shaped, without throwing', () => {
    for (const evidence of [{}, null, { cves: [] }, { catalogue_id: 'x' }]) {
      expect(configurationEvidence(finding({ evidence }))).toBeNull();
    }
    expect(configurationEvidence({} as ComplianceFinding)).toBeNull();
  });
});

describe('hygieneEvidence', () => {
  it('reads the stale ladder detail', () => {
    const e = hygieneEvidence(finding({
      producer: 'hygiene', kind: 'stale',
      evidence: { days_unseen: 97, last_seen_at: '2026-06-07T09:00:00Z', subject_type: 'asset' },
    }));
    expect(e!.daysUnseen).toBe(97);
    expect(e!.lastSeenAt).toBe('2026-06-07T09:00:00Z');
  });

  it('reads the duplicate proposal', () => {
    const e = hygieneEvidence(finding({
      producer: 'hygiene', kind: 'duplicate_suspected',
      evidence: { proposal_id: 'p1', other_asset_ids: [HOST, 3, ''], reason: 'contested identifiers' },
    }));
    expect(e!.proposalId).toBe('p1');
    // Non-strings and blanks are dropped rather than rendered as "3" or "".
    expect(e!.otherAssetIds).toEqual([HOST]);
    expect(e!.proposalReason).toBe('contested identifiers');
  });

  it('reads the orphan edge, naming the missing end and the survivor', () => {
    const e = hygieneEvidence(finding({
      subject_type: 'relationship', producer: 'hygiene', kind: 'orphan_relationship',
      evidence: {
        relationship_type: 'connects_to', missing_asset_label: 'gone-1', missing_reason: 'archived',
        surviving_asset_label: 'core-sw-1', asset_id: HOST,
      },
    }));
    expect(e!.relationshipType).toBe('connects_to');
    expect(e!.missingAssetLabel).toBe('gone-1');
    expect(e!.missingReason).toBe('archived');
    expect(e!.survivingAssetLabel).toBe('core-sw-1');
    // The relationship subject has no page of its own, so the drawer's link
    // goes to the survivor through the same evidence.asset_id path a
    // software_install finding uses.
    expect(subjectAssetID(finding({
      subject_type: 'relationship', evidence: { asset_id: HOST },
    }))).toBe(HOST);
  });

  it('returns null for a finding with no hygiene detail, without throwing', () => {
    for (const evidence of [{}, null, { cves: [] }]) {
      expect(hygieneEvidence(finding({ evidence }))).toBeNull();
    }
    expect(hygieneEvidence({} as ComplianceFinding)).toBeNull();
  });
});

describe('driftEvidence', () => {
  const portProfile = finding({
    subject_type: 'asset',
    subject_id: HOST,
    producer: 'drift',
    kind: 'port_profile_changed',
    evidence: {
      window_days: 30,
      window_start: '2026-08-13T12:00:00Z',
      window_end: '2026-09-12T12:00:00Z',
      observation_key: '+22,-8080',
      asset_id: HOST,
      baseline: { ports: ['443', '8080'] },
      observed: { opened: ['22'], closed: ['8080'] },
    },
  });

  it('reads the two sides of the comparison and the window it was judged under', () => {
    const d = driftEvidence(portProfile);
    expect(d).not.toBeNull();
    expect(d!.windowDays).toBe(30);
    expect(d!.windowStart).toBe('2026-08-13T12:00:00Z');
    expect(d!.baseline).toEqual([{ label: 'Ports', value: '443, 8080' }]);
    expect(d!.observed).toEqual([
      { label: 'Opened', value: '22' },
      { label: 'Closed', value: '8080' },
    ]);
  });

  it('renders an EMPTY side as "none", because "nothing closed" is half the answer', () => {
    const onlyOpened = finding({
      producer: 'drift',
      evidence: { window_days: 30, observed: { opened: ['22'], closed: [] }, baseline: { ports: ['443'] } },
    });
    const d = driftEvidence(onlyOpened);
    expect(d!.observed).toContainEqual({ label: 'Closed', value: 'none' });
  });

  it('never renders the bookkeeping keys a reader has no use for', () => {
    const d = driftEvidence(finding({
      producer: 'drift',
      evidence: {
        window_days: 30,
        baseline: { protocols: ['TLS'] },
        observed: {
          protocols: ['SSH'],
          first_observed_at: '2026-09-08T00:00:00Z',
          // The per-entry array is what would turn the drawer into a JSON dump.
          detail: [{ protocol: 'SSH', source: 'endpoint', source_id: HOST }],
        },
      },
    }));
    expect(d!.observed).toEqual([{ label: 'Protocols', value: 'SSH' }]);
    // first_observed_at is carried on its own field rather than as a row.
    expect(d!.firstObservedAt).toBe('2026-09-08T00:00:00Z');
  });

  it('reads the other three kinds the producer writes', () => {
    const newClass = driftEvidence(finding({
      producer: 'drift',
      evidence: {
        window_days: 30,
        baseline: { classes_in_segment: ['server'], segment_assets_before_window: 12 },
        observed: { class: 'printer', class_label: 'Printer', assets_in_window: 3 },
      },
    }));
    expect(newClass!.baseline).toContainEqual({ label: 'Classes in segment', value: 'server' });
    expect(newClass!.baseline).toContainEqual({ label: 'Segment assets before window', value: '12' });
    expect(newClass!.observed).toContainEqual({ label: 'Class label', value: 'Printer' });

    const newIssuer = driftEvidence(finding({
      producer: 'drift',
      evidence: {
        window_days: 30,
        baseline: { issuers: ['Settled CA'], issuer_dns: ['CN=Settled CA'] },
        observed: { issuer_dns: ['CN=Surprise CA'] },
      },
    }));
    expect(newIssuer!.baseline).toContainEqual({ label: 'Issuers', value: 'Settled CA' });
  });

  it('returns null for a finding with nothing drift-shaped, so the generic block renders', () => {
    expect(driftEvidence(finding({ evidence: {} }))).toBeNull();
    expect(driftEvidence(finding({ evidence: null }))).toBeNull();
    expect(driftEvidence(finding({ evidence: { catalogue_id: 'x' } }))).toBeNull();
  });

  it('tolerates a malformed document rather than throwing and taking the page with it', () => {
    expect(() => driftEvidence(finding({
      evidence: { window_days: 'thirty', baseline: 'not an object', observed: ['not', 'an', 'object'] },
    }))).not.toThrow();
    const d = driftEvidence(finding({
      evidence: { window_days: 30, baseline: 'not an object', observed: null },
    }));
    expect(d!.windowDays).toBe(30);
    expect(d!.baseline).toEqual([]);
    expect(d!.observed).toEqual([]);
  });
});

describe('cryptoEvidence', () => {
  // The `crypto` producer was the ONE producer with no evidence panel: its
  // findings landed on the generic "raised by the Crypto producer" card while
  // the producer had written the whole derivation. Which made the drawer
  // answer "why this score?" for five producers and not for the producer whose
  // entire output is a score.
  it('reads a weak_configuration: the score, what it is made of, and the components behind it', () => {
    const e = cryptoEvidence(finding({
      producer: 'crypto',
      kind: 'weak_configuration',
      subject_type: 'crypto_configuration',
      evidence: {
        score: 85,
        catalogue_score: 85,
        stored_score: 40,
        protocol: 'TLS',
        protocol_version: 'TLS1.0',
        cipher_suite: 'TLS_RSA_WITH_RC4_128_SHA',
        linked_component_count: 3,
        components: [
          { code: 'RC4', role: 'symmetric', risk_score: 85, strength: 'weak', deprecation_status: 'deprecated' },
          { code: 'SHA1', role: 'hash', risk_score: 60, strength: 'weak', deprecation_status: 'deprecated' },
        ],
      },
    }));
    expect(e).not.toBeNull();
    expect(e!.score).toBe(85);
    // The two opinions stay apart: a catalogue score is fixed by editing the
    // `algorithms` row, a stored score by re-observing the service, and a
    // reader who sees only the total is sent to the wrong one.
    expect(e!.catalogueScore).toBe(85);
    expect(e!.storedScore).toBe(40);
    expect(e!.protocol).toBe('TLS');
    expect(e!.protocolVersion).toBe('TLS1.0');
    expect(e!.cipherSuite).toBe('TLS_RSA_WITH_RC4_128_SHA');
    expect(e!.components).toHaveLength(2);
    expect(e!.components[0]).toEqual({
      code: 'RC4', role: 'symmetric', riskScore: 85, strength: 'weak', deprecationStatus: 'deprecated',
    });
    expect(e!.assessmentLimitations).toEqual([]);
    expect(e!.reassessmentRequired).toBe(false);
  });

  it('reads a weak_certificate: the algorithms judged and why they failed', () => {
    const e = cryptoEvidence(finding({
      producer: 'crypto',
      kind: 'weak_certificate',
      subject_type: 'certificate',
      evidence: {
        score: 70,
        risk_factors: ['RSA key below the SP 800-131A 2048-bit floor', 'SHA-1 signature'],
        public_key_algorithm: 'RSA',
        public_key_size: 1024,
        signature_algorithm: 'SHA1withRSA',
      },
    }));
    expect(e!.publicKeyAlgorithm).toBe('RSA');
    expect(e!.publicKeySize).toBe(1024);
    expect(e!.signatureAlgorithm).toBe('SHA1withRSA');
    expect(e!.riskFactors).toHaveLength(2);
  });

  it('reads a pqc_vulnerable: the Shor-breakable codes and the standard that says so', () => {
    const e = cryptoEvidence(finding({
      producer: 'crypto',
      kind: 'pqc_vulnerable',
      evidence: {
        vulnerable_algorithms: ['RSA', 'ECDSA'],
        key_algorithm: 'RSA',
        authority: 'NIST IR 8547',
      },
    }));
    expect(e!.vulnerableAlgorithms).toEqual(['RSA', 'ECDSA']);
    // key_algorithm is the pqc shape's spelling of the same field the
    // certificate shape calls public_key_algorithm; both have to land.
    expect(e!.publicKeyAlgorithm).toBe('RSA');
    expect(e!.authority).toBe('NIST IR 8547');
  });

  it('returns null for a finding with nothing crypto-shaped, so the generic block renders', () => {
    expect(cryptoEvidence(finding({ evidence: {} }))).toBeNull();
    expect(cryptoEvidence(finding({ evidence: null }))).toBeNull();
    expect(cryptoEvidence(finding({ evidence: { catalogue_id: 'x' } }))).toBeNull();
  });

  it('reads explicit reassessment limitations without guessing from component counts', () => {
    const e = cryptoEvidence(finding({ producer: 'crypto', evidence: {
      reassessment_required: true,
      assessment_limitations: ['missing key size', 'unknown strength for FOO'],
      current_reassessment: { score: 0, components: [] },
    } }));
    expect(e).toMatchObject({
      reassessmentRequired: true,
      assessmentLimitations: ['missing key size', 'unknown strength for FOO'],
    });
  });

  it('tolerates a malformed document rather than throwing and taking the page with it', () => {
    expect(() => cryptoEvidence(finding({
      evidence: { score: 'eighty', components: 'not an array', risk_factors: [1, 2] },
    }))).not.toThrow();
    const e = cryptoEvidence(finding({
      evidence: {
        protocol: 'TLS',
        score: 'eighty',
        components: ['not an object', { role: 'symmetric' }, { code: 'RC4' }],
        risk_factors: [1, 'a real one'],
        vulnerable_algorithms: 'RSA',
      },
    }));
    expect(e!.score).toBeNull();
    // A component with no `code` is not nameable, and a row reading "— (85)"
    // is worse than no row.
    expect(e!.components).toEqual([{ code: 'RC4', role: null, riskScore: null, strength: null, deprecationStatus: null }]);
    expect(e!.riskFactors).toEqual(['a real one']);
    expect(e!.vulnerableAlgorithms).toEqual([]);
  });
});
