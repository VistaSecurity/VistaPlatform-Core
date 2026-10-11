import { describe, expect, it } from 'vitest';
import { UNTRUSTED_CA_FLAG_TEXT, connectionTrustStatus, presentHygieneFlags } from './connection-trust';

const PROBE = 'Certificate signed by an untrusted certificate authority (not in the system trust store — may be a private or pinned CA)';
const SCT = 'Certificate has no Signed Certificate Timestamp';

describe('3rd Party lens · certificate trust', () => {
  it('reads trust_status only when the server sent a non-empty string', () => {
    expect(connectionTrustStatus({ trust_status: 'untrusted' })).toBe('untrusted');
    expect(connectionTrustStatus({ trust_status: '' })).toBeUndefined();
    expect(connectionTrustStatus({ trust_status: 3 })).toBeUndefined();
    expect(connectionTrustStatus({})).toBeUndefined();
    expect(connectionTrustStatus(null)).toBeUndefined();
  });

  it('rewords the probe\'s unknown-CA flag to say whose trust and where to change it', () => {
    expect(presentHygieneFlags([SCT, PROBE], undefined)).toEqual([SCT, UNTRUSTED_CA_FLAG_TEXT]);
    expect(UNTRUSTED_CA_FLAG_TEXT).toContain('not trusted by your organisation');
    expect(UNTRUSTED_CA_FLAG_TEXT).toContain('Settings → Policies → Trusted CAs');
  });

  it('drops the probe\'s flag once the platform has a trust status — the chip carries that answer', () => {
    expect(presentHygieneFlags([PROBE, SCT], 'private_trusted')).toEqual([SCT]);
  });

  it('passes every other flag through untouched', () => {
    expect(presentHygieneFlags([SCT], 'untrusted')).toEqual([SCT]);
    expect(presentHygieneFlags(undefined, undefined)).toEqual([]);
  });
});
