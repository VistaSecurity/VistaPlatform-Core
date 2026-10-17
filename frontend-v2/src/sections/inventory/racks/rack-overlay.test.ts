// The crypto overlay's colours come from the ratings module (DCIM row 2.5):
// each finding severity maps to its RISK_BANDS band and that band's
// LEVEL_COLOR token — asserted against the generated exports, so a hand-coded
// colour or threshold here goes red. "Not assessed" is never drawn as clean.
import { describe, expect, it } from 'vitest';
import { RISK_BANDS, SEVERITIES } from '@vistasecurity/primitives/ratings';
import { LEVEL_COLOR } from '../../../components/ui/risk';
import { bandForSeverity, certBadgeText, certDaysLeft, overlayState, overlayTooltip, type DevicePosture } from './rack-overlay';

const posture = (over: Partial<DevicePosture> = {}): DevicePosture => ({
  assessed: true, open_findings: 0, top_finding: null, weak_protocol: false, cert_expires_at: null, ...over,
});
const finding = (severity: string) => ({ id: 'f', producer: 'crypto', kind: 'weak_configuration', severity, score: 80, summary: 'TLS 1.0 negotiated' });

describe('overlay colour', () => {
  it('every severity tints with its band colour from the ratings module', () => {
    for (const s of SEVERITIES) {
      const band = RISK_BANDS.find((b) => b.severity === s.value)!;
      const state = overlayState(posture({ open_findings: 1, top_finding: finding(s.value) }));
      expect(state.kind).toBe('finding');
      expect(bandForSeverity(s.value)).toBe(band.label);
      expect(state.color).toBe(LEVEL_COLOR[band.label]);
    }
  });
  it('high is the High band, critical the Critical band', () => {
    expect(overlayState(posture({ open_findings: 2, top_finding: finding('high') })).color).toBe(LEVEL_COLOR.High);
    expect(overlayState(posture({ open_findings: 1, top_finding: finding('critical') })).color).toBe(LEVEL_COLOR.Critical);
  });
  it('an unknown severity is not given a band', () => {
    expect(bandForSeverity('severe')).toBeNull();
    expect(overlayState(posture({ open_findings: 1, top_finding: finding('severe') })).kind).toBe('unknown');
    expect(overlayState(posture({ open_findings: 1, top_finding: finding('severe') })).label).toContain('severity not recognised');
  });
  it('assessed with nothing open is clean; never assessed is not', () => {
    expect(overlayState(posture()).kind).toBe('clean');
    expect(overlayState(posture({ assessed: false })).kind).toBe('unassessed');
    expect(overlayState(posture({ assessed: false })).label).toBe('Not assessed');
    expect(overlayState(undefined).kind).toBe('unknown');
  });
});

describe('certificate badge', () => {
  const now = new Date('2026-10-16T00:00:00Z');
  it('counts whole days and says when it has passed', () => {
    expect(certDaysLeft(posture({ cert_expires_at: '2026-10-28T12:00:00Z' }), now)).toBe(12);
    expect(certBadgeText(12)).toBe('Certificate expires in 12 days');
    expect(certBadgeText(-1)).toBe('Certificate expired');
    expect(certDaysLeft(posture(), now)).toBeNull();
  });
  it('the tooltip leads with the top finding', () => {
    const t = overlayTooltip('core-sw-1', posture({ open_findings: 1, top_finding: finding('high'), weak_protocol: true, cert_expires_at: '2026-10-20T00:00:00Z' }), now);
    expect(t.split('\n')).toEqual(['core-sw-1', 'High · 1 open finding', 'Top finding: TLS 1.0 negotiated', 'Weak protocol version in use', 'Certificate expires in 4 days']);
  });
});
