// The Network view's decisions: where an asset is drawn, what colour
// its badge is, and which crypto rows the By-crypto view shows.
import { describe, expect, it } from 'vitest';
import { LEVEL_MIN } from '../../components/ui/risk';
import {
  DEVICES_ZOOM_BELOW, arcPath, assetIcon, assetTone, badgeCount, cryptoTraits, defaultPrefs,
  emptySegmentCount, groupSites, networkTruncationNotice, parsePrefs, splitArc, toneCounts,
  visibleAssets,
  type NetworkMap, type NetworkMapAsset, type NetworkMapComponent,
} from './network-map-model';

const SEG_A = '00000000-0000-4000-8000-00000000000a';
const SEG_B = '00000000-0000-4000-8000-00000000000b';
const SEG_EMPTY = '00000000-0000-4000-8000-0000000000ee';

let n = 0;
function asset(over: Partial<NetworkMapAsset> = {}): NetworkMapAsset {
  n += 1;
  return {
    asset_id: `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`,
    display_name: `host-${n}`,
    class_key: 'server',
    asset_status: 'monitoring',
    site: 'Head office',
    segment_id: SEG_A,
    risk_score: 0,
    risk_assessed: false,
    service_count: 0,
    crypto_service_count: 0,
    crypto: { components: [], pqc: { needs_migration: 0, pqc_ready: 0, symmetric_safe: 0, unclassified: 0 }, certs_expiring_90d: 0 },
    ...over,
  };
}

function withCrypto(over: Partial<NetworkMapAsset> = {}, crypto: Partial<NetworkMapAsset['crypto']> = {}): NetworkMapAsset {
  const a = asset({ service_count: 1, crypto_service_count: 1, ...over });
  return { ...a, crypto: { ...a.crypto, ...crypto } };
}

function map(assets: NetworkMapAsset[], over: Partial<NetworkMap> = {}): NetworkMap {
  return {
    segments: [
      { segment_id: SEG_A, name: 'Office LAN', value: '10.0.0.0/24', segment_type: 'cidr' },
      { segment_id: SEG_B, name: 'Servers', value: '10.0.1.0/24', segment_type: 'cidr' },
      { segment_id: SEG_EMPTY, name: 'Guest', value: '10.0.9.0/24', segment_type: 'cidr' },
    ],
    assets,
    total_assets: assets.length,
    truncated: false,
    asset_cap: 5000,
    ...over,
  };
}

const comp = (over: Partial<NetworkMapComponent>): NetworkMapComponent => ({
  algorithm_type: 'key_exchange', name: 'X', strength: 'strong', is_pqc: false, observed: true, ...over,
});

describe('grouping (D2)', () => {
  it('places assets by site, then by their ASSIGNED segment', () => {
    const a = asset({ segment_id: SEG_A });
    const b = asset({ segment_id: SEG_B });
    const b2 = asset({ segment_id: SEG_B });
    const [site] = groupSites(map([a, b, b2]), [a, b, b2]);
    expect(site.name).toBe('Head office');
    // Biggest tray first.
    expect(site.trays.map((t) => t.name)).toEqual(['Servers', 'Office LAN']);
    expect(site.trays[0].detail).toBe('10.0.1.0/24');
  });

  it('never infers a network from the address', () => {
    // The address says 10.0.1.x, the data says Office LAN. The map shows what
    // the data says — correcting it silently would hide the thing to fix.
    const a = asset({ segment_id: SEG_A, address: '10.0.1.7' });
    const [site] = groupSites(map([a]), [a]);
    expect(site.trays[0].name).toBe('Office LAN');
  });

  it('puts an unsegmented asset in an explicit Unsegmented tray, last', () => {
    const lone = asset({ segment_id: null });
    const x = asset({ segment_id: SEG_A });
    const [site] = groupSites(map([lone, x]), [lone, x]);
    expect(site.trays.map((t) => t.name)).toEqual(['Office LAN', 'Unsegmented']);
    expect(site.trays[1].segmentId).toBeNull();
  });

  it('keeps an asset on an inactive segment in its own tray, not Unsegmented', () => {
    const gone = asset({ segment_id: '00000000-0000-4000-8000-0000000000ff' });
    const [site] = groupSites(map([gone]), [gone]);
    expect(site.trays[0].name).toBe('Inactive network');
    expect(site.trays[0].segmentId).not.toBeNull();
  });

  it('groups a siteless cloud resource under its account, one tray per region', () => {
    const e1 = asset({ site: 'Unassigned', segment_id: null, cloud_account: '1234', cloud_region: 'us-east-1' });
    const w1 = asset({ site: 'Unassigned', segment_id: null, cloud_account: '1234', cloud_region: 'eu-west-1' });
    const e2 = asset({ site: 'Unassigned', segment_id: null, cloud_account: '1234', cloud_region: 'us-east-1' });
    const [site] = groupSites(map([e1, w1, e2]), [e1, w1, e2]);
    expect(site.kind).toBe('cloud');
    expect(site.name).toBe('Cloud account 1234');
    expect(site.trays.map((t) => t.name)).toEqual(['us-east-1', 'eu-west-1']);
  });

  it('keeps two cloud accounts apart', () => {
    const a = asset({ site: 'Unassigned', segment_id: null, cloud_account: '111' });
    const b = asset({ site: 'Unassigned', segment_id: null, cloud_account: '222' });
    expect(groupSites(map([a, b]), [a, b]).map((s) => s.name).sort()).toEqual(['Cloud account 111', 'Cloud account 222']);
  });

  it('puts assets with no site and no cloud account in "No site recorded", last', () => {
    const big = [asset(), asset(), asset()];
    const lost = asset({ site: 'Unassigned' });
    const small = asset({ site: 'Branch' });
    const all = [...big, lost, small];
    const sites = groupSites(map(all), all);
    expect(sites.map((s) => s.name)).toEqual(['Head office', 'Branch', 'No site recorded']);
    expect(sites[2].kind).toBe('unassigned');
  });

  it('counts active segments nothing sits in, rather than drawing them', () => {
    const a = asset({ segment_id: SEG_A });
    const b = asset({ segment_id: SEG_B });
    expect(emptySegmentCount(map([a, b]))).toBe(1);
  });

  it('filters to devices with crypto when asked', () => {
    const plain = asset({ service_count: 3 });
    const c = withCrypto();
    expect(visibleAssets(map([plain, c]), true)).toEqual([c]);
    expect(visibleAssets(map([plain, c]), false)).toHaveLength(2);
  });
});

describe('the badge tone', () => {
  it('draws an unassessed score as "not assessed", never as a low score (D4)', () => {
    expect(assetTone(withCrypto({ risk_score: 0, risk_assessed: false }), 'risk')).toBe('unassessed');
    // The other polarity: an ASSESSED zero is a real, informational answer.
    expect(assetTone(withCrypto({ risk_score: 0, risk_assessed: true }), 'risk')).toBe('info');
  });

  it('bands through the canonical ladder, at its own boundaries', () => {
    const at = (s: number) => assetTone(withCrypto({ risk_score: s, risk_assessed: true }), 'risk');
    expect(at(LEVEL_MIN.High - 1)).toBe('medium');
    expect(at(LEVEL_MIN.High)).toBe('high');
    expect(at(LEVEL_MIN.Critical)).toBe('critical');
    expect(at(LEVEL_MIN.Low)).toBe('low');
  });

  it('marks a device needing PQC migration even when some configs are ready', () => {
    // One classical asymmetric configuration is enough: the classifier's
    // precedence, not a vote.
    const a = withCrypto({}, { pqc: { needs_migration: 1, pqc_ready: 3, symmetric_safe: 0, unclassified: 0 } });
    expect(assetTone(a, 'pqc')).toBe('migrate');
  });

  it('does not call a device quantum-safe when a config is unclassified', () => {
    const a = withCrypto({}, { pqc: { needs_migration: 0, pqc_ready: 2, symmetric_safe: 0, unclassified: 1 } });
    expect(assetTone(a, 'pqc')).toBe('unclassified');
    const none = withCrypto({}, { pqc: { needs_migration: 0, pqc_ready: 0, symmetric_safe: 0, unclassified: 0 } });
    expect(assetTone(none, 'pqc')).toBe('unclassified');
  });

  it('calls a device ready only when every config is ready or symmetric-only', () => {
    const a = withCrypto({}, { pqc: { needs_migration: 0, pqc_ready: 1, symmetric_safe: 2, unclassified: 0 } });
    expect(assetTone(a, 'pqc')).toBe('ready');
  });

  it('gives a device with services but no crypto its own tone, and one with neither none', () => {
    const svc = asset({ service_count: 4 });
    expect(assetTone(svc, 'risk')).toBe('services');
    expect(assetTone(svc, 'pqc')).toBe('services');
    expect(badgeCount(svc)).toBe(4);
    expect(assetTone(asset(), 'risk')).toBeNull();
  });

  it('counts tones worst first and skips devices with nothing to badge', () => {
    const list = [
      withCrypto({ risk_score: 95, risk_assessed: true }),
      withCrypto({ risk_score: 10, risk_assessed: true }),
      withCrypto({ risk_score: 92, risk_assessed: true }),
      asset(),
    ];
    expect(toneCounts(list, 'risk')).toEqual([{ tone: 'critical', count: 2 }, { tone: 'low', count: 1 }]);
  });
});

describe('the By-crypto rows', () => {
  it('orders weak before acceptable before the rest, and by reach within a tone', () => {
    const weakSig = comp({ algorithm_type: 'signature', name: 'ssh-rsa (SHA-1)', strength: 'weak' });
    const okKex = comp({ name: 'dh-group14', strength: 'acceptable' });
    const a = withCrypto({}, { components: [weakSig, okKex] });
    const b = withCrypto({}, { components: [okKex] });
    const rows = cryptoTraits([a, b]);
    expect(rows.map((r) => r.label)).toEqual(['Signature · ssh-rsa (SHA-1)', 'Key exchange · dh-group14']);
    expect(rows[0].tone).toBe('bad');
    expect(rows[1].assetIds).toHaveLength(2);
  });

  it('hides strong non-PQC rows by default but keeps PQC and unassessed ones visible', () => {
    const rows = cryptoTraits([withCrypto({}, {
      components: [
        comp({ name: 'ecdhe', strength: 'strong' }),
        comp({ name: 'mlkem768x25519', strength: 'recommended', is_pqc: true }),
        comp({ name: 'mystery', strength: '' }),
      ],
    })]);
    const byName = Object.fromEntries(rows.map((r) => [r.label.split(' · ')[1], r]));
    expect(byName.ecdhe.quiet).toBe(true);
    expect(byName.mlkem768x25519.quiet).toBe(false);
    expect(byName.mlkem768x25519.tone).toBe('good');
    // No strength recorded is unassessed, not strong.
    expect(byName.mystery.quiet).toBe(false);
    expect(byName.mystery.tone).toBe('neutral');
  });

  it('marks a component nobody uses as offered only, and clears it once anyone uses it', () => {
    const offered = comp({ algorithm_type: 'hash', name: 'hmac-sha1', strength: 'weak', observed: false });
    expect(cryptoTraits([withCrypto({}, { components: [offered] })])[0].offeredOnly).toBe(true);
    const used = { ...offered, observed: true };
    const rows = cryptoTraits([withCrypto({}, { components: [offered] }), withCrypto({}, { components: [used] })]);
    expect(rows[0].offeredOnly).toBe(false);
  });

  it('adds an expiring-certificate row next to the weakest', () => {
    const rows = cryptoTraits([
      withCrypto({}, { certs_expiring_90d: 1, components: [comp({ strength: 'acceptable', name: 'dh' })] }),
    ]);
    expect(rows[0].label).toBe('Certificate expires within 90 days');
  });
});

describe('prefs (D1)', () => {
  it('opens a small estate on every device and a large one on the sites', () => {
    expect(defaultPrefs(DEVICES_ZOOM_BELOW - 1).zoom).toBe(2);
    expect(defaultPrefs(DEVICES_ZOOM_BELOW).zoom).toBe(0);
    expect(defaultPrefs(10).view).toBe('funnel');
  });

  it('keeps the valid fields of a stale saved record and defaults the rest', () => {
    const fb = defaultPrefs(10);
    expect(parsePrefs({ view: 'hexagon', zoom: 1, colour: 'pqc', onlyCrypto: 'yes' }, fb))
      .toEqual({ view: 'funnel', zoom: 1, colour: 'pqc', onlyCrypto: false });
    expect(parsePrefs(null, fb)).toBe(fb);
    expect(parsePrefs({ view: 'radial', zoom: 7 }, fb)).toMatchObject({ view: 'radial', zoom: fb.zoom });
  });
});

describe('radial geometry', () => {
  it('splits proportionally but never gives a slice nothing', () => {
    const arcs = splitArc(0, 12, [0, 2, 3]);
    expect(arcs.map((a) => a.a1 - a.a0)).toEqual([2, 4, 6]);
    expect(arcs[2].a1).toBe(12);
  });

  it('draws a full ring as two half-arcs, never a zero-length arc', () => {
    const d = arcPath(100, 100, 10, 20, 0, Math.PI * 2);
    expect(d.match(/A/g)).toHaveLength(4);
    expect(d).not.toContain('NaN');
  });
});

describe('icons and truncation', () => {
  it('uses a class\'s own icon, and its group\'s for an unknown class', () => {
    expect(assetIcon('router')).toBe('router');
    expect(assetIcon('tenant_leaf_nobody_knows')).toBe('circle-dashed');
  });

  it('admits to a capped map, and says nothing about an uncapped one', () => {
    const a = asset();
    expect(networkTruncationNotice(map([a]))).toBeNull();
    expect(networkTruncationNotice(map([a], { truncated: true, total_assets: 9000 }))).toMatch(/Showing 1 of 9,000 assets/);
  });
});
