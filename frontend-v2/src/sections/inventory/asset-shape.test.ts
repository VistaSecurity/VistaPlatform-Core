// The ADR-0002 asset shape, and the primary-endpoint rule in particular.
//
// The case that motivated the previous version of these tests was a
// sensor-discovered asset with nothing but an IP. The case that motivates this
// one is the opposite: an asset with NO network face at all — an object store, a
// declared service — which the old flat row could not represent and which the
// old `port` column gave a fabricated port to. Every assertion below is about
// the same rule in a different place: a field the service does not know renders
// as an explicit absence, never as a confident-looking value.
import { describe, expect, it, vi, afterEach } from 'vitest';
import {
  assetIdentity, assetLocation, assetRisk, assetService, attr, classDeclares,
  classIcon, classLabel, confidenceLabel, endpointCount, identifierKindLabel,
  operatingSystem, primaryAddress, primaryAddressPort, primaryEndpoint,
  relativeSeen, riskBand, sourceKindLabel, stripMask,
  type AssetLike,
} from './asset-shape';

const SERVER: AssetLike = {
  class_key: 'server',
  hostname: 'edge-01',
  endpoints: [{ id: 'e1', address: '192.0.2.10', port: 443, transport: 'tcp', service_name: 'nginx', service_version: '1.25.3' }],
  attributes: { operating_system: 'Ubuntu', os_version: '24.04' },
};

/** The at-rest case: a bucket has nothing to connect to, and saying so is the
 *  answer. This shape is what the old model could not express. */
const BUCKET: AssetLike = {
  class_key: 'object_storage',
  display_name: 'payroll-exports',
  endpoints: [],
  attributes: { cloud_provider: 'aws', account_id: '0123456789' },
};

describe('primaryEndpoint', () => {
  it('prefers the server-supplied primary_endpoint over the first of the list', () => {
    const a: AssetLike = {
      primary_endpoint: { id: 'chosen', address: '10.0.0.1', port: 22 },
      endpoints: [{ id: 'first', address: '10.0.0.2', port: 80 }],
    };
    expect(primaryEndpoint(a)?.id).toBe('chosen');
  });

  it('falls back to the first endpoint when the server sent no primary', () => {
    expect(primaryEndpoint(SERVER)?.id).toBe('e1');
  });

  it('is null for an asset with no endpoints at all', () => {
    expect(primaryEndpoint(BUCKET)).toBeNull();
    expect(primaryEndpoint({})).toBeNull();
  });
});

describe('primaryAddressPort — the rule that matters', () => {
  it('renders address:port when the endpoint has both', () => {
    expect(primaryAddressPort(SERVER)).toBe('192.0.2.10:443');
  });

  it('NEVER fabricates a port when the endpoint has none', () => {
    // An at-rest or declared endpoint has no port. The "AT-REST" sentinel the
    // port-as-asset model needed is retired, so there is nothing to print.
    const atRest: AssetLike = { endpoints: [{ id: 'e', address: '10.0.0.5', transport: 'none' }] };
    expect(primaryAddressPort(atRest)).toBe('10.0.0.5');
    expect(primaryAddressPort(atRest)).not.toContain(':');
  });

  it('treats port 0 as absent, not as a port', () => {
    const zero: AssetLike = { endpoints: [{ id: 'e', address: '10.0.0.5', port: 0 }] };
    expect(primaryAddressPort(zero)).toBe('10.0.0.5');
  });

  it('is EMPTY for an asset with no network face — never a placeholder', () => {
    expect(primaryAddressPort(BUCKET)).toBe('');
    expect(primaryAddress(BUCKET)).toBe('');
  });

  it('falls back to the endpoint fqdn when it carries no address', () => {
    const byName: AssetLike = { endpoints: [{ id: 'e', fqdn: 'api.example.com', port: 443 }] };
    expect(primaryAddressPort(byName)).toBe('api.example.com:443');
  });

  it('falls back to the convenience primary_address column when there is no endpoint', () => {
    expect(primaryAddressPort({ primary_address: '203.0.113.9' })).toBe('203.0.113.9');
  });

  it('strips a /32 host mask, which inet columns bake in', () => {
    expect(stripMask('198.51.100.7/32')).toBe('198.51.100.7');
    expect(stripMask('2001:db8::1/128')).toBe('2001:db8::1');
    // A real prefix is NOT a host mask and must survive.
    expect(stripMask('10.0.0.0/24')).toBe('10.0.0.0/24');
  });
});

describe('classLabel / classIcon', () => {
  it('resolves a known class through the generated registry', () => {
    expect(classLabel('server')).toBe('Server');
    expect(classLabel('object_storage')).toBe('Object storage');
  });

  it('names the icon the way Icon is keyed, not the way the registry spells it', () => {
    // The registry says `CircuitBoard` (a lucide export, checked by the
    // generator); Icon's map says `circuit-board`. Handing the export name
    // through unconverted drew a question mark for every class.
    expect(classIcon('hardware')).toBe('circuit-board');
    expect(classIcon('server')).toBe('server');
  });

  it('renders an UNKNOWN class as its key rather than as nothing', () => {
    // A tenant subclass, or a class this build predates. The key is still the
    // truest thing we hold about the row.
    expect(classLabel('tenant_custom_thing')).toBe('tenant_custom_thing');
    expect(classIcon('tenant_custom_thing')).toBe('box');
  });

  it('is empty for no class', () => {
    expect(classLabel(null)).toBe('');
    expect(classLabel(undefined)).toBe('');
  });
});

describe('operatingSystem — an attribute, not a column', () => {
  it('reads it off the attributes bag for a class that declares one', () => {
    expect(operatingSystem(SERVER)).toBe('Ubuntu 24.04');
  });

  it('is EMPTY for a class with no OS concept, even if the bag somehow carries one', () => {
    // "Cannot have one" and "has one we did not collect" are different facts,
    // and only the class can tell them apart. A switch has no OS slot.
    const switchWithStrayAttr: AssetLike = { class_key: 'switch', attributes: { operating_system: 'NX-OS' } };
    expect(classDeclares('switch', 'operating_system')).toBe(false);
    expect(operatingSystem(switchWithStrayAttr)).toBe('');
  });

  it('is empty when the class declares one but nothing was collected', () => {
    expect(operatingSystem({ class_key: 'server', attributes: {} })).toBe('');
  });
});

describe('attr', () => {
  it('renders numbers and joins arrays', () => {
    expect(attr({ attributes: { cpu_count: 8 } }, 'cpu_count')).toBe('8');
    expect(attr({ attributes: { tags: ['a', 'b'] } }, 'tags')).toBe('a, b');
  });

  it('is empty for an absent key, a null value, and a nested object', () => {
    expect(attr({ attributes: {} }, 'model')).toBe('');
    expect(attr({ attributes: { model: null } }, 'model')).toBe('');
    expect(attr({ attributes: { model: { a: 1 } } }, 'model')).toBe('');
    expect(attr({}, 'model')).toBe('');
  });
});

describe('assetIdentity', () => {
  it('titles by display name, then hostname, then the address', () => {
    expect(assetIdentity(SERVER).primary).toBe('edge-01');
    expect(assetIdentity({ ...SERVER, display_name: 'Edge gateway' }).primary).toBe('Edge gateway');
    expect(assetIdentity({ endpoints: [{ id: 'e', address: '192.0.2.41' }] }).primary).toBe('192.0.2.41');
  });

  it('puts the address, class and OS on the sub-line when the title took a name', () => {
    expect(assetIdentity(SERVER).secondary).toBe('192.0.2.10:443 · Server · Ubuntu 24.04');
  });

  it('does NOT repeat the address below when the title already is the address', () => {
    const bare: AssetLike = { endpoints: [{ id: 'e', address: '192.0.2.41' }] };
    expect(assetIdentity(bare)).toEqual({ primary: '192.0.2.41', secondary: '' });
  });

  it('gives an em dash, not an empty string, when nothing at all is known', () => {
    expect(assetIdentity({}).primary).toBe('—');
  });

  it('ignores a whitespace-only hostname', () => {
    expect(assetIdentity({ hostname: '   ', endpoints: [{ id: 'e', address: '192.0.2.9' }] }).primary).toBe('192.0.2.9');
  });

  it('titles a bucket by its display name and says its class, with no address', () => {
    expect(assetIdentity(BUCKET)).toEqual({ primary: 'payroll-exports', secondary: 'Object storage' });
  });
});

describe('assetLocation', () => {
  it('splits the environment badge from the path', () => {
    expect(assetLocation({ environment: 'production', network_segment_name: 'DMZ', region: 'us-east-1' }))
      .toEqual({ environment: 'production', path: 'DMZ · us-east-1' });
  });

  it('falls back to the business unit when there is no segment', () => {
    expect(assetLocation({ business_unit: 'Payments' }).path).toBe('Payments');
  });

  it('is null/null when nothing is known — the cell then reads "unknown", not "no segment"', () => {
    expect(assetLocation({})).toEqual({ environment: null, path: null });
  });
});

describe('assetService — read off the ENDPOINT, not the host', () => {
  it('takes the primary endpoint’s service', () => {
    expect(assetService(SERVER)).toEqual({ name: 'nginx', version: 'v1.25.3' });
  });

  it('does not double the v prefix', () => {
    const a: AssetLike = { endpoints: [{ id: 'e', service_name: 'nginx', service_version: 'v1.2' }] };
    expect(assetService(a).version).toBe('v1.2');
  });

  it('collapses a version with no name to null/null — a version is not a service', () => {
    const a: AssetLike = { endpoints: [{ id: 'e', service_version: '1.2' }] };
    expect(assetService(a)).toEqual({ name: null, version: null });
  });

  it('is null/null for an asset with no endpoints', () => {
    expect(assetService(BUCKET)).toEqual({ name: null, version: null });
  });
});

describe('endpointCount', () => {
  it('reports 0 for an asset that genuinely has none', () => {
    expect(endpointCount(BUCKET)).toBe(0);
  });

  it('reports NULL when the payload did not carry the list at all', () => {
    // A list row omits endpoints. Rendering "0 endpoints" for that would be a
    // claim about the asset made from the absence of a field.
    expect(endpointCount({ class_key: 'server' })).toBeNull();
  });
});

// The three-valued honesty guard, now that `risk_assessed_by` exists to make it
// three-valued. Before that field, a score of 0 had to stand for both "nobody
// looked" and "looked, found nothing", and the UI guessed the first for both.
describe('assetRisk', () => {
  it('marks score 0 with an EMPTY risk_assessed_by as NOT assessed', () => {
    const r = assetRisk({ risk_score: 0, risk_assessed_by: [] });
    expect(r.assessed).toBe(false);
    expect(r.label).toBe('—');
    expect(r.level).toBe('Informational');
    expect(r.title).toMatch(/not assessed/i);
  });

  it('marks score 0 with a NON-empty risk_assessed_by as assessed CLEAN', () => {
    // This is the case the old two-valued logic got wrong: a genuinely clean
    // asset was denied its clean bill of health.
    const r = assetRisk({ risk_score: 0, risk_assessed_by: ['crypto'] });
    expect(r.assessed).toBe(true);
    expect(r.label).toBe('0');
    expect(r.assessedBy).toEqual(['crypto']);
    expect(r.title).toMatch(/assessed by crypto/i);
  });

  it('treats a non-zero score as assessed even when the array was omitted', () => {
    const r = assetRisk({ risk_score: 72, risk_level: 'High' });
    expect(r.assessed).toBe(true);
    expect(r.level).toBe('High');
    expect(r.label).toBe('72');
  });

  it('ignores blank entries in risk_assessed_by', () => {
    expect(assetRisk({ risk_score: 0, risk_assessed_by: ['', '  '] }).assessed).toBe(false);
  });

  it('bands from the score when the backend sent no level', () => {
    expect(assetRisk({ risk_score: 95 }).level).toBe('Critical');
    expect(assetRisk({ risk_score: 41 }).level).toBe('Medium');
  });

  it('treats a non-numeric score as 0 / not assessed', () => {
    expect(assetRisk({ risk_score: 'high' }).assessed).toBe(false);
    expect(assetRisk({ risk_score: NaN }).assessed).toBe(false);
  });
});

// The CVSS v3.1/v4.0 qualitative ratings ×10, mirroring models.RiskBands.
describe('riskBand', () => {
  it.each([
    [100, 'Critical'], [90, 'Critical'], [89, 'High'], [70, 'High'],
    [69, 'Medium'], [40, 'Medium'], [39, 'Low'], [1, 'Low'], [0, 'Informational'],
  ])('bands %i as %s', (score, band) => {
    expect(riskBand(score)).toBe(band);
  });
});

describe('label helpers', () => {
  it('names the identifier kinds a person recognises', () => {
    expect(identifierKindLabel('ssh_host_key_fingerprint')).toBe('SSH host key');
    expect(identifierKindLabel('cmdb_sys_id')).toBe('CMDB sys_id');
    // An unknown kind degrades to readable words rather than to nothing.
    expect(identifierKindLabel('future_kind')).toBe('future kind');
  });

  it('names the source kinds', () => {
    expect(sourceKindLabel('measured')).toBe('Measured');
    expect(sourceKindLabel('inferred')).toBe('Inferred');
    expect(sourceKindLabel(null)).toBe('');
  });

  it('renders confidence as a percentage from either 0..1 or 0..100', () => {
    expect(confidenceLabel(0.85)).toBe('85%');
    expect(confidenceLabel(85)).toBe('85%');
  });

  it('renders an ABSENT confidence as empty, never as 0%', () => {
    // "Nothing classified it" is not "classified with zero confidence".
    expect(confidenceLabel(undefined)).toBe('');
    expect(confidenceLabel(null)).toBe('');
  });
});

describe('relativeSeen', () => {
  afterEach(() => vi.useRealTimers());

  it('coarsens a recent timestamp', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-09-11T12:00:00Z'));
    expect(relativeSeen('2026-09-11T11:30:00Z')).toBe('30m ago');
    expect(relativeSeen('2026-09-10T12:00:00Z')).toBe('1d ago');
    expect(relativeSeen('2026-09-11T11:59:50Z')).toBe('just now');
  });

  it('says nothing for a missing timestamp or Go’s zero time', () => {
    // "0001-01-01T00:00:00Z" reaches the UI as a real date on rows never
    // actually seen; rendering it as "24237mo ago" would be a confident answer
    // to a question we cannot answer.
    expect(relativeSeen(null)).toBe('');
    expect(relativeSeen('0001-01-01T00:00:00Z')).toBe('');
    expect(relativeSeen('not a date')).toBe('');
  });
});
