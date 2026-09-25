import { describe, expect, it } from 'vitest';
import { hybridKexHint, type CryptoComponent } from './risk-explanation';

// W1.9: a server that supports hybrid post-quantum key exchange but
// negotiated a classical group gets a configuration-change hint on its
// key-exchange component. The backend decides when; this pins what the copy
// says and that nothing else can make it appear.

function kex(overrides: Partial<CryptoComponent> = {}): CryptoComponent {
  return {
    algorithm_type: 'key_exchange',
    algorithm_id: '00000000-0000-4000-8000-000000000001',
    code: 'X25519',
    name: 'X25519',
    category: 'key_exchange',
    strength: 'strong',
    deprecation_status: 'current',
    risk_score: 15,
    risk_level: 'Low',
    sets_score: false,
    is_inferred: false,
    recommended_alternatives: ['X25519MLKEM768'],
    is_pqc: false,
    ...overrides,
  };
}

describe('hybridKexHint', () => {
  it('names the accepted hybrid group and the classical group negotiated', () => {
    const h = hybridKexHint(kex({ hybrid_kex_available: { groups: ['X25519MLKEM768'] } }));
    expect(h?.text).toBe(
      'This server supports hybrid post-quantum key exchange (X25519MLKEM768), but negotiated X25519. ' +
        "Prefer the hybrid group in the server's configuration, or update the clients that connect to it.",
    );
  });

  it('says why the category and score have not moved', () => {
    const h = hybridKexHint(kex({ hybrid_kex_available: { groups: [] } }));
    expect(h?.note).toContain('still counts as needing PQC migration');
    expect(h?.note).toContain('risk score is unchanged');
  });

  it('omits the group list when the producer did not record one, rather than inventing it', () => {
    const h = hybridKexHint(kex({ code: 'DH-ECP-256', hybrid_kex_available: { groups: [] } }));
    expect(h?.text).toContain('supports hybrid post-quantum key exchange, but negotiated DH-ECP-256.');
    expect(h?.text).not.toContain('(');
  });

  it('is absent when the backend reports no hybrid support (flag absent or false)', () => {
    expect(hybridKexHint(kex())).toBeNull();
  });

  it('is absent on a key exchange that is already hybrid', () => {
    expect(hybridKexHint(kex({ code: 'X25519MLKEM768', is_pqc: true, hybrid_kex_available: { groups: ['X25519MLKEM768'] } }))).toBeNull();
  });

  it('is absent on any component that is not the key exchange', () => {
    expect(hybridKexHint(kex({ algorithm_type: 'symmetric', code: 'AES128-GCM', hybrid_kex_available: { groups: [] } }))).toBeNull();
  });
});
