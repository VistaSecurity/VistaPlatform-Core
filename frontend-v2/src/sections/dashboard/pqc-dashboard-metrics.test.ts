import { describe, expect, it } from 'vitest';
import {
  NIST_DEPRECATED_YEAR, NIST_DISALLOWED_YEAR,
  migrationWorklist, nistTimeline, pqcCategories, pqcHeadline, safeFamilies,
  type PqcProgress,
} from './pqc-dashboard-metrics';

/** A progress rollup whose four categories genuinely partition the total. */
const progress = (over: Partial<PqcProgress> = {}): PqcProgress => ({
  total_implementations: 100,
  pqc_ready: 10,
  symmetric_safe: 20,
  non_pqc: 60,
  unclassified: 10,
  pqc_percentage: 30,
  by_family: [],
  ...over,
});

describe('the four-way partition', () => {
  it('reports the four categories in reading order', () => {
    expect(pqcCategories(progress()).map((c) => c.key)).toEqual(['pqc_ready', 'symmetric_safe', 'non_pqc', 'unclassified']);
  });

  it('sums to the implementation total', () => {
    // The backend classifies each implementation exactly once, which is what
    // makes the percentage bounded by 100. If these ever stop summing, the page
    // is showing something other than a partition.
    const p = progress();
    const sum = pqcCategories(p).reduce((n, c) => n + c.count, 0);
    expect(sum).toBe(p.total_implementations);
  });

  it('keeps "not yet assessed" SEPARATE from "needs migration"', () => {
    // M-2: `non_pqc` is a real migration target; `unclassified` is an
    // implementation whose algorithms did not resolve against the catalogue at
    // all. Folding the second into the first overstates the migration workload
    // by exactly the number of things nobody has looked at.
    const cats = pqcCategories(progress({ non_pqc: 5, unclassified: 40 }));
    expect(cats.find((c) => c.key === 'non_pqc')!.count).toBe(5);
    expect(cats.find((c) => c.key === 'unclassified')!.count).toBe(40);
  });

  it('never describes unclassified as classical crypto', () => {
    const hint = pqcCategories(progress()).find((c) => c.key === 'unclassified')!.hint;
    expect(hint).toMatch(/not classical crypto/i);
  });

  it('is all-zero rather than throwing with no data', () => {
    expect(pqcCategories(null).every((c) => c.count === 0)).toBe(true);
  });
});

describe('the readiness headline', () => {
  it('rounds the float percentage', () => {
    // 4 of 11 arrives as 36.36363636363637 and renders as exactly that unless
    // it is rounded here.
    expect(pqcHeadline(progress({ pqc_percentage: 36.36363636363637 })).readinessPercent).toBe(36);
  });

  it('counts symmetric-safe as needing no migration', () => {
    expect(pqcHeadline(progress({ pqc_ready: 10, symmetric_safe: 20 })).safe).toBe(30);
  });

  it('returns a NULL percentage — not 0% — when the tenant has no crypto', () => {
    // 0% reads as "everything you have is broken". The truth is that nothing
    // has been found to assess, which is what `empty` says instead.
    const h = pqcHeadline(progress({ total_implementations: 0, pqc_ready: 0, symmetric_safe: 0, non_pqc: 0, unclassified: 0, pqc_percentage: 0 }));
    expect(h.readinessPercent).toBeNull();
    expect(h.empty).toBe(true);
  });

  it('keeps a genuine 0% when there IS crypto and none of it is safe', () => {
    const h = pqcHeadline(progress({ pqc_ready: 0, symmetric_safe: 0, non_pqc: 100, unclassified: 0, pqc_percentage: 0 }));
    expect(h.readinessPercent).toBe(0);
    expect(h.empty).toBe(false);
  });

  it('is empty with no data at all', () => {
    expect(pqcHeadline(null).empty).toBe(true);
    expect(pqcHeadline(null).readinessPercent).toBeNull();
  });
});

describe('the migration worklist', () => {
  // The trap this whole suite exists for. AES-256 is NOT a post-quantum
  // algorithm (`is_pqc: false`) but IS quantum-safe at its key size. Filtering
  // the worklist on `!is_pqc` would put every symmetric cipher in the tenant on
  // a list of things to replace — the same shape as the allowlist bug that
  // misclassified eleven catalogue algorithms, including plain AES128/AES256,
  // as needing PQC migration.
  const families = [
    { family: 'RSA', count: 40, is_pqc: false, quantum_safe: false, migrate_to: 'ML-KEM' },
    { family: 'ECDSA', count: 25, is_pqc: false, quantum_safe: false, migrate_to: 'ML-DSA' },
    { family: 'AES', count: 90, is_pqc: false, quantum_safe: true },
    { family: 'SHA-2', count: 80, is_pqc: false, quantum_safe: true },
    { family: 'ML-KEM', count: 3, is_pqc: true, quantum_safe: true },
    { family: 'DH', count: 5, is_pqc: false, quantum_safe: false },
  ];
  const p = progress({ by_family: families });

  it('lists only families that are NOT quantum-safe', () => {
    expect(migrationWorklist(p).map((r) => r.family)).toEqual(['RSA', 'ECDSA', 'DH']);
  });

  it('keeps AES off the worklist even though it is not post-quantum', () => {
    expect(migrationWorklist(p).some((r) => r.family === 'AES')).toBe(false);
  });

  it('ranks biggest first', () => {
    expect(migrationWorklist(p).map((r) => r.count)).toEqual([40, 25, 5]);
  });

  it('carries the catalogue\'s recommended target', () => {
    expect(migrationWorklist(p).find((r) => r.family === 'RSA')!.migrateTo).toBe('ML-KEM');
  });

  it('reports NO recommendation as null rather than inventing one', () => {
    // The page renders this as "no recommendation in the catalogue". Guessing a
    // target here would be the dashboard asserting cryptographic advice the
    // algorithms table never made.
    expect(migrationWorklist(p).find((r) => r.family === 'DH')!.migrateTo).toBeNull();
  });

  it('treats an empty migrate_to string as no recommendation', () => {
    const rows = migrationWorklist(progress({ by_family: [{ family: 'RSA', count: 1, is_pqc: false, quantum_safe: false, migrate_to: '' }] }));
    expect(rows[0].migrateTo).toBeNull();
  });

  it('lists the quantum-safe families as the counterpart, including the symmetric ones', () => {
    expect(safeFamilies(p).map((r) => r.family)).toEqual(['AES', 'SHA-2', 'ML-KEM']);
  });

  it('partitions by_family exactly between the two lists', () => {
    expect(migrationWorklist(p).length + safeFamilies(p).length).toBe(families.length);
  });

  // The endpoint really does return one family twice. Verified live:
  // `AES` at 18 AND at 5, `SHA-2` at 11 AND at 7, identical flags, nothing in
  // the payload telling them apart. Two rows with one name read on screen as a
  // rendering bug, and the reader cannot act on a difference that is not there.
  describe('duplicate family rows from the server', () => {
    const dupes = [
      { family: 'AES', count: 18, is_pqc: false, quantum_safe: true },
      { family: 'AES', count: 5, is_pqc: false, quantum_safe: true },
      { family: 'SHA-2', count: 11, is_pqc: false, quantum_safe: true },
      { family: 'SHA-2', count: 7, is_pqc: false, quantum_safe: true },
      { family: 'RSA', count: 11, is_pqc: false, quantum_safe: false, migrate_to: 'ML-KEM' },
      { family: 'RSA', count: 4, is_pqc: false, quantum_safe: false },
    ];
    const q = progress({ by_family: dupes });

    it('shows each family ONCE on the safe list', () => {
      expect(safeFamilies(q).map((r) => r.family)).toEqual(['AES', 'SHA-2']);
    });

    it('shows each family ONCE on the worklist', () => {
      expect(migrationWorklist(q).map((r) => r.family)).toEqual(['RSA']);
    });

    it('sums the duplicate counts', () => {
      expect(safeFamilies(q).find((r) => r.family === 'AES')!.count).toBe(23);
      expect(safeFamilies(q).find((r) => r.family === 'SHA-2')!.count).toBe(18);
      expect(migrationWorklist(q)[0].count).toBe(15);
    });

    it('keeps a recommendation carried by only ONE of the duplicate rows', () => {
      // The 11-count RSA row has migrate_to; the 4-count one does not. Merging
      // must not lose it — a worklist row reading "no recommendation" when the
      // catalogue has one is the page failing at its single job.
      expect(migrationWorklist(q)[0].migrateTo).toBe('ML-KEM');
    });

    it('re-sorts after merging, so the biggest merged family leads', () => {
      const mixed = progress({ by_family: [
        { family: 'Small', count: 9, is_pqc: false, quantum_safe: true },
        { family: 'Split', count: 5, is_pqc: false, quantum_safe: true },
        { family: 'Split', count: 6, is_pqc: false, quantum_safe: true },
      ] });
      // Split merges to 11 and must overtake Small's 9 — sorting before the
      // merge would leave Small on top.
      expect(safeFamilies(mixed).map((r) => r.family)).toEqual(['Split', 'Small']);
    });
  });

  // SHA-1 is quantum-safe and classically broken. It belongs on the safe list
  // on this page's terms, which is exactly why the panel must not call that
  // list "needs no action" — see safeFamilies' doc comment and the page caption.
  it('puts SHA-1 on the quantum-safe list, since Shor and Grover are not what break it', () => {
    const q = progress({ by_family: [{ family: 'SHA-1', count: 5, is_pqc: false, quantum_safe: true }] });
    expect(safeFamilies(q).map((r) => r.family)).toEqual(['SHA-1']);
    expect(migrationWorklist(q)).toEqual([]);
  });

  it('handles the null by_family a tenant with no crypto gets', () => {
    expect(migrationWorklist(progress({ by_family: null }))).toEqual([]);
    expect(safeFamilies(progress({ by_family: null }))).toEqual([]);
  });
});

describe('the NIST IR 8547 timeline', () => {
  it('quotes the published milestones', () => {
    expect(NIST_DEPRECATED_YEAR).toBe(2030);
    expect(NIST_DISALLOWED_YEAR).toBe(2035);
  });

  it('counts the years remaining from the given date', () => {
    const [dep, dis] = nistTimeline(new Date('2026-09-21T00:00:00Z'));
    expect(dep.yearsAway).toBe(4);
    expect(dis.yearsAway).toBe(9);
    expect(dep.passed).toBe(false);
  });

  it('marks a milestone PASSED rather than counting down past it', () => {
    // A naive subtraction renders "-1 years away" in 2031, which is not a
    // sentence. The page branches on `passed`.
    const [dep, dis] = nistTimeline(new Date('2031-01-15T00:00:00Z'));
    expect(dep.passed).toBe(true);
    expect(dis.passed).toBe(false);
    expect(dis.yearsAway).toBe(4);
  });

  it('does not call the milestone year itself "passed"', () => {
    // During 2030 the deadline has not passed; the page reads "this year".
    const [dep] = nistTimeline(new Date('2030-06-01T00:00:00Z'));
    expect(dep.passed).toBe(false);
    expect(dep.yearsAway).toBe(0);
  });

  it('marks both passed once 2035 is behind us', () => {
    expect(nistTimeline(new Date('2036-02-01T00:00:00Z')).every((m) => m.passed)).toBe(true);
  });

  it('reads the year in UTC, so a late-December local evening does not shift it', () => {
    expect(nistTimeline(new Date('2026-12-31T23:30:00Z'))[0].yearsAway).toBe(4);
  });
});
