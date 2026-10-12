import { describe, expect, it, vi } from 'vitest';
import { fetchAllPages } from './paged';

const rows = (n: number, from = 0) => Array.from({ length: n }, (_, i) => from + i);

describe('fetchAllPages', () => {
  it('stops once the server total is reached', async () => {
    const fetchPage = vi.fn(async (p: number) => ({ items: rows(p < 3 ? 100 : 50, (p - 1) * 100), total: 250 }));
    const r = await fetchAllPages(fetchPage, { pageSize: 100 });
    expect(fetchPage).toHaveBeenCalledTimes(3);
    expect(r.items).toHaveLength(250);
    expect(r.total).toBe(250);
    expect(r.truncated).toBe(false);
  });

  it('stops on an empty page when the total over-reports', async () => {
    const fetchPage = vi.fn(async (p: number) => ({ items: p === 1 ? rows(10) : [], total: 999 }));
    const r = await fetchAllPages(fetchPage, { pageSize: 10 });
    expect(fetchPage).toHaveBeenCalledTimes(2);
    expect(r.items).toHaveLength(10);
    expect(r.truncated).toBe(false);
  });

  it('without a total, a short page ends the walk', async () => {
    const fetchPage = vi.fn(async (p: number) => ({ items: p === 1 ? rows(5) : rows(2, 5) }));
    const r = await fetchAllPages(fetchPage, { pageSize: 5 });
    expect(fetchPage).toHaveBeenCalledTimes(2);
    expect(r.items).toHaveLength(7);
    expect(r.total).toBe(7);
  });

  it('sets truncated at the ceiling and stops fetching', async () => {
    const fetchPage = vi.fn(async (p: number) => ({ items: rows(100, (p - 1) * 100), total: 100000 }));
    const r = await fetchAllPages(fetchPage, { pageSize: 100, maxRows: 250 });
    expect(r.truncated).toBe(true);
    expect(r.items).toHaveLength(250);
    expect(r.total).toBe(100000);
    expect(fetchPage).toHaveBeenCalledTimes(3);
  });

  it('does not flag truncation when the ceiling lands exactly on the end', async () => {
    const fetchPage = async (p: number) => ({ items: rows(100, (p - 1) * 100), total: 200 });
    const r = await fetchAllPages(fetchPage, { pageSize: 100, maxRows: 200 });
    expect(r.truncated).toBe(false);
    expect(r.items).toHaveLength(200);
  });
});
