/**
 * How long an inventory record may go unobserved before the product calls it
 * stale.
 *
 * ONE number, because the product has one definition of stale and used to
 * render two. The Inventory page's Stale lens cut at 14 days while the hygiene
 * producer's stale ladder — and IH-004 in the seeded Inventory Hygiene
 * framework (`last_seen_days <= 30`) — started at 30. A record could therefore
 * be listed under "Stale" with no finding, no compliance failure and nothing
 * anywhere agreeing that it was stale, which reads as a bug in whichever
 * surface the user happened to check second.
 *
 * The source of truth is Go: `staleLadderDays[0]` in
 * `services/inventory-service/internal/producers/hygiene.go`, where the ladder
 * is declared beside the producer that acts on it. This constant is the TS
 * mirror, and `stale-threshold.test.ts` reads that file and fails if the two
 * numbers part company — a generated constant would be tidier but would need a
 * generator for one integer, and a parity test that reads the real declaration
 * cannot be satisfied by a stale copy.
 *
 * The same number is also the `asset_endpoints.status = 'stale'` boundary the
 * hygiene pass writes, so the lens, the finding, the control and the column all
 * mean the same thing by the word.
 */
export const STALE_DAYS = 30;
