import { describe, it, expect } from 'vitest';
import { exposureChip } from './asset-page';

/**
 * The Endpoints tab's exposure chip is three-valued, and the third state is
 * "render nothing".
 *
 * `bound_local` can only be established by a host's own view of its sockets —
 * the agent's host inventory reads the machine's socket table. A network scan
 * cannot establish it even in principle: it only ever sees what answers, never
 * what the socket is bound to. So the great majority of endpoints in any
 * inventory carry no value at all, and collapsing that into "reachable" would
 * have almost the whole table asserting an exposure nobody measured.
 *
 * The other half matters just as much: an explicit `false` IS a measurement —
 * the host told us this socket is on a non-loopback address — and hiding it
 * alongside the unmeasured ones would throw away the one signal a
 * network-exposure finding is computed from.
 */
describe('exposureChip', () => {
  it('names a loopback-only socket', () => {
    const chip = exposureChip({ bound_local: true });
    expect(chip?.label).toBe('bound to localhost');
    expect(chip?.tone).toBe('quiet');
    // The tooltip has to say WHO established it, or a reader cannot tell this
    // apart from an absent value.
    expect(chip?.title).toMatch(/host reported/i);
  });

  it('names a measured exposure, and does not treat it as the absence of one', () => {
    const chip = exposureChip({ bound_local: false });
    expect(chip?.label).toBe('reachable');
    // Warn, not quiet: an exposed service is the finding input, not the
    // reassuring case.
    expect(chip?.tone).toBe('warn');
    expect(chip?.title).toMatch(/measurement, not an assumption/i);
  });

  it('says NOTHING when nobody established the binding', () => {
    // undefined: the field is omitted from the JSON, which is how the Go model
    // serialises a NULL column.
    expect(exposureChip({})).toBeNull();
    expect(exposureChip({ bound_local: undefined })).toBeNull();
    // null, in case a source ever serialises it explicitly. It is the same
    // claim and must render the same way.
    expect(exposureChip({ bound_local: null as unknown as undefined })).toBeNull();
  });

  it('never renders an absent value as the false chip', () => {
    // The regression this file exists for: `!e.bound_local` would make
    // undefined and false indistinguishable, and every scanned endpoint in the
    // product would claim a measured exposure.
    expect(exposureChip({})).not.toEqual(exposureChip({ bound_local: false }));
  });
});
