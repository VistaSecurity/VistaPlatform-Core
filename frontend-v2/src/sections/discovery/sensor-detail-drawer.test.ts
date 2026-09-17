import { describe, expect, it } from 'vitest';
import { sensorHostAssetHref } from './sensor-detail-drawer';

// The Sensors & Agents drawer's "Host" row (asset-inventory decision 9):
// once a sensor's own self-report has resolved to an asset, `asset_id` on
// the Sensor record links there. Absent for an older sensor build that never
// sent a `host` block, or before its first self-observation lands — both
// look identical on the wire (asset_id: null), and the row must be omitted
// for both rather than rendering a broken link.
describe('sensorHostAssetHref', () => {
  it('links to the resolved asset when asset_id is set', () => {
    expect(sensorHostAssetHref({ asset_id: 'a1b2c3d4-0000-0000-0000-000000000000' })).toBe(
      '/inventory/assets/a1b2c3d4-0000-0000-0000-000000000000',
    );
  });

  it('is null when asset_id is null (older sensor, or no self-observation yet)', () => {
    expect(sensorHostAssetHref({ asset_id: null })).toBeNull();
  });

  it('is null when asset_id is an empty string', () => {
    expect(sensorHostAssetHref({ asset_id: '' })).toBeNull();
  });

  it('is null when asset_id is undefined', () => {
    expect(sensorHostAssetHref({ asset_id: undefined as unknown as null })).toBeNull();
  });
});
