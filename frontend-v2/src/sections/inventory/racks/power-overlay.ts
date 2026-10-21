// The rack elevation's power overlay (DCIM row 6.2): each device block tinted
// by its share of the rack's available power — the draw its own power ports
// declare (allocated), against what the feeds serving the rack can supply
// (GET /dcim/racks/{id}/power). The crypto overlay's mechanics (rack-overlay.ts),
// a second meaning.
//
// The colour is the Facilities dashboard's capacity colour (fillColor: over 80
// % / over 95 %, strictly greater) — a proportion, not a risk or health band.
// The tint's strength grows with the share. A device whose power ports declare
// no draw is drawn dashed and labelled "not recorded", never as 0 W.
import { fillColor } from '../../dashboard/facilities-dashboard-metrics';
import type { RackPowerDevice } from '../power/power-queries';

export type PowerOverlayState =
  | { kind: 'share'; share: number; color: string; opacity: number; label: string }
  | { kind: 'no-budget'; color: string; opacity: number; label: string }
  | { kind: 'unrecorded'; color: string; label: string }
  | { kind: 'unknown'; color: string; label: string };

const fmtShare = (p: number): string => `${Number(p.toFixed(1))}%`;

function measuredText(d: RackPowerDevice): string {
  return d.measured_draw != null ? ` · ${d.measured_draw} W measured` : '';
}

/** How the power overlay draws one device. */
export function powerOverlayState(d: RackPowerDevice | null | undefined, availablePower: number | null | undefined): PowerOverlayState {
  if (!d) return { kind: 'unknown', color: 'var(--app-t3)', label: 'Power not loaded' };
  if (d.allocated_draw == null) {
    const what = d.power_port_count === 0 ? 'No power ports recorded' : 'Draw not recorded';
    return { kind: 'unrecorded', color: 'var(--app-t3)', label: `${what}${measuredText(d)}` };
  }
  if (d.share == null || !availablePower) {
    return { kind: 'no-budget', color: 'var(--accent)', opacity: 0.2, label: `${d.allocated_draw} W allocated · no feed serves this rack${measuredText(d)}` };
  }
  const share = d.share;
  return {
    kind: 'share', share, color: fillColor(share),
    opacity: 0.12 + 0.6 * Math.min(Math.max(share, 0), 100) / 100,
    label: `${d.allocated_draw} W allocated · ${fmtShare(share)} of the rack's ${availablePower} VA${measuredText(d)}`,
  };
}
