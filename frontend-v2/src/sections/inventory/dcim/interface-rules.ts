// The interface form's rules, mirrored from the service
// (services/inventory-service/internal/services/interface_rules.go) so the
// drawer can disable what the server would refuse. The server stays the
// authority; this only keeps a person from filling in a field that cannot be
// saved.
import type { InterfaceMode, InterfaceType } from '@vistasecurity/primitives/dcim';
import { INTERFACE_TYPE_GROUP } from '@vistasecurity/primitives/dcim';
import type { Interface } from './interface-queries';

export interface ModeControls {
  /** An untagged VLAN can be set. */
  untagged: boolean;
  /** A tagged VLAN list can be set. */
  tagged: boolean;
  /** The tagged VLAN list must have at least one entry. */
  taggedRequired: boolean;
}

/** Which 802.1Q controls a mode enables (NetBox Interface.clean()). */
export function modeControls(mode: InterfaceMode | '' | null | undefined): ModeControls {
  switch (mode) {
    case 'access':
    case 'q-in-q':
      return { untagged: true, tagged: false, taggedRequired: false };
    case 'tagged':
      return { untagged: true, tagged: true, taggedRequired: true };
    case 'tagged-all':
      return { untagged: true, tagged: false, taggedRequired: false };
    default:
      return { untagged: false, tagged: false, taggedRequired: false };
  }
}

/** LAG choices for an interface: the asset's other interfaces of type `lag`.
 *  A LAG, a virtual interface and a bridge cannot be members. */
export function lagChoices(all: readonly Interface[], selfId: string | undefined, selfType: InterfaceType | ''): Interface[] {
  if (selfType === 'lag' || selfType === 'virtual' || selfType === 'bridge') return [];
  return all.filter((i) => i.type === 'lag' && i.id !== selfId);
}

/** Parent / bridge choices: the asset's other interfaces, minus any that sit
 *  below this one (choosing one would close a cycle). */
export function hierarchyChoices(all: readonly Interface[], selfId: string | undefined, link: 'parent_id' | 'bridge_id'): Interface[] {
  if (!selfId) return [...all];
  const byId = new Map(all.map((i) => [i.id, i]));
  const below = (candidate: Interface): boolean => {
    let cur: Interface | undefined = candidate;
    for (let steps = 0; cur && steps < 64; steps++) {
      if (cur.id === selfId) return true;
      const next: string | null | undefined = cur[link];
      cur = next ? byId.get(next) : undefined;
    }
    return false;
  };
  return all.filter((i) => i.id !== selfId && !below(i));
}

/** Wireless fields apply to ieee802.11 types only. */
export function isWireless(t: InterfaceType | ''): boolean {
  return t !== '' && INTERFACE_TYPE_GROUP[t] === 'wireless';
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Parses the tagged-VLAN box: ids separated by commas, spaces or lines. */
export function parseVlanIds(text: string): { ids: string[]; bad: string[] } {
  const parts = text.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
  const ids: string[] = [];
  const bad: string[] = [];
  for (const p of parts) {
    if (UUID.test(p)) {
      if (!ids.includes(p.toLowerCase())) ids.push(p.toLowerCase());
    } else bad.push(p);
  }
  return { ids, bad };
}

/** Display speed: 1000000 kbps → "1 Gbps". */
export function speedText(kbps: number | null | undefined): string {
  if (kbps === null || kbps === undefined) return '';
  if (kbps >= 1_000_000 && kbps % 1_000_000 === 0) return `${kbps / 1_000_000} Gbps`;
  if (kbps >= 1_000_000) return `${(kbps / 1_000_000).toFixed(1)} Gbps`;
  if (kbps >= 1000) return `${Math.round(kbps / 1000)} Mbps`;
  return `${kbps} kbps`;
}
