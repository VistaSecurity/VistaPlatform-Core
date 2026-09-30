// Settings · Integrations — the NetBox section as a tenant WITHOUT the
// connector sees it: an upgrade card, and no request to anything.
//
// Core. The connector itself runs in an Enterprise-only service
// (platform ADR-0002 M2), so a Core install has no NetBox route to ask — the
// card is decided by the `connector_netbox` feature flag and the connector
// catalogue alone, both of which every edition serves. The Enterprise section
// (netbox-section.tsx) renders this same card for an unentitled tenant, so the
// two editions say the same sentence.
import { StateNote, SCard, SSection } from './kit';

export const NETBOX_SECTION_TITLE = 'NetBox';
export const NETBOX_SECTION_DESC =
  'Pull sites, prefixes, VLANs and devices from your network source of truth. Read-only towards NetBox — nothing is ever written back.';

/** The upgrade card on its own, for a section that decides when to show it. */
export function NetBoxUpgradeNote() {
  return (
    <SCard>
      <StateNote icon="lock" tone="var(--accent)" title="An Enterprise feature"
        message="The NetBox connector reads your network source of truth — sites, prefixes, VLANs, device types and devices — so an address means something and a device arrives already classified. It also shows the drift between NetBox and what Vista discovered. Discovery and the whole inventory are included in every edition; reading a foreign source of truth is the paid part." />
    </SCard>
  );
}

/** The whole NetBox section as an unentitled tenant, or a Core install, sees it. */
export function NetBoxUpgradeSection() {
  return (
    <SSection title={NETBOX_SECTION_TITLE} desc={NETBOX_SECTION_DESC} style={{ marginTop: 22 }}>
      <NetBoxUpgradeNote />
    </SSection>
  );
}
