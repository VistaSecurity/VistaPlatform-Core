// Settings · Integrations — the CMDB / ITSM sync section as a tenant WITHOUT
// the capability sees it: an upgrade card, and no request to anything.
//
// Core. CMDB sync runs in an Enterprise-only service (platform ADR-0002 M3),
// so a Core install has no CMDB route to ask — the card is decided by the
// `cmdb_sync` feature flag and the connector catalogue alone, both of which
// every edition serves. The Enterprise section (cmdb-section.tsx) renders this
// same card for an unentitled tenant, so the two editions say the same
// sentence.
import { StateNote, SCard, SSection } from './kit';

export const CMDB_SECTION_TITLE = 'CMDB / ITSM sync';
export const CMDB_SECTION_DESC =
  'Sync your inventory with ServiceNow, Device42 and Oomnitza (two-way), and pull monitored nodes in from SolarWinds (read-only).';

/** The upgrade card on its own, for a section that decides when to show it. */
export function CmdbUpgradeNote() {
  return (
    <SCard>
      <StateNote icon="lock" tone="var(--accent)" title="An Enterprise feature"
        message="CMDB sync pushes your inventory into ServiceNow, Device42 or Oomnitza and pulls their records back in, and pulls monitored nodes in from SolarWinds. The internal CMDB, and every discovery and inventory capability behind it, is included in every edition. Upgrade to Enterprise to connect an external CMDB." />
    </SCard>
  );
}

/** The whole CMDB section as an unentitled tenant, or a Core install, sees it. */
export function CmdbUpgradeSection() {
  return (
    <SSection title={CMDB_SECTION_TITLE} desc={CMDB_SECTION_DESC} style={{ marginTop: 22 }}>
      <CmdbUpgradeNote />
    </SSection>
  );
}
