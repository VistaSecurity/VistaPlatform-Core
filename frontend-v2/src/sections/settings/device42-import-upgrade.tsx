// Settings · Integrations — the Device42 import section as a tenant WITHOUT
// the entitlement, or a Core install, sees it: an upgrade card, and no request
// to anything.
//
// Core. The importer runs in an Enterprise-only service, so a Core
// install has no route to ask; the card is decided by the `cmdb_sync` flag
// alone. The Enterprise section (device42-import-section.tsx) renders this same
// card for an unentitled tenant, so both editions say the same sentence.
import { SCard, SSection, StateNote } from './kit';

export const DEVICE42_IMPORT_TITLE = 'Device42 (import)';
export const DEVICE42_IMPORT_DESC =
  'Import buildings, rooms, racks, devices in their rack position, ports and the cables between them, IP networks and addresses, VLANs and circuits from Device42. Nothing is written back.';

export function Device42ImportUpgradeNote() {
  return (
    <SCard>
      <StateNote icon="lock" tone="var(--accent)" title="An Enterprise feature"
        message="The Device42 import brings your existing data-centre record — sites, racks, devices in their rack units, cabling, IP space and circuits — into the inventory in one planned run you review before anything is written. Discovery and the whole inventory are included in every edition; importing a foreign record is the paid part." />
    </SCard>
  );
}

export function Device42ImportUpgradeSection() {
  return (
    <SSection title={DEVICE42_IMPORT_TITLE} desc={DEVICE42_IMPORT_DESC} style={{ marginTop: 22 }}>
      <Device42ImportUpgradeNote />
    </SSection>
  );
}
