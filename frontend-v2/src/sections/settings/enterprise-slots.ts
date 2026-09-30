// Settings — the page sections that exist only in the Enterprise build.
//
// A page that ships in every edition cannot import a component that exists in
// only one: the public-tree export removes the Enterprise files, and an import
// of a missing module fails the Core build. So a Core-shipped page reads the
// Enterprise sections from here, and renders its Core fallback when a slot is
// empty. The lines that fill the slots are edition fences, which the export
// strips — leaving every slot empty in Core, with nothing to import.
//
// Today: the NetBox connector and CMDB / ITSM sync, which run in an
// Enterprise-only service (platform ADR-0002 M2 and M3). A Core Integrations
// page shows their upgrade cards (netbox-upgrade.tsx, cmdb-upgrade.tsx) in
// their place.
import type { ComponentType } from 'react';

/** What the Integrations page hands the NetBox section. */
export interface NetBoxSectionProps {
  /** The connector catalogue asked for a new connection. */
  createOpen: boolean;
  /** The new-connection dialog closed. */
  onCreateClose: () => void;
}

/** What the Integrations page hands the CMDB sync section. */
export interface CmdbSectionProps {
  /** The connector catalogue asked for a new CMDB profile. */
  createOpen: boolean;
  /** The new-profile dialog closed. */
  onCreateClose: () => void;
}

export interface EnterpriseSettingsSlots {
  NetBoxSection?: ComponentType<NetBoxSectionProps>;
  CmdbSection?: ComponentType<CmdbSectionProps>;
}

export const enterpriseSettings: EnterpriseSettingsSlots = {
};
