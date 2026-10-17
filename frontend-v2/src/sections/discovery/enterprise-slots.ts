// Discovery — the sections that exist only in the Enterprise build.
//
// The same arrangement as settings/enterprise-slots.ts: a Core-shipped page
// cannot import a module the public-tree export removes, so it reads the
// Enterprise sections from here and renders nothing when a slot is empty. The
// lines that fill the slots are edition fences, which the export strips.
//
// Today: the NetBox sync's conflicts (ADR-0010 D7), which come from an
// Enterprise-only service and land in Approvals, the one proposal queue
// (ADR-0006 D6).
import type { ComponentType } from 'react';

export interface EnterpriseDiscoverySlots {
  SyncConflictsSection?: ComponentType;
}

export const enterpriseDiscovery: EnterpriseDiscoverySlots = {
};
