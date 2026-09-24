// Which identity-provider purposes the Settings → Identity Providers form may
// offer (settings-8, admin-ui review decision 11).
//
// A "Sign-up" provider powers "Sign up with Google/Microsoft" on the public
// sign-up page, and that flow is served only by auth-service's Enterprise
// build. On Core — no active licence, which is also every Core build — a
// sign-up row would save, read "Enabled", and do nothing, so the form does not
// offer it and admin-service refuses it (402). "Admin login" (staff sign-in to
// this console) is Core and always offered.
//
// Decided from the licence half of GET /admin/platform/edition, the same
// read-out that hides Plans & Pricing and Billing. The pending/unknown rules
// follow lib/edition.ts:
//   - pending: hidden until the answer lands (the list can only grow, never
//     offer an option that is about to vanish);
//   - unknown (the read failed): offered — fail open like the rest of the
//     console; the server still refuses it on Core, so nothing wrong is saved.
import type { LicenseState } from '../../lib/edition';

export type IdPPurpose = 'signup' | 'admin_login';

/** Whether a new Sign-up provider may be offered under this licence state. */
export function signupPurposeOffered(license: LicenseState): boolean {
  return license === 'enterprise' || license === 'msp' || license === 'unknown';
}

/**
 * The purposes the form's "Used for" select lists. An existing provider always
 * keeps its own purpose in the list (the select is read-only on edit, and a
 * sign-up row left behind by a lapsed licence must still display, switch off
 * and delete).
 */
export function purposeOptions(license: LicenseState, existing?: string | null): IdPPurpose[] {
  if (signupPurposeOffered(license) || existing === 'signup') return ['signup', 'admin_login'];
  return ['admin_login'];
}

/** The purpose a NEW provider starts on: Sign-up where offered, else Admin login. */
export function defaultPurpose(license: LicenseState): IdPPurpose {
  return signupPurposeOffered(license) ? 'signup' : 'admin_login';
}
