// One rule for "is this a usable organization name", shared by the email
// sign-up form and the SSO complete-profile step so the two can't drift (the
// email path used to accept a single character that the SSO path rejected).
export const ORG_NAME_MIN_LENGTH = 2;

export function orgNameValid(name: string): boolean {
  return name.trim().length >= ORG_NAME_MIN_LENGTH;
}
