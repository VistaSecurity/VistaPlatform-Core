// Routes reachable while signed out. Keep this in sync with App.tsx.
export const PUBLIC_PATHS: readonly string[] = [
  '/login',
  '/reset-password',
  '/forgot-password',
];

/** True when `pathname` is a route reachable while signed out. */
export function isPublicPath(pathname: string): boolean {
  return PUBLIC_PATHS.includes(pathname);
}
