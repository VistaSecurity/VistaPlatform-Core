// Platform branding (white-label) consumer. The platform admin sets the product
// name + logos + favicon in admin-ui → Settings → Branding; auth-service persists
// them and serves them (unauthenticated) at GET /platform/config. This module is
// the tenant-app consumer of that config: a cached hook the brand lockups read,
// a <BrandLogo> that swaps the built-in mark for an uploaded logo, and a
// side-effect component that applies the favicon + tab title.
//
// Everything falls back to the built-in VISTA / Shield / favicon.svg when a value
// is unset, so an un-branded deployment looks exactly as before.
import { type ReactNode, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { clients } from '../lib/clients';

export interface PlatformBranding {
  /** Product/wordmark name. Never empty — falls back to "VISTA". */
  name: string;
  /** Header (in-app) logo URL, or undefined to use the built-in mark. */
  logoUrl?: string;
  /** Login-screen logo URL; falls back to the header logo, then the built-in mark. */
  loginLogoUrl?: string;
  /** Favicon URL, or undefined to keep the static /favicon.svg. */
  faviconUrl?: string;
}

const FALLBACK_NAME = 'VISTA';

/**
 * Cached platform branding. Public + unauthenticated, so this resolves on the
 * login screen too. A failed/absent config yields the built-in defaults.
 */
export function usePlatformBranding(): PlatformBranding {
  const { data } = useQuery({
    queryKey: ['platform-config'],
    queryFn: async () => {
      const { data, error } = await clients.auth.GET('/platform/config', {});
      if (error || !data) throw new Error('platform config unavailable');
      return data;
    },
    staleTime: 5 * 60_000,
    retry: false,
  });

  return {
    name: data?.platform_name?.trim() || FALLBACK_NAME,
    logoUrl: data?.platform_logo_url || undefined,
    loginLogoUrl: data?.platform_login_logo_url || data?.platform_logo_url || undefined,
    faviconUrl: data?.platform_favicon_url || undefined,
  };
}

/**
 * Renders an uploaded logo (bounded to the badge box) when `url` is set,
 * otherwise the supplied built-in `fallback` mark — so call sites keep their
 * existing accent/Shield lockup unchanged when no logo is configured.
 */
export function BrandLogo({
  url, size, radius, shadow, alt, fallback,
}: {
  url?: string;
  size: number;
  radius: number | string;
  shadow?: string;
  alt: string;
  fallback: ReactNode;
}) {
  if (!url) return <>{fallback}</>;
  return (
    <div
      style={{
        width: size, height: size, borderRadius: radius, flex: 'none', overflow: 'hidden',
        boxShadow: shadow, display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}
    >
      <img
        src={url}
        alt={alt}
        style={{ width: '100%', height: '100%', objectFit: 'contain' }}
        onError={(e) => { (e.currentTarget.style.display = 'none'); }}
      />
    </div>
  );
}

/**
 * Side effects: swap the favicon and tab title to the branded values. Mount once
 * near the app root (inside the QueryClientProvider). No-ops to the built-in
 * defaults when nothing is configured.
 */
export function PlatformBrandingEffects() {
  const { name, faviconUrl } = usePlatformBranding();

  useEffect(() => {
    document.title = name === FALLBACK_NAME ? 'Vista Console' : `${name} Console`;
  }, [name]);

  useEffect(() => {
    if (!faviconUrl) return;
    const link = document.querySelector<HTMLLinkElement>('link[rel="icon"]');
    if (!link) return;
    const prev = link.getAttribute('href');
    link.setAttribute('href', faviconUrl);
    return () => { if (prev) link.setAttribute('href', prev); };
  }, [faviconUrl]);

  return null;
}
