// Platform branding (white-label) consumer — admin-console side. Mirrors
// frontend-v2/src/app/platform-branding.tsx: the platform admin sets the product
// name + logos + favicon in Settings → Branding, auth-service serves them
// (unauthenticated) at GET /platform/config, and the admin console reads them
// here. Everything falls back to the built-in VISTA / Shield / favicon.svg.
import { type ReactNode, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { clients } from '../lib/clients';

export interface PlatformBranding {
  name: string;
  logoUrl?: string;
  loginLogoUrl?: string;
  faviconUrl?: string;
}

const FALLBACK_NAME = 'VISTA';

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

/** Uploaded logo bounded to the badge box, else the built-in `fallback` mark. */
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

/** Swap the favicon + tab title to the branded values. Mount once near the root. */
export function PlatformBrandingEffects() {
  const { name, faviconUrl } = usePlatformBranding();

  useEffect(() => {
    document.title = name === FALLBACK_NAME ? 'VISTA Operations' : `${name} Operations`;
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
