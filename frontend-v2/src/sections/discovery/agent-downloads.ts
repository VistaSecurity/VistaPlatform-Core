// Where an operator gets the sensor and device-agent binaries.
//
// The platform does not serve them itself. Every release publishes them on the
// public Core repository's GitHub release: the agents contain no Enterprise
// code, so the same binaries serve every edition, and the commercial release
// ships none of its own. The install steps link to the release matching the
// version this platform is running, so an agent is never newer or older than
// the control plane it enrols with.
//
// Serving the binaries from the platform (for air-gapped installs) is a
// separate, later piece of work.
import { useQuery } from '@tanstack/react-query';
import { clients } from '../../lib/clients';

export const CORE_RELEASES_URL = 'https://github.com/VistaSecurity/VistaPlatform-Core/releases';
const CORE_RAW_URL = 'https://raw.githubusercontent.com/VistaSecurity/VistaPlatform-Core';

/**
 * The public release tag for a platform version string, or null when the
 * version is not a release (a dev build reports "dev" or nothing).
 *
 * Build suffixes are dropped: an internal build tagged `v1.1.0-rc.8-enterprise`
 * runs the code of the `v1.1.0-rc.8` release, whose binaries it needs. A
 * release candidate keeps its `-rc.N`, which is a real public release.
 */
export function releaseTagFromVersion(version: string | null | undefined): string | null {
  const m = /^v?(\d+\.\d+\.\d+(?:-rc\.\d+)?)(?:$|-)/.exec((version ?? '').trim());
  return m ? `v${m[1]}` : null;
}

/** The release page for a tag, or the releases list when the tag is unknown. */
export function releasePageUrl(tag: string | null): string {
  return tag ? `${CORE_RELEASES_URL}/tag/${tag}` : CORE_RELEASES_URL;
}

/** A published binary: `<name>-<os>-<arch>-<tag>[.exe]`. */
export function binaryUrl(tag: string, name: 'crypto-sensor' | 'device-agent', os: 'linux' | 'windows', arch = 'amd64'): string {
  const ext = os === 'windows' ? '.exe' : '';
  return `${CORE_RELEASES_URL}/download/${tag}/${name}-${os}-${arch}-${tag}${ext}`;
}

/** A sensor installer script at the release's tag in the public source. */
export function installerUrl(tag: string, file: 'install-sensor.sh' | 'install-sensor.ps1'): string {
  return `${CORE_RAW_URL}/${tag}/scripts/${file}`;
}

/**
 * The release tag of the platform this console is talking to, from the same
 * monitoring-service GET /version the About page reads (shared query key).
 * null while loading, on error, or on a non-release build.
 */
export function usePlatformReleaseTag(): string | null {
  const { data } = useQuery({
    queryKey: ['about', 'version'],
    queryFn: async () => {
      const { data, error } = await clients.monitoring.GET('/version', {});
      if (error || !data) throw new Error('Failed to load version information');
      return data;
    },
    staleTime: 60_000,
  });
  return releaseTagFromVersion(data?.self?.app_version);
}
