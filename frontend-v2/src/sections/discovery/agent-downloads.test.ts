// @vitest-environment jsdom
//
// The install steps download agent binaries from the public release matching
// the platform's version. These pin the URL shapes to what a release actually
// publishes (release-core.yml stages `<name>-<os>-<arch>-<tag>[.exe]`; the
// installers live in the tag's source under scripts/), and that a version this
// cannot map to a release never produces an invented download.
import { describe, expect, it } from 'vitest';
import { binaryUrl, installerUrl, releasePageUrl, releaseTagFromVersion } from './agent-downloads';
import { buildDeviceAgentCommands, buildInstallCommands } from './sensor-modals';

// Asset names published on the v4.0.0 release, verbatim.
const V4_ASSETS = [
  'crypto-sensor-linux-amd64-v4.0.0',
  'crypto-sensor-windows-amd64-v4.0.0.exe',
  'device-agent-linux-amd64-v4.0.0',
  'device-agent-windows-amd64-v4.0.0.exe',
];
const RELEASE = 'https://github.com/VistaSecurity/VistaPlatform-Core/releases';

describe('releaseTagFromVersion', () => {
  it.each([
    ['v4.0.0', 'v4.0.0'],
    ['4.0.0', 'v4.0.0'],
    ['v1.1.0-rc.8', 'v1.1.0-rc.8'],
    // Internal builds carry a suffix; they run the code of the public release.
    ['v1.1.0-rc.8-enterprise', 'v1.1.0-rc.8'],
    ['v4.0.0-licensed', 'v4.0.0'],
  ])('%s → %s', (version, tag) => {
    expect(releaseTagFromVersion(version)).toBe(tag);
  });

  it.each([['dev'], [''], ['unknown'], ['v4.0'], ['v4.0.0.1']])('%s is not a release', (version) => {
    expect(releaseTagFromVersion(version)).toBeNull();
  });

  it('is null with no version at all', () => {
    expect(releaseTagFromVersion(undefined)).toBeNull();
    expect(releaseTagFromVersion(null)).toBeNull();
  });
});

describe('download URLs', () => {
  it('name the assets a release publishes', () => {
    const urls = [
      binaryUrl('v4.0.0', 'crypto-sensor', 'linux'),
      binaryUrl('v4.0.0', 'crypto-sensor', 'windows'),
      binaryUrl('v4.0.0', 'device-agent', 'linux'),
      binaryUrl('v4.0.0', 'device-agent', 'windows'),
    ];
    expect(urls).toEqual(V4_ASSETS.map((a) => `${RELEASE}/download/v4.0.0/${a}`));
  });

  it('take the installers from the same tag', () => {
    expect(installerUrl('v4.0.0', 'install-sensor.sh')).toBe(
      'https://raw.githubusercontent.com/VistaSecurity/VistaPlatform-Core/v4.0.0/scripts/install-sensor.sh',
    );
  });

  it('fall back to the releases list without a tag', () => {
    expect(releasePageUrl('v4.0.0')).toBe(`${RELEASE}/tag/v4.0.0`);
    expect(releasePageUrl(null)).toBe(RELEASE);
  });
});

describe('install steps', () => {
  it('download the sensor and its installer for the platform release, then install', () => {
    const { linux, windows } = buildInstallCommands('KEY-1', '10.0.0.5', 'dc01', 'v4.0.0');
    expect(linux).toContain(`curl -fLo crypto-sensor ${RELEASE}/download/v4.0.0/crypto-sensor-linux-amd64-v4.0.0`);
    expect(linux).toContain('/v4.0.0/scripts/install-sensor.sh');
    expect(linux).toContain('sudo bash install-sensor.sh --url');
    expect(linux).toContain('--key KEY-1 --ip 10.0.0.5 --name "dc01"');
    expect(windows).toContain(`-OutFile crypto-sensor.exe`);
    expect(windows).toContain('crypto-sensor-windows-amd64-v4.0.0.exe');
    expect(windows).toContain('-Key KEY-1');
  });

  it('download the device agent for the platform release', () => {
    const { linux, windows } = buildDeviceAgentCommands('KEY-2', 'v4.0.0');
    expect(linux).toContain(`curl -fLo device-agent ${RELEASE}/download/v4.0.0/device-agent-linux-amd64-v4.0.0`);
    expect(linux).toContain('registration_key: KEY-2');
    expect(windows).toContain('device-agent-windows-amd64-v4.0.0.exe');
  });

  it('never invent a version when the platform has none', () => {
    for (const cmds of [buildInstallCommands('K', '10.0.0.5', 'n', null), buildDeviceAgentCommands('K', null)]) {
      for (const text of [cmds.linux, cmds.windows]) {
        expect(text).toContain(RELEASE);
        expect(text).not.toContain('/download/');
        expect(text).toContain('About');
      }
    }
  });
});
