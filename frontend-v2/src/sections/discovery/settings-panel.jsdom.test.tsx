// @vitest-environment jsdom
//
// The settings panel after a successful save, MOUNTED.
//
// Turning host_observation_dns on wrote the config, then crashed the drawer:
// Go encoded a nil `adjusted` slice as JSON `null`, and the banner did
// `result.adjusted.map`. A helper unit test stays green with that `.map` line
// restored; this one does not.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SettingsPanel } from './settings-panel';
import type { Setting } from './agent-config';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const DNS: Setting = {
  key: 'host_observation_dns',
  value: false,
  origin: 'built_in',
  kind: 'bool',
  apply: 'restart',
  description: 'Decode DNS queries from captured traffic.',
  confirm: 'DNS names from captured traffic will be stored.',
};

let host: HTMLDivElement;
let root: Root;

beforeEach(() => {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});

afterEach(() => {
  act(() => {
    root.unmount();
  });
  host.remove();
});

describe('SettingsPanel save banner', () => {
  it('renders after a save whose adjusted array is JSON null', async () => {
    const save = vi.fn(async () => ({
      changed: ['host_observation_dns: false → true'],
      adjusted: null as unknown as string[],
      needs_restart: null as unknown as string[],
    }));

    await act(async () => {
      root.render(
        <SettingsPanel
          settings={[DNS]}
          scope="device"
          canEdit
          saving={false}
          save={save}
        />,
      );
    });

    const checkbox = host.querySelector('input[type="checkbox"]') as HTMLInputElement;
    await act(async () => {
      checkbox.click();
    });
    const saveBtn = [...host.querySelectorAll('button')].find((b) => b.textContent?.startsWith('Save'));
    expect(saveBtn).toBeTruthy();
    await act(async () => {
      saveBtn!.click();
    });
    // Confirmation is required client-side too for this setting.
    const confirm = [...host.querySelectorAll('button')].find((b) => b.textContent === 'Yes, turn it on');
    expect(confirm).toBeTruthy();
    await act(async () => {
      confirm!.click();
    });

    expect(save).toHaveBeenCalled();
    expect(host.textContent).toMatch(/Saved:/);
    expect(host.textContent).not.toMatch(/something went wrong/i);
  });
});
