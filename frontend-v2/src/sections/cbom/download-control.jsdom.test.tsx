// @vitest-environment jsdom
//
// The per-artifact Download control, MOUNTED — in the compact form the
// artifact list uses.
//
// The list row is where this went wrong once. Three of the four kinds offer a
// single format, and the compact single-format button rendered a bare download
// icon with no text, while the inventory row (two formats) rendered a menu
// that spelled out "CycloneDX 1.7". Read side by side, that said the CBOM,
// SBOM and HBOM had no CycloneDX export. They always did.
//
// `downloadFormatsFor` is unit-tested in artifact-kind.test.ts; that proves
// the DATA names the format. This proves the BUTTON does, by mounting the real
// component: delete `only.short` from the compact branch and the first case
// goes red while every artifact-kind test stays green.
//
// Follows `command-palette.jsdom.test.tsx`: jsdom + React's own `act`, no
// testing-library.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// The control's only side effect is the download itself. Stub it at the module
// boundary so a click is observable without a network.
const downloadArtifact = vi.fn<(a: CBOMArtifact, format: string) => Promise<void>>(async () => {});
vi.mock('./queries', () => ({ downloadArtifact: (a: CBOMArtifact, format: string) => downloadArtifact(a, format) }));

import { DownloadControl } from './download-control';
import type { CBOMArtifact } from './queries';

function artifact(kind: string): CBOMArtifact {
  return {
    id: '00000000-0000-4000-8000-000000000001',
    tenant_id: '00000000-0000-4000-8000-000000000002',
    scope_id: '00000000-0000-4000-8000-000000000003',
    scope_version: 1,
    scope_name_snapshot: 'All',
    artifact_kind: kind,
    content_hash: 'ab'.repeat(32),
    size_bytes: 1,
    component_count: 1,
    cyclonedx_spec_version: '1.7',
    generated_at: '2026-09-21T00:00:00Z',
    input_data_freshness_at: '2026-09-21T00:00:00Z',
    has_inline_content: true,
  } as unknown as CBOMArtifact;
}

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  downloadArtifact.mockClear();
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
});

function mount(kind: string, compact: boolean) {
  act(() => {
    root.render(<DownloadControl artifact={artifact(kind)} compact={compact} />);
  });
}

function buttons(): HTMLButtonElement[] {
  return Array.from(container.querySelectorAll('button'));
}

describe('DownloadControl, compact (the list row)', () => {
  it.each(['cbom', 'sbom', 'hbom'])('names CycloneDX on the single-format button for a %s', (kind) => {
    mount(kind, true);
    const [btn] = buttons();
    expect(btn, 'no button rendered').toBeTruthy();
    expect(btn.textContent, `${kind} compact button has no format name`).toContain('CycloneDX');
    expect(btn.title, `${kind} compact tooltip does not name the format`).toContain('CycloneDX');
    // Single format, so no menu — the format name IS the button, not a chevron
    // into a list of one.
    expect(btn.getAttribute('aria-haspopup')).toBeNull();
  });

  it('names both formats on the inventory menu button, and lists them when opened', () => {
    mount('inventory', true);
    const [btn] = buttons();
    expect(btn.getAttribute('aria-haspopup')).toBe('menu');
    expect(btn.textContent).toContain('CycloneDX');
    expect(btn.textContent).toContain('OCSF');
    expect(btn.title).toContain('CycloneDX');
    expect(btn.title).toContain('OCSF');

    act(() => { btn.click(); });
    const items = Array.from(container.querySelectorAll('[role="menuitem"]')).map((el) => el.textContent ?? '');
    expect(items).toHaveLength(2);
    expect(items[0]).toContain('CycloneDX 1.7');
    expect(items[1]).toContain('OCSF 1.9');
  });

  it('downloads CycloneDX on click of the single-format button', async () => {
    mount('hbom', true);
    await act(async () => { buttons()[0].click(); });
    expect(downloadArtifact).toHaveBeenCalledTimes(1);
    expect(downloadArtifact.mock.calls[0][1]).toBe('cyclonedx');
  });
});

describe('DownloadControl, full width (the drawer)', () => {
  it('shows the full CycloneDX label for a single-format kind', () => {
    mount('sbom', false);
    expect(buttons()[0].textContent).toContain('CycloneDX 1.7');
  });
});
