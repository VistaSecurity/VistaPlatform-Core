// @vitest-environment jsdom
//
// The deep-link backstop for the hide rule: a bookmark to /maintenance on an
// install without maintenance-service lands on a notice, not on a page whose
// calls all 404. A section without a service gate passes straight through.
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const availability = vi.hoisted(() => ({ value: 'available' }));
vi.mock('./maintenance-queries', () => ({ useMaintenanceAvailability: () => availability.value }));

import { RequireService } from '../../app/require-service';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let root: Root | null = null;
let host: HTMLDivElement;
beforeEach(() => {
  host = document.createElement('div');
  document.body.appendChild(host);
  root = createRoot(host);
});
afterEach(() => {
  act(() => root?.unmount());
  host.remove();
});

function render(service: 'maintenance' | undefined) {
  act(() => root!.render(<RequireService service={service}><div data-testid="page">page</div></RequireService>));
}

describe('RequireService', () => {
  it('absent → the not-deployed notice, never the page', () => {
    availability.value = 'absent';
    render('maintenance');
    expect(host.querySelector('[data-testid="page"]')).toBeNull();
    expect(host.querySelector('[data-testid="service-absent"]')?.textContent).toContain('maintenance.enabled=false');
  });
  it('pending → neither, until the answer lands', () => {
    availability.value = 'pending';
    render('maintenance');
    expect(host.querySelector('[data-testid="page"]')).toBeNull();
    expect(host.querySelector('[data-testid="service-absent"]')).toBeNull();
  });
  it('available → the page', () => {
    availability.value = 'available';
    render('maintenance');
    expect(host.querySelector('[data-testid="page"]')).not.toBeNull();
  });
  it('no service gate → the page, whatever maintenance-service says', () => {
    availability.value = 'absent';
    render(undefined);
    expect(host.querySelector('[data-testid="page"]')).not.toBeNull();
  });
});
