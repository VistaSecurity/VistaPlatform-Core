// @vitest-environment jsdom
//
// Staff rows render role.display_name, so a role mutation must refresh the
// staff list as well as the roles list.
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../lib/clients', () => ({
  clients: { admin: { PUT: async () => ({ error: undefined, response: new Response(null, { status: 200 }) }), DELETE: async () => ({ error: undefined, response: new Response(null, { status: 200 }) }), POST: async () => ({ data: {}, error: undefined, response: new Response(null, { status: 200 }) }) } },
}));

import { useUpdateRole, useCreateRole, useDeleteRole } from './queries';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

async function run(hook: 'update' | 'create' | 'delete') {
  const qc = new QueryClient();
  const spy = vi.spyOn(qc, 'invalidateQueries');
  let fire: () => Promise<unknown> = async () => {};
  function C() {
    const u = useUpdateRole(); const c = useCreateRole(); const d = useDeleteRole();
    fire = async () =>
      hook === 'update' ? u.mutateAsync({ id: 'r1', body: {} as never })
        : hook === 'create' ? c.mutateAsync({} as never)
          : d.mutateAsync('r1');
    return null;
  }
  const host = document.createElement('div');
  const root = createRoot(host);
  await act(async () => { root.render(<QueryClientProvider client={qc}><C /></QueryClientProvider>); });
  await act(async () => { await fire(); });
  act(() => root.unmount());
  return spy.mock.calls.map((c) => JSON.stringify((c[0] as { queryKey: unknown }).queryKey));
}

describe('role mutations', () => {
  for (const k of ['update', 'create', 'delete'] as const) {
    it(`${k} invalidates roles and staff`, async () => {
      const keys = await run(k);
      expect(keys).toContain('["platform","roles"]');
      expect(keys).toContain('["platform","staff"]');
    });
  }
});
