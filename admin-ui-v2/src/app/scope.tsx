// Global tenant SCOPE — an operator signature. When set, the cross-tenant lists
// (Tenants, Fleet, Audit, Jobs) narrow to one tenant and the scope bar shows.
// Pure client-side filter over already-fetched data (the lists fetch all + filter
// client-side today); when those move to server-side params, scope feeds the query.
import { createContext, useContext, useState, type ReactNode } from 'react';

interface ScopeState {
  scopeId: string | null;
  scopeName: string | null;
  setScope: (id: string, name: string) => void;
  clear: () => void;
}

const ScopeContext = createContext<ScopeState | undefined>(undefined);

export function useScope(): ScopeState {
  const ctx = useContext(ScopeContext);
  if (!ctx) throw new Error('useScope must be used within a ScopeProvider');
  return ctx;
}

export function ScopeProvider({ children }: { children: ReactNode }) {
  const [scopeId, setScopeId] = useState<string | null>(null);
  const [scopeName, setScopeName] = useState<string | null>(null);
  const value: ScopeState = {
    scopeId,
    scopeName,
    setScope: (id, name) => { setScopeId(id); setScopeName(name); },
    clear: () => { setScopeId(null); setScopeName(null); },
  };
  return <ScopeContext.Provider value={value}>{children}</ScopeContext.Provider>;
}
