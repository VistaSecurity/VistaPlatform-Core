import React from 'react';
import { isPublicPath } from './app/public-routes';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router';
import { QueryClientProvider } from '@tanstack/react-query';
import toast, { Toaster } from 'react-hot-toast';
import { AuthProvider, createAuthClient, tokenManager } from '@vistasecurity/primitives/auth';
import { createSessionExpiryHandler } from '@vistasecurity/primitives/shared';
import { setSessionExpiredHandler } from '@vistasecurity/api-contract';
import { queryClient } from './lib/query-client';
import { ErrorBoundary } from './app/error-boundary';
import App from './App';
import './index.css';

// The auth notifier is injected (the package is headless — it never imports a
// toast lib). On logout / dead session, hard-navigate to /login.
const notifier = {
  success: (m: string) => toast.success(m),
  error: (m: string) => toast.error(m),
};

// Session-timeout handling: when any API call 401s mid-session, try one silent
// refresh-token exchange (concurrent 401s share it); if the refresh token is
// dead too, clear the session signal and land on /login, which explains the
// expiry via ?reason=. Auth-flow endpoints are exempt inside the middleware, so
// a wrong password never triggers this.
const sessionAuthClient = createAuthClient();
setSessionExpiredHandler(
  createSessionExpiryHandler({
    hasSession: () => tokenManager.hasToken(),
    refresh: () => sessionAuthClient.refresh(),
    onSessionExpired: (reason) => {
      tokenManager.clearTokens();
      // Only bounce off APP routes. Public routes (signup / invite / reset /
      // SSO callback / legal) are reachable signed out by design, and a stale
      // cookie must not evict a visitor from the link they just followed.
      if (!isPublicPath(window.location.pathname)) {
        window.location.assign(`/login?reason=${reason === 'expired' ? 'session-expired' : 'signed-out'}`);
      }
    },
  }),
);

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <AuthProvider notifier={notifier} onUnauthenticated={() => window.location.assign('/login')}>
            <App />
          </AuthProvider>
          <Toaster position="top-right" toastOptions={{ style: { background: 'var(--app-panel)', color: 'var(--app-t1)', border: '1px solid var(--app-border2)' } }} />
        </BrowserRouter>
      </QueryClientProvider>
    </ErrorBoundary>
  </React.StrictMode>,
);
