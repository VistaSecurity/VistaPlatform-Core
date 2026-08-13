import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router';
import { QueryClientProvider } from '@tanstack/react-query';
import toast, { Toaster } from 'react-hot-toast';
import { PlatformAuthProvider, createPlatformAuthClient, platformTokenManager } from '@vistasecurity/primitives/platform-auth';
import { createSessionExpiryHandler } from '@vistasecurity/primitives/shared';
import { setSessionExpiredHandler } from '@vistasecurity/api-contract';
import { queryClient } from './lib/query-client';
import App from './App';
import './index.css';

// The auth notifier is injected (the primitive is headless — it never imports a
// toast lib). On logout / dead session, hard-navigate to /login. Mirrors
// frontend-v2's main.tsx, but with the PLATFORM auth provider (admin-service
// session, platform_* cookies — see @vistasecurity/primitives/platform-auth).
const notifier = {
  success: (m: string) => toast.success(m),
  error: (m: string) => toast.error(m),
};

// Session-timeout handling (mirrors frontend-v2, on the platform_* cookie
// family): a mid-session 401 tries one silent refresh; if the refresh token is
// dead too, clear the session signal and land on /login with a "session
// expired" notice. Auth-flow endpoints are exempt inside the middleware.
const sessionAuthClient = createPlatformAuthClient();
setSessionExpiredHandler(
  createSessionExpiryHandler({
    hasSession: () => platformTokenManager.hasToken(),
    refresh: () => sessionAuthClient.refresh(),
    onSessionExpired: () => {
      platformTokenManager.clearTokens();
      if (window.location.pathname !== '/login') {
        window.location.assign('/login?reason=session-expired');
      }
    },
  }),
);

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <PlatformAuthProvider notifier={notifier} onUnauthenticated={() => window.location.assign('/login')}>
          <App />
        </PlatformAuthProvider>
        <Toaster position="top-right" toastOptions={{ style: { background: 'var(--op-panel)', color: 'var(--op-t1)', border: '1px solid var(--op-border2)' } }} />
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
);
