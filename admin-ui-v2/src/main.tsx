import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router';
import { QueryClientProvider } from '@tanstack/react-query';
import toast, { Toaster } from 'react-hot-toast';
import { PlatformAuthProvider } from '@vistasecurity/primitives/platform-auth';
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
