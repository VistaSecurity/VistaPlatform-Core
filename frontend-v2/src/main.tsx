import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router';
import { QueryClientProvider } from '@tanstack/react-query';
import toast, { Toaster } from 'react-hot-toast';
import { AuthProvider } from '@vistasecurity/primitives/auth';
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
