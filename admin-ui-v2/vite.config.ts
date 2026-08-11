import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The shared workspace packages ship TypeScript source (not a prebuilt dist),
// so exclude them from dep pre-bundling — Vite compiles their source directly.
//
// Dev port 3007: admin-ui (v1) holds :3006, and frontend-v2 holds :3001, so
// the admin rebuild gets its own port for parallel (strangler) running.
export default defineConfig({
  plugins: [react()],
  optimizeDeps: {
    exclude: ['@vistasecurity/primitives', '@vistasecurity/api-contract'],
  },
  server: {
    host: true, // bind 0.0.0.0 — reachable from other hosts on the LAN
    port: 3007,
    allowedHosts: true, // accept any Host header (dev only) — reached via a LAN hostname
    proxy: {
      // Dev: proxy API calls (and their cookies) to the running gateway, so the
      // browser sees same-origin requests (no CORS) and httpOnly cookies flow.
      // changeOrigin only rewrites Host; the services' gin CORS middleware 403s
      // mutations from origins outside CORS_ORIGINS (dev-server ports aren't
      // listed), so drop Origin entirely — the browser enforces same-origin here.
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
        // Dev-only proxy plumbing. Vite's bundled proxy types don't expose the
        // event-emitter `.on` surface consistently across versions, so type these
        // loosely — this block never ships in the production bundle.
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        configure: (proxy: any) => {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          proxy.on('proxyReq', (proxyReq: any) => proxyReq.removeHeader('origin'));
        },
      },
      // Platform branding assets are served by admin-service (via the gateway) at
      // /uploads/platform-branding/*. In prod the gateway serves both the UI and
      // these assets same-origin, so the relative URL just works; proxy it in dev
      // too so logo/favicon previews resolve against the running gateway.
      '/uploads': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
});
