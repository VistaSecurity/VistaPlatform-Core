import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The shared workspace packages ship TypeScript source (not a prebuilt dist),
// so exclude them from dep pre-bundling — Vite compiles their source directly.
export default defineConfig({
  plugins: [react()],
  optimizeDeps: {
    exclude: ['@vistasecurity/primitives', '@vistasecurity/api-contract'],
  },
  server: {
    host: true, // bind 0.0.0.0 — reachable from other hosts on the LAN
    port: 3001,
    allowedHosts: true, // accept any Host header (dev only) — reached via a LAN hostname
    proxy: {
      // Dev: proxy API calls (and their cookies) to the running gateway, so the
      // browser sees same-origin requests (no CORS) and httpOnly cookies flow.
      // Target is env-driven: a host dev server reaches the gateway at
      // localhost:8080 (the default); inside docker-compose the gateway is the
      // `api-gateway` service, so the compose web-ui service sets
      // VITE_DEV_PROXY_TARGET=http://api-gateway:8080.
      // changeOrigin only rewrites Host — the browser's Origin header would
      // still reach the services, whose gin CORS middleware 403s mutations from
      // any origin outside CORS_ORIGINS (dev-server ports aren't listed). The
      // browser already enforces same-origin here, so drop Origin entirely.
      '/api': {
        target: process.env.VITE_DEV_PROXY_TARGET || 'http://localhost:8080',
        changeOrigin: true,
        configure: (proxy) => {
          proxy.on('proxyReq', (proxyReq) => proxyReq.removeHeader('origin'));
        },
      },
      // User-uploaded static assets (avatars, tenant branding) are served by the
      // backend at /uploads/* and routed there by the gateway/Traefik. The dev
      // server must proxy them too, or an <img src="/uploads/avatars/..."> would
      // hit Vite (which only knows the SPA) and never load.
      '/uploads': {
        target: process.env.VITE_DEV_PROXY_TARGET || 'http://localhost:8080',
        changeOrigin: true,
        configure: (proxy) => {
          proxy.on('proxyReq', (proxyReq) => proxyReq.removeHeader('origin'));
        },
      },
    },
  },
});
