import { defineConfig, type ProxyOptions } from 'vite';
import react from '@vitejs/plugin-react';

// The shared workspace packages ship TypeScript source (not a prebuilt dist),
// so exclude them from dep pre-bundling — Vite compiles their source directly.
// Where dev API calls go. A host dev server reaches the gateway at
// localhost:8080 (the default); inside docker-compose the gateway is the
// `api-gateway` service, so the compose web-ui service sets
// VITE_DEV_PROXY_TARGET=http://api-gateway:8080. Pointing it at a DEPLOYED
// backend (a cluster's edge) also works, which is the point of the cookie
// rewrite below.
const devProxyTarget = process.env.VITE_DEV_PROXY_TARGET;

const devProxy: ProxyOptions = {
  target: devProxyTarget || 'http://localhost:8080',
  changeOrigin: true,
  // changeOrigin only rewrites Host — the browser's Origin header would still
  // reach the services, whose gin CORS middleware 403s mutations from any origin
  // outside CORS_ORIGINS (dev-server ports aren't listed). The browser already
  // enforces same-origin here, so drop Origin entirely.
  configure: (proxy) => {
    proxy.on('proxyReq', (proxyReq) => proxyReq.removeHeader('origin'));
    // A deployed backend also sets COOKIE_SECURE, and a `Secure` cookie is only
    // stored by a browser on a trustworthy origin. `http://localhost` counts; a
    // private LAN address — the dev server reached from a browser on another
    // machine — does not, so the cookies are dropped and the app says
    // "Authorization required" while the login itself returned 200. The
    // proxy→backend leg is still HTTPS; only the browser→dev-server hop on your
    // own network is plaintext. Dev-target only, same as the domain rewrite above.
    if (devProxyTarget) {
      proxy.on('proxyRes', (proxyRes) => {
        const cookies = proxyRes.headers['set-cookie'];
        if (cookies) proxyRes.headers['set-cookie'] = cookies.map((c) => c.replace(/;\s*Secure/gi, ''));
      });
    }
  },
  // A DEPLOYED backend stamps its own COOKIE_DOMAIN on the session cookies
  // (e.g. `Domain=console.example.com`). A browser on localhost domain-rejects
  // those outright, so /auth/login answers 200 and then nothing sticks — the app
  // bounces straight back to the login page with no error to read. Stripping the
  // Domain attribute makes them host-only for whatever host the dev server was
  // loaded on. Applied ONLY when the target was overridden: the default
  // localhost gateway's cookies are already host-scoped, so that path is left
  // exactly as it was.
  ...(devProxyTarget ? { cookieDomainRewrite: '' } : {}),
};

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
      // `/api` is the API; `/uploads` is user-uploaded static content (avatars,
      // tenant branding) served by the backend — an <img src="/uploads/..."> must
      // be proxied too, or it hits Vite (which only knows the SPA) and never loads.
      '/api': devProxy,
      '/uploads': devProxy,
    },
  },
});
