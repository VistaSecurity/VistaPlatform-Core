// Pre-paint theme bootstrap. Served same-origin from /public so it satisfies the
// production CSP `script-src 'self'` (an inline <script> would be blocked) while
// still running synchronously in <head> before first paint to avoid a theme flash.
(function () {
  try {
    var t = localStorage.getItem('vista-theme');
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
  } catch (e) {
    /* localStorage unavailable (private mode / disabled) — keep the default theme */
  }
})();
