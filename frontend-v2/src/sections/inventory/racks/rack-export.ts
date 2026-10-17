// PNG / SVG download of a rack elevation (DCIM row 2.5): client-side, from the
// drawing on screen, like the map's export. A picture, not evidence.
//
// The drawing is styled with the app's CSS custom properties (`var(--danger)`
// and friends) so it follows the theme; a standalone file has no stylesheet,
// so every var() is resolved to its computed value before the file is
// written. Device images are left out (an SVG rendered through <img> loads no
// external resources); their class-coloured block underneath carries the
// device instead.

/** Replaces every `var(--name)` / `var(--name, fallback)` with resolve(name),
 *  falling back to the declared fallback, then to `fallbackColor`. */
export function inlineCssVars(text: string, resolve: (name: string) => string, fallbackColor = '#888888'): string {
  let out = text;
  // Nested vars (a fallback that is itself a var) resolve innermost first.
  for (let i = 0; i < 4 && out.includes('var('); i++) {
    out = out.replace(/var\(\s*(--[A-Za-z0-9_-]+)\s*(?:,\s*([^()]*))?\)/g, (_m, name: string, fb?: string) => {
      const v = resolve(name).trim();
      if (v) return v;
      const declared = fb?.trim() ?? '';
      return declared.length > 0 ? declared : fallbackColor;
    });
  }
  return out;
}

/** The standalone SVG text of an elevation drawing. */
export function serializeElevation(svg: SVGSVGElement, resolve: (name: string) => string): string {
  const clone = svg.cloneNode(true) as SVGSVGElement;
  for (const el of Array.from(clone.querySelectorAll('image, [data-export="skip"]'))) el.remove();
  clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
  const vb = clone.viewBox?.baseVal;
  if (vb && vb.width) {
    clone.setAttribute('width', String(vb.width));
    clone.setAttribute('height', String(vb.height));
  }
  const bg = clone.ownerDocument.createElementNS('http://www.w3.org/2000/svg', 'rect');
  bg.setAttribute('x', vb ? String(vb.x) : '0');
  bg.setAttribute('y', vb ? String(vb.y) : '0');
  bg.setAttribute('width', '100%');
  bg.setAttribute('height', '100%');
  bg.setAttribute('fill', 'var(--app-panel)');
  clone.insertBefore(bg, clone.firstChild);
  const text = new XMLSerializer().serializeToString(clone);
  return '<?xml version="1.0" encoding="UTF-8"?>\n' + inlineCssVars(text, resolve);
}

/** Resolves a custom property against the document root. */
export function documentVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name);
}

export function saveBlob(filename: string, blob: Blob): void {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

/** Rasterises standalone SVG text at `scale`× into a PNG blob. */
export function svgToPng(svgText: string, width: number, height: number, scale = 2): Promise<Blob> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    const url = URL.createObjectURL(new Blob([svgText], { type: 'image/svg+xml' }));
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = Math.ceil(width * scale);
      canvas.height = Math.ceil(height * scale);
      const ctx = canvas.getContext('2d');
      if (!ctx) { URL.revokeObjectURL(url); reject(new Error('This browser cannot draw the PNG')); return; }
      ctx.scale(scale, scale);
      ctx.drawImage(img, 0, 0, width, height);
      URL.revokeObjectURL(url);
      canvas.toBlob((b) => (b ? resolve(b) : reject(new Error('The PNG could not be written'))), 'image/png');
    };
    img.onerror = () => { URL.revokeObjectURL(url); reject(new Error('The drawing could not be rasterised')); };
    img.src = url;
  });
}

/** "rack-r12-.svg". */
export function exportFilename(rackName: string, ext: 'svg' | 'png', now: Date = new Date()): string {
  const slug = rackName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'rack';
  return `rack-${slug}-${now.toISOString().slice(0, 10)}.${ext}`;
}
