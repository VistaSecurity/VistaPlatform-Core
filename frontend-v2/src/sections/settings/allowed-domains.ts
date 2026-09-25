// Form-side mirror of shared/security/ssoclaims.NormalizeAllowedDomains.
// The server is authoritative; keeping the same rules here lets an admin fix
// an invalid entry before a save that would otherwise fail with 400.

const MAX_ALLOWED_DOMAINS = 50;
// Any UTF-16 code unit above 0x7f is non-ASCII (astral characters arrive as
// surrogates, which are in range too).
const NON_ASCII = /[\u0080-\uffff]/;

export type NormalizedAllowedDomains = { domains: string[]; error: string | null };

function normalizeAllowedDomain(raw: string): { domain: string; error: string | null } {
  const domain = raw.trim();
  if (!domain) return { domain: '', error: 'Domain is empty.' };
  if (NON_ASCII.test(domain)) {
    return { domain: '', error: `“${domain}” contains non-ASCII characters. Enter an internationalized domain in its punycode (xn--) form.` };
  }
  if (domain.startsWith('*')) return { domain: '', error: `“${domain}” is a wildcard. List each exact domain instead.` };
  if (domain.includes('@')) return { domain: '', error: `“${domain}” is an email address. Enter only the part after @.` };
  if (domain.includes('/') || domain.includes(':')) return { domain: '', error: `“${domain}” is not a bare domain.` };
  if (domain.endsWith('.')) return { domain: '', error: `“${domain}” ends with a dot.` };

  const canonical = domain.toLowerCase();
  if (canonical.length > 253) return { domain: '', error: `“${domain}” is longer than 253 characters.` };
  const labels = canonical.split('.');
  if (labels.length < 2) return { domain: '', error: `“${domain}” is not a fully qualified domain, such as example.com.` };
  for (const label of labels) {
    if (!label || label.length > 63) return { domain: '', error: `“${domain}” has an empty or over-long label.` };
    if (label.startsWith('-') || label.endsWith('-')) return { domain: '', error: `“${domain}” has a label starting or ending with a hyphen.` };
    if (!/^[a-z0-9-]+$/.test(label)) return { domain: '', error: `“${domain}” may contain only letters, digits, hyphens, and dots.` };
  }
  return { domain: canonical, error: null };
}

// The UI accepts a comma-separated string. Empty comma slots are ignored,
// matching the existing form behavior; every non-empty entry is normalized,
// duplicate canonical entries are removed, and the API receives that result.
export function normalizeAllowedDomains(raw: string): NormalizedAllowedDomains {
  const domains: string[] = [];
  const seen = new Set<string>();
  for (const entry of raw.split(',').map((value) => value.trim()).filter(Boolean)) {
    const normalized = normalizeAllowedDomain(entry);
    if (normalized.error) return { domains: [], error: normalized.error };
    if (!seen.has(normalized.domain)) {
      seen.add(normalized.domain);
      domains.push(normalized.domain);
    }
  }
  if (domains.length > MAX_ALLOWED_DOMAINS) {
    return { domains: [], error: `Enter at most ${MAX_ALLOWED_DOMAINS} allowed domains.` };
  }
  return { domains, error: null };
}
