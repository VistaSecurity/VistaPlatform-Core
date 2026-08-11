// Public standalone legal document page (/legal/terms, /legal/privacy). Fetches
// the current published version from the public auth endpoint and renders it.
// Linked from the signup form, the social-signup step, and the post-login
// re-acceptance modal. Mounted outside RequireAuth so cold visitors can read it.
import { useQuery } from '@tanstack/react-query';
import { clients } from '../lib/clients';

const DOC_TYPE: Record<string, 'terms_of_service' | 'privacy_policy'> = {
  terms: 'terms_of_service',
  privacy: 'privacy_policy',
};

// Minimal markdown-ish renderer: '#'/'##'/'###' headings and blank-line-
// separated paragraphs. The document body is trusted platform-authored content
// (published by a platform admin), not tenant input.
function renderBody(body: string) {
  const blocks = body.replace(/\r\n/g, '\n').split(/\n{2,}/);
  return blocks.map((block, i) => {
    const line = block.trim();
    if (line.startsWith('### ')) return <h3 key={i} style={hStyle(15)}>{line.slice(4)}</h3>;
    if (line.startsWith('## ')) return <h2 key={i} style={hStyle(18)}>{line.slice(3)}</h2>;
    if (line.startsWith('# ')) return <h1 key={i} style={hStyle(24)}>{line.slice(2)}</h1>;
    return <p key={i} style={{ margin: '0 0 14px', lineHeight: 1.7, color: 'rgba(255,255,255,.78)' }}>{line}</p>;
  });
}

function hStyle(size: number): React.CSSProperties {
  return { fontFamily: 'var(--font-head, inherit)', fontSize: size, fontWeight: 700, color: '#F1F1F2', margin: '22px 0 10px' };
}

export function LegalPage({ kind }: { kind: 'terms' | 'privacy' }) {
  const docType = DOC_TYPE[kind];
  const q = useQuery({
    queryKey: ['legal', docType],
    queryFn: async () => {
      const { data, error } = await clients.auth.GET('/auth/legal/documents/{docType}', {
        params: { path: { docType } },
      });
      if (error || !data) throw new Error('Document not available');
      return data;
    },
  });

  return (
    <div style={{ minHeight: '100vh', background: '#0d0f14', padding: '48px 20px' }}>
      <div style={{ maxWidth: 760, margin: '0 auto' }}>
        <a href="/signup" style={{ color: 'var(--accent-light)', textDecoration: 'none', fontSize: 13 }}>&larr; Back</a>
        {q.isLoading && <p style={{ color: 'rgba(255,255,255,.6)', marginTop: 24 }}>Loading…</p>}
        {q.isError && (
          <p style={{ color: 'rgba(255,255,255,.6)', marginTop: 24 }}>
            This document has not been published yet.
          </p>
        )}
        {q.data && (
          <article style={{ marginTop: 20 }}>
            <h1 style={{ ...hStyle(30), marginTop: 8 }}>{q.data.title}</h1>
            <div style={{ fontSize: 12.5, color: 'rgba(255,255,255,.45)', marginBottom: 24 }}>
              Version {q.data.version} · Effective {new Date(q.data.effective_date).toLocaleDateString()}
            </div>
            {renderBody(q.data.body)}
          </article>
        )}
      </div>
    </div>
  );
}
