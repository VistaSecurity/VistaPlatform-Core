// Shared helpers for rendering links to the current legal documents (Terms of
// Service / Privacy Policy). Used by the signup form, the social-signup org-name
// step, and the post-login re-acceptance modal so the wording stays consistent.

export type LegalDoc = {
  doc_type: string;
  title: string;
  version?: number;
};

// Maps a doc_type to its standalone public page path.
export function legalPath(docType: string): string {
  return docType === 'privacy_policy' ? '/legal/privacy' : '/legal/terms';
}

// Renders "the <Terms of Service> and the <Privacy Policy>" as links opening in
// a new tab, in the order the API returned them.
export function LegalLinks({ docs }: { docs: LegalDoc[] }) {
  return (
    <>
      {docs.map((d, i) => (
        <span key={d.doc_type}>
          {i > 0 && (i === docs.length - 1 ? ' and ' : ', ')}
          <a href={legalPath(d.doc_type)} target="_blank" rel="noreferrer"
            style={{ color: 'var(--accent-light)', textDecoration: 'none' }}>
            {d.title}
          </a>
        </span>
      ))}
    </>
  );
}
