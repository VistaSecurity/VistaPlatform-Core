// Scope editing modals — create / edit and delete confirmation.
//
// The clause BUILDER that used to live here (three comma-separated fields per
// include/exclude clause) is gone, because the shape it built is gone: a scope
// is a query-language string now. What replaced it is the SAME editor the
// Inventory rail uses — `QueryInput` — with autocomplete over the generated
// vocabulary and the caret-under-the-error diagnostics.
//
// That sharing is the point of ADR-0006 D2, not a convenience: a scope, an
// auto-approval rule and the Inventory filter are one language, and a scope
// authored in a weaker editor than the one that teaches the language is a scope
// somebody writes by guessing.
import { useMemo, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { clients } from '../../lib/clients';
import { Modal, ModalField, ModalInput } from '../../components/ui';
import { QueryInput, ServerQueryErrors, checkAssetQuery } from '../inventory/query-editor';
import { queryDiagnostics, type QueryDiagnostic } from '../inventory/asset-queries';
import type { components as CbomComponents } from '@vistasecurity/api-contract';

type Scope = CbomComponents['schemas']['Scope'];

/**
 * A save the server refused because of the QUERY, with its diagnostics intact.
 *
 * Closes A2's `TODO(phase1-E)`: the spans are rendered under the query field
 * with the offending word underlined, which is what a byte span is FOR. A2
 * joined them into the footer as one sentence in the meantime, which was the
 * right interim answer and is not the answer — a message that names a field is
 * useful, and one that points at it in what you typed is the difference between
 * reading an error and seeing one.
 *
 * The envelope is `{error, query, errors[]}`, identical to the asset list's, so
 * it is parsed by the same `queryDiagnostics` and rendered by the same
 * `ServerQueryErrors` — including the UTF-8-byte → UTF-16 span conversion,
 * without which the caret lands on the wrong word from the first accented
 * value onwards.
 */
export class ScopeQueryError extends Error {
  readonly diagnostics: { query: string; errors: QueryDiagnostic[] };
  constructor(diagnostics: { query: string; errors: QueryDiagnostic[] }) {
    super('The server refused this query.');
    this.name = 'ScopeQueryError';
    this.diagnostics = diagnostics;
  }
}

/** Throws the right error for a failed scope write: the structured one when the
 *  query was the problem, a plain message otherwise. */
export function throwScopeError(error: unknown, fallback: string): never {
  const diagnostics = queryDiagnostics(error);
  if (diagnostics) throw new ScopeQueryError(diagnostics);
  throw new Error(scopeError(error, fallback));
}

// scopeError turns the API's failure body into one line a person can act on.
//
// Still the path for a failure that is NOT about the query — a duplicate name,
// a system scope, a 500 — where there are no spans to point at and a sentence
// is the whole of what can be said.
function scopeError(error: unknown, fallback: string): string {
  if (typeof error !== 'object' || error === null) return fallback;
  const body = error as { error?: unknown; errors?: unknown };
  const details = Array.isArray(body.errors)
    ? body.errors
        .map((e) => {
          const d = e as { message?: unknown; suggestion?: unknown };
          return [d.message, d.suggestion].filter((s) => typeof s === 'string' && s).join(' — ');
        })
        .filter(Boolean)
    : [];
  if (details.length > 0) return details.join('; ');
  return 'error' in body ? String(body.error) : fallback;
}

export function ScopeEditModal({ scope, open, onClose }: { scope: Scope | null; open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const isEdit = !!scope;
  const [name, setName] = useState(scope?.name ?? '');
  const [description, setDescription] = useState(scope?.description ?? '');
  const [query, setQuery] = useState(scope?.query ?? '');
  // Derived, not mirrored: validity is a pure function of the text this modal
  // already holds, so there is nothing for the editor to report back and no
  // second copy of the answer to fall out of step with the first.
  const queryOk = useMemo(() => checkAssetQuery(query).ok, [query]);

  const mutation = useMutation({
    mutationFn: async () => {
      const body = { name: name.trim(), description: description.trim() || undefined, query: query.trim() };
      if (isEdit) {
        const { error, response } = await clients.cbom.PUT('/scopes/{id}', { params: { path: { id: scope.id } }, body });
        if (error || !response.ok) throwScopeError(error, 'Failed to update the scope');
      } else {
        const { error, response } = await clients.cbom.POST('/scopes', { body });
        if (error || !response.ok) throwScopeError(error, 'Failed to create the scope');
      }
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['settings', 'scopes'] });
      onClose();
    },
  });

  // A refusal ABOUT THE QUERY renders under the query field, with the span
  // underlined; anything else stays a sentence in the footer. Saying it twice
  // would be worse than either.
  const serverRefusal = mutation.error instanceof ScopeQueryError ? mutation.error.diagnostics : null;

  return (
    <Modal
      open={open}
      onClose={onClose}
      icon="crop"
      eyebrow="Policies · Scopes"
      title={isEdit ? `Edit scope — ${scope.name}` : 'New scope'}
      description={isEdit
        ? 'Changing the name or query bumps the scope version; existing CBOM artifacts keep the version they captured.'
        : 'A named, versioned asset boundary. CBOM artifacts generated against it record the exact query in force.'}
      primary={
        <button
          className="ui-btn sm accent"
          // A scope with a broken query cannot be saved. The server refuses it
          // too — this just refuses it a round trip earlier, with the caret
          // already under the offending word.
          disabled={!name.trim() || !queryOk || mutation.isPending}
          title={queryOk ? undefined : 'Fix the query first'}
          onClick={() => mutation.mutate()}
        >
          {mutation.isPending ? 'Saving…' : isEdit ? 'Save changes' : 'Create scope'}
        </button>
      }
      secondary={<button className="ui-btn sm" onClick={onClose}>Cancel</button>}
      footerNote={mutation.isError && !serverRefusal ? <span style={{ color: 'var(--danger-text)' }}>{mutation.error instanceof Error ? mutation.error.message : 'Request failed'}</span> : undefined}
    >
      <ModalField label="Name">
        <ModalInput value={name} data-autofocus onChange={(e) => setName(e.target.value)} placeholder="e.g. PCI cardholder environment" />
      </ModalField>
      <ModalField label="Description" hint="Optional — shown in the scope list.">
        <ModalInput value={description} onChange={(e) => setDescription(e.target.value)} placeholder="What boundary does this scope attest to?" />
      </ModalField>
      <ModalField label="Query" hint="The same one-line form the Inventory filter writes — and the same editor.">
        <QueryInput
          value={query}
          ariaLabel="Scope query"
          onDraftChange={setQuery}
          placeholder="e.g. environment:production and not tag:dev — empty matches every asset"
        />
        {/* The server's own refusal, under the field it is about. This editor
            validates locally too, so reaching here means the two validators
            disagreed — `untranslatable`, or a value set the generated catalogue
            is a release behind on. Those are the refusals a user can make least
            sense of from a sentence. */}
        {serverRefusal && (
          <div style={{ marginTop: 8 }}>
            <ServerQueryErrors query={serverRefusal.query} errors={serverRefusal.errors} />
          </div>
        )}
      </ModalField>
      <p style={{ margin: '0 0 10px', fontSize: 11.5, color: 'var(--app-t3)', lineHeight: 1.5 }}>
        An empty query matches every asset in the tenant. The query is checked when you save: a scope that would fail when a CBOM is generated is refused now rather than producing evidence with a boundary nobody verified.
      </p>
    </Modal>
  );
}

export function ScopeDeleteModal({ scope, open, onClose }: { scope: Scope | null; open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: async () => {
      if (!scope) return;
      const { error, response } = await clients.cbom.DELETE('/scopes/{id}', { params: { path: { id: scope.id } } });
      if (error || !response.ok) throw new Error('Failed to delete the scope');
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['settings', 'scopes'] });
      onClose();
    },
  });

  return (
    <Modal
      open={open}
      onClose={onClose}
      size="sm"
      tone="danger"
      icon="alert-triangle"
      eyebrow="Policies · Scopes"
      title={`Delete scope — ${scope?.name ?? ''}`}
      description="The scope is soft-deleted: CBOM artifacts that referenced it keep their snapshot and show the scope as deleted instead of breaking."
      primary={
        <button className="ui-btn sm" style={{ borderColor: 'color-mix(in srgb, var(--danger) 40%, transparent)', color: 'var(--danger-text)' }} disabled={mutation.isPending} onClick={() => mutation.mutate()}>
          {mutation.isPending ? 'Deleting…' : 'Delete scope'}
        </button>
      }
      secondary={<button className="ui-btn sm" onClick={onClose}>Cancel</button>}
      footerNote={mutation.isError ? <span style={{ color: 'var(--danger-text)' }}>{mutation.error instanceof Error ? mutation.error.message : 'Request failed'}</span> : undefined}
    />
  );
}
