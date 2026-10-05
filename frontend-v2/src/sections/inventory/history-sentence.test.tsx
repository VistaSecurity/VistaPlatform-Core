// The asset timeline's identity-drift entries (owner Decision 4 of).
//
// Two halves: the wording (historySentence), and the wiring — HistoryRow, the
// component the History tab renders, actually uses it. Delete the
// historySentence call in HistoryRow and the second describe goes red on the
// raw `ssh host key rotated` heading and the missing fingerprints.
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { HistoryRow } from './asset-page';
import type { AssetHistoryEntry } from './asset-queries';
import { historySentence } from './history-sentence';

const OLD = 'SHA256:old-host-key';
const NEW = 'SHA256:new-host-key';

const entry = (action: string, changes: Record<string, unknown>): AssetHistoryEntry =>
  ({ id: `h-${action}`, asset_id: 'a-1', action, source: 'identity_engine', created_at: '2026-10-02T09:00:00Z', changes }) as unknown as AssetHistoryEntry;

const rotated = entry('ssh_host_key_rotated', {
  verdict: 'rotated',
  rule: 'mac_and_address_kept_key_changed',
  explanation: 'the SSH host key changed on a device whose hardware address and IP address are unchanged (rule mac_and_address_kept_key_changed)',
  changes: [{ kind: 'ssh_host_key_fingerprint', previous: [OLD], current: [NEW], retired: true }],
});

describe('historySentence', () => {
  it('says a rotated key was rotated, from what to what, and that the old one was retired', () => {
    const s = historySentence(rotated);
    expect(s?.title).toBe('SSH host key rotated');
    expect(s?.details).toEqual([`SSH host key: ${OLD} → ${NEW} (old one retired)`]);
    expect(s?.needsReview).toBe(false);
    expect(s?.explanation).toContain('hardware address and IP address are unchanged');
  });

  it('says a moved device released its old address', () => {
    const s = historySentence(entry('address_moved', {
      changes: [{ kind: 'ip_address', previous: ['192.0.2.10'], current: ['192.0.2.20'], retired: true }],
    }));
    expect(s?.title).toBe('Moved to a new address');
    expect(s?.details).toEqual(['Address: 192.0.2.10 → 192.0.2.20 (old address released)']);
  });

  it('lists every material a reimage changed', () => {
    const s = historySentence(entry('identity_material_rotated', {
      changes: [
        { kind: 'ssh_host_key_fingerprint', previous: [OLD], current: [NEW], retired: true },
        { kind: 'hostname', previous: ['db-primary'], current: ['build-07'] },
        { kind: 'tls_certificate', current: ['bb22'] },
      ],
    }));
    expect(s?.title).toMatch(/^Reimaged/);
    expect(s?.details).toEqual([
      `SSH host key: ${OLD} → ${NEW} (old one retired)`,
      'Name: db-primary → build-07',
      'TLS certificate: none recorded → bb22',
    ]);
  });

  it('flags an unconfirmed change for review and says both keys are kept', () => {
    const s = historySentence(entry('identity_drift_flagged', {
      needs_review: true,
      changes: [{ kind: 'ssh_host_key_fingerprint', previous: [OLD], current: [NEW] }],
    }));
    expect(s?.title).toBe('SSH host key changed: needs review');
    expect(s?.needsReview).toBe(true);
    expect(s?.details).toEqual([`SSH host key: ${OLD} → ${NEW} (both kept until reviewed)`]);
  });

  it('leaves every other action to the generic rendering', () => {
    expect(historySentence(entry('updated', { decided_by: 'mac_address' }))).toBeNull();
    expect(historySentence(entry('identifier_reassigned', {}))).toBeNull();
  });

  it('survives a malformed changes payload without inventing values', () => {
    const s = historySentence(entry('ssh_host_key_rotated', { changes: 'not-a-list' }));
    expect(s?.title).toBe('SSH host key rotated');
    expect(s?.details).toEqual([]);
  });
});

describe('HistoryRow renders the drift sentence', () => {
  it('shows the sentence and both fingerprints, not the raw action and JSON dump', () => {
    const html = renderToStaticMarkup(<HistoryRow entry={rotated} />);
    expect(html).toContain('SSH host key rotated');
    expect(html).toContain(OLD);
    expect(html).toContain(NEW);
    expect(html).not.toContain('ssh host key rotated');
    expect(html).not.toContain('verdict:');
    expect(html).not.toContain('history-needs-review');
  });

  it('marks a flagged change as needing review', () => {
    const html = renderToStaticMarkup(<HistoryRow entry={entry('identity_drift_flagged', {
      needs_review: true,
      changes: [{ kind: 'ssh_host_key_fingerprint', previous: [OLD], current: [NEW] }],
    })} />);
    expect(html).toContain('history-needs-review');
    expect(html).toContain('Needs review');
  });

  it('still renders an ordinary entry the old way', () => {
    const html = renderToStaticMarkup(<HistoryRow entry={entry('merge_proposed', { proposal_id: 'p-1' })} />);
    expect(html).toContain('merge proposed');
    expect(html).toContain('proposal_id');
  });
});
