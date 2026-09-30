// What the Delivery History "Channels" cell says about one row.
//
// The cell used to print "— (no rule matched)" for ANY row whose channels_used
// was empty. That was wrong for a row where a rule DID match and every channel
// failed — the tenant was told nothing was routed when delivery had actually
// broken — and it said nothing at all about a partial delivery. The row's own
// `metadata.channel_results` (one entry per attempted channel, written by
// notification-service) is the per-channel truth; fall back to `channels_used`
// for rows that predate it.

export type HistoryLike = {
  status?: string | null;
  channels_used?: string[] | null;
  metadata?: unknown;
};

export type ChannelResult = { channel_type: string; status: string; retries_exhausted?: boolean; reason?: string };

export type DeliverySummary = {
  text: string;
  /** The caller maps the tone to a colour. */
  tone: 'ok' | 'warn' | 'bad';
  /** Row should be tinted: nothing was delivered, or the row needs attention. */
  attention: boolean;
  /**
   * Why each failed channel failed, one line per channel, in the server's
   * sanitized vocabulary (never a URL or token) — for the cell's tooltip. Null
   * when nothing failed or the row predates `reason`.
   */
  detail?: string | null;
};

function failureDetail(results: ChannelResult[]): string | null {
  const lines = results
    .filter((r) => r.status !== 'sent' && typeof r.reason === 'string' && r.reason.trim())
    .map((r) => `${r.channel_type}: ${r.reason}`);
  return lines.length > 0 ? lines.join('\n') : null;
}

export function channelResults(row: HistoryLike): ChannelResult[] {
  const meta = row.metadata;
  if (!meta || typeof meta !== 'object') return [];
  const raw = (meta as Record<string, unknown>).channel_results;
  if (!Array.isArray(raw)) return [];
  return raw.filter(
    (r): r is ChannelResult =>
      !!r && typeof r === 'object' && typeof (r as ChannelResult).channel_type === 'string' && typeof (r as ChannelResult).status === 'string',
  );
}

function label(r: ChannelResult): string {
  if (r.status === 'sent') return `${r.channel_type} ✓`;
  if (r.status === 'retrying') return `${r.channel_type} ✗ (retrying)`;
  return `${r.channel_type} ✗${r.retries_exhausted ? ' (gave up)' : ''}`;
}

/**
 * How many channels this notification was batched for a digest on
 * (`metadata.digest_queued_channels`, written by notification-service). A row
 * routed ONLY to digest channels has no channel_results and no channels_used yet
 * — nothing has been sent, by design — and used to fall through to "no rule
 * matched", which is the opposite of what happened.
 */
function digestQueued(row: HistoryLike): number {
  const meta = row.metadata;
  if (!meta || typeof meta !== 'object') return 0;
  const n = (meta as Record<string, unknown>).digest_queued_channels;
  return typeof n === 'number' && n > 0 ? n : 0;
}

export function deliverySummary(row: HistoryLike): DeliverySummary {
  const status = (row.status ?? '').toLowerCase();
  const results = channelResults(row);
  const used = row.channels_used ?? [];
  const queued = digestQueued(row);
  const queuedNote = queued > 0 ? ` · ${queued} queued for digest` : '';

  if (results.length > 0) {
    const anyFailed = results.some((r) => r.status !== 'sent');
    const noneSent = results.every((r) => r.status !== 'sent');
    return {
      text: results.map(label).join(', ') + queuedNote,
      tone: noneSent ? 'bad' : anyFailed ? 'warn' : 'ok',
      attention: anyFailed,
      ...(failureDetail(results) ? { detail: failureDetail(results) } : {}),
    };
  }
  if (used.length > 0) {
    return { text: used.join(', ') + queuedNote, tone: status === 'partial' ? 'warn' : 'ok', attention: status === 'partial' };
  }
  if (queued > 0) {
    // Batched for a digest: not delivered YET, and not a routing gap.
    return { text: `queued for digest (${queued} channel${queued === 1 ? '' : 's'})`, tone: 'ok', attention: false };
  }
  if (status === 'failed') {
    return { text: 'delivery failed', tone: 'bad', attention: true };
  }
  return { text: '— (no rule matched)', tone: 'warn', attention: true };
}
