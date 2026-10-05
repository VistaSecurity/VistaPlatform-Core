import { expect, it } from 'vitest';
import { jobActionError } from './job-action-error';

it('shows the reason a refused cancel or re-run carries', () => {
  expect(jobActionError({ error: 'job_not_cancellable', details: 'job already completed' }, 'Failed to cancel job').message).toBe(
    'job already completed',
  );
});

it('shows a sentence-shaped error and never a bare code', () => {
  expect(jobActionError({ error: 'job not found' }, 'Failed to cancel job').message).toBe('job not found');
  expect(jobActionError({ error: 'job_not_rerunnable' }, 'Failed to re-run job').message).toBe('Failed to re-run job');
});

it('falls back when the body is not the error shape', () => {
  expect(jobActionError(undefined, 'Failed to cancel job').message).toBe('Failed to cancel job');
  expect(jobActionError('boom', 'Failed to cancel job').message).toBe('Failed to cancel job');
  expect(jobActionError({ details: '  ' }, 'Failed to cancel job').message).toBe('Failed to cancel job');
});
