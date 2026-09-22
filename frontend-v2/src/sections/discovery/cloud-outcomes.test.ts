import { describe, expect, it } from 'vitest';
import {
  failureAction,
  failureLine,
  hasResourceOutcomes,
  outcomeView,
  resourceTypeLabel,
  runBanner,
  type ResourceTypeOutcome,
} from './cloud-outcomes';

// slice E. Every assertion here is about a DISTINCTION the tenant has to
// be able to make from Discovery → Discovery Jobs → job detail. If two
// different situations start rendering the same, one of these goes red.

const succeeded = (found: number): ResourceTypeOutcome => ({
  resource_type: 's3',
  status: 'succeeded',
  found,
  scopes_succeeded: 1,
  scopes_attempted: 1,
});

const failed: ResourceTypeOutcome = {
  resource_type: 'kms',
  status: 'failed',
  found: 0,
  scopes_succeeded: 0,
  scopes_attempted: 1,
  failures: [
    {
      scope: 'us-east-1',
      reason: 'access_denied',
      code: 'AccessDeniedException',
      message: 'User: arn:aws:iam::123456789012:user/discovery is not authorized to perform: kms:ListKeys',
    },
  ],
};

describe('outcomeView — empty is not failed', () => {
  it('renders "none in this account" for a type that was read and found nothing', () => {
    const v = outcomeView(succeeded(0));
    expect(v.tone).toBe('ok');
    expect(v.detail).toMatch(/none in this account/i);
    expect(v.action).toBeUndefined();
  });

  it('renders a type that could not be read as not measured, never as zero', () => {
    const v = outcomeView(failed);
    expect(v.tone).toBe('danger');
    expect(v.detail).toMatch(/not measured/i);
    expect(v.detail).not.toMatch(/\b0\b/);
    expect(v.action).toBeTruthy();
  });

  it('never renders the two the same way — this is the bug', () => {
    const empty = outcomeView(succeeded(0));
    const denied = outcomeView(failed);
    expect(empty.label).not.toBe(denied.label);
    expect(empty.tone).not.toBe(denied.tone);
    expect(empty.detail).not.toBe(denied.detail);
  });

  it('counts what it found when it found something', () => {
    expect(outcomeView(succeeded(1)).detail).toBe('1 found');
    expect(outcomeView(succeeded(4)).detail).toBe('4 found');
  });

  it('says how many regions failed on a partial type rather than rounding', () => {
    const v = outcomeView({
      resource_type: 'rds',
      status: 'partial',
      found: 2,
      scopes_succeeded: 1,
      scopes_attempted: 3,
      failures: [{ scope: 'eu-west-1', reason: 'access_denied', code: 'AccessDenied' }],
    });
    expect(v.tone).toBe('warn');
    expect(v.detail).toContain('2 found');
    expect(v.detail).toContain('1 of 3');
    expect(v.detail).toMatch(/2 could not be read/);
    expect(v.action).toMatch(/permission/i);
  });

  it('distinguishes "we do not collect that" from "there is none"', () => {
    const v = outcomeView({
      resource_type: 'efs',
      status: 'not_attempted',
      found: 0,
      scopes_succeeded: 0,
      scopes_attempted: 0,
    });
    expect(v.tone).toBe('muted');
    expect(v.detail).toMatch(/does not collect it/i);
    expect(v.detail).not.toMatch(/none in this account/i);
  });
});

describe('failureAction — a reason a human can act on', () => {
  it('tells an access_denied user to grant a permission, not to retry', () => {
    expect(failureAction('access_denied')).toMatch(/permission/i);
    expect(failureAction('access_denied')).not.toMatch(/rate-limit/i);
  });

  it('tells a throttled user to re-run, not to change IAM', () => {
    expect(failureAction('throttled')).toMatch(/re-run/i);
    expect(failureAction('throttled')).not.toMatch(/permission/i);
  });

  it('gives different advice for every reason — collapsing them loses the point', () => {
    const reasons = ['access_denied', 'credentials', 'throttled', 'region_unavailable', 'timeout', 'network'];
    const advice = reasons.map(failureAction);
    expect(new Set(advice).size).toBe(reasons.length);
  });

  it('falls back to something useful for an unknown reason', () => {
    expect(failureAction(undefined)).toBeTruthy();
    expect(failureAction('something-new')).toBeTruthy();
  });
});

describe('failureLine', () => {
  it('names the region, the provider code and the message', () => {
    const line = failureLine(failed.failures![0]);
    expect(line).toContain('us-east-1');
    expect(line).toContain('AccessDeniedException');
    expect(line).toContain('kms:ListKeys');
  });

  it('says "global" for a non-regional API', () => {
    expect(failureLine({ scope: 'global', code: 'AccessDenied', message: 'nope' })).toMatch(/^global —/);
  });
});

describe('runBanner', () => {
  it('asserts nothing when the run reported no verdict', () => {
    expect(runBanner(undefined, [])).toBeUndefined();
  });

  it('names the failing types on a partial run', () => {
    const b = runBanner('partial', [succeeded(4), failed])!;
    expect(b.tone).toBe('warn');
    expect(b.body.toLowerCase()).toContain('kms keys');
    expect(b.body.toLowerCase()).not.toContain('s3 buckets');
  });

  it('says an empty result means the account was not read when everything failed', () => {
    const b = runBanner('failed', [failed])!;
    expect(b.tone).toBe('danger');
    expect(b.body).toMatch(/not read/i);
  });

  it('says a zero is a real zero when everything succeeded', () => {
    const b = runBanner('complete', [succeeded(0)])!;
    expect(b.tone).toBe('ok');
    expect(b.body).toMatch(/genuinely has none/i);
  });
});

describe('resourceTypeLabel', () => {
  it('names the AWS types the Cloud modal offers', () => {
    expect(resourceTypeLabel('kms')).toBe('KMS keys');
    expect(resourceTypeLabel('s3')).toBe('S3 buckets');
    expect(resourceTypeLabel('alb')).toBe('Application load balancers');
  });

  it('degrades readably for a type it has no name for', () => {
    expect(resourceTypeLabel('some_new_type')).toBe('some new type');
  });
});

describe('hasResourceOutcomes', () => {
  it('is false for a job that reported none — absent is not "all good"', () => {
    expect(hasResourceOutcomes(undefined)).toBe(false);
    expect(hasResourceOutcomes([])).toBe(false);
    expect(hasResourceOutcomes([succeeded(1)])).toBe(true);
  });
});
