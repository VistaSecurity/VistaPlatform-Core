import { describe, expect, it } from 'vitest';
import type { adminServiceComponents } from '@vistasecurity/api-contract';
import { changedPriceFields } from './plan-builder';

type SubscriptionTier = adminServiceComponents['schemas']['SubscriptionTier'];

const tier = {
  price_cents: 1200,
  annual_price_cents: 12000,
} as SubscriptionTier;

describe('changedPriceFields', () => {
  it('omits unchanged prices so an ordinary save does not re-price in Stripe', () => {
    expect(changedPriceFields(tier, 1200, 12000)).toEqual({});
  });

  it('sends only prices that actually changed', () => {
    expect(changedPriceFields(tier, 1300, 12000)).toEqual({ price_cents: 1300 });
    expect(changedPriceFields(tier, 1200, 12500)).toEqual({ annual_price_cents: 12500 });
  });
});
