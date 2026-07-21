import { describe, expect, it } from 'vitest';
import { mapWithConcurrency } from './async';

describe('mapWithConcurrency', () => {
  it('preserves result order and never exceeds the worker limit', async () => {
    let active = 0;
    let peak = 0;
    const results = await mapWithConcurrency([5, 4, 3, 2, 1], 2, async (value) => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, value));
      active -= 1;
      return value * 10;
    });

    expect(results).toEqual([50, 40, 30, 20, 10]);
    expect(peak).toBe(2);
  });

  it('rejects an invalid concurrency value', async () => {
    await expect(mapWithConcurrency([1], 0, async (value) => value)).rejects.toThrow(RangeError);
  });
});
