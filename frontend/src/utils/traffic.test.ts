import { describe, expect, it } from 'vitest';
import {
  BYTES_PER_GB,
  MAX_SAFE_TRAFFIC_GB,
  bytesToGb,
  gbToBytes,
  trafficGbChanged,
} from './traffic';

describe('traffic form conversions', () => {
  it('does not mark an unchanged rounded display value as an edit', () => {
    const exactBytes = BYTES_PER_GB + 123_456;
    expect(bytesToGb(exactBytes)).toBe(1);
    expect(gbToBytes(bytesToGb(exactBytes))).not.toBe(exactBytes);
    expect(trafficGbChanged(exactBytes, 1)).toBe(false);
  });

  it('detects an explicit GB change', () => {
    expect(trafficGbChanged(2 * BYTES_PER_GB, 3)).toBe(true);
  });

  it('keeps the advertised maximum in the exact integer range', () => {
    expect(gbToBytes(MAX_SAFE_TRAFFIC_GB)).toBeLessThanOrEqual(Number.MAX_SAFE_INTEGER);
  });
});
