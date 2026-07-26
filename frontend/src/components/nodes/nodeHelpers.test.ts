import { describe, expect, it } from 'vitest';
import { usageColor } from './NodeResourceBar';
import { CONNECTION_ANOMALY_BPS, hasConnectionCountAnomaly } from './shared';

// Colors track the theme palette (styles/theme.css): healthy = brand teal,
// warning = amber, critical = red.
describe('usageColor', () => {
  it('is teal below the 70% warning threshold', () => {
    expect(usageColor(0)).toBe('#0d9488');
    expect(usageColor(69)).toBe('#0d9488');
  });

  it('is amber in the 70–89% band', () => {
    expect(usageColor(70)).toBe('#d97706');
    expect(usageColor(89)).toBe('#d97706');
  });

  it('is red at or above 90%', () => {
    expect(usageColor(90)).toBe('#dc2626');
    expect(usageColor(100)).toBe('#dc2626');
  });
});

describe('hasConnectionCountAnomaly', () => {
  it('is true for online nodes with zero connections and sustained NIC rate', () => {
    expect(hasConnectionCountAnomaly({
      online: true,
      connections: 0,
      upload_bps: CONNECTION_ANOMALY_BPS,
      download_bps: 0,
    })).toBe(true);
  });

  it('is false when connections are reported', () => {
    expect(hasConnectionCountAnomaly({
      online: true,
      connections: 3,
      upload_bps: 50_000,
      download_bps: 50_000,
    })).toBe(false);
  });

  it('is false for offline nodes even with residual rates', () => {
    expect(hasConnectionCountAnomaly({
      online: false,
      connections: 0,
      upload_bps: 50_000,
      download_bps: 50_000,
    })).toBe(false);
  });

  it('is false below the rate threshold (idle chatter)', () => {
    expect(hasConnectionCountAnomaly({
      online: true,
      connections: 0,
      upload_bps: CONNECTION_ANOMALY_BPS - 1,
      download_bps: 0,
    })).toBe(false);
  });
});
