import { describe, expect, it } from 'vitest';
import { usageColor } from './NodeResourceBar';

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
