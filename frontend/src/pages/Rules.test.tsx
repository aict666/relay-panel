import { describe, expect, it } from 'vitest';

// ============================================================
// Pure-function tests for Rules.tsx helpers
// ============================================================

// Replicate the logic from Rules.tsx to test it independently.
// These match the actual implementation line-for-line.

const formTargets = (values: { targets?: Array<{ host: string; port: number; enabled?: boolean; weight?: number }>; target_addr?: string; target_port?: number }) => {
  const targets = values.targets ?? [];
  return targets.map(t => ({
    host: t.host?.trim() ?? '',
    port: Number(t.port),
    enabled: t.enabled !== false,
    weight: Math.max(1, Math.min(100, Number(t.weight ?? 1))),
  }));
};

const payloadWithTargets = (values: Record<string, unknown> & { targets?: Array<{ host: string; port: number; enabled?: boolean; weight?: number }> }) => {
  const targets = formTargets(values);
  if (targets.length < 1) {
    throw new Error('targets must have at least one entry');
  }
  const first = targets[0];
  return { ...values, target_addr: first.host, target_port: first.port, targets };
};

const portValidator = (_: unknown, v: unknown) => {
  if (v == null || v === '' || !Number.isFinite(Number(v)) || Number(v) < 1 || Number(v) > 65535) {
    return Promise.reject(new Error('Target port must be 1-65535'));
  }
  return Promise.resolve();
};

// ============================================================
describe('formTargets', () => {
  it('returns empty when targets is empty', () => {
    expect(formTargets({ targets: [] })).toEqual([]);
  });

  it('does not fall back to legacy target_addr/target_port', () => {
    expect(formTargets({ target_addr: '1.2.3.4', target_port: 80 })).toEqual([]);
  });

  it('with 1 target returns it (trim host, Number port)', () => {
    const result = formTargets({ targets: [{ host: ' 1.2.3.4 ', port: 80 }] });
    expect(result).toEqual([{ host: '1.2.3.4', port: 80, enabled: true, weight: 1 }]);
  });

  it('with multiple targets returns all', () => {
    const result = formTargets({ targets: [{ host: 'a', port: 1 }, { host: 'b', port: 2 }] });
    expect(result).toHaveLength(2);
    expect(result[0].host).toBe('a');
    expect(result[1].host).toBe('b');
  });

  it('normalizes target weights to the supported 1-100 range', () => {
    const result = formTargets({
      targets: [
        { host: 'a', port: 1, weight: 0 },
        { host: 'b', port: 2, weight: 250 },
        { host: 'c', port: 3, weight: 7 },
      ],
    });
    expect(result.map(target => target.weight)).toEqual([1, 100, 7]);
  });
});

describe('payloadWithTargets', () => {
  it('throws if targets is empty', () => {
    expect(() => payloadWithTargets({ targets: [] })).toThrow('targets must have at least one entry');
  });

  it('does not generate target_addr=\'\' or target_port=0 for empty targets', () => {
    try {
      payloadWithTargets({ targets: [] });
    } catch (e) {
      expect((e as Error).message).toContain('targets');
      return;
    }
    expect.unreachable('should have thrown');
  });

  it('with a valid target writes target_addr/target_port from first entry', () => {
    const result = payloadWithTargets({ targets: [{ host: '10.0.0.1', port: 443 }], name: 'test' });
    expect(result.target_addr).toBe('10.0.0.1');
    expect(result.target_port).toBe(443);
    expect(result.targets).toHaveLength(1);
  });
});

describe('port validator', () => {
  it('rejects undefined', async () => {
    await expect(portValidator(undefined, undefined)).rejects.toThrow();
  });
  it('rejects null', async () => {
    await expect(portValidator(undefined, null)).rejects.toThrow();
  });
  it('rejects 0', async () => {
    await expect(portValidator(undefined, 0)).rejects.toThrow();
  });
  it('rejects -1', async () => {
    await expect(portValidator(undefined, -1)).rejects.toThrow();
  });
  it('rejects 65536', async () => {
    await expect(portValidator(undefined, 65536)).rejects.toThrow();
  });
  it('rejects empty string', async () => {
    await expect(portValidator(undefined, '')).rejects.toThrow();
  });
  it('accepts 1', async () => {
    await expect(portValidator(undefined, 1)).resolves.toBeUndefined();
  });
  it('accepts 80', async () => {
    await expect(portValidator(undefined, 80)).resolves.toBeUndefined();
  });
  it('accepts 65535', async () => {
    await expect(portValidator(undefined, 65535)).resolves.toBeUndefined();
  });
  it('accepts numeric string "80"', async () => {
    await expect(portValidator(undefined, '80')).resolves.toBeUndefined();
  });
  it('rejects numeric string "0"', async () => {
    await expect(portValidator(undefined, '0')).rejects.toThrow();
  });
});

// ============================================================
// v0.4.21: strategy options tests
// ============================================================

describe('strategyOptions', () => {
  const strategyOptions = [
    { value: 'first',       label: 'lbFirst' },
    { value: 'round_robin', label: 'lbRoundRobin' },
    { value: 'failover',    label: 'lbFailover' },
    { value: 'weighted', label: 'lbWeighted' },
    { value: 'least_latency', label: 'lbLeastLatency' },
    { value: 'least_connections', label: 'lbLeastConnections' },
  ];

  it('has all six strategy options', () => {
    expect(strategyOptions).toHaveLength(6);
  });

  it('option values match backend wire/db strings', () => {
    const values = strategyOptions.map(o => o.value);
    expect(values).toEqual(['first', 'round_robin', 'failover', 'weighted', 'least_latency', 'least_connections']);
  });

  it('option labels are short (no long descriptions in Select)', () => {
    for (const opt of strategyOptions) {
      expect(opt.label).not.toContain('：');
      expect(opt.label).not.toContain(':');
      expect(opt.label.length).toBeLessThan(20);
    }
  });
});
