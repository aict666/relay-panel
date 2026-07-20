import { describe, expect, it } from 'vitest';
import type { Tunnel } from '../api/types';
import { tunnelPathChanged, tunnelPathSnapshot, tunnelScalarChanges } from './tunnels';

describe('tunnelPathSnapshot', () => {
  it('keeps allocated automatic ports for optimistic path concurrency', () => {
    const tunnel = {
      hops: [
        { device_group_id: 10, listen_port: null },
        { device_group_id: 20, listen_port: 36000 },
        { device_group_id: 30, listen_port: 36001 },
      ],
    } as Pick<Tunnel, 'hops'>;

    expect(tunnelPathSnapshot(tunnel)).toEqual([
      { device_group_id: 10, listen_port: null },
      { device_group_id: 20, listen_port: 36000 },
      { device_group_id: 30, listen_port: 36001 },
    ]);
  });
});

describe('tunnelScalarChanges', () => {
  it('does not resend unchanged stale form fields during a path replacement', () => {
    const original = { name: 'route-a', enabled: true, shared: false };
    expect(tunnelScalarChanges(original, original)).toEqual({});
    expect(tunnelScalarChanges(original, {
      name: 'route-b',
      enabled: true,
      shared: true,
    })).toEqual({ name: 'route-b', shared: true });
  });
});

describe('tunnelPathChanged', () => {
  const tunnel = {
    hops: [
      { device_group_id: 1, listen_port: null },
      { device_group_id: 2, listen_port: 35001 },
    ],
  } as Parameters<typeof tunnelPathChanged>[0];

  it('treats unchanged automatic ports as the persisted allocated ports', () => {
    expect(tunnelPathChanged(tunnel, [
      { device_group_id: 1, port_mode: 'auto' },
      { device_group_id: 2, port_mode: 'auto', listen_port: 35001 },
    ])).toBe(false);
  });

  it('detects group, order, and explicit fixed-port changes', () => {
    expect(tunnelPathChanged(tunnel, [
      { device_group_id: 1 },
      { device_group_id: 3, port_mode: 'auto' },
    ])).toBe(true);
    expect(tunnelPathChanged(tunnel, [
      { device_group_id: 1 },
      { device_group_id: 2, port_mode: 'fixed', listen_port: 35002 },
    ])).toBe(true);
  });
});
