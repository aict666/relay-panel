import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Tunnel } from '../api/types';

const { mockGet, mockPost, mockPut } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPost: vi.fn(),
  mockPut: vi.fn(),
}));

vi.mock('../api/client', () => ({
  default: {
    get: mockGet,
    post: mockPost,
    put: mockPut,
    delete: vi.fn(),
  },
}));

import Tunnels from './Tunnels';

beforeEach(() => {
  mockGet.mockReset();
  mockPost.mockReset();
  mockPut.mockReset();
});

const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });

const tunnel: Tunnel = {
  id: 1,
  name: 'primary-tunnel',
  enabled: true,
  shared: false,
  uid: 1,
  created_at: '2026-01-01',
  bound_rule_count: 0,
  hops: [
    { id: 1, tunnel_id: 1, position: 0, device_group_id: 1, listen_port: null, created_at: '2026-01-01', group_name: 'entry' },
    { id: 2, tunnel_id: 1, position: 1, device_group_id: 2, listen_port: 20000, created_at: '2026-01-01', group_name: 'exit' },
  ],
};

describe('Tunnels loading interaction', () => {
  it('does not allow a create mutation while an older refresh is pending', async () => {
    let resolveLoad!: (value: ReturnType<typeof ok<never[]>>) => void;
    const pendingLoad = new Promise<ReturnType<typeof ok<never[]>>>((resolve) => {
      resolveLoad = resolve;
    });
    mockGet.mockImplementation(() => pendingLoad);
    render(<Tunnels />);

    expect(await screen.findByRole('button', { name: /createTunnel/ })).toBeDisabled();
    resolveLoad(ok<never[]>([]));
    await waitFor(() => expect(screen.getByRole('button', { name: /createTunnel/ })).toBeEnabled());
  });

  it('disables refresh while a toggle mutation is pending', async () => {
    const user = userEvent.setup();
    mockGet.mockImplementation((url: string) => {
      if (url === '/admin/tunnels') return Promise.resolve(ok([tunnel]));
      if (url === '/groups') return Promise.resolve(ok([]));
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    let resolveToggle!: (value: ReturnType<typeof ok<Tunnel>>) => void;
    mockPut.mockImplementation(() => new Promise<ReturnType<typeof ok<Tunnel>>>((resolve) => {
      resolveToggle = resolve;
    }));
    render(<Tunnels />);

    await user.click(await screen.findByRole('switch'));
    await waitFor(() => expect(mockPut).toHaveBeenCalledTimes(1));
    expect(screen.getByRole('button', { name: /refresh/ })).toBeDisabled();
    resolveToggle(ok(tunnel));
    await waitFor(() => expect(screen.getByRole('button', { name: /refresh/ })).toBeEnabled());
  });

  it('keeps retained tunnels read-only when a refresh fails', async () => {
    const user = userEvent.setup();
    let failLoad = false;
    mockGet.mockImplementation((url: string) => {
      if (failLoad) return Promise.reject(new Error('network'));
      if (url === '/admin/tunnels') return Promise.resolve(ok([tunnel]));
      if (url === '/groups') return Promise.resolve(ok([]));
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    render(<Tunnels />);

    expect(await screen.findByText('primary-tunnel')).toBeInTheDocument();
    failLoad = true;
    await user.click(screen.getByRole('button', { name: /refresh/ }));

    expect(await screen.findByText('loadFailed')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /createTunnel/ })).toBeDisabled();
    expect(screen.getByRole('button', { name: /edit/ })).toBeDisabled();
    expect(screen.getByRole('switch')).toBeDisabled();
  });

  it('diagnoses a tunnel and displays its name instead of the wire id', async () => {
    const user = userEvent.setup();
    mockGet.mockImplementation((url: string) => {
      if (url === '/admin/tunnels') return Promise.resolve(ok([{ ...tunnel, bound_rule_count: 1 }]));
      if (url === '/groups') return Promise.resolve(ok([]));
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    mockPost.mockResolvedValue(ok({
      request_id: 'diagnosis-1',
      rule_id: 9,
      tunnel_id: 1,
      tunnel_name: 'primary-tunnel',
      nodes: [{
        status: 'result',
        type: 'diagnose_result',
        request_id: 'diagnosis-1',
        rule_id: 9,
        node_id: 'node-1',
        group_name: 'entry',
        listener_running: true,
        listen_port: 30000,
        protocol: 'tcp',
        transport: 'raw',
        results: [{ address: 'tunnel:1 / rule:9', outcome: { reachable: { elapsed_ms: 12 } } }],
      }],
    }));
    render(<Tunnels />);

    await user.click(await screen.findByRole('button', { name: /diagnose/ }));

    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/admin/tunnels/1/diagnose'));
    expect(await screen.findByText('tunnel:primary-tunnel / rule:9')).toBeInTheDocument();
    expect(screen.queryByText('tunnel:1 / rule:9')).not.toBeInTheDocument();
  });
});
