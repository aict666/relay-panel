import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Tunnel } from '../api/types';

const { mockGet, mockPut } = vi.hoisted(() => ({ mockGet: vi.fn(), mockPut: vi.fn() }));

vi.mock('../api/client', () => ({
  default: {
    get: mockGet,
    post: vi.fn(),
    put: mockPut,
    delete: vi.fn(),
  },
}));

import Tunnels from './Tunnels';

beforeEach(() => {
  mockGet.mockReset();
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
});
