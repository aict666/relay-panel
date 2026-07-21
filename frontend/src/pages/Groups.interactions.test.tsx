import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { DeviceGroup } from '../api/types';

const { authState, mockGet, mockPut } = vi.hoisted(() => ({
  authState: {
    isAdmin: false,
    user: { id: 2, username: 'member' },
  },
  mockGet: vi.fn(),
  mockPut: vi.fn(),
}));

vi.mock('../api/client', () => ({
  default: {
    get: mockGet,
    post: vi.fn(),
    put: mockPut,
    delete: vi.fn(),
  },
}));

vi.mock('../auth/useAuth', () => ({
  useAuth: () => authState,
}));

// Ant Design's global message API mounts a detached React root. The update
// interaction only needs to verify the request payload; leaving that root's
// scheduled render alive can race Vitest's jsdom teardown on slower CI runners
// and surface as `window is not defined` after every assertion has passed.
vi.mock('antd', async (importOriginal) => {
  const actual = await importOriginal<typeof import('antd')>();
  return {
    ...actual,
    message: {
      ...actual.message,
      success: vi.fn(),
      error: vi.fn(),
    },
  };
});

import Groups from './Groups';

const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((next) => { resolve = next; });
  return { promise, resolve };
}

const group: DeviceGroup = {
  id: 1,
  name: 'member-group',
  group_type: 'in',
  token: 'a-token-long-enough-for-copy',
  uid: 2,
  connect_host: 'group.example.com',
  port_range: '10000-65535',
  fallback_group: null,
  config: '{}',
  blocked_protocols: ['http', 'tls'],
  rate: 1,
  created_at: '2026-01-01',
};

beforeEach(() => {
  mockGet.mockReset();
  mockPut.mockReset();
  mockPut.mockResolvedValue(ok(null));
  authState.isAdmin = false;
  authState.user = { id: 2, username: 'member' };
  mockGet.mockImplementation((url: string) => {
    if (url === '/groups/owned') {
      return Promise.resolve(ok([{
        id: group.id,
        name: group.name,
        group_type: group.group_type,
        connect_host: group.connect_host,
        capabilities: '[]',
        region: null,
        line_type: null,
        blocked_protocols: ['http', 'tls'],
      }]));
    }
    return Promise.reject(new Error(`unexpected ${url}`));
  });
});

describe('Groups permissions', () => {
  it('keeps a regular user view read-only and does not request the admin user catalog', async () => {
    render(<Groups />);

    expect(await screen.findByText('member-group')).toBeInTheDocument();
    expect(screen.getByText('httpBlocked')).toBeInTheDocument();
    expect(screen.getByText('tlsBlocked')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /addGroup/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /edit/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /delete/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'copyInstallCommand' })).not.toBeInTheDocument();
    await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(1));
    expect(mockGet).not.toHaveBeenCalledWith('/admin/users');
    expect(mockGet).not.toHaveBeenCalledWith('/nodes/shared');
  });

  it('lets an administrator clear TLS while retaining the HTTP policy', async () => {
    authState.isAdmin = true;
    const user = userEvent.setup();
    mockGet.mockImplementation((url: string) => {
      if (url === '/groups') return Promise.resolve(ok([group]));
      if (url === '/nodes') return Promise.resolve(ok([{
        group_id: group.id,
        online: true,
        blocked_protocol_connections: { http: 3, tls: 7 },
      }]));
      return Promise.reject(new Error(`unexpected ${url}`));
    });

    render(<Groups />);
    expect(await screen.findByText('7')).toBeInTheDocument();
    await user.click(await screen.findByRole('button', { name: /edit/ }));
    await user.click(await screen.findByRole('checkbox', { name: 'TLS', checked: true }));
    await user.click(screen.getByRole('button', { name: /save/ }));

    await waitFor(() => expect(mockPut).toHaveBeenCalledWith('/groups/1', {
      blocked_protocols: ['http'],
    }));
    await waitFor(() => {
      expect(mockGet.mock.calls.filter(([url]) => url === '/groups')).toHaveLength(2);
    });
  });

  it('does not reopen an old install command after the authenticated account changes', async () => {
    authState.isAdmin = true;
    const user = userEvent.setup();
    const version = deferred<{ public_panel_url: string }>();
    mockGet.mockImplementation((url: string) => {
      if (url === '/groups') return Promise.resolve(ok([group]));
      if (url === '/nodes') return Promise.resolve(ok([]));
      if (url === '/system/version') return version.promise;
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    const view = render(<Groups />);

    await user.click(await screen.findByRole('button', { name: 'copyInstallCommand' }));
    await waitFor(() => expect(mockGet).toHaveBeenCalledWith('/system/version'));

    authState.user = { id: 3, username: 'next-member' };
    view.rerender(<Groups />);
    await waitFor(() => {
      expect(mockGet.mock.calls.filter(([url]) => url === '/groups')).toHaveLength(2);
    });
    version.resolve({ public_panel_url: 'https://panel.example.com' });

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });
});
