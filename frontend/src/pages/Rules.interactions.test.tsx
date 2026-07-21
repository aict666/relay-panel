import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useNavigate } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { DeviceGroup, DiagnoseResponse, ForwardRule, Tunnel } from '../api/types';

const { mockGet, mockPost, mockPut, authState } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPost: vi.fn(),
  mockPut: vi.fn(),
  authState: {
    isAdmin: true,
    user: { id: 1, username: 'admin' },
  },
}));

vi.mock('../api/client', () => ({
  default: {
    get: mockGet,
    post: mockPost,
    put: mockPut,
    delete: vi.fn(),
  },
}));

vi.mock('../auth/useAuth', () => ({
  useAuth: () => authState,
}));

import Rules from './Rules';

const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((next) => { resolve = next; });
  return { promise, resolve };
}

function OwnerSwitchHarness() {
  const navigate = useNavigate();
  return (
    <>
      <button onClick={() => navigate('/rules?owner_uid=3')}>switch-owner</button>
      <Rules />
    </>
  );
}

const group: DeviceGroup = {
  id: 1,
  name: 'group-one',
  token: 'token',
  uid: 1,
  connect_host: 'group.example.com',
  group_type: 'in',
  port_range: '10000-65535',
  fallback_group: null,
  config: '{}',
  rate: 1,
  created_at: '2026-01-01',
};

const makeRule = (overrides: Partial<ForwardRule> = {}): ForwardRule => ({
  id: 1,
  name: 'alpha-rule',
  uid: 1,
  paused: false,
  listen_port: 30001,
  protocol: 'tcp',
  route_mode: 'direct',
  device_group_in: 1,
  device_group_out: null,
  forward_mode: 'direct',
  target_addr: '1.2.3.4',
  target_port: 8080,
  max_connections: 17,
  auto_restart_minutes: 30,
  config: '{}',
  traffic_used: 0,
  status: 'active',
  created_at: '2026-01-01',
  ...overrides,
});

let rules: ForwardRule[];

beforeEach(() => {
  mockGet.mockReset();
  mockPost.mockReset();
  mockPut.mockReset();
  authState.isAdmin = true;
  authState.user = { id: 1, username: 'admin' };
  rules = [];
  mockGet.mockImplementation((url: string) => {
    if (url === '/rules?owner_uid=1') return Promise.resolve(ok(rules));
    if (url === '/groups') return Promise.resolve(ok([group]));
    if (url === '/tunnels') return Promise.resolve(ok([]));
    if (url === '/admin/users') return Promise.resolve(ok([]));
    return Promise.reject(new Error(`unexpected ${url}`));
  });
});

describe('Rules import interaction', () => {
  it('shows the HTTP and TLS policies on a shared preset tunnel entry', async () => {
    authState.isAdmin = false;
    authState.user = { id: 2, username: 'member' };
    const user = userEvent.setup();
    const sharedEntry = { ...group, blocked_protocols: ['http', 'tls'] as const };
    const tunnel: Tunnel = {
      id: 77,
      name: 'shared-path',
      enabled: true,
      shared: true,
      uid: 1,
      created_at: '2026-01-01',
      bound_rule_count: 0,
      hops: [{
        id: 701,
        tunnel_id: 77,
        position: 0,
        device_group_id: sharedEntry.id,
        listen_port: null,
        created_at: '2026-01-01',
        group_name: sharedEntry.name,
      }],
    };
    mockGet.mockImplementation((url: string) => {
      if (url === '/rules') return Promise.resolve(ok([]));
      if (url === '/tunnels') return Promise.resolve(ok([tunnel]));
      if (url === '/groups/shared') return Promise.resolve(ok([sharedEntry]));
      if (url === '/user/me') return Promise.resolve(ok(null));
      return Promise.reject(new Error(`unexpected ${url}`));
    });

    render(<MemoryRouter><Rules /></MemoryRouter>);
    await user.click(await screen.findByRole('button', { name: /addRule/ }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.mouseDown(within(dialog).getByLabelText('forwardMode'));
    const presetOptions = await screen.findAllByText('modePresetTunnel');
    await user.click(presetOptions[presetOptions.length - 1]);
    expect(within(dialog).queryByText('tunnelSelectHint')).not.toBeInTheDocument();

    fireEvent.mouseDown(within(dialog).getByLabelText('modePresetTunnel'));
    const tunnelOption = await screen.findByText(/shared-path/);
    expect(tunnelOption).toBeInTheDocument();
    expect(await screen.findByText('httpBlocked')).toBeInTheDocument();
    expect(await screen.findByText('tlsBlocked')).toBeInTheDocument();

    await user.click(tunnelOption);
    expect(within(dialog).queryByText('tunnelPortsReused')).not.toBeInTheDocument();
  });

  it('cannot be closed or edited while sequential imports are running', async () => {
    const user = userEvent.setup();
    mockPost.mockImplementation(() => new Promise(() => {}));
    render(<MemoryRouter><Rules /></MemoryRouter>);

    await user.click(await screen.findByRole('button', { name: /exportImport/ }));
    await user.click(await screen.findByRole('menuitem', { name: /import/ }));

    const dialog = await screen.findByRole('dialog');
    const combo = within(dialog).getByRole('combobox');
    fireEvent.mouseDown(combo);
    fireEvent.click(await screen.findByText('group-one (#1)'));

    const input = within(dialog).getByRole('textbox');
    fireEvent.change(input, {
      target: {
        value: '[{"dest":["1.2.3.4:8080"],"listen_port":30000,"name":"rule-one"}]',
      },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'import' }));

    await waitFor(() => expect(mockPost).toHaveBeenCalledTimes(1));
    expect(within(dialog).getByRole('button', { name: 'cancel' })).toBeDisabled();
    expect(within(dialog).getByRole('textbox')).toBeDisabled();
    expect(within(dialog).queryByRole('button', { name: 'Close' })).not.toBeInTheDocument();
  });

  it('drops selections that are no longer visible after a refresh', async () => {
    const user = userEvent.setup();
    rules = [makeRule()];
    render(<MemoryRouter><Rules /></MemoryRouter>);

    await user.type(await screen.findByRole('textbox', { name: 'searchRules' }), 'alpha');
    await user.click(await screen.findByRole('checkbox', { name: 'select #1' }));
    expect(await screen.findByRole('button', { name: /selectedCount/ })).toBeInTheDocument();

    rules = [makeRule({ name: 'beta-rule' })];
    await user.click(screen.getByRole('button', { name: /refresh/ }));

    await waitFor(() => {
      expect(screen.queryByRole('button', { name: /selectedCount/ })).not.toBeInTheDocument();
    });
  });

  it('resets stale create values and copies connection controls', async () => {
    const user = userEvent.setup();
    rules = [makeRule()];
    render(<MemoryRouter><Rules /></MemoryRouter>);

    await user.click(await screen.findByRole('button', { name: /addRule/ }));
    let dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('tab', { name: 'tabForward' }));
    fireEvent.change(within(dialog).getByLabelText('maxConnections'), { target: { value: '99' } });
    fireEvent.change(within(dialog).getByLabelText('autoRestart'), { target: { value: '60' } });
    await user.click(within(dialog).getByRole('button', { name: 'cancel' }));

    await user.click(await screen.findByRole('button', { name: 'action' }));
    await user.click(await screen.findByRole('menuitem', { name: /copy/ }));
    dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('tab', { name: 'tabForward' }));

    expect(within(dialog).getByLabelText('maxConnections')).toHaveValue('17');
    expect(within(dialog).getByLabelText('autoRestart')).toHaveValue('30');
  });

  it('ignores an older owner response after the URL switches to another user', async () => {
    const user = userEvent.setup();
    const ownerTwo = deferred<{ code: number; message: string; data: ForwardRule[] }>();
    const ownerThree = deferred<{ code: number; message: string; data: ForwardRule[] }>();
    mockGet.mockImplementation((url: string) => {
      if (url === '/rules?owner_uid=2') return ownerTwo.promise;
      if (url === '/rules?owner_uid=3') return ownerThree.promise;
      if (url === '/groups') return Promise.resolve(ok([group]));
      if (url === '/tunnels') return Promise.resolve(ok([]));
      if (url === '/admin/users') return Promise.resolve(ok([]));
      return Promise.reject(new Error(`unexpected ${url}`));
    });

    render(<MemoryRouter initialEntries={['/rules?owner_uid=2']}><OwnerSwitchHarness /></MemoryRouter>);
    await waitFor(() => expect(mockGet).toHaveBeenCalledWith('/rules?owner_uid=2'));
    await user.click(screen.getByRole('button', { name: 'switch-owner' }));
    await waitFor(() => expect(mockGet).toHaveBeenCalledWith('/rules?owner_uid=3'));

    ownerThree.resolve(ok([makeRule({ id: 3, uid: 3, name: 'new-owner-rule' })]));
    expect(await screen.findByText('new-owner-rule')).toBeInTheDocument();

    ownerTwo.resolve(ok([makeRule({ id: 2, uid: 2, name: 'old-owner-rule' })]));
    await waitFor(() => {
      expect(mockGet.mock.calls.filter(([url]) => url === '/admin/users')).toHaveLength(2);
    });
    expect(screen.queryByText('old-owner-rule')).not.toBeInTheDocument();
    expect(screen.getByText('new-owner-rule')).toBeInTheDocument();
  });

  it('keeps retained rows read-only when a refresh fails', async () => {
    const user = userEvent.setup();
    let failRulesLoad = false;
    rules = [makeRule()];
    mockGet.mockImplementation((url: string) => {
      if (url === '/rules?owner_uid=1') {
        return failRulesLoad ? Promise.reject(new Error('network')) : Promise.resolve(ok(rules));
      }
      if (url === '/groups') return Promise.resolve(ok([group]));
      if (url === '/tunnels') return Promise.resolve(ok([]));
      if (url === '/admin/users') return Promise.resolve(ok([]));
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    render(<MemoryRouter><Rules /></MemoryRouter>);

    expect(await screen.findByText('alpha-rule')).toBeInTheDocument();
    failRulesLoad = true;
    await user.click(screen.getByRole('button', { name: /refresh/ }));

    expect(await screen.findByText('loadFailed')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /addRule/ })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'action' })).toBeDisabled();
    expect(screen.getByRole('checkbox', { name: 'select #1' })).toBeDisabled();
  });

  it('does not let a completed mutation reload the previous owner after navigation', async () => {
    const user = userEvent.setup();
    const update = deferred<{ code: number; message: string; data: null }>();
    mockPut.mockReturnValue(update.promise);
    mockGet.mockImplementation((url: string) => {
      if (url === '/rules?owner_uid=2') return Promise.resolve(ok([makeRule({ id: 2, uid: 2, name: 'old-owner-rule' })]));
      if (url === '/rules?owner_uid=3') return Promise.resolve(ok([makeRule({ id: 3, uid: 3, name: 'new-owner-rule' })]));
      if (url === '/groups') return Promise.resolve(ok([group]));
      if (url === '/tunnels') return Promise.resolve(ok([]));
      if (url === '/admin/users') return Promise.resolve(ok([]));
      return Promise.reject(new Error(`unexpected ${url}`));
    });

    render(<MemoryRouter initialEntries={['/rules?owner_uid=2']}><OwnerSwitchHarness /></MemoryRouter>);
    expect(await screen.findByText('old-owner-rule')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /pause/ }));
    await waitFor(() => expect(mockPut).toHaveBeenCalledTimes(1));

    await user.click(screen.getByRole('button', { name: 'switch-owner' }));
    expect(await screen.findByText('new-owner-rule')).toBeInTheDocument();
    update.resolve(ok(null));
    await waitFor(() => expect(screen.getByRole('button', { name: 'action' })).toBeEnabled());

    expect(mockGet.mock.calls.filter(([url]) => url === '/rules?owner_uid=2')).toHaveLength(1);
    expect(screen.queryByText('old-owner-rule')).not.toBeInTheDocument();
  });

  it('reloads auth-scoped data when one regular account is replaced by another', async () => {
    authState.isAdmin = false;
    authState.user = { id: 2, username: 'first' };
    mockGet.mockImplementation((url: string) => {
      if (url === '/rules') {
        const id = authState.user.id;
        return Promise.resolve(ok([makeRule({ id, uid: id, name: id === 2 ? 'first-account-rule' : 'second-account-rule' })]));
      }
      if (url === '/groups') return Promise.resolve(ok([]));
      if (url === '/tunnels') return Promise.resolve(ok([]));
      if (url === '/groups/shared') return Promise.resolve(ok([group]));
      if (url === '/user/me') return Promise.resolve(ok(null));
      return Promise.reject(new Error(`unexpected ${url}`));
    });

    const view = render(<MemoryRouter><Rules /></MemoryRouter>);
    expect(await screen.findByText('first-account-rule')).toBeInTheDocument();

    authState.user = { id: 3, username: 'second' };
    view.rerender(<MemoryRouter><Rules /></MemoryRouter>);

    expect(await screen.findByText('second-account-rule')).toBeInTheDocument();
    expect(screen.queryByText('first-account-rule')).not.toBeInTheDocument();
    expect(mockGet.mock.calls.filter(([url]) => url === '/rules')).toHaveLength(2);
  });

  it('does not show a completed diagnosis from the previous owner scope', async () => {
    const user = userEvent.setup();
    const oldDiagnosis = deferred<{ code: number; message: string; data: DiagnoseResponse }>();
    mockGet.mockImplementation((url: string) => {
      if (url === '/rules?owner_uid=2') return Promise.resolve(ok([makeRule({ id: 2, uid: 2, name: 'old-owner-rule' })]));
      if (url === '/rules?owner_uid=3') return Promise.resolve(ok([makeRule({ id: 3, uid: 3, name: 'new-owner-rule' })]));
      if (url === '/groups') return Promise.resolve(ok([group]));
      if (url === '/tunnels') return Promise.resolve(ok([]));
      if (url === '/admin/users') return Promise.resolve(ok([]));
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    mockPost.mockImplementation((url: string) => {
      if (url === '/rules/2/diagnose') return oldDiagnosis.promise;
      if (url === '/rules/3/diagnose') {
        return Promise.resolve(ok<DiagnoseResponse>({
          request_id: 'new',
          rule_id: 3,
          nodes: [{ status: 'timeout', node_id: 'new-node', group_name: 'new-diagnosis-group' }],
        }));
      }
      return Promise.reject(new Error(`unexpected ${url}`));
    });

    render(<MemoryRouter initialEntries={['/rules?owner_uid=2']}><OwnerSwitchHarness /></MemoryRouter>);
    expect(await screen.findByText('old-owner-rule')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'action' }));
    await user.click(await screen.findByRole('menuitem', { name: /diagnose/ }));
    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/rules/2/diagnose'));

    await user.click(screen.getByRole('button', { name: 'switch-owner' }));
    expect(await screen.findByText('new-owner-rule')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'action' }));
    await user.click(await screen.findByRole('menuitem', { name: /diagnose/ }));
    expect(await screen.findByText(/new-diagnosis-group/)).toBeInTheDocument();

    oldDiagnosis.resolve(ok<DiagnoseResponse>({
      request_id: 'old',
      rule_id: 2,
      nodes: [{ status: 'timeout', node_id: 'old-node', group_name: 'old-diagnosis-group' }],
    }));
    await waitFor(() => expect(screen.queryByText(/old-diagnosis-group/)).not.toBeInTheDocument());
    expect(screen.getByText(/new-diagnosis-group/)).toBeInTheDocument();
  });
});
