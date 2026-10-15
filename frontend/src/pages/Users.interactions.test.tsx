import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Plan, User } from '../api/types';

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

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ isAdmin: true }),
}));

import Users from './Users';

const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });

const account: User = {
  id: 2,
  username: 'buyer',
  balance: '10.00',
  plan_id: null,
  all_device_groups: false,
  max_rules: 5,
  speed_limit: 0,
  ip_limit: 0,
  traffic_used: 0,
  traffic_limit: 1024,
  admin: false,
  banned: false,
  suspended: false,
  created_at: '2026-01-01',
};

const plan: Plan = {
  id: 1,
  name: 'Starter',
  max_rules: 5,
  traffic: 1024,
  speed_limit: 0,
  ip_limit: 0,
  price: '6.00',
  purchase_revision: 'revision-1',
  plan_type: 'data',
  created_at: '2026-01-01',
};

let failLoads = false;

beforeEach(() => {
  sessionStorage.clear();
  failLoads = false;
  mockGet.mockReset();
  mockPost.mockReset();
  mockPut.mockReset();
  mockPut.mockResolvedValue(ok(null));
  mockGet.mockImplementation((url: string) => {
    if (failLoads) return Promise.reject(new Error('refresh failed'));
    if (url === '/admin/users') return Promise.resolve(ok([account]));
    if (url === '/admin/plans') return Promise.resolve(ok([plan]));
    return Promise.reject(new Error(`unexpected ${url}`));
  });
});

describe('Users mutation locking', () => {
  it('includes the original balance only when the balance is deliberately changed', async () => {
    const user = userEvent.setup();
    render(<MemoryRouter><Users /></MemoryRouter>);
    await user.click(await screen.findByRole('button', { name: /edit/ }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.change(within(dialog).getByRole('spinbutton', { name: /balance/ }), { target: { value: '25.00' } });
    await user.click(within(dialog).getByRole('button', { name: 'save' }));
    await waitFor(() => expect(mockPut).toHaveBeenCalledTimes(1));
    expect(mockPut.mock.calls[0][1]).toMatchObject({ balance: '25', expected_balance: '10.00' });
  });

  it('does not resubmit an unchanged balance with ordinary user edits', async () => {
    const user = userEvent.setup();
    render(<MemoryRouter><Users /></MemoryRouter>);
    await user.click(await screen.findByRole('button', { name: /edit/ }));
    const dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('button', { name: 'save' }));
    await waitFor(() => expect(mockPut).toHaveBeenCalledTimes(1));
    const payload = mockPut.mock.calls[0][1];
    expect(payload).not.toHaveProperty('balance');
    expect(payload).not.toHaveProperty('expected_balance');
  });

  it('keeps stale user data read-only after a refresh failure', async () => {
    const user = userEvent.setup();
    render(<MemoryRouter><Users /></MemoryRouter>);

    expect(await screen.findByText('buyer')).toBeInTheDocument();
    failLoads = true;
    await user.click(screen.getByRole('button', { name: /refresh/ }));

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /addUser/ })).toBeDisabled();
      expect(screen.getByRole('button', { name: /edit/ })).toBeDisabled();
    });
    expect(screen.getByText('loadFailed')).toBeInTheDocument();
  });

  it('locks the main edit modal while a plan purchase is running', async () => {
    const user = userEvent.setup();
    mockPost.mockImplementation(() => new Promise(() => {}));
    render(<MemoryRouter><Users /></MemoryRouter>);

    await user.click(await screen.findByRole('button', { name: /edit/ }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.mouseDown(within(dialog).getByRole('combobox'));
    fireEvent.click(await screen.findByText(/Starter · 6\.00/));
    await user.click(within(dialog).getByRole('button', { name: 'assignAndCharge' }));

    await waitFor(() => expect(mockPost).toHaveBeenCalledTimes(1));
    expect(mockPost).toHaveBeenCalledWith('/admin/users/2/buy-plan', {
      request_id: expect.any(String),
      plan_id: 1,
      expected_current_plan_id: 0,
      expected_price: '6.00',
      expected_revision: 'revision-1',
    });
    expect(within(dialog).getByRole('button', { name: 'save' })).toBeDisabled();
    expect(within(dialog).getByRole('button', { name: 'cancel' })).toBeDisabled();
    expect(within(dialog).queryByRole('button', { name: 'Close' })).not.toBeInTheDocument();
  });
});
