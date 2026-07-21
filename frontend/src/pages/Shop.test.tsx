import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Plan, UserSelf } from '../api/types';

const { mockGet, mockPost } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPost: vi.fn(),
}));

vi.mock('../api/client', () => ({
  default: { get: mockGet, post: mockPost },
}));

import Shop from './Shop';

const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });

const plan: Plan = {
  id: 1,
  name: 'Starter',
  max_rules: 5,
  traffic: 1000,
  speed_limit: 0,
  ip_limit: 0,
  price: '6.00',
  purchase_revision: 'revision-1',
  created_at: '2026-01-01',
};

const me: UserSelf = {
  id: 1,
  username: 'buyer',
  admin: false,
  balance: '10.00',
  plan_id: null,
  plan_name: null,
  max_rules: 5,
  current_rules: 0,
  traffic_used: 0,
  traffic_limit: 1000,
  registered_at: '2026-01-01',
  must_change_password: false,
};

beforeEach(() => {
  mockGet.mockReset();
  mockPost.mockReset();
});

describe('Shop purchase refresh', () => {
  it('keeps purchase buttons disabled until the refreshed balance arrives', async () => {
    let refreshing = false;
    const pendingRefresh = new Promise<never>(() => {});

    mockGet.mockImplementation((url: string) => {
      if (refreshing) return pendingRefresh;
      if (url === '/plans') return Promise.resolve(ok([plan]));
      if (url === '/user/orders') return Promise.resolve(ok([]));
      if (url === '/user/me') return Promise.resolve(ok(me));
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    mockPost.mockImplementation(() => {
      refreshing = true;
      return Promise.resolve(ok(null));
    });

    render(<Shop />);

    const buyButton = await screen.findByRole('button', { name: 'buyNow' });
    expect(buyButton).toBeEnabled();
    fireEvent.click(buyButton);
    fireEvent.click(await screen.findByRole('button', { name: 'confirmPurchase' }));

    await waitFor(() => expect(mockPost).toHaveBeenCalledTimes(1));
    expect(mockPost).toHaveBeenCalledWith('/user/buy-plan', {
      plan_id: 1,
      expected_price: '6.00',
      expected_revision: 'revision-1',
    });
    await waitFor(() => expect(screen.getByRole('button', { name: 'buyNow' })).toBeDisabled());
  });

  it('refreshes an open confirmation to the current price', async () => {
    let currentPlan = plan;
    mockGet.mockImplementation((url: string) => {
      if (url === '/plans') return Promise.resolve(ok([currentPlan]));
      if (url === '/user/orders') return Promise.resolve(ok([]));
      if (url === '/user/me') return Promise.resolve(ok(me));
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    render(<Shop />);

    fireEvent.click(await screen.findByRole('button', { name: 'buyNow' }));
    let dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('6.00')).toBeInTheDocument();

    currentPlan = { ...plan, price: '12.00' };
    fireEvent.click(screen.getByRole('button', { name: /refresh/ }));

    dialog = await screen.findByRole('dialog');
    expect(await within(dialog).findByText('12.00')).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: 'confirmPurchase' })).toBeDisabled();
    expect(within(dialog).getByText('insufficientBalance')).toBeInTheDocument();
  });

  it('reloads the confirmation after the server rejects a stale plan snapshot', async () => {
    let currentPlan = plan;
    mockGet.mockImplementation((url: string) => {
      if (url === '/plans') return Promise.resolve(ok([currentPlan]));
      if (url === '/user/orders') return Promise.resolve(ok([]));
      if (url === '/user/me') return Promise.resolve(ok(me));
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    mockPost.mockImplementation(() => {
      currentPlan = { ...plan, price: '12.00' };
      return Promise.resolve({ code: 409, message: 'plan changed', data: null });
    });
    render(<Shop />);

    fireEvent.click(await screen.findByRole('button', { name: 'buyNow' }));
    let dialog = await screen.findByRole('dialog');
    fireEvent.click(within(dialog).getByRole('button', { name: 'confirmPurchase' }));

    dialog = await screen.findByRole('dialog');
    expect(await within(dialog).findByText('12.00')).toBeInTheDocument();
    expect(mockGet.mock.calls.filter(([url]) => url === '/plans')).toHaveLength(2);
  });
});
