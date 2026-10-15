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
  sessionStorage.clear();
  mockGet.mockReset();
  mockPost.mockReset();
});

describe('Shop purchase refresh', () => {
  it('distinguishes prepaid orders and displays the purchased UTC period', async () => {
    mockGet.mockImplementation((url: string) => Promise.resolve(ok(url === '/plans' ? [] : url === '/user/me' ? me : [{
      id: 7, plan_name: 'Paid snapshot', price: '6', kind: 'prepayment',
      cycle_start: '2026-11-01 00:00:00', cycle_end: '2026-12-01 00:00:00', created_at: '2026-10-15 00:00:00',
    }])));
    render(<Shop />);
    expect(await screen.findByText('billingPrepayment')).toBeInTheDocument();
    expect(screen.getByText('2026-11-01 00:00:00 UTC')).toBeInTheDocument();
    expect(screen.getByText('→ 2026-12-01 00:00:00 UTC')).toBeInTheDocument();
    expect(screen.queryByText('prepayment')).not.toBeInTheDocument();
  });

  it('replays the same transaction after a lost response and remount, even with a hidden product and lower balance', async () => {
    let retrying = false;
    mockGet.mockImplementation((url: string) => {
      if (url === '/plans') return Promise.resolve(ok(retrying ? [] : [plan]));
      if (url === '/user/orders') return Promise.resolve(ok([]));
      if (url === '/user/me') return Promise.resolve(ok(retrying ? { ...me, balance: '4.00', plan_id: 1 } : me));
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    mockPost.mockRejectedValueOnce(new Error('ACK lost')).mockResolvedValueOnce(ok(null));
    const first = render(<Shop />);
    fireEvent.click(await screen.findByRole('button', { name: 'buyNow' }));
    fireEvent.click(await screen.findByRole('button', { name: 'confirmPurchase' }));
    await waitFor(() => expect(mockPost).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(screen.getByRole('button', { name: 'confirmPurchase' })).toBeEnabled());
    const originalBody = mockPost.mock.calls[0][1];
    first.unmount();
    retrying = true;
    render(<Shop />);
    const confirm = await screen.findByRole('button', { name: 'confirmPurchase' });
    expect(confirm).toBeEnabled();
    fireEvent.click(confirm);
    await waitFor(() => expect(mockPost).toHaveBeenCalledTimes(2));
    expect(mockPost.mock.calls[1][1]).toEqual(originalBody);
    await waitFor(() => expect(sessionStorage.length).toBe(0));
  });

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
      request_id: expect.any(String),
      plan_id: 1,
      expected_current_plan_id: 0,
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
