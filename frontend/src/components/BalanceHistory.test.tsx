import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const { mockGet } = vi.hoisted(() => ({ mockGet: vi.fn() }));
vi.mock('../api/client', () => ({ default: { get: mockGet } }));
import BalanceHistory from './BalanceHistory';

beforeEach(() => { mockGet.mockReset(); });

describe('BalanceHistory', () => {
  it('uses the admin-scoped endpoint only when a target user is explicitly supplied', async () => {
    mockGet.mockResolvedValue({ code: 0, data: [] });
    render(<BalanceHistory userId={42} />);
    await userEvent.click(screen.getByRole('button', { name: 'loadBalanceHistory' }));
    expect(mockGet).toHaveBeenCalledWith('/admin/users/42/balance-ledger', { params: { limit: 50, offset: 0 } });
  });
  it('loads only the current user ledger on demand and displays signed cents', async () => {
    mockGet.mockResolvedValue({ code: 0, data: [{ id: 'one', kind: 'purchase', amount_cents: -123,
      balance_after: '8.77', reference_id: 'transaction-one', created_at: '2026-10-15 00:00:00' }] });
    render(<BalanceHistory />);
    expect(mockGet).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole('button', { name: 'loadBalanceHistory' }));
    expect(mockGet).toHaveBeenCalledWith('/user/balance-ledger', { params: { limit: 50, offset: 0 } });
    expect(await screen.findByText('-1.23')).toBeInTheDocument();
    expect(screen.getByText('8.77')).toBeInTheDocument();
    expect(screen.getByText('billingPurchase')).toBeInTheDocument();
  });

  it('never treats an API failure as an empty successful ledger', async () => {
    mockGet.mockRejectedValue(new Error('offline'));
    render(<BalanceHistory />);
    await userEvent.click(screen.getByRole('button', { name: 'loadBalanceHistory' }));
    expect(await screen.findByText('loadFailed')).toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });

  it('paginates using a bounded server offset', async () => {
    mockGet.mockResolvedValue({ code: 0, data: Array.from({ length: 50 }, (_, id) => ({
      id: String(id), kind: 'redeem', amount_cents: 100, balance_after: '1', reference_id: String(id), created_at: 'UTC',
    })) });
    await act(async () => { render(<BalanceHistory />); });
    await userEvent.click(screen.getByRole('button', { name: 'loadBalanceHistory' }));
    await userEvent.click(await screen.findByRole('button', { name: '→' }));
    expect(mockGet).toHaveBeenLastCalledWith('/user/balance-ledger', { params: { limit: 50, offset: 50 } });
  });
});
