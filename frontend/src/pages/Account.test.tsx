import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { UserSelf } from '../api/types';
import { I18nContext } from '../i18n/context';

const { mockGet, mockPut } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPut: vi.fn(),
}));

vi.mock('../api/client', () => ({
  default: { get: mockGet, put: mockPut, post: vi.fn() },
}));

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ logout: vi.fn() }),
}));

vi.mock('../hooks/useSiteNotice', () => ({
  useSiteNotice: () => ({ contact: '' }),
}));

vi.mock('../components/SiteAnnouncement', () => ({ default: () => null }));
vi.mock('../components/TrafficChart', () => ({ default: () => null }));
vi.mock('../components/RedeemHistory', () => ({ default: () => null }));

import Account from './Account';

const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });

const account: UserSelf = {
  id: 2,
  username: 'buyer',
  admin: false,
  balance: '100.00',
  plan_id: 7,
  plan_name: 'Standard Monthly',
  plan_type: 'monthly',
  plan_price: '10.00',
  plan_billing_revision: 3,
  max_rules: 5,
  current_rules: 1,
  traffic_used: 100,
  traffic_limit: 1_000,
  registered_at: '2026-01-01',
  must_change_password: false,
  plan_expire_at: '2026-09-01 00:00:00',
  plan_auto_renew: false,
};

const translations: Record<string, string> = {
  autoRenewPriceHint: 'Charge {price} every 30 days',
  confirmAutoRenewTitle: 'Confirm auto-renew',
  confirmAutoRenewCharge: 'The plan price of {price} will be charged automatically at expiry',
  confirmAutoRenew: 'Enable auto-renew',
  cancel: 'Cancel',
};

beforeEach(() => {
  mockGet.mockReset();
  mockPut.mockReset();
  mockGet.mockResolvedValue(ok(account));
  mockPut.mockResolvedValue(ok(null));
});

describe('Account monthly renewal consent', () => {
  it('shows the exact amount and sends the confirmed billing contract', async () => {
    const user = userEvent.setup();
    render(
      <I18nContext.Provider
        value={{ t: (key) => translations[key] ?? String(key), lang: 'en-US', setLang: vi.fn() }}
      >
        <MemoryRouter><Account /></MemoryRouter>
      </I18nContext.Provider>,
    );

    expect(await screen.findByText('Charge 10.00 every 30 days')).toBeInTheDocument();
    await user.click(screen.getByRole('switch'));

    const dialog = await screen.findByRole('dialog', { name: 'Confirm auto-renew' });
    expect(
      within(dialog).getByText('The plan price of 10.00 will be charged automatically at expiry'),
    ).toBeInTheDocument();
    expect(mockPut).not.toHaveBeenCalled();

    await user.click(within(dialog).getByRole('button', { name: 'Enable auto-renew' }));
    await waitFor(() => expect(mockPut).toHaveBeenCalledWith('/user/plan/auto-renew', {
      enabled: true,
      expected_price: '10.00',
      expected_revision: 3,
    }));
  });
});
