import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { mockGet, mockPut, mockSetSiteName } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPut: vi.fn(),
  mockSetSiteName: vi.fn(),
}));

vi.mock('../api/client', () => ({
  default: { get: mockGet, put: mockPut },
}));
vi.mock('../site/useSiteConfig', () => ({
  useSiteConfig: () => ({ siteName: 'RelayPanel', setSiteName: mockSetSiteName }),
}));

import SystemSettings from './SystemSettings';

const settings = {
  registration_enabled: false,
  default_registration_plan_id: 1,
  allowed_plan_ids: [1],
  site_name: 'RelayPanel',
};

beforeEach(() => {
  mockGet.mockReset();
  mockPut.mockReset();
  mockSetSiteName.mockReset();
  mockGet.mockImplementation((url: string) => {
    if (url === '/admin/settings/registration') {
      return Promise.resolve({ code: 0, data: settings });
    }
    if (url === '/admin/plans') {
      return Promise.resolve({ code: 0, data: [{ id: 1, name: 'free', max_rules: 5 }] });
    }
    return Promise.reject(new Error(`unexpected ${url}`));
  });
  mockPut.mockResolvedValue({ code: 0, data: { ...settings, site_name: 'My Relay' } });
});

describe('SystemSettings site name', () => {
  it('loads, saves, and immediately publishes the configured name', async () => {
    render(<SystemSettings />);
    const input = await screen.findByLabelText('siteName');
    expect(input).toHaveValue('RelayPanel');

    fireEvent.change(input, { target: { value: '  My Relay  ' } });
    fireEvent.click(screen.getByRole('button', { name: 'save' }));

    await waitFor(() => expect(mockPut).toHaveBeenCalledWith(
      '/admin/settings/registration',
      expect.objectContaining({ site_name: 'My Relay' }),
    ));
    expect(mockSetSiteName).toHaveBeenCalledWith('My Relay');
  });
});
