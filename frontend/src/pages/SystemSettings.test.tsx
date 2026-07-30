import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { mockGet, mockPut } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPut: vi.fn(),
}));

vi.mock('../api/client', () => ({
  default: { get: mockGet, put: mockPut },
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

describe('SystemSettings registration policy', () => {
  it('saves registration policy without overwriting the dedicated site settings', async () => {
    render(<SystemSettings />);
    expect((await screen.findAllByText('free (5 rules)')).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole('button', { name: 'save' }));

    await waitFor(() => expect(mockPut).toHaveBeenCalledWith(
      '/admin/settings/registration',
      {
        enabled: false,
        default_plan_id: 1,
        allowed_plan_ids: [1],
      },
    ));
  });
});
