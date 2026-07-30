import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { mockGet, mockPut, mockInvalidateSite, mockInvalidateSiteNotice } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPut: vi.fn(),
  mockInvalidateSite: vi.fn(),
  mockInvalidateSiteNotice: vi.fn(),
}));

vi.mock('../api/client', () => ({
  default: { get: mockGet, put: mockPut },
}));
vi.mock('../hooks/useSite', () => ({
  invalidateSite: mockInvalidateSite,
}));
vi.mock('../hooks/useSiteNotice', () => ({
  invalidateSiteNotice: mockInvalidateSiteNotice,
}));

import SiteSettings from './SiteSettings';

beforeEach(() => {
  mockGet.mockReset();
  mockPut.mockReset();
  mockInvalidateSite.mockReset();
  mockInvalidateSiteNotice.mockReset();
  mockGet.mockResolvedValue({
    code: 0,
    data: {
      site_name: 'RelayPanel',
      subtitle: '',
      announcement: '',
      announcement_type: 'info',
      contact: '',
    },
  });
  mockPut.mockImplementation((_url: string, values: Record<string, string>) => Promise.resolve({
    code: 0,
    data: values,
  }));
});

describe('SiteSettings', () => {
  it('saves branding and invalidates the public and signed-in caches', async () => {
    render(<SiteSettings />);
    const input = await screen.findByLabelText('siteName');
    fireEvent.change(input, { target: { value: 'My Relay' } });
    fireEvent.click(screen.getByRole('button', { name: 'save' }));

    await waitFor(() => expect(mockPut).toHaveBeenCalledWith(
      '/admin/settings/site',
      expect.objectContaining({ site_name: 'My Relay' }),
    ));
    expect(mockInvalidateSite).toHaveBeenCalledOnce();
    expect(mockInvalidateSiteNotice).toHaveBeenCalledOnce();
  });
});
