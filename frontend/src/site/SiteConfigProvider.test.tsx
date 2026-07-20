import { act, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { mockGet } = vi.hoisted(() => ({ mockGet: vi.fn() }));

vi.mock('../api/client', () => ({
  default: { get: mockGet },
}));

import { SiteConfigProvider } from './SiteConfigProvider';
import { useSiteConfig } from './useSiteConfig';

function Probe() {
  const { siteName, setSiteName } = useSiteConfig();
  return (
    <div>
      <span>{siteName}</span>
      <button type="button" onClick={() => setSiteName('  Updated Site  ')}>update</button>
    </div>
  );
}

beforeEach(() => {
  mockGet.mockReset();
  document.title = '';
});

describe('SiteConfigProvider', () => {
  it('loads the public site name and keeps document.title in sync', async () => {
    mockGet.mockResolvedValue({
      code: 0,
      data: {
        enabled: false,
        default_plan_id: 1,
        plans: [],
        site_name: '星海中转',
        default_password_change_required: false,
      },
    });

    render(<SiteConfigProvider><Probe /></SiteConfigProvider>);
    expect(screen.getByText('RelayPanel')).toBeInTheDocument();
    await screen.findByText('星海中转');
    expect(mockGet).toHaveBeenCalledWith('/auth/registration-status');
    await waitFor(() => expect(document.title).toBe('星海中转'));

    await act(async () => screen.getByRole('button', { name: 'update' }).click());
    expect(screen.getByText('Updated Site')).toBeInTheDocument();
    await waitFor(() => expect(document.title).toBe('Updated Site'));
  });

  it('falls back to RelayPanel when the public probe fails', async () => {
    mockGet.mockRejectedValue(new Error('offline'));
    render(<SiteConfigProvider><Probe /></SiteConfigProvider>);

    await waitFor(() => expect(mockGet).toHaveBeenCalled());
    expect(screen.getByText('RelayPanel')).toBeInTheDocument();
    expect(document.title).toBe('RelayPanel');
  });
});
