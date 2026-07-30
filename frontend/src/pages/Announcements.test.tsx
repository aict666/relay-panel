import { act, render, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LanguageProvider } from '../i18n';
import Announcements from './Announcements';
import { resetAnnouncementBadgeCache } from '../hooks/useAnnouncementBadge';

const { mockGet } = vi.hoisted(() => ({ mockGet: vi.fn() }));
vi.mock('../api/client', () => ({ default: { get: mockGet } }));
vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ user: { id: 42, username: 'reader', admin: false } }),
}));

const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });

beforeEach(() => {
  mockGet.mockReset();
  localStorage.clear();
  resetAnnouncementBadgeCache();
});

const renderPage = async () => {
  await act(async () => {
    render(
      <LanguageProvider>
        <Announcements />
      </LanguageProvider>,
    );
  });
};

describe('Announcements unread semantics', () => {
  it('keeps the unread marker when the archive fails to load', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('latest-id')) return Promise.resolve(ok({ latest_id: 5 }));
      return Promise.reject(new Error('archive unavailable'));
    });

    await renderPage();
    await waitFor(() =>
      expect(mockGet.mock.calls.some(([url]) => String(url).includes('/user/announcements?')))
        .toBe(true),
    );

    expect(localStorage.getItem('relaypanel_ann_seen_42')).toBeNull();
  });

  it('marks seen only after the latest row was rendered successfully', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url.includes('latest-id')) return Promise.resolve(ok({ latest_id: 5 }));
      return Promise.resolve(ok({
        items: [{
          id: 5,
          title: 'Latest',
          content: 'visible',
          kind: 'info',
          pinned: false,
          published_at: '2026-07-30 10:00:00',
          expires_at: null,
          author_id: 1,
          author_name: 'admin',
        }],
        total: 1,
      }));
    });

    await renderPage();

    await waitFor(() =>
      expect(localStorage.getItem('relaypanel_ann_seen_42')).toBe('5'),
    );
  });
});
