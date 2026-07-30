import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

// Mock the api client before importing the page. Dashboard calls /admin/users,
// /rules, /groups, and /system/version.
const { mockGet } = vi.hoisted(() => ({ mockGet: vi.fn() }));
const { mockNavigate } = vi.hoisted(() => ({ mockNavigate: vi.fn() }));

vi.mock('../api/client', () => ({
  default: { get: mockGet },
}));
vi.mock('../components/TrafficChart', () => ({
  default: () => <div data-testid="traffic-history-chart" />,
}));
vi.mock('../components/NodeMetricsChart', () => ({
  default: () => <div data-testid="node-metrics-chart" />,
}));
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return { ...actual, useNavigate: () => mockNavigate };
});

import Dashboard from './Dashboard';

const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });

// Drain pending promises under fake timers (see NodeStatus.test.tsx rationale).
const flush = (ms = 0) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });

beforeEach(() => {
  mockGet.mockReset();
  mockNavigate.mockReset();
  vi.useFakeTimers();
});
afterEach(() => {
  vi.runOnlyPendingTimers();
  vi.useRealTimers();
});

/** Resolve every Dashboard API call. Unspecified endpoints 404-reject so a
 *  missed mock is loud rather than silently swallowed. */
function mockAll() {
  mockGet.mockImplementation((url: string) => {
    if (url === '/admin/users') return Promise.resolve(ok([{}]));
    if (url === '/rules') return Promise.resolve(ok([{}]));
    if (url === '/groups') return Promise.resolve(ok([{}]));
    if (url === '/system/version') {
      return Promise.resolve({ current_version: '0.4.17', latest_version: '', has_update: false, is_outdated: false, release_url: '', release_notes: '', published_at: '', check_failed: false, error_message: '' });
    }
    return Promise.reject(new Error(`unexpected ${url}`));
  });
}

function renderDashboard() {
  return render(<MemoryRouter><Dashboard /></MemoryRouter>);
}

describe('Dashboard', () => {
  it('does not overlap catalog polling while the previous load is still pending', async () => {
    let resolveGroups!: (value: ReturnType<typeof ok<unknown[]>>) => void;
    const pendingGroups = new Promise<ReturnType<typeof ok<unknown[]>>>((resolve) => {
      resolveGroups = resolve;
    });
    mockGet.mockImplementation((url: string) => {
      if (url === '/admin/users' || url === '/rules') return Promise.resolve(ok([]));
      if (url === '/groups') return pendingGroups;
      if (url === '/system/version') {
        return Promise.resolve({ current_version: '1.0.0', latest_version: '', has_update: false, is_outdated: false, release_url: '', release_notes: '', published_at: '', check_failed: false, error_message: '' });
      }
      return Promise.reject(new Error(`unexpected ${url}`));
    });

    renderDashboard();
    await flush();
    expect(mockGet.mock.calls.filter(([url]) => url === '/admin/users')).toHaveLength(1);

    await flush(10000);
    expect(mockGet.mock.calls.filter(([url]) => url === '/admin/users')).toHaveLength(1);

    resolveGroups(ok([]));
    await flush();
  });

  it('keeps the newest version response when an older request finishes later', async () => {
    type VersionResponse = {
      current_version: string;
      latest_version: string;
      has_update: boolean;
      is_outdated: boolean;
      release_url: string;
      release_notes: string;
      published_at: string;
      check_failed: boolean;
      error_message: string;
    };
    let resolveInitial!: (value: VersionResponse) => void;
    let resolveForced!: (value: VersionResponse) => void;
    const initial = new Promise<VersionResponse>((resolve) => { resolveInitial = resolve; });
    const forced = new Promise<VersionResponse>((resolve) => { resolveForced = resolve; });
    mockGet.mockImplementation((url: string) => {
      if (url === '/admin/users' || url === '/rules' || url === '/groups') {
        return Promise.resolve(ok([]));
      }
      if (url === '/system/version') return initial;
      if (url === '/system/version?refresh=true') return forced;
      return Promise.reject(new Error(`unexpected ${url}`));
    });

    renderDashboard();
    await flush();
    screen.getByRole('button', { name: /checkUpdate/ }).click();
    await flush();

    // A scheduled cached check must not supersede a pending manual refresh.
    await flush(1800000);
    expect(mockGet.mock.calls.filter(([url]) => url === '/system/version')).toHaveLength(1);
    expect(mockGet.mock.calls.filter(([url]) => url === '/system/version?refresh=true')).toHaveLength(1);

    resolveForced({ current_version: '2.0.0', latest_version: '', has_update: false, is_outdated: false, release_url: '', release_notes: '', published_at: '', check_failed: false, error_message: '' });
    await flush();
    expect(screen.getByText('v2.0.0')).toBeInTheDocument();

    resolveInitial({ current_version: '1.0.0', latest_version: '', has_update: false, is_outdated: false, release_url: '', release_notes: '', published_at: '', check_failed: false, error_message: '' });
    await flush();
    expect(screen.getByText('v2.0.0')).toBeInTheDocument();
    expect(screen.queryByText('v1.0.0')).not.toBeInTheDocument();
  });

  it('keeps only the traffic and node-metrics charts without retired data requests', async () => {
    mockAll();
    renderDashboard();
    await flush();

    expect(screen.getByTestId('traffic-history-chart')).toBeInTheDocument();
    expect(screen.getByTestId('node-metrics-chart')).toBeInTheDocument();
    expect(screen.queryByText('dashboardNetworkTrend')).not.toBeInTheDocument();
    expect(screen.queryByText('dashboardGroupHealth')).not.toBeInTheDocument();
    expect(screen.queryByText('nodeStatus')).not.toBeInTheDocument();
    expect(screen.queryByText('dashboardGroupRateTop')).not.toBeInTheDocument();
    expect(screen.queryByText('dashboardRuleTrafficTop')).not.toBeInTheDocument();
    expect(document.querySelector('.ant-table')).toBeNull();
    expect(mockGet.mock.calls.some(([url]) => url === '/nodes')).toBe(false);
    expect(mockGet.mock.calls.some(([url]) => String(url).startsWith('/dashboard/history'))).toBe(false);
  });
});
