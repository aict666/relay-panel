import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

// Mock the api client before importing the page. Dashboard calls /admin/users,
// /rules, /groups, /nodes, and /system/version.
const { mockGet } = vi.hoisted(() => ({ mockGet: vi.fn() }));
const { mockNavigate } = vi.hoisted(() => ({ mockNavigate: vi.fn() }));
const { mockArea, mockLine } = vi.hoisted(() => ({ mockArea: vi.fn(), mockLine: vi.fn() }));

vi.mock('../api/client', () => ({
  default: { get: mockGet },
}));
// G2 renders to canvas, which jsdom deliberately does not implement. Dashboard
// tests verify data flow/layout around charts; pure chart-data transforms have
// their own tests, so lightweight stand-ins keep this suite deterministic.
vi.mock('@ant-design/charts', () => ({
  Area: (props: unknown) => { mockArea(props); return <div data-testid="area-chart" />; },
  Line: (props: unknown) => { mockLine(props); return <div data-testid="line-chart" />; },
  Pie: () => <div data-testid="pie-chart" />,
  Bar: () => <div data-testid="bar-chart" />,
}));
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return { ...actual, useNavigate: () => mockNavigate };
});

import Dashboard from './Dashboard';
import type { DashboardHistoryPoint, NodeStatus } from '../api/types';

const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });

// Drain pending promises under fake timers (see NodeStatus.test.tsx rationale).
const flush = (ms = 0) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });

function ns(group_id: number, over: Partial<NodeStatus>): NodeStatus {
  return { group_id, group_name: `g${group_id}`, cpu: 0, mem: 0, connections: 0, uptime: 0, last_seen: '', ...over } as NodeStatus;
}

beforeEach(() => {
  mockGet.mockReset();
  mockNavigate.mockReset();
  mockArea.mockReset();
  mockLine.mockReset();
  vi.useFakeTimers();
});
afterEach(() => {
  vi.runOnlyPendingTimers();
  vi.useRealTimers();
});

/** Resolve every Dashboard API call. Unspecified endpoints 404-reject so a
 *  missed mock is loud rather than silently swallowed. */
function mockAll(nodes: NodeStatus[], historyPoints: DashboardHistoryPoint[] = []) {
  mockGet.mockImplementation((url: string) => {
    if (url === '/admin/users') return Promise.resolve(ok([{}]));
    if (url === '/rules') return Promise.resolve(ok([{}]));
    if (url === '/groups') return Promise.resolve(ok([{}]));
    if (url === '/nodes') return Promise.resolve(ok(nodes));
    if (url.startsWith('/dashboard/history?range=')) {
      return Promise.resolve(ok({ range: url.split('=').pop(), bucket_seconds: 300, points: historyPoints }));
    }
    if (url === '/system/version') {
      return Promise.resolve({ current_version: '0.4.17', latest_version: '', has_update: false, is_outdated: false, release_url: '', release_notes: '', published_at: '', check_failed: false, error_message: '' });
    }
    return Promise.reject(new Error(`unexpected ${url}`));
  });
}

function renderDashboard() {
  return render(<MemoryRouter><Dashboard /></MemoryRouter>);
}

describe('Dashboard group aggregation', () => {
  it('renders one row per group with online/total and aggregates the rate', async () => {
    mockAll([
      ns(1, { node_id: 'a', online: true, upload_bps: 100, download_bps: 200, connections: 3 }),
      ns(1, { node_id: 'b', online: true, upload_bps: 50, download_bps: 30, connections: 1 }),
      ns(2, { node_id: 'c', online: false }),
    ]);
    renderDashboard();
    await flush();

    // group names appear
    expect(screen.getAllByText('g1').length).toBeGreaterThan(0);
    expect(screen.getAllByText('g2').length).toBeGreaterThan(0);
    // g1 has both nodes online → 2/2
    expect(screen.getByText('2/2')).toBeInTheDocument();
    // g2 fully offline → 0/1
    expect(screen.getByText('0/1')).toBeInTheDocument();
  });

  it('does NOT render CPU / MEM columns (aggregation dropped them)', async () => {
    mockAll([ns(1, { node_id: 'a', online: true })]);
    renderDashboard();
    await flush();
    const headers = screen.getAllByRole('columnheader').map((h) => h.textContent);
    // No header should contain "CPU" or the mem label
    expect(headers.some((h) => h && /CPU/i.test(h))).toBe(false);
    // i18n keys are echoed by the fake-t router only for t() calls; the mem
    // column header would be the raw 'mem' key — assert it's absent too.
    expect(headers.some((h) => h === 'mem')).toBe(false);
  });

  it('clicking a row navigates to /nodes', async () => {
    mockAll([ns(1, { node_id: 'a', online: true })]);
    renderDashboard();
    await flush();

    // the first table body row is clickable
    // A horizontally scrollable Ant table injects a hidden measurement row;
    // target the real data row instead of clicking that layout-only element.
    const row = document.querySelector('.ant-table-tbody tr:not(.ant-table-measure-row)');
    expect(row).not.toBeNull();
    await act(async () => {
      row!.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    });
    expect(mockNavigate).toHaveBeenCalledWith('/nodes');
  });

  it('shows the empty hint when no nodes report', async () => {
    mockAll([]);
    renderDashboard();
    await flush();
    expect(screen.getByText('noNodesReporting')).toBeInTheDocument();
  });

  it('loads 24h history by default and reloads when the range changes', async () => {
    mockAll([]);
    renderDashboard();
    await flush();
    expect(mockGet).toHaveBeenCalledWith('/dashboard/history?range=24h');

    const sevenDays = screen.getByText('7d');
    await act(async () => {
      sevenDays.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(mockGet).toHaveBeenCalledWith('/dashboard/history?range=7d');
  });

  it('keeps both history chart x-axis labels horizontal', async () => {
    mockAll([], [{
      timestamp: '2026-07-19T09:00:00Z',
      upload_bps_avg: 100,
      download_bps_avg: 200,
      connections_max: 3,
      online_nodes_min: 2,
      recent_nodes_max: 2,
      sample_count: 1,
    }]);
    renderDashboard();
    await flush();

    const areaProps = mockArea.mock.calls.at(-1)?.[0] as { axis?: { x?: Record<string, unknown> } };
    const lineProps = mockLine.mock.calls.at(-1)?.[0] as { axis?: { x?: Record<string, unknown> } };
    expect(areaProps.axis?.x?.labelAutoRotate).toBe(false);
    expect(areaProps.axis?.x?.labelAutoHide).toBe(true);
    expect(lineProps.axis?.x?.labelAutoRotate).toBe(false);
    expect(lineProps.axis?.x?.labelAutoHide).toBe(true);
  });

  it('stops the history refresh timer after unmount', async () => {
    mockAll([]);
    const view = renderDashboard();
    await flush();
    const before = mockGet.mock.calls.filter(([url]) => String(url).startsWith('/dashboard/history')).length;
    view.unmount();
    await flush(60000);
    const after = mockGet.mock.calls.filter(([url]) => String(url).startsWith('/dashboard/history')).length;
    expect(after).toBe(before);
  });

  it('shows history and live-data failures as independent states', async () => {
    mockGet.mockImplementation((url: string) => {
      if (url === '/dashboard/history?range=24h') return Promise.reject(new Error('history down'));
      if (url === '/nodes') return Promise.reject(new Error('nodes down'));
      if (url === '/system/version') {
        return Promise.resolve({ current_version: '0.4.17', latest_version: '', has_update: false, is_outdated: false, release_url: '', release_notes: '', published_at: '', check_failed: false, error_message: '' });
      }
      if (url === '/admin/users' || url === '/rules' || url === '/groups') return Promise.resolve(ok([]));
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    renderDashboard();
    await flush();

    expect(screen.getByText('dashboardHistoryFailed')).toBeInTheDocument();
    expect(screen.getByText('dashboardLiveFailed')).toBeInTheDocument();
  });
});
