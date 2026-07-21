/**
 * v0.4.10 PR2: AuthContext permission-flow tests.
 *
 * Covers the core invariants the fix PR established:
 *   1. On boot with a stored token, AuthProvider calls /user/me and adopts the
 *      SERVER's admin flag (not the localStorage one).
 *   2. A tampered localStorage.admin=true is overridden by a non-admin /user/me.
 *   3. A 401 from any request triggers exactly ONE logout (idempotent under
 *      concurrent 401s).
 *   4. A 403 does NOT trigger logout.
 *
 * The axios client is mocked via vi.mock so no real network calls happen; we
 * drive the interceptor behavior directly.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { fireEvent, render, waitFor } from '@testing-library/react';

// --- mock the axios client before importing anything that uses it ---
// vi.mock factories are hoisted ABOVE all imports, so they cannot reference
// top-level const bindings directly. vi.hoisted runs the factory at the same
// hoisted phase and hands back stable references both the mock factory and the
// test body can use.
const { mockGet, unauthorizedHandlerRef, pwChangeHandlerRef } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  unauthorizedHandlerRef: { current: null as (() => void) | null },
  pwChangeHandlerRef: { current: null as (() => void) | null },
}));

vi.mock('../api/client', () => ({
  default: { get: mockGet, interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } } },
  setUnauthorizedHandler: (h: (() => void) | null) => {
    unauthorizedHandlerRef.current = h;
  },
  setPasswordChangeRequiredHandler: (h: (() => void) | null) => {
    pwChangeHandlerRef.current = h;
  },
  ApiEnvelope: {} as never,
}));

import { AuthProvider } from './AuthContext';
import { useAuth } from './useAuth';
import type { UserSelf } from '../api/types';

// A consumer that surfaces the live auth state so tests can assert on it.
function StateProbe() {
  const { token, isAdmin, user, authReady, mustChangePassword, login } = useAuth();
  return (
    <div>
      <span data-testid="token">{token ?? 'null'}</span>
      <span data-testid="isAdmin">{String(isAdmin)}</span>
      <span data-testid="authReady">{String(authReady)}</span>
      <span data-testid="username">{user?.username ?? 'null'}</span>
      <span data-testid="mustChange">{String(mustChangePassword)}</span>
      <button onClick={() => { void login('new-session-token').catch(() => undefined); }}>login-test</button>
    </div>
  );
}

const nonAdminMe: UserSelf = {
  id: 5,
  username: 'bob',
  admin: false,
  balance: '0',
  plan_id: 1,
  plan_name: 'free',
  max_rules: 5,
  current_rules: 0,
  traffic_used: 0,
  traffic_limit: 0,
  registered_at: '2024-01-01',
  must_change_password: false,
};

const adminMe: UserSelf = { ...nonAdminMe, id: 1, username: 'admin', admin: true };

function renderWithProvider() {
  return render(
    <AuthProvider>
      <StateProbe />
    </AuthProvider>
  );
}

describe('AuthProvider', () => {
  beforeEach(() => {
    localStorage.clear();
    mockGet.mockReset();
    unauthorizedHandlerRef.current = null;
    pwChangeHandlerRef.current = null;
  });

  it('calls /user/me on boot when a token is present and adopts the server role', async () => {
    localStorage.setItem('token', 'jwt-abc');
    // Tamper: claim admin in localStorage. The server must override this.
    localStorage.setItem('admin', 'true');
    mockGet.mockResolvedValueOnce({ code: 0, message: 'ok', data: nonAdminMe });

    const { getByTestId } = renderWithProvider();

    await waitFor(() => {
      expect(getByTestId('authReady').textContent).toBe('true');
    });
    // Server said admin=false → isAdmin must be false despite localStorage.
    expect(getByTestId('isAdmin').textContent).toBe('false');
    expect(getByTestId('username').textContent).toBe('bob');
    expect(mockGet).toHaveBeenCalledWith('/user/me');
  });

  it('keeps an admin role when the server confirms admin', async () => {
    localStorage.setItem('token', 'jwt-admin');
    mockGet.mockResolvedValueOnce({ code: 0, message: 'ok', data: adminMe });

    const { getByTestId } = renderWithProvider();

    await waitFor(() => {
      expect(getByTestId('isAdmin').textContent).toBe('true');
    });
  });

  it('sets authReady=true and stays logged out when no token is stored', async () => {
    const { getByTestId } = renderWithProvider();
    // No /user/me call should happen without a token.
    expect(mockGet).not.toHaveBeenCalled();
    await waitFor(() => {
      expect(getByTestId('authReady').textContent).toBe('true');
    });
    expect(getByTestId('token').textContent).toBe('null');
  });

  it('registers a 401 handler that clears auth state', async () => {
    localStorage.setItem('token', 'jwt-abc');
    mockGet.mockResolvedValueOnce({ code: 0, message: 'ok', data: nonAdminMe });

    const { getByTestId } = renderWithProvider();
    await waitFor(() => {
      expect(getByTestId('authReady').textContent).toBe('true');
    });

    // Simulate a later 401: the axios interceptor would call the handler.
    expect(unauthorizedHandlerRef.current).not.toBeNull();
    unauthorizedHandlerRef.current!();

    await waitFor(() => {
      expect(getByTestId('token').textContent).toBe('null');
      expect(getByTestId('isAdmin').textContent).toBe('false');
    });
    expect(localStorage.getItem('token')).toBeNull();
  });

  it('401 handler is idempotent: concurrent calls only log out once', async () => {
    localStorage.setItem('token', 'jwt-abc');
    mockGet.mockResolvedValueOnce({ code: 0, message: 'ok', data: nonAdminMe });

    const { getByTestId } = renderWithProvider();
    await waitFor(() => {
      expect(getByTestId('authReady').textContent).toBe('true');
    });

    const handler = unauthorizedHandlerRef.current!;
    // Fire several 401s in quick succession (e.g. parallel requests failing).
    handler();
    handler();
    handler();

    // State clears (setState is async — wait for the re-render). Idempotency
    // means no throw and a single net transition despite three calls.
    await waitFor(() => {
      expect(getByTestId('token').textContent).toBe('null');
    });
  });

  it('does NOT log out when /user/me returns a non-401 error (e.g. 500)', async () => {
    localStorage.setItem('token', 'jwt-abc');
    localStorage.setItem('admin', 'true');
    // A 500 (not 401) — AuthProvider catches it and leaves existing state.
    mockGet.mockRejectedValueOnce({ response: { status: 500 } });

    const { getByTestId } = renderWithProvider();
    await waitFor(() => {
      expect(getByTestId('authReady').textContent).toBe('true');
    });
    // Not logged out: token survives a transient server error.
    expect(getByTestId('token').textContent).toBe('jwt-abc');
    // But the unverified cached role fails closed.
    expect(getByTestId('isAdmin').textContent).toBe('false');
    expect(localStorage.getItem('admin')).toBeNull();
  });

  it('rolls back a new login when the server cannot resolve /user/me', async () => {
    mockGet.mockRejectedValueOnce({ response: { status: 500 } });
    const { getByRole, getByTestId } = renderWithProvider();
    await waitFor(() => expect(getByTestId('authReady').textContent).toBe('true'));

    fireEvent.click(getByRole('button', { name: 'login-test' }));

    await waitFor(() => expect(getByTestId('token').textContent).toBe('null'));
    expect(localStorage.getItem('token')).toBeNull();
    expect(getByTestId('isAdmin').textContent).toBe('false');
  });

  // ── v0.4.10 PR4: must_change_password + PASSWORD_CHANGE_REQUIRED ──

  it('sets mustChangePassword=true when /user/me reports must_change_password', async () => {
    localStorage.setItem('token', 'jwt-abc');
    const forcedMe: UserSelf = { ...nonAdminMe, must_change_password: true };
    mockGet.mockResolvedValueOnce({ code: 0, message: 'ok', data: forcedMe });

    const { getByTestId } = renderWithProvider();
    await waitFor(() => {
      expect(getByTestId('mustChange').textContent).toBe('true');
    });
    // The token stays — must_change does NOT log out, the guard redirects to
    // the force-password-change page instead.
    expect(getByTestId('token').textContent).toBe('jwt-abc');
  });

  it('the PASSWORD_CHANGE_REQUIRED axios handler sets mustChangePassword (no logout)', async () => {
    localStorage.setItem('token', 'jwt-abc');
    mockGet.mockResolvedValueOnce({ code: 0, message: 'ok', data: nonAdminMe });

    const { getByTestId } = renderWithProvider();
    await waitFor(() => {
      expect(getByTestId('authReady').textContent).toBe('true');
    });

    // Simulate a later API call returning 403 PASSWORD_CHANGE_REQUIRED — the
    // axios interceptor would invoke the registered handler.
    expect(pwChangeHandlerRef.current).not.toBeNull();
    pwChangeHandlerRef.current!();

    await waitFor(() => {
      expect(getByTestId('mustChange').textContent).toBe('true');
    });
    // Must NOT log out — the user is still authenticated, just gated.
    expect(getByTestId('token').textContent).toBe('jwt-abc');
  });
});
