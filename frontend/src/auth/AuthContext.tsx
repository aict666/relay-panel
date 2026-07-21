import {
  createContext,
  useCallback,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import api from '../api/client';
import {
  setUnauthorizedHandler,
  setPasswordChangeRequiredHandler,
  type ApiEnvelope,
} from '../api/client';
import type { UserSelf } from '../api/types';

// v0.4.10: AuthContext is the single source of truth for auth state.
//
// Why this exists: before v0.4.10 every component read localStorage('admin') /
// ('token') directly, so there was no way to (a) refresh the user's role from
// the server (localStorage can be tampered with), (b) show a loading state on
// page refresh before /user/me resolves, or (c) centralize logout so a single
// 401 only logs out once even under concurrent failing requests.
//
// Design:
//   - authReady gates every guarded route — guards render a spinner until the
//     initial /user/me (if any) resolves, avoiding a flash of wrong content.
//   - The role (isAdmin) is taken from the SERVER (/user/me), never trusted
//     long-term from localStorage. localStorage only seeds the initial token.
//   - logout is idempotent (a ref guards against concurrent 401s firing it
//     repeatedly) and stable (useCallback), so it can be safely registered
//     as the axios unauthorized handler.

interface AuthState {
  token: string | null;
  isAdmin: boolean;
  user: UserSelf | null;
  authReady: boolean;
  /** v0.4.10 PR4: true when the user must change their password before using
   *  the app. Sourced from /user/me's must_change_password AND from any API
   *  403 PASSWORD_CHANGE_REQUIRED (the axios handler sets it). The route guard
   *  redirects to /force-password-change while this is true. */
  mustChangePassword: boolean;
}

interface AuthContextValue extends AuthState {
  /** Persist the token, then immediately fetch /user/me to resolve the real
   *  role + account projection. Await this in Login before navigating. */
  login: (token: string) => Promise<void>;
  /** Clear all auth state + localStorage. Idempotent: safe to call many times
   *  (e.g. concurrent 401s). Does NOT navigate — RequireAuth handles that. */
  logout: () => void;
  /** Re-fetch /user/me and refresh the cached user. Use after password change,
   *  plan change, etc. */
  refreshCurrentUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);
// Exported (not just module-local) so useAuth.ts can consume it. The hook
// itself lives in useAuth.ts to keep this file component-only (fast refresh).
export { AuthContext };

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(() =>
    localStorage.getItem('token')
  );
  const [isAdmin, setIsAdmin] = useState<boolean>(
    () => localStorage.getItem('admin') === 'true'
  );
  const [user, setUser] = useState<UserSelf | null>(null);
  const [authReady, setAuthReady] = useState(false);
  const [mustChangePassword, setMustChangePassword] = useState(false);

  // Idempotency guard: once logout has run, subsequent concurrent 401s must
  // not re-run it (no-op clears are fine, but we avoid redundant state churn).
  const loggedOutRef = useRef(false);
  // Invalidates in-flight /user/me responses across logout/account changes so
  // an older session can never overwrite the role of a newer one.
  const authGenerationRef = useRef(0);

  const clearAuth = useCallback(() => {
    authGenerationRef.current += 1;
    localStorage.removeItem('token');
    localStorage.removeItem('admin');
    setToken(null);
    setIsAdmin(false);
    setUser(null);
    setMustChangePassword(false);
  }, []);

  const logout = useCallback(() => {
    if (loggedOutRef.current) return;
    loggedOutRef.current = true;
    clearAuth();
  }, [clearAuth]);

  const fetchCurrentUser = useCallback(async (): Promise<UserSelf> => {
    const res = await api.get<unknown, ApiEnvelope<UserSelf>>('/user/me');
    if (!res.data) throw new Error('current-user response did not contain a user');
    return res.data;
  }, []);

  const applyCurrentUser = useCallback((me: UserSelf) => {
    setUser(me);
    setIsAdmin(me.admin);
    setMustChangePassword(me.must_change_password === true);
    localStorage.setItem('admin', String(me.admin));
  }, []);

  const refreshCurrentUser = useCallback(async () => {
    // No token → nothing to refresh. (login sets the token before calling this.)
    const requestToken = localStorage.getItem('token');
    if (!requestToken) return;
    const generation = authGenerationRef.current;
    try {
      const me = await fetchCurrentUser();
      if (
        generation !== authGenerationRef.current
        || localStorage.getItem('token') !== requestToken
      ) return;
      // The server is the source of truth for the role — never trust
      // localStorage.admin long-term (a user can edit it).
      applyCurrentUser(me);
    } catch {
      // /user/me failed. If it was a 401, the axios interceptor already
      // invoked logout via the unauthorized handler. On a non-401 outage keep
      // the token for retry, but fail the cached role closed: a stale/tampered
      // localStorage admin flag must never become authoritative.
      if (
        generation === authGenerationRef.current
        && localStorage.getItem('token') === requestToken
      ) {
        setUser(null);
        setIsAdmin(false);
        localStorage.removeItem('admin');
      }
    }
  }, [applyCurrentUser, fetchCurrentUser]);

  const login = useCallback(
    async (newToken: string) => {
      // Reset the idempotency guard for the new session.
      loggedOutRef.current = false;
      const generation = ++authGenerationRef.current;
      localStorage.setItem('token', newToken);
      localStorage.removeItem('admin');
      setToken(newToken);
      setUser(null);
      setIsAdmin(false);
      setMustChangePassword(false);
      try {
        const me = await fetchCurrentUser();
        if (
          generation !== authGenerationRef.current
          || localStorage.getItem('token') !== newToken
        ) {
          throw new Error('login session was superseded');
        }
        applyCurrentUser(me);
      } catch (error) {
        if (
          generation === authGenerationRef.current
          && localStorage.getItem('token') === newToken
        ) {
          clearAuth();
        }
        throw error;
      }
    },
    [applyCurrentUser, clearAuth, fetchCurrentUser]
  );

  // Boot: if a token exists in localStorage, resolve the real user + role
  // from the server before flipping authReady. Without this, guards would
  // briefly trust a tampered localStorage.admin on page refresh.
  useEffect(() => {
    const storedToken = localStorage.getItem('token');
    if (!storedToken) {
      setAuthReady(true);
      return;
    }
    let cancelled = false;
    (async () => {
      await refreshCurrentUser();
      if (!cancelled) setAuthReady(true);
    })();
    return () => {
      cancelled = true;
    };
    // Run once on mount — refreshCurrentUser is stable (useCallback).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Register the axios 401 handler. logout is stable (useCallback + ref), so
  // this effect binds once and unbinds on unmount.
  useEffect(() => {
    setUnauthorizedHandler(logout);
    return () => setUnauthorizedHandler(null);
  }, [logout]);

  // v0.4.10 PR4: register the PASSWORD_CHANGE_REQUIRED handler. A 403 with that
  // code from any API call flips mustChangePassword on, which the route guard
  // turns into a redirect to /force-password-change. (Does NOT log out.)
  useEffect(() => {
    setPasswordChangeRequiredHandler(() => setMustChangePassword(true));
    return () => setPasswordChangeRequiredHandler(null);
  }, []);

  const value: AuthContextValue = {
    token,
    isAdmin,
    user,
    authReady,
    mustChangePassword,
    login,
    logout,
    refreshCurrentUser,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
