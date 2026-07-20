import axios from 'axios';

// Central API client. In dev the Vite proxy forwards /api to the panel; in
// production the panel serves the built bundle and /api hits itself.
const api = axios.create({
  baseURL: '/api/v1',
  timeout: 10000,
});

// Attach JWT to every request if present
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// v0.4.10: 401 handling is delegated to an injected handler (registered by
// AuthProvider) instead of mutating localStorage / forcing a navigation here.
// This keeps a SINGLE logout path (AuthContext.logout) and lets React state
// drive the redirect. The handler is idempotent — concurrent 401s only fire
// one effective logout (AuthContext guards with a ref).
//
// 403 is intentionally NOT routed to logout: a 403 means "logged in but lacks
// the role", which must NOT log the user out. It falls through to the caller /
// route guard (RequireAdmin → /403).
//
// v0.4.10 PR4: a 403 whose structured body carries code
// "PASSWORD_CHANGE_REQUIRED" is special — the user must change their password
// before using the app. It is routed to a separate injected handler (which
// navigates to the force-password-change page); it must NOT log out and must
// NOT be treated as an ordinary role 403.
let unauthorizedHandler: (() => void) | null = null;
let passwordChangeRequiredHandler: (() => void) | null = null;

export function setUnauthorizedHandler(handler: (() => void) | null) {
  unauthorizedHandler = handler;
}

export function setPasswordChangeRequiredHandler(handler: (() => void) | null) {
  passwordChangeRequiredHandler = handler;
}

// Unwrap the envelope { code, message, data }. Delegate 401 to the injected
// handler; 403+PASSWORD_CHANGE_REQUIRED to its own handler; other errors fall
// through (caller / route guard decides).
api.interceptors.response.use(
  (res) => {
    // Our backend always returns { code, message, data }. Surface the whole
    // envelope so callers can inspect code/message; data is at .data.data.
    const body = res.data;
    // Most API handlers use a business envelope even for server failures, so
    // the HTTP status can still be 200 when `code` is 500. Treat those exactly
    // like transport-level 5xx responses: list pages must enter their existing
    // load-failure path instead of rendering `data: null` as an empty catalog.
    // Validation/authorization/conflict envelopes remain resolved so mutation
    // callers can continue showing the backend's specific message.
    if (body && typeof body.code === 'number' && body.code >= 500) {
      const error = new Error(body.message || 'Server error') as Error & {
        response?: typeof res;
      };
      error.response = res;
      throw error;
    }
    return body;
  },
  (err) => {
    const status = err.response?.status;
    if (status === 401) {
      unauthorizedHandler?.();
    } else if (
      status === 403 &&
      err.response?.data?.code === 'PASSWORD_CHANGE_REQUIRED'
    ) {
      // Forced password change — redirect, do NOT log out.
      passwordChangeRequiredHandler?.();
    }
    // Everything else (ordinary 403, 4xx, 5xx, network) falls through to the
    // caller. A non-admin on an admin page is redirected by RequireAdmin, not
    // by a forced logout.
    return Promise.reject(err);
  }
);

export interface ApiEnvelope<T> {
  code: number;
  message: string;
  data: T | null;
}

export default api;
