import { Spin } from 'antd';
import { lazy, Suspense } from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from './auth/useAuth';

// Keep the chart-heavy administrator dashboard out of the regular-user path.
// RoleHome itself is lazy-loaded by the router, then only administrators fetch
// this second chunk; regular users can redirect to /account without downloading
// G2 / @ant-design/charts.
const Dashboard = lazy(() => import('./pages/Dashboard'));

/**
 * v0.4.10: the index-route switch. Renders the admin Dashboard for admins.
 * v1.0.7: the regular-user dashboard was removed — its stats (rules / traffic)
 * duplicated the 个人中心 (Account) page, and its line/node counts duplicated
 * Node Status. Regular users are redirected to /account instead. Kept in its
 * own module (not in router.tsx) so router.tsx only exports route config —
 * this satisfies react-refresh/only-export-components.
 *
 * Shows a spinner until authReady flips, so a page refresh doesn't redirect or
 * flash the wrong home while /user/me resolves the real role.
 */
export default function RoleHome() {
  const { isAdmin, authReady } = useAuth();
  if (!authReady) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}>
        <Spin />
      </div>
    );
  }
  return isAdmin ? (
    <Suspense fallback={<div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}><Spin /></div>}>
      <Dashboard />
    </Suspense>
  ) : <Navigate to="/account" replace />;
}
