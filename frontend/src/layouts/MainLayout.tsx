import {
  Layout, Menu, Button, Segmented, Modal, Form, Input, message, Spin,
  Grid, Drawer, Dropdown, Avatar,
} from 'antd';
import type { MenuProps } from 'antd';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import { useState, Suspense } from 'react';
import {
  DashboardOutlined,
  ApiOutlined,
  CloudServerOutlined,
  UserOutlined,
  LogoutOutlined,
  LockOutlined,
  SettingOutlined,
  ShoppingOutlined,
  MenuOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  ThunderboltFilled,
} from '@ant-design/icons';
import { useI18n } from '../i18n/context';
import api from '../api/client';
import type { ApiEnvelope } from '../api/types';
import { useAuth } from '../auth/useAuth';
import { makePasswordValidator } from '../utils/password';

const { Sider, Content, Header } = Layout;

/** Sidebar masthead. Shrinks to just the mark when the rail is collapsed. */
function Brand({ collapsed = false }: { collapsed?: boolean }) {
  return (
    <div className="rp-brand">
      <span className="rp-brand-mark"><ThunderboltFilled /></span>
      {!collapsed && <span className="rp-brand-name">RelayPanel</span>}
    </div>
  );
}

export default function MainLayout() {
  const navigate = useNavigate();
  const location = useLocation();
  const { t, lang, setLang } = useI18n();
  const { isAdmin, user, logout: authLogout } = useAuth();
  const [changePwOpen, setChangePwOpen] = useState(false);
  const [pwForm] = Form.useForm();
  const [pwSubmitting, setPwSubmitting] = useState(false);
  // Below lg the rail is replaced by a drawer; above it the rail collapses to
  // an icon-only strip so wide tables get the horizontal room back.
  const screens = Grid.useBreakpoint();
  const isMobile = !screens.lg;
  const [collapsed, setCollapsed] = useState(false);
  const [navOpen, setNavOpen] = useState(false);

  // v0.4.11 PR2: role-based navigation.
  // Admin: Dashboard → 个人中心, 转发规则, 设备分组, 节点状态, 隧道配置, 用户管理, 系统设置
  // Regular: 个人中心, 我的规则, 可用节点
  // v1.0.7: 仪表盘 (/) is admin-only — the regular-user dashboard was removed
  // (redirects to /account), so regular users no longer get this menu entry.
  const dashboardItem = { key: '/', icon: <DashboardOutlined />, label: t('dashboard') };
  const sharedItems = [
    { key: '/account', icon: <UserOutlined />, label: t('personalCenter') },
    { key: '/shop', icon: <ShoppingOutlined />, label: t('shop') },
    { key: '/rules', icon: <ApiOutlined />, label: t('myRules') },
    { key: '/nodes', icon: <CloudServerOutlined />, label: t('availableNodes') },
  ];
  const adminOnlyItems = [
    { key: '/groups', icon: <CloudServerOutlined />, label: t('deviceGroups') },
    { key: '/plans', icon: <ShoppingOutlined />, label: t('planManagement') },
    { key: '/users', icon: <UserOutlined />, label: t('users') },
    { key: '/settings', icon: <SettingOutlined />, label: t('systemSettings') },
  ];
  // Admins get three sections so the 9-entry list scans; regular users have
  // four entries, where a section header would be noise.
  const sections = isAdmin
    ? [
        { label: t('navGroupOverview'), items: [dashboardItem] },
        { label: t('navGroupWorkspace'), items: sharedItems },
        { label: t('navGroupAdmin'), items: adminOnlyItems },
      ]
    : [{ label: '', items: sharedItems }];
  const flatItems = sections.flatMap((s) => s.items);
  // Group titles are dropped on the collapsed rail — antd renders them as
  // clipped text next to icon-only entries.
  const railCollapsed = collapsed && !isMobile;
  const menuItems: MenuProps['items'] = isAdmin && !railCollapsed
    ? sections.map((s) => ({ type: 'group' as const, label: s.label, children: s.items }))
    : flatItems;

  // The header shows a breadcrumb, not a repeat of the page's own <h1>.
  const currentTitle = flatItems.find((i) => i.key === location.pathname)?.label;
  const currentSection = sections.find((s) => s.items.some((i) => i.key === location.pathname));

  const logout = () => {
    authLogout();
    navigate('/login');
  };

  const go = (key: string) => {
    navigate(key);
    setNavOpen(false);
  };

  const nav = (
    <Menu
      className="rp-nav"
      mode="inline"
      selectedKeys={[location.pathname]}
      items={menuItems}
      onClick={({ key }) => go(key)}
    />
  );

  const userMenu: MenuProps['items'] = [
    {
      key: 'password',
      icon: <LockOutlined />,
      label: t('changePassword'),
      onClick: () => setChangePwOpen(true),
    },
    { type: 'divider' },
    {
      key: 'logout',
      icon: <LogoutOutlined />,
      label: t('logout'),
      danger: true,
      onClick: logout,
    },
  ];

  const handleChangePassword = async (values: { current_password: string; new_password: string }) => {
    setPwSubmitting(true);
    try {
      const res = await api.put<unknown, ApiEnvelope<null>>('/user/password', values);
      if (res.code !== 0) {
        message.error(res.message);
        return;
      }
      message.success(t('passwordChanged'));
      setChangePwOpen(false);
      pwForm.resetFields();
    } catch {
      message.error(t('passwordChangeFailed'));
    } finally {
      setPwSubmitting(false);
    }
  };

  return (
    <Layout style={{ minHeight: '100vh' }}>
      {!isMobile && (
        <Sider
          theme="light"
          width={232}
          collapsedWidth={72}
          collapsed={collapsed}
          trigger={null}
          className={`rp-sidebar${collapsed ? ' rp-sidebar-collapsed' : ''}`}
          style={{ position: 'sticky', top: 0, height: '100dvh', overflow: 'hidden' }}
        >
          <Brand collapsed={collapsed} />
          {nav}
        </Sider>
      )}

      <Drawer
        placement="left"
        open={navOpen}
        onClose={() => setNavOpen(false)}
        size={272}
        closable={false}
        styles={{ body: { padding: 0 }, header: { display: 'none' } }}
      >
        <Brand />
        {nav}
      </Drawer>

      <Layout style={{ minWidth: 0 }}>
        <Header className="rp-app-header">
          <div className="rp-header-left">
            <Button
              type="text"
              className="rp-icon-button"
              aria-label={t('toggleMenu')}
              icon={isMobile ? <MenuOutlined /> : collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
              onClick={() => (isMobile ? setNavOpen(true) : setCollapsed((c) => !c))}
            />
            <span className="rp-header-crumb">
              {currentSection?.label && (
                <>
                  <span className="rp-crumb-parent">{currentSection.label}</span>
                  <span className="rp-crumb-sep">/</span>
                </>
              )}
              <span className="rp-header-title">{currentTitle}</span>
            </span>
          </div>
          <div className="rp-header-actions">
            <Segmented
              size="small"
              value={lang}
              onChange={(v) => setLang(v as 'zh-CN' | 'en-US')}
              options={[
                { value: 'zh-CN', label: t('langZhCN') },
                { value: 'en-US', label: t('langEnUS') },
              ]}
            />
            <span className="rp-header-divider" />
            <Dropdown menu={{ items: userMenu }} trigger={['click']} placement="bottomRight">
              <div className="rp-user-chip" role="button" tabIndex={0}>
                <Avatar
                  size={30}
                  style={{
                    background: 'var(--rp-primary-soft)',
                    color: 'var(--rp-primary-strong)',
                    fontSize: 13,
                    fontWeight: 600,
                  }}
                >
                  {(user?.username || 'U').slice(0, 1).toUpperCase()}
                </Avatar>
                <span className="rp-user-chip-meta">
                  <span className="rp-user-chip-name">{user?.username || t('user')}</span>
                  <span className="rp-user-chip-role">{isAdmin ? t('admin') : t('user')}</span>
                </span>
              </div>
            </Dropdown>
          </div>
        </Header>
        <Content className="rp-content">
          <div className="rp-content-inner">
            {/* v1.2 (PR4): lazy-loaded pages (router.tsx) suspend here on first
                navigation to their chunk, showing a centered spinner instead of a
                blank pane. */}
            <Suspense fallback={<div style={{ textAlign: 'center', padding: 48 }}><Spin /></div>}>
              <Outlet />
            </Suspense>
          </div>
        </Content>
      </Layout>

      <Modal
        title={t('changePassword')}
        open={changePwOpen}
        onCancel={() => { setChangePwOpen(false); pwForm.resetFields(); }}
        onOk={() => pwForm.submit()}
        okText={t('save')}
        cancelText={t('cancel')}
        confirmLoading={pwSubmitting}
      >
        <Form form={pwForm} onFinish={handleChangePassword} layout="vertical">
          <Form.Item
            name="current_password"
            label={t('currentPassword')}
            rules={[{ required: true }]}
          >
            <Input.Password autoComplete="current-password" />
          </Form.Item>
          <Form.Item
            name="new_password"
            label={t('newPassword')}
            rules={[
              { required: true, message: t('passwordRequired') },
              { validator: makePasswordValidator(t('newPasswordTooShort'), t('passwordTooLong')) },
            ]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item
            name="confirm_password"
            label={t('confirmPassword')}
            dependencies={['new_password']}
            rules={[
              { required: true },
              ({ getFieldValue }) => ({
                validator(_, value) {
                  if (!value || getFieldValue('new_password') === value) {
                    return Promise.resolve();
                  }
                  return Promise.reject(new Error(t('passwordsDoNotMatch')));
                },
              }),
            ]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
        </Form>
      </Modal>
    </Layout>
  );
}
