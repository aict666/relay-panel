import { Table, Button, Tag, Popconfirm, message, Progress, Tooltip, Modal, Form, Input, InputNumber, Switch, Space, Select, DatePicker, Divider, Dropdown, Alert } from 'antd';
import type { MenuProps } from 'antd';
import { DeleteOutlined, EditOutlined, ReloadOutlined, UndoOutlined, UserOutlined, PlusOutlined, KeyOutlined, ApiOutlined, ShoppingOutlined, MoreOutlined, SearchOutlined } from '@ant-design/icons';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import dayjs, { type Dayjs } from 'dayjs';
import api from '../api/client';
import type { ApiEnvelope, User, Plan } from '../api/types';
import { useI18n } from '../i18n/context';
import { formatBytes } from '../utils/format';
import { makePasswordValidator } from '../utils/password';
import { useAuth } from '../auth/useAuth';
import { MAX_SAFE_TRAFFIC_GB, bytesToGb, gbToBytes, trafficGbChanged } from '../utils/traffic';

// traffic_limit is stored in BYTES in the database. The edit form works in GB
// for usability (a raw byte count is meaningless to a human). Convert on the
// boundary only — the backend and DB stay byte-based.
interface UserFormValues {
  // Stored as a string (not number) so the wire format matches the backend's
  // TEXT-typed `users.balance` column and the strict `parse_balance` rules
  // in crates/shared/src/money.rs. InputNumber with `stringMode` keeps the
  // value as a string end-to-end.
  balance: string | null;
  max_rules: number;
  // Edited in GB; converted to bytes before sending to the backend.
  traffic_limit_gb: number;
  banned: boolean;
  // v1.0.8: admin suspension (forwarding gated; login still allowed).
  suspended: boolean;
  // v1.0.7: per-user device-group authorization. all_device_groups short-
  // circuits the explicit list (when on, the user may use every group).
  all_device_groups: boolean;
  device_group_ids: number[];
}

interface CreateUserFormValues {
  username: string;
  password: string;
}

// v0.4.10 PR4: admin password-reset form.
interface ResetFormValues {
  new_password: string;
  confirm_password: string;
  must_change_password: boolean;
}

export default function Users() {
  const { t } = useI18n();
  const navigate = useNavigate();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadFailed, setLoadFailed] = useState(false);
  const [saving, setSaving] = useState(false);
  const [actionBusyId, setActionBusyId] = useState<number | null>(null);
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'suspended' | 'banned'>('all');
  const [editing, setEditing] = useState<User | null>(null);
  const [creating, setCreating] = useState(false);
  // v0.4.10 PR4: admin password reset state. resetting = the target user row.
  const [resetting, setResetting] = useState<User | null>(null);
  // v1.0.7: admin "edit user plan" panel state. planEditing = the target row;
  // plans = the catalog (for the assign dropdown); planChoice = the selected
  // plan to buy; planExpire = the expiry being edited (treated as UTC).
  const [plans, setPlans] = useState<Plan[]>([]);
  const [planChoice, setPlanChoice] = useState<number | undefined>(undefined);
  const [planExpire, setPlanExpire] = useState<Dayjs | null>(null);
  const [planBusy, setPlanBusy] = useState(false);
  const userBusy = loading || loadFailed || saving || planBusy || actionBusyId !== null;
  const [form] = Form.useForm<UserFormValues>();
  const [createForm] = Form.useForm<CreateUserFormValues>();
  const [resetForm] = Form.useForm<ResetFormValues>();
  const loadGenerationRef = useRef(0);

  // Only admins can create users / delete regular users. v0.4.10: read from
  // AuthContext (server-verified role) instead of localStorage. The backend
  // enforces this independently — this only governs UI affordances. (Users.tsx
  // is itself behind RequireAdmin, so isAdmin is effectively always true here,
  // but we keep the guard for clarity + future reuse.)
  const { isAdmin } = useAuth();

  const load = useCallback(async () => {
    const requestId = ++loadGenerationRef.current;
    Modal.destroyAll();
    setEditing(null);
    setCreating(false);
    setResetting(null);
    setLoading(true);
    setLoadFailed(false);
    try {
      // The plan catalog is required by the embedded plan editor. Do not turn
      // a failed catalog request into an empty selector that looks authoritative.
      const [usersRes, pRes] = await Promise.all([
        api.get<unknown, ApiEnvelope<User[]>>('/admin/users'),
        api.get<unknown, ApiEnvelope<Plan[]>>('/admin/plans'),
      ]);
      if (requestId !== loadGenerationRef.current) return false;
      setUsers(usersRes.data || []);
      setPlans(pRes.data || []);
      return true;
    } catch {
      if (requestId === loadGenerationRef.current) {
        setLoadFailed(true);
        message.error(t('loadFailed'));
      }
      return false;
    } finally {
      if (requestId === loadGenerationRef.current) setLoading(false);
    }
  }, [t]);

  // Resolve a plan id → display name (falls back to #id, or "no plan" for null).
  const planName = (id: number | null): string =>
    id == null ? t('noPlan') : (plans.find(p => p.id === id)?.name ?? `#${id}`);

  // v1.0.8: the editing user's current plan, and two flags that gate the plan
  // panel: only a TIME plan has a meaningful expiry (data plans are "unlimited
  // duration", so the expiry editor is disabled), and "remove plan" only makes
  // sense when the user actually has a plan.
  const editingPlan = editing ? plans.find(p => p.id === editing.plan_id) : undefined;
  const isTimePlan = editingPlan?.plan_type === 'time';
  const hasPlan = editing?.plan_id != null;
  // Selecting the user's current plan again is a RENEW (extend time / add
  // traffic), not a no-op — it's allowed. Show a hint so the admin knows the
  // charge stacks rather than switches.
  const isRenewSamePlan = hasPlan && planChoice != null && planChoice === editing?.plan_id;

  // v1.0.7: plan management is embedded in the edit-user modal, so these act on
  // the `editing` user. Admin assigns a plan, charging the user's balance.
  // v1.0.9: switching to a DIFFERENT plan wipes the user's current traffic +
  // expiry (REPLACE semantics), so confirm first. Renew (same plan) / first
  // assignment proceed directly.
  const handleBuyPlanForUser = () => {
    if (!editing || planChoice == null || userBusy) return;
    const target = editing;
    const selectedPlan = plans.find(plan => plan.id === planChoice);
    if (!selectedPlan) return;
    const doBuy = async () => {
      setPlanBusy(true);
      try {
        const res = await api.post<unknown, ApiEnvelope<null>>(`/admin/users/${target.id}/buy-plan`, {
          plan_id: selectedPlan.id,
          expected_current_plan_id: target.plan_id ?? 0,
          expected_price: selectedPlan.price,
          expected_revision: selectedPlan.purchase_revision,
        });
        if (res.code !== 0) {
          message.error(res.message);
          if (res.code === 409) await load();
          return;
        }
        message.success(t('planAssigned'));
        setEditing(null);
        await load();
      } catch {
        message.error(t('purchaseFailed'));
      } finally { setPlanBusy(false); }
    };
    const isSwitch = target.plan_id != null && planChoice !== target.plan_id;
    if (isSwitch) {
      Modal.confirm({
        title: t('switchPlanConfirmTitle'),
        content: t('adminSwitchPlanWarning'),
        okText: t('assignAndCharge'),
        cancelText: t('cancel'),
        onOk: doBuy,
      });
    } else {
      doBuy();
    }
  };

  // Edit the plan association/expiry without charging. clear=true removes the
  // plan (and revokes device-group authorization on the backend); otherwise
  // keep plan_id and set the expiry (null = never expires).
  const handleSetUserPlan = async (clear: boolean, expire: string | null) => {
    if (!editing || editing.plan_id == null || userBusy) return;
    const target = editing;
    setPlanBusy(true);
    try {
      const res = await api.put<unknown, ApiEnvelope<null>>(`/admin/users/${target.id}/plan`, {
        expected_plan_id: target.plan_id,
        clear,
        plan_expire_at: expire,
      });
      if (res.code !== 0) {
        message.error(res.message);
        if (res.code === 409) await load();
        return;
      }
      message.success(t('userUpdated'));
      setEditing(null);
      await load();
    } catch {
      message.error(t('saveFailed'));
    } finally { setPlanBusy(false); }
  };

  useEffect(() => { load(); }, [load]);

  const filteredUsers = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    return users.filter((u) => {
      const matchesQuery = !needle
        || u.username.toLocaleLowerCase().includes(needle)
        || String(u.id).includes(needle);
      const status = u.banned ? 'banned' : u.suspended ? 'suspended' : 'active';
      return matchesQuery && (statusFilter === 'all' || status === statusFilter);
    });
  }, [query, statusFilter, users]);

  const handleDelete = async (id: number) => {
    if (userBusy) return;
    setActionBusyId(id);
    try {
      const res = await api.delete<unknown, ApiEnvelope<null>>(`/admin/users/${id}`);
      if (res.code !== 0) { message.error(res.message); return; }
      message.success(t('userDeleted'));
      await load();
    } catch {
      message.error(t('deleteFailed'));
    } finally {
      setActionBusyId(null);
    }
  };

  const openEdit = (u: User) => {
    setEditing(u);
    // v1.0.7: preload the embedded plan panel (assign choice + expiry picker).
    setPlanChoice(undefined);
    setPlanExpire(u.plan_expire_at ? dayjs(u.plan_expire_at) : null);
    form.setFieldsValue({
      // InputNumber with stringMode wants a string. Existing rows already have
      // a canonical TEXT-form value (e.g. "12.30"); pass it through unchanged.
      balance: u.balance,
      max_rules: u.max_rules,
      // DB stores bytes; show GB in the form.
      traffic_limit_gb: bytesToGb(u.traffic_limit),
      banned: u.banned,
      suspended: !!u.suspended,
    });
  };

  const handleSave = async () => {
    if (!editing || userBusy) return;
    const values = await form.validateFields().catch(() => null);
    if (!values) return;
    // Trim the balance string and convert empty input to undefined so the
    // backend leaves the column unchanged. The strict validator below ensures
    // we only ever forward a value the backend will accept.
    const balance = typeof values.balance === 'string' ? values.balance.trim() : '';
    const payload: Record<string, unknown> = {
      max_rules: values.max_rules,
      banned: values.banned,
      suspended: values.suspended,
    };
    // The form displays only two decimal places. Do not round-trip an exact
    // byte quota merely because the administrator changed another field.
    if (trafficGbChanged(editing.traffic_limit, values.traffic_limit_gb)) {
      payload.traffic_limit = gbToBytes(values.traffic_limit_gb);
    }
    if (balance !== '') {
      payload.balance = balance;
    }
    // v1.0.8: device-group authorization is owned entirely by the user's plan
    // (buy_plan REPLACEs it). The manual controls were removed from this modal,
    // so this save never touches all_device_groups / device_group_ids — those
    // change only when a plan is assigned/removed.
    setSaving(true);
    try {
      const res = await api.put<unknown, ApiEnvelope<null>>(`/admin/users/${editing.id}`, payload);
      if (res.code !== 0) { message.error(res.message); return; }
      message.success(t('userUpdated'));
      setEditing(null);
      await load();
    } catch {
      message.error(t('saveFailed'));
    } finally { setSaving(false); }
  };

  const openCreate = () => {
    createForm.resetFields();
    setCreating(true);
  };

  const handleCreate = async () => {
    if (userBusy) return;
    const values = await createForm.validateFields().catch(() => null);
    if (!values) return;
    setSaving(true);
    try {
      const res = await api.post<unknown, ApiEnvelope<null>>('/admin/users', {
        username: values.username,
        password: values.password,
      });
      if (res.code !== 0) { message.error(res.message); return; }
      message.success(t('userCreated'));
      setCreating(false);
      await load();
    } catch {
      message.error(t('saveFailed'));
    } finally { setSaving(false); }
  };

  const handleResetTraffic = async (id: number) => {
    if (userBusy) return;
    setActionBusyId(id);
    try {
      const res = await api.post<unknown, ApiEnvelope<null>>(`/admin/users/${id}/reset-traffic`);
      if (res.code !== 0) { message.error(res.message); return; }
      message.success(t('trafficReset'));
      await load();
    } catch {
      message.error(t('saveFailed'));
    } finally {
      setActionBusyId(null);
    }
  };

  // v1.0.8: suspend / unsuspend a user (non-admin only). Stops forwarding via
  // the config gate WITHOUT bumping token_version (the user stays logged in).
  const handleToggleSuspend = async (u: User) => {
    if (userBusy) return;
    setActionBusyId(u.id);
    try {
      const res = await api.put<unknown, ApiEnvelope<null>>(`/admin/users/${u.id}`, {
        suspended: !u.suspended,
      });
      if (res.code !== 0) { message.error(res.message); return; }
      message.success(u.suspended ? t('userUnsuspended') : t('userSuspended'));
      await load();
    } catch {
      message.error(t('saveFailed'));
    } finally {
      setActionBusyId(null);
    }
  };

  // v0.4.10 PR4: open the admin password-reset modal for a user.
  const openReset = (u: User) => {
    setResetting(u);
    resetForm.resetFields();
    // Default: force the user to change this temporary password on next login.
    resetForm.setFieldsValue({ must_change_password: true });
  };

  const handleReset = async () => {
    if (!resetting || userBusy) return;
    const values = await resetForm.validateFields().catch(() => null);
    if (!values) return;
    setSaving(true);
    try {
      const res = await api.put<unknown, ApiEnvelope<null>>(
        `/admin/users/${resetting.id}/password`,
        {
          new_password: values.new_password,
          must_change_password: values.must_change_password,
        }
      );
      if (res.code !== 0) { message.error(res.message); return; }
      message.success(t('passwordResetSuccess'));
      setResetting(null);
    } catch {
      message.error(t('saveFailed'));
    } finally { setSaving(false); }
  };

  const userActionMenu = (u: User): MenuProps => ({
    items: [
      { key: 'rules', icon: <ApiOutlined />, label: t('manageRules'), disabled: userBusy },
      { key: 'reset-traffic', icon: <UndoOutlined />, label: t('resetTraffic'), disabled: userBusy },
      ...(isAdmin && !u.admin ? [
        { type: 'divider' as const },
        { key: 'password', icon: <KeyOutlined />, label: t('resetPassword'), disabled: userBusy },
        { key: 'suspend', label: u.suspended ? t('unsuspend') : t('suspend'), disabled: userBusy },
        { type: 'divider' as const },
        { key: 'delete', icon: <DeleteOutlined />, label: t('delete'), danger: true, disabled: userBusy },
      ] : []),
    ],
    onClick: ({ key }) => {
      if (key === 'rules') {
        navigate(`/rules?owner_uid=${u.id}`);
        return;
      }
      if (key === 'password') {
        openReset(u);
        return;
      }
      if (key === 'reset-traffic') {
        Modal.confirm({
          title: t('resetTrafficConfirm'),
          onOk: () => handleResetTraffic(u.id),
        });
        return;
      }
      if (key === 'suspend') {
        Modal.confirm({
          title: u.suspended ? t('unsuspendConfirm') : t('suspendConfirm'),
          onOk: () => handleToggleSuspend(u),
        });
        return;
      }
      if (key === 'delete') {
        Modal.confirm({
          title: t('deleteUserConfirm'),
          okText: t('delete'),
          okButtonProps: { danger: true },
          onOk: () => handleDelete(u.id),
        });
      }
    },
  });

  const columns = [
    { title: t('id'), dataIndex: 'id', key: 'id', width: 60 },
    { title: t('username'), dataIndex: 'username', key: 'username' },
    {
      title: t('role'), dataIndex: 'admin', key: 'admin',
      render: (a: boolean) => a ? <Tag color="gold">{t('admin')}</Tag> : <Tag>{t('user')}</Tag>,
    },
    {
      // v1.0.8: three-state status — banned (red) > suspended (orange) > active (green).
      title: t('status'), key: 'status',
      render: (_: unknown, u: User) => {
        if (u.banned) return <Tag color="red">{t('banned')}</Tag>;
        if (u.suspended) return <Tag color="orange">{t('suspended')}</Tag>;
        return <Tag color="green">{t('active')}</Tag>;
      },
    },
    { title: t('balance'), dataIndex: 'balance', key: 'balance' },
    {
      title: t('deviceGroupAccess'), dataIndex: 'all_device_groups', key: 'all_device_groups', width: 110,
      render: (all: boolean, u: User) => {
        if (u.admin) return <Tag color="gold">{t('accessAll')}</Tag>;
        return all
          ? <Tag color="green">{t('accessAll')}</Tag>
          : <Tag color="blue">{t('accessLimited')}</Tag>;
      },
    },
    { title: t('maxRules'), dataIndex: 'max_rules', key: 'max_rules' },
    {
      title: t('trafficUsed'), key: 'traffic', width: 200,
      render: (_: unknown, u: User) => {
        const used = u.traffic_used;
        const limit = u.traffic_limit;
        const unlimited = limit === 0;
        const pct = unlimited ? 0 : Math.min(100, Math.round((used / limit) * 100));
        const overQuota = !unlimited && used >= limit;
        const remaining = unlimited ? null : Math.max(0, limit - used);
        return (
          <Tooltip
            title={
              `${t('trafficUsed')}: ${formatBytes(used)}\n` +
              `${t('trafficLimit')}: ${unlimited ? t('unlimited') : formatBytes(limit)}\n` +
              `${t('remaining')}: ${remaining !== null ? formatBytes(remaining) : t('unlimited')}`
            }
          >
            {/* Fixed width + block children: antd's Progress is inline-block,
                so inside a nowrap table cell the usage text used to run onto
                the same line and overlap the next column. */}
            <div style={{ width: 176 }}>
              <Progress
                percent={pct}
                size="small"
                status={overQuota ? 'exception' : 'normal'}
              />
              <div style={{ fontSize: 11, color: 'var(--rp-text-secondary)' }}>
                {formatBytes(used)}
                {' / '}
                {unlimited ? t('unlimited') : formatBytes(limit)}
                {overQuota && <Tag color="red" style={{ marginLeft: 4 }}>{t('overQuota')}</Tag>}
              </div>
            </div>
          </Tooltip>
        );
      },
    },
    { title: t('joined'), dataIndex: 'created_at', key: 'created_at' },
    {
      title: t('action'), key: 'action', width: 115, fixed: 'right' as const,
      render: (_: unknown, u: User) => (
        <Space size={0}>
          <Button icon={<EditOutlined />} size="small" type="text" disabled={userBusy} onClick={() => openEdit(u)}>{t('edit')}</Button>
          <Dropdown menu={userActionMenu(u)} trigger={['click']} placement="bottomRight">
            <Button icon={<MoreOutlined />} size="small" type="text" loading={actionBusyId === u.id} disabled={userBusy && actionBusyId !== u.id} aria-label={t('action')} title={t('action')} />
          </Dropdown>
        </Space>
      ),
    },
  ];

  return (
    <>
      <div className="rp-page-header">
        <h2 className="rp-page-title"><UserOutlined /> {t('users')}</h2>
        <Space className="rp-page-actions" wrap>
          {isAdmin && (
            <Button type="primary" icon={<PlusOutlined />} disabled={userBusy} onClick={openCreate}>{t('addUser')}</Button>
          )}
          <Button icon={<ReloadOutlined />} loading={loading} disabled={saving || planBusy || actionBusyId !== null || !!editing || creating || !!resetting} onClick={load}>{t('refresh')}</Button>
        </Space>
      </div>
      {loadFailed && (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 14 }}
          title={t('loadFailed')}
        />
      )}
      <div className="rp-list-filters">
        <Input
          allowClear
          prefix={<SearchOutlined />}
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder={t('searchUsers')}
          aria-label={t('searchUsers')}
        />
        <Select
          value={statusFilter}
          onChange={setStatusFilter}
          aria-label={t('filterUserStatus')}
          options={[
            { value: 'all', label: t('allStatuses') },
            { value: 'active', label: t('active') },
            { value: 'suspended', label: t('suspended') },
            { value: 'banned', label: t('banned') },
          ]}
        />
      </div>
      <Table className="rp-responsive-table" dataSource={filteredUsers} columns={columns} rowKey="id" loading={loading} pagination={{ pageSize: 20, hideOnSinglePage: true }} scroll={{ x: 'max-content' }} />

      <Modal
        title={editing ? `${t('editUser')}: ${editing.username}` : t('editUser')}
        open={!!editing}
        confirmLoading={saving}
        onOk={handleSave}
        onCancel={() => { if (!saving && !planBusy) setEditing(null); }}
        closable={!saving && !planBusy}
        mask={{ closable: !saving && !planBusy }}
        keyboard={!saving && !planBusy}
        cancelButtonProps={{ disabled: saving || planBusy }}
        okButtonProps={{ disabled: planBusy }}
        okText={t('save')}
        cancelText={t('cancel')}
      >
        <Form form={form} layout="vertical" disabled={saving || planBusy}>
          <Form.Item
            name="balance"
            label={t('balance')}
            tooltip={t('balanceHint')}
            // Rules mirror the backend `parse_balance` checks in
            // crates/shared/src/money.rs. Anything that slips past the form
            // will be rejected by the backend as a 400 — the form check just
            // gives a friendlier inline message before the round-trip.
            rules={[
              { required: true, message: t('balanceRequired') },
              {
                pattern: /^\d+(\.\d{1,2})?$/,
                message: t('balanceInvalid'),
              },
              {
                validator: (_rule, value: string | null | undefined) => {
                  if (!value) return Promise.resolve();
                  // Same cap the backend enforces (9 999 999 999.99).
                  if (value.length > 14 || Number(value) > 9999999999.99) {
                    return Promise.reject(new Error(t('balanceTooLarge')));
                  }
                  return Promise.resolve();
                },
              },
            ]}
          >
            {/*
              stringMode keeps the wire format identical to the DB TEXT
              column and matches the backend parser. precision=2 matches the
              backend's "at most 2 fraction digits" rule.
            */}
            <InputNumber
              stringMode
              min={0}
              max={9999999999.99}
              step={0.01}
              precision={2}
              style={{ width: '100%' }}
              addonBefore={t('balanceUnit')}
              placeholder="0.00"
            />
          </Form.Item>
          <Form.Item
            name="max_rules"
            label={t('maxRules')}
            rules={[{ type: 'number', min: 0, max: 100000, message: t('maxRulesRange') }]}
          >
            <InputNumber min={0} max={100000} precision={0} style={{ width: 200 }} />
          </Form.Item>
          <Form.Item
            name="traffic_limit_gb"
            label={t('trafficLimitGb')}
            tooltip={t('trafficLimitGbHint')}
            rules={[
              { type: 'number', min: 0, message: t('trafficLimitNonNegative') },
              { type: 'number', max: MAX_SAFE_TRAFFIC_GB, message: t('trafficLimitTooLarge') },
            ]}
          >
            <InputNumber min={0} max={MAX_SAFE_TRAFFIC_GB} step={1} style={{ width: '100%' }} addonAfter="GB" />
          </Form.Item>
          <Form.Item name="banned" label={t('banned')} valuePropName="checked">
            <Switch disabled={!!editing?.admin} />
          </Form.Item>
          {/* v1.0.8: suspension toggle (admin can't be suspended). */}
          <Form.Item name="suspended" label={t('suspended')} valuePropName="checked" tooltip={t('suspendedHint')}>
            <Switch disabled={!!editing?.admin} />
          </Form.Item>
          {/* v1.0.8: the manual device-group controls (allow-all switch +
              multi-select) were removed — device-group authorization is owned
              entirely by the user's plan (assign/remove a plan in the panel
              below). This avoids the two-way conflict where a manual edit and a
              plan purchase silently overwrote each other. */}
        </Form>

        {/* v1.0.7: plan management embedded in the edit-user modal (non-admin
            only). Assign a plan (charges balance), adjust expiry, or remove the
            plan. These act outside the form and refresh the list on success. */}
        {editing && !editing.admin && (
          <>
            <Divider style={{ margin: '8px 0 16px' }} />
            <div style={{ marginBottom: 8 }}>
              <strong><ShoppingOutlined /> {t('editUserPlan')}</strong>
            </div>
            <p style={{ marginTop: 0 }}>
              <strong>{t('currentPlan')}:</strong> {planName(editing.plan_id)}
              <span style={{ marginLeft: 16 }}>
                <strong>{t('planExpiry')}:</strong> {editing.plan_expire_at || t('neverExpires')}
              </span>
            </p>

            <div style={{ marginBottom: 4 }}><strong>{t('assignPlan')}</strong></div>
            <Space.Compact style={{ width: '100%' }}>
              <Select
                style={{ flex: 1 }}
                placeholder={t('selectPlan')}
                value={planChoice}
                onChange={setPlanChoice}
                disabled={userBusy}
                options={plans.map(p => ({
                  value: p.id,
                  label: `${p.name} · ${p.price} · ${p.plan_type === 'time' ? `${p.duration_days}${t('days')}` : t('planTypeData')}`,
                }))}
              />
              <Button type="primary" loading={planBusy} disabled={userBusy || planChoice == null} onClick={handleBuyPlanForUser}>
                {isRenewSamePlan ? t('renewAndCharge') : t('assignAndCharge')}
              </Button>
            </Space.Compact>

            {isTimePlan && (
              <>
                <Divider style={{ margin: '12px 0' }} />
                <div style={{ marginBottom: 8 }}>
                  <strong>{t('editExpiry')}</strong>
                  <span style={{ color: '#999', fontSize: 12, marginLeft: 6 }}>(UTC)</span>
                </div>
                <Space wrap>
                  <DatePicker showTime disabled={userBusy} value={planExpire} onChange={setPlanExpire} placeholder={t('neverExpires')} />
                  <Button loading={planBusy} disabled={userBusy} onClick={() => handleSetUserPlan(false, planExpire ? planExpire.format('YYYY-MM-DD HH:mm:ss') : null)}>
                    {t('saveExpiry')}
                  </Button>
                  <Button loading={planBusy} disabled={userBusy} onClick={() => { setPlanExpire(null); handleSetUserPlan(false, null); }}>
                    {t('setNeverExpires')}
                  </Button>
                </Space>
              </>
            )}

            <Divider style={{ margin: '12px 0' }} />

            {/* v1.0.8: "remove plan" is only enabled when the user actually has
                a plan — you can't remove what isn't there. */}
            <Popconfirm title={t('removePlanConfirm')} disabled={userBusy || !hasPlan} onConfirm={() => handleSetUserPlan(true, null)}>
              <Button danger loading={planBusy} disabled={userBusy || !hasPlan}>{t('removePlan')}</Button>
            </Popconfirm>
          </>
        )}
      </Modal>

      <Modal
        title={t('addUser')}
        open={creating}
        confirmLoading={saving}
        onOk={handleCreate}
        onCancel={() => { if (!saving) setCreating(false); }}
        closable={!saving}
        mask={{ closable: !saving }}
        keyboard={!saving}
        cancelButtonProps={{ disabled: saving }}
        okText={t('create')}
        cancelText={t('cancel')}
      >
        <Form form={createForm} layout="vertical">
          <Form.Item
            name="username"
            label={t('username')}
            tooltip={t('createUsernameHint')}
            rules={[
              { required: true, message: t('createUsernameRequired') },
              {
                pattern: /^[A-Za-z0-9_]{1,64}$/,
                message: t('createUsernameInvalid'),
              },
            ]}
          >
            <Input autoComplete="off" placeholder="username" />
          </Form.Item>
          <Form.Item
            name="password"
            label={t('password')}
            tooltip={t('createPasswordHint')}
            rules={[
              { required: true, message: t('createPasswordRequired') },
              { validator: makePasswordValidator(t('createPasswordTooShort'), t('passwordTooLong')) },
            ]}
          >
            <Input.Password autoComplete="new-password" placeholder="••••••" />
          </Form.Item>
        </Form>
      </Modal>

      {/* v0.4.10 PR4: admin password reset modal. */}
      <Modal
        title={resetting ? `${t('resetPassword')}: ${resetting.username}` : t('resetPassword')}
        open={!!resetting}
        confirmLoading={saving}
        onOk={handleReset}
        onCancel={() => { if (!saving) setResetting(null); }}
        closable={!saving}
        mask={{ closable: !saving }}
        keyboard={!saving}
        cancelButtonProps={{ disabled: saving }}
        okText={t('confirmReset')}
        cancelText={t('cancel')}
        okButtonProps={{ danger: true }}
      >
        <p style={{ color: '#cf1322', fontSize: 13, marginTop: 0 }}>
          {t('resetPasswordWarning')}
        </p>
        <Form form={resetForm} layout="vertical">
          <Form.Item
            name="new_password"
            label={t('temporaryPassword')}
            rules={[
              { required: true, message: t('passwordRequired') },
              { validator: makePasswordValidator(t('passwordTooShort'), t('passwordTooLong')) },
            ]}
          >
            <Input.Password autoComplete="new-password" placeholder="••••••••" />
          </Form.Item>
          <Form.Item
            name="confirm_password"
            label={t('confirmPassword')}
            dependencies={['new_password']}
            rules={[
              { required: true, message: t('confirmPasswordRequired') },
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
          <Form.Item
            name="must_change_password"
            label={t('mustChangePasswordNext')}
            valuePropName="checked"
          >
            <Switch />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
}
