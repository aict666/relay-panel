import { Table, Button, Modal, Form, Input, InputNumber, Select, Switch, Space, message, Popconfirm, Typography, Tag } from 'antd';
import { PlusOutlined, ReloadOutlined, EditOutlined, ShoppingOutlined } from '@ant-design/icons';
import { useCallback, useEffect, useState } from 'react';
import api from '../api/client';
import type { ApiEnvelope, Plan, DeviceGroup, Tunnel } from '../api/types';
import { useI18n } from '../i18n/context';
import { formatBytes } from '../utils/format';

const { Text } = Typography;

// Traffic is stored in BYTES, but the admin form works in GB (a raw byte count
// is unfriendly to type). Convert only at the form boundary — storage stays
// byte-based. 0 GB = unlimited.
const BYTES_PER_GB = 1024 * 1024 * 1024;
const bytesToGb = (b: number): number => (b > 0 ? Math.round((b / BYTES_PER_GB) * 100) / 100 : 0);
const gbToBytes = (gb: number): number => Math.round((gb || 0) * BYTES_PER_GB);

/**
 * v1.0.8: admin plan management (CRUD). GET /admin/plans lists ALL plans
 * (including hidden). Create/Update validate name, traffic≥0, price (decimal),
 * and duration_days>0 for time plans. Delete is blocked (409) when any user's
 * plan_id still references the plan.
 */
export default function Plans() {
  const { t } = useI18n();
  const [plans, setPlans] = useState<Plan[]>([]);
  const [groups, setGroups] = useState<DeviceGroup[]>([]);
  const [tunnels, setTunnels] = useState<Tunnel[]>([]);
  const [loading, setLoading] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [editing, setEditing] = useState<Plan | null>(null);
  const [createForm] = Form.useForm();
  const [editForm] = Form.useForm();
  // v1.0.9: when the "grant all groups" switch is on, the device-group
  // multi-select is disabled (the explicit list is moot). Tracked per-form.
  const [createGrantAll, setCreateGrantAll] = useState(false);
  const [editGrantAll, setEditGrantAll] = useState(false);
  // Duration only applies to time plans — the buy path forces duration_days=0
  // for data plans (see shop.rs). Watch plan_type so the form hides the
  // duration field for data plans instead of offering a no-op input.
  const createPlanType = Form.useWatch('plan_type', createForm);
  const editPlanType = Form.useWatch('plan_type', editForm);
  const createGroupIds = Form.useWatch('device_group_ids', createForm) as number[] | undefined;
  const editGroupIds = Form.useWatch('device_group_ids', editForm) as number[] | undefined;

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [plansRes, groupsRes, tunnelsRes] = await Promise.all([
        api.get<unknown, ApiEnvelope<Plan[]>>('/admin/plans'),
        api.get<unknown, ApiEnvelope<DeviceGroup[]>>('/groups'),
        api.get<unknown, ApiEnvelope<Tunnel[]>>('/admin/tunnels'),
      ]);
      setPlans(plansRes.data || []);
      // Only inbound-capable groups are meaningful as plan grants. A `both`
      // group can be a rule entry and therefore belongs in this list too.
      setGroups((groupsRes.data || []).filter((g) => g.group_type === 'in' || g.group_type === 'both'));
      setTunnels(tunnelsRes.data || []);
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Map device-group ids → a readable label for the table summary.
  const groupName = useCallback(
    (id: number) => groups.find((g) => g.id === id)?.name ?? `#${id}`,
    [groups],
  );

  // Tunnel access deliberately follows the existing line authorization model:
  // a user can select a shared tunnel only when their plan grants its entry
  // group. Surface that derived set here so the effective permission is no
  // longer hidden from administrators.
  const grantedTunnels = useCallback((grantAll: boolean, groupIds: number[]) => {
    const allowed = new Set(groupIds);
    return tunnels.filter((tunnel) => {
      const entryGroupId = tunnel.hops[0]?.device_group_id;
      return tunnel.shared && entryGroupId != null && (grantAll || allowed.has(entryGroupId));
    });
  }, [tunnels]);

  const tunnelGrantPreview = (grantAll: boolean, groupIds: number[]) => {
    const granted = grantedTunnels(grantAll, groupIds);
    return (
      <div className="rp-plan-tunnel-grants">
        {granted.length > 0 ? granted.map((tunnel) => (
          <Tag key={tunnel.id} color={tunnel.enabled ? 'geekblue' : 'default'}>
            {tunnel.name}{tunnel.enabled ? '' : ` · ${t('disabled')}`}
          </Tag>
        )) : <Text type="secondary">-</Text>}
      </div>
    );
  };

  const handleCreate = async (values: {
    name: string; max_rules: number; traffic_gb: number; price: string;
    plan_type: string; duration_days: number; hidden: boolean;
    reset_traffic: boolean; description: string;
    grant_all_groups?: boolean; device_group_ids?: number[];
  }) => {
    try {
      const { traffic_gb, ...rest } = values;
      const res = await api.post<unknown, ApiEnvelope<number>>('/admin/plans', {
        ...rest,
        traffic: gbToBytes(traffic_gb),
        grant_all_groups: !!values.grant_all_groups,
        // When granting all, the explicit list is moot — send [] to keep it clean.
        device_group_ids: values.grant_all_groups ? [] : (values.device_group_ids || []),
      });
      if (res.code !== 0) { message.error(res.message); return; }
      message.success(t('planCreated'));
      setCreateOpen(false);
      createForm.resetFields();
      load();
    } catch { message.error(t('failedCreatePlan')); }
  };

  const handleEdit = (p: Plan) => {
    setEditing(p);
    setEditGrantAll(!!p.grant_all_groups);
    editForm.setFieldsValue({
      name: p.name, max_rules: p.max_rules, traffic_gb: bytesToGb(p.traffic), price: p.price,
      plan_type: p.plan_type || 'data', duration_days: p.duration_days || 0,
      hidden: !!p.hidden, reset_traffic: !!p.reset_traffic, description: p.description || '',
      grant_all_groups: !!p.grant_all_groups, device_group_ids: p.device_group_ids || [],
    });
    setEditOpen(true);
  };

  const handleUpdate = async (values: {
    name?: string; max_rules?: number; traffic_gb?: number; price?: string;
    plan_type?: string; duration_days?: number; hidden?: boolean;
    reset_traffic?: boolean; description?: string;
    grant_all_groups?: boolean; device_group_ids?: number[];
  }) => {
    if (!editing) return;
    const payload: Record<string, unknown> = {};
    if (values.name !== undefined && values.name !== editing.name) payload.name = values.name;
    if (values.max_rules !== undefined && values.max_rules !== editing.max_rules) payload.max_rules = values.max_rules;
    if (values.traffic_gb !== undefined && gbToBytes(values.traffic_gb) !== editing.traffic) payload.traffic = gbToBytes(values.traffic_gb);
    if (values.price !== undefined && values.price !== editing.price) payload.price = values.price;
    if (values.plan_type !== undefined && values.plan_type !== (editing.plan_type || 'data')) payload.plan_type = values.plan_type;
    if (values.duration_days !== undefined && values.duration_days !== (editing.duration_days || 0)) payload.duration_days = values.duration_days;
    if (values.hidden !== undefined && values.hidden !== !!editing.hidden) payload.hidden = values.hidden;
    if (values.reset_traffic !== undefined && values.reset_traffic !== !!editing.reset_traffic) payload.reset_traffic = values.reset_traffic;
    if (values.description !== undefined && values.description !== (editing.description || '')) payload.description = values.description;
    if (values.grant_all_groups !== undefined && values.grant_all_groups !== !!editing.grant_all_groups) payload.grant_all_groups = values.grant_all_groups;
    // v1.0.9: always send the device-group set (REPLACE semantics). When
    // grant_all is on, send [] so flipping it off later starts from a clean set.
    const newIds = values.grant_all_groups ? [] : (values.device_group_ids || []);
    const oldIds = [...(editing.device_group_ids || [])].sort((a, b) => a - b);
    const sortedNew = [...newIds].sort((a, b) => a - b);
    if (JSON.stringify(oldIds) !== JSON.stringify(sortedNew)) payload.device_group_ids = newIds;
    if (Object.keys(payload).length === 0) { setEditOpen(false); return; }
    try {
      const res = await api.put<unknown, ApiEnvelope<null>>(`/admin/plans/${editing.id}`, payload);
      if (res.code !== 0) { message.error(res.message); return; }
      message.success(t('planUpdated'));
      setEditOpen(false);
      load();
    } catch { message.error(t('failedUpdatePlan')); }
  };

  const handleDelete = async (id: number) => {
    try {
      const res = await api.delete<unknown, ApiEnvelope<null>>(`/admin/plans/${id}`);
      if (res.code !== 0) {
        message.error(res.code === 409 ? (res.message || t('planInUse')) : (res.message || t('failedDeletePlan')));
        return;
      }
      message.success(t('planDeleted'));
      load();
    } catch {
      message.error(t('failedDeletePlan'));
    }
  };

  const openCreate = () => {
    createForm.resetFields();
    setCreateGrantAll(false);
    setCreateOpen(true);
  };

  const columns = [
    { title: t('id'), dataIndex: 'id', key: 'id', width: 60 },
    { title: t('name'), dataIndex: 'name', key: 'name' },
    {
      title: t('type'), dataIndex: 'plan_type', key: 'plan_type', width: 90,
      render: (pt: string) => <Tag color={pt === 'time' ? 'purple' : 'blue'}>{pt === 'time' ? t('planTypeTime') : t('planTypeData')}</Tag>,
    },
    {
      title: t('planTraffic'), dataIndex: 'traffic', key: 'traffic',
      render: (v: number) => v > 0 ? formatBytes(v) : t('unlimited'),
    },
    { title: t('planMaxRules'), dataIndex: 'max_rules', key: 'max_rules', width: 90 },
    { title: t('planDuration'), key: 'duration', width: 100, render: (_: unknown, p: Plan) => p.duration_days ? `${p.duration_days} ${t('days')}` : '-' },
    {
      // v1.0.9: device groups this plan grants on purchase.
      title: t('planGrantGroups'), key: 'grant_groups', width: 160,
      render: (_: unknown, p: Plan) => {
        if (p.grant_all_groups) return <Tag color="gold">{t('planGrantAll')}</Tag>;
        const ids = p.device_group_ids || [];
        if (ids.length === 0) return <Text type="secondary">-</Text>;
        return <span>{ids.map(groupName).join(', ')}</span>;
      },
    },
    {
      title: t('planGrantTunnels'), key: 'grant_tunnels', width: 180,
      render: (_: unknown, p: Plan) => {
        const granted = grantedTunnels(!!p.grant_all_groups, p.device_group_ids || []);
        if (granted.length === 0) return <Text type="secondary">-</Text>;
        const names = granted.map((tunnel) => tunnel.name).join(', ');
        return <Text ellipsis={{ tooltip: names }}>{names}</Text>;
      },
    },
    { title: t('planPrice'), dataIndex: 'price', key: 'price', render: (v: string) => <span className="rp-mono">{v}</span> },
    {
      title: t('planHidden'), dataIndex: 'hidden', key: 'hidden', width: 80,
      render: (h: boolean) => h ? <Tag>{t('yes')}</Tag> : <Text type="secondary">{t('no')}</Text>,
    },
    {
      title: t('action'), key: 'action', width: 120,
      render: (_: unknown, p: Plan) => (
        <Space>
          <Button size="small" type="text" icon={<EditOutlined />} onClick={() => handleEdit(p)}>{t('edit')}</Button>
          <Popconfirm title={t('deletePlanConfirm')} onConfirm={() => handleDelete(p.id)}>
            <Button danger size="small" type="text">{t('delete')}</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <>
      <div className="rp-page-header">
        <h2 className="rp-page-title"><ShoppingOutlined /> {t('planManagement')}</h2>
        <Space className="rp-page-actions" wrap>
          <Button icon={<ReloadOutlined />} onClick={load}>{t('refresh')}</Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>{t('addPlan')}</Button>
        </Space>
      </div>
      <Table className="rp-responsive-table" dataSource={plans} columns={columns} rowKey="id" loading={loading} pagination={{ pageSize: 20 }} scroll={{ x: 'max-content' }} />

      <Modal title={t('addPlan')} open={createOpen} onCancel={() => setCreateOpen(false)} onOk={() => createForm.submit()} okText={t('create')} cancelText={t('cancel')} width={520}>
        <Form form={createForm} onFinish={handleCreate} layout="vertical" initialValues={{ plan_type: 'data', duration_days: 0, hidden: false, reset_traffic: false, description: '', grant_all_groups: false, device_group_ids: [] }}>
          <Form.Item name="name" label={t('name')} rules={[{ required: true }]}><Input placeholder="Pro 100GB" /></Form.Item>
          <Form.Item name="plan_type" label={t('type')} rules={[{ required: true }]}>
            <Select
              options={[{ value: 'data', label: t('planTypeData') }, { value: 'time', label: t('planTypeTime') }]}
              onChange={(v) => { if (v === 'data') createForm.setFieldValue('duration_days', 0); }}
            />
          </Form.Item>
          <Space align="start" style={{ display: 'flex' }}>
            <Form.Item name="traffic_gb" label={t('planTrafficGb')} rules={[{ required: true }]} style={{ flex: 1 }} extra={t('planTrafficGbHint')}>
              <InputNumber min={0} step={1} style={{ width: '100%' }} addonAfter="GB" />
            </Form.Item>
            <Form.Item name="max_rules" label={t('planMaxRules')} rules={[{ required: true }]} initialValue={5} style={{ flex: 1 }}>
              <InputNumber min={0} max={100000} style={{ width: '100%' }} />
            </Form.Item>
          </Space>
          <Space align="start" style={{ display: 'flex' }}>
            <Form.Item name="price" label={t('planPrice')} rules={[{ required: true }]} style={{ flex: 1 }}>
              <Input placeholder="9.99" />
            </Form.Item>
            {createPlanType === 'time' && (
              <Form.Item name="duration_days" label={t('planDuration')} rules={[{ required: true, type: 'number', min: 1, message: t('planDurationHint') }]} style={{ flex: 1 }} extra={t('planDurationHint')}>
                <InputNumber min={1} style={{ width: '100%' }} />
              </Form.Item>
            )}
          </Space>
          {/* v1.0.9: device-group grants. The switch disables the multi-select. */}
          <Form.Item name="grant_all_groups" label={t('planGrantAll')} valuePropName="checked" extra={t('planGrantAllHint')}>
            <Switch onChange={setCreateGrantAll} />
          </Form.Item>
          <Form.Item name="device_group_ids" label={t('planGrantGroups')} extra={t('planGrantGroupsHint')}>
            <Select
              mode="multiple"
              allowClear
              disabled={createGrantAll}
              placeholder={t('planGrantGroupsPlaceholder')}
              options={groups.map((g) => ({ value: g.id, label: g.name }))}
            />
          </Form.Item>
          <Form.Item label={t('planGrantTunnels')}>
            {tunnelGrantPreview(createGrantAll, createGroupIds || [])}
          </Form.Item>
          <Space align="start" style={{ display: 'flex' }}>
            <Form.Item name="hidden" label={t('planHidden')} valuePropName="checked" style={{ flex: 1 }}>
              <Switch />
            </Form.Item>
            <Form.Item name="reset_traffic" label={t('planResetTraffic')} valuePropName="checked" style={{ flex: 1 }} extra={t('planResetTrafficHint')}>
              <Switch />
            </Form.Item>
          </Space>
          <Form.Item name="description" label={t('planDescription')}><Input.TextArea rows={2} /></Form.Item>
        </Form>
      </Modal>

      <Modal title={t('editPlan')} open={editOpen} onCancel={() => setEditOpen(false)} onOk={() => editForm.submit()} okText={t('save')} cancelText={t('cancel')} width={520}>
        <Form form={editForm} onFinish={handleUpdate} layout="vertical">
          <Form.Item name="name" label={t('name')}><Input /></Form.Item>
          <Form.Item name="plan_type" label={t('type')}>
            <Select
              options={[{ value: 'data', label: t('planTypeData') }, { value: 'time', label: t('planTypeTime') }]}
              onChange={(v) => { if (v === 'data') editForm.setFieldValue('duration_days', 0); }}
            />
          </Form.Item>
          <Space align="start" style={{ display: 'flex' }}>
            <Form.Item name="traffic_gb" label={t('planTrafficGb')} style={{ flex: 1 }} extra={t('planTrafficGbHint')}>
              <InputNumber min={0} step={1} style={{ width: '100%' }} addonAfter="GB" />
            </Form.Item>
            <Form.Item name="max_rules" label={t('planMaxRules')} style={{ flex: 1 }}>
              <InputNumber min={0} max={100000} style={{ width: '100%' }} />
            </Form.Item>
          </Space>
          <Space align="start" style={{ display: 'flex' }}>
            <Form.Item name="price" label={t('planPrice')} style={{ flex: 1 }}><Input /></Form.Item>
            {editPlanType === 'time' && (
              <Form.Item name="duration_days" label={t('planDuration')} rules={[{ required: true, type: 'number', min: 1, message: t('planDurationHint') }]} style={{ flex: 1 }} extra={t('planDurationHint')}>
                <InputNumber min={1} style={{ width: '100%' }} />
              </Form.Item>
            )}
          </Space>
          {/* v1.0.9: device-group grants. */}
          <Form.Item name="grant_all_groups" label={t('planGrantAll')} valuePropName="checked" extra={t('planGrantAllHint')}>
            <Switch onChange={setEditGrantAll} />
          </Form.Item>
          <Form.Item name="device_group_ids" label={t('planGrantGroups')} extra={t('planGrantGroupsHint')}>
            <Select
              mode="multiple"
              allowClear
              disabled={editGrantAll}
              placeholder={t('planGrantGroupsPlaceholder')}
              options={groups.map((g) => ({ value: g.id, label: g.name }))}
            />
          </Form.Item>
          <Form.Item label={t('planGrantTunnels')}>
            {tunnelGrantPreview(editGrantAll, editGroupIds || [])}
          </Form.Item>
          <Space align="start" style={{ display: 'flex' }}>
            <Form.Item name="hidden" label={t('planHidden')} valuePropName="checked" style={{ flex: 1 }}><Switch /></Form.Item>
            <Form.Item name="reset_traffic" label={t('planResetTraffic')} valuePropName="checked" style={{ flex: 1 }}><Switch /></Form.Item>
          </Space>
          <Form.Item name="description" label={t('planDescription')}><Input.TextArea rows={2} /></Form.Item>
        </Form>
      </Modal>
    </>
  );
}
