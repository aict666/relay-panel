import { Table, Button, Modal, Form, Input, Select, Switch, Space, message, Popconfirm, Typography, Tag } from 'antd';
import { PlusOutlined, ReloadOutlined, EditOutlined, DeleteOutlined } from '@ant-design/icons';
import { useCallback, useEffect, useState } from 'react';
import api from '../api/client';
import type { ApiEnvelope, DeviceGroup } from '../api/types';
import { useI18n } from '../i18n/context';

const { Text } = Typography;

interface UserGroup {
  id: number;
  name: string;
  remark: string;
  allow_all_groups: boolean;
  created_at: string;
}

export default function UserGroups() {
  const { t } = useI18n();
  const [groups, setGroups] = useState<UserGroup[]>([]);
  const [deviceGroups, setDeviceGroups] = useState<DeviceGroup[]>([]);
  const [loading, setLoading] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [deviceGroupsOpen, setDeviceGroupsOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [editing, setEditing] = useState<UserGroup | null>(null);
  const [assigningGroupId, setAssigningGroupId] = useState<number | null>(null);
  const [createForm] = Form.useForm();
  const [editForm] = Form.useForm();
  const [assignForm] = Form.useForm();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const g = await api.get<unknown, ApiEnvelope<UserGroup[]>>('/user-groups');
      setGroups(g.data || []);
      const d = await api.get<unknown, ApiEnvelope<DeviceGroup[]>>('/groups');
      setDeviceGroups((d.data || []).filter(dg => dg.group_type === 'in'));
    } catch { /* ignore */ }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async (values: { name: string; remark?: string; allow_all_groups?: boolean }) => {
    const res = await api.post<unknown, ApiEnvelope<UserGroup>>('/user-groups', values);
    if (res.code !== 0) { message.error(res.message); return; }
    message.success(t('settingsSaved'));
    setCreateOpen(false);
    createForm.resetFields();
    load();
  };

  const handleEdit = (g: UserGroup) => {
    setEditing(g);
    editForm.setFieldsValue({ name: g.name, remark: g.remark, allow_all_groups: g.allow_all_groups });
    setEditOpen(true);
  };

  const handleUpdate = async (values: { name?: string; remark?: string; allow_all_groups?: boolean }) => {
    if (!editing) return;
    const res = await api.put<unknown, ApiEnvelope<UserGroup>>(`/user-groups/${editing.id}`, values);
    if (res.code !== 0) { message.error(res.message); return; }
    message.success(t('settingsSaved'));
    setEditOpen(false);
    load();
  };

  const handleDelete = async (id: number) => {
    try {
      const res = await api.delete<unknown, ApiEnvelope<null>>(`/user-groups/${id}`);
      if (res.code !== 0) { message.error(res.message); return; }
      message.success(t('groupDeleted'));
      load();
    } catch (e: unknown) {
      const err = e as { response?: { data?: { message?: string } } };
      message.error(err?.response?.data?.message || t('failedDeleteGroup'));
    }
  };

  const handleAssignDeviceGroups = async (g: UserGroup) => {
    setAssigningGroupId(g.id);
    const res = await api.get<unknown, ApiEnvelope<number[]>>(`/user-groups/${g.id}/device-groups`);
    const ids = res.data || [];
    assignForm.setFieldsValue({ device_group_ids: ids });
    setDeviceGroupsOpen(true);
  };

  const handleSaveAssignments = async () => {
    if (assigningGroupId == null) return;
    const values = await assignForm.validateFields();
    const res = await api.put<unknown, ApiEnvelope<null>>(
      `/user-groups/${assigningGroupId}/device-groups`,
      { device_group_ids: values.device_group_ids || [] }
    );
    if (res.code !== 0) { message.error(res.message); return; }
    message.success(t('settingsSaved'));
    setDeviceGroupsOpen(false);
  };

  const columns = [
    { title: 'ID', dataIndex: 'id', key: 'id', width: 60 },
    { title: t('name'), dataIndex: 'name', key: 'name' },
    { title: t('remark'), dataIndex: 'remark', key: 'remark', render: (v: string) => v || '-' },
    { title: t('allowAllGroups'), dataIndex: 'allow_all_groups', key: 'allow_all_groups', width: 120,
      render: (v: boolean) => v ? <Tag color="green">{t('yes')}</Tag> : <Tag>{t('no')}</Tag> },
    {
      title: t('action'), key: 'action', width: 200,
      render: (_: unknown, g: UserGroup) => (
        <Space>
          <Button size="small" type="text" icon={<EditOutlined />} onClick={() => handleEdit(g)}>{t('edit')}</Button>
          <Button size="small" type="text" onClick={() => handleAssignDeviceGroups(g)}>{t('assignDeviceGroups')}</Button>
          <Popconfirm title={t('deleteGroupConfirm')} onConfirm={() => handleDelete(g.id)}>
            <Button danger size="small" type="text" icon={<DeleteOutlined />} />
          </Popconfirm>
        </Space>
      ),
    },
  ];

  const inGroups = deviceGroups.map(d => ({ value: d.id, label: `${d.name} (#${d.id})` }));

  return (
    <>
      <div className="rp-page-header">
        <h2 className="rp-page-title">{t('userGroups')}</h2>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={load}>{t('refresh')}</Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => { createForm.resetFields(); setCreateOpen(true); }}>{t('addUserGroup')}</Button>
        </Space>
      </div>
      <Table dataSource={groups} columns={columns} rowKey="id" loading={loading} pagination={{ pageSize: 20 }} />

      <Modal title={t('addUserGroup')} open={createOpen} onCancel={() => setCreateOpen(false)} onOk={() => createForm.submit()} okText={t('create')}>
        <Form form={createForm} onFinish={handleCreate} layout="vertical" initialValues={{ allow_all_groups: false }}>
          <Form.Item name="name" label={t('name')} rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="remark" label={t('remark')}><Input.TextArea rows={2} /></Form.Item>
          <Form.Item name="allow_all_groups" label={t('allowAllGroups')} valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>

      <Modal title={t('editUserGroup')} open={editOpen} onCancel={() => setEditOpen(false)} onOk={() => editForm.submit()} okText={t('save')}>
        <Form form={editForm} onFinish={handleUpdate} layout="vertical">
          <Form.Item name="name" label={t('name')} rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="remark" label={t('remark')}><Input.TextArea rows={2} /></Form.Item>
          <Form.Item name="allow_all_groups" label={t('allowAllGroups')} valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>

      <Modal title={t('assignDeviceGroups')} open={deviceGroupsOpen} onCancel={() => setDeviceGroupsOpen(false)} onOk={handleSaveAssignments} okText={t('save')} width={500}>
        <Form form={assignForm} layout="vertical">
          <Form.Item name="device_group_ids" label={t('allowedInboundGroups')}>
            <Select mode="multiple" options={inGroups} placeholder={t('selectDeviceGroups')} />
          </Form.Item>
          <Text type="secondary" style={{ fontSize: 12 }}>{t('assignDeviceGroupsHint')}</Text>
        </Form>
      </Modal>
    </>
  );
}
