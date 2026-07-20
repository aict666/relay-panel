import {
  Alert, Button, Card, Form, Input, InputNumber, List, Modal, Popconfirm,
  Select, Space, Switch, Table, Tag, Tooltip, Typography, message, Grid,
} from 'antd';
import {
  ApiOutlined, DeleteOutlined, EditOutlined, PlusOutlined, QuestionCircleOutlined, ReloadOutlined,
} from '@ant-design/icons';
import { useCallback, useEffect, useMemo, useState } from 'react';
import api from '../api/client';
import type { ApiEnvelope, DeviceGroup, Tunnel } from '../api/types';
import { useI18n } from '../i18n/context';
import { tunnelPathChanged, tunnelPathSnapshot, tunnelScalarChanges } from '../utils/tunnels';

const { Text } = Typography;

interface HopFormValue {
  device_group_id?: number;
  port_mode?: 'auto' | 'fixed';
  listen_port?: number;
}

interface TunnelFormValue {
  name: string;
  enabled: boolean;
  shared: boolean;
  hops: HopFormValue[];
}

export default function Tunnels() {
  const { t } = useI18n();
  const screens = Grid.useBreakpoint();
  const mobile = !screens.md;
  const [tunnels, setTunnels] = useState<Tunnel[]>([]);
  const [groups, setGroups] = useState<DeviceGroup[]>([]);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<Tunnel | null>(null);
  const [form] = Form.useForm<TunnelFormValue>();
  const watchedHops = Form.useWatch('hops', form) ?? [];
  const watchedShared = Form.useWatch('shared', form) ?? false;

  const load = useCallback(async () => {
    setLoading(true);
    setTunnels([]);
    setGroups([]);
    try {
      const [tr, gr] = await Promise.all([
        api.get<unknown, ApiEnvelope<Tunnel[]>>('/admin/tunnels'),
        api.get<unknown, ApiEnvelope<DeviceGroup[]>>('/groups'),
      ]);
      setTunnels(tr.data ?? []);
      setGroups(gr.data ?? []);
    } catch {
      message.error(t('loadFailed'));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => { load(); }, [load]);

  const groupMap = useMemo(() => new Map(groups.map(group => [group.id, group])), [groups]);
  const entryGroups = groups.filter(group => group.group_type === 'in' || group.group_type === 'both');
  const relayGroups = groups.filter(group => group.group_type !== 'monitor' && !!group.connect_host);
  const selectedGroupIds = watchedHops.map(hop => hop?.device_group_id).filter(Boolean) as number[];
  const oldEntry = editing?.hops[0]
    ? groupMap.get(editing.hops[0].device_group_id)
    : undefined;
  const newEntry = watchedHops[0]?.device_group_id
    ? groupMap.get(watchedHops[0].device_group_id!)
    : undefined;

  const beginCreate = () => {
    setEditing(null);
    form.resetFields();
    form.setFieldsValue({
      name: '',
      enabled: true,
      shared: false,
      hops: [
        { port_mode: 'auto' },
        { port_mode: 'auto' },
      ],
    });
    setOpen(true);
  };

  const beginEdit = (tunnel: Tunnel) => {
    setEditing(tunnel);
    form.resetFields();
    form.setFieldsValue({
      name: tunnel.name,
      enabled: tunnel.enabled,
      shared: tunnel.shared,
      // Automatic entries preserve the allocated port when their group stays
      // at the same route position. An administrator can switch to fixed and
      // type a replacement explicitly.
      hops: tunnel.hops.map(hop => ({
        device_group_id: hop.device_group_id,
        port_mode: 'auto',
        listen_port: hop.listen_port ?? undefined,
      })),
    });
    setOpen(true);
  };

  const submit = async (values: TunnelFormValue) => {
    const ids = values.hops.map(hop => hop.device_group_id);
    if (new Set(ids).size !== ids.length) {
      message.error(t('tunnelDuplicateHop'));
      return;
    }
    const hops = values.hops.map((hop, position) => ({
      device_group_id: hop.device_group_id,
      listen_port: position === 0 || hop.port_mode !== 'fixed'
        ? null
        : (hop.listen_port ?? null),
    }));
    const pathChanged = editing ? tunnelPathChanged(editing, values.hops) : true;
    try {
      const response = editing
        ? await api.put<unknown, ApiEnvelope<Tunnel>>(`/admin/tunnels/${editing.id}`, {
          ...tunnelScalarChanges(editing, values),
          ...(pathChanged ? { hops, expected_hops: tunnelPathSnapshot(editing) } : {}),
        })
        : await api.post<unknown, ApiEnvelope<Tunnel>>('/admin/tunnels', { ...values, hops });
      if (response.code !== 0 || !response.data) {
        message.error(response.message);
        return;
      }
      message.success(editing ? t('tunnelUpdated') : t('tunnelCreated'));
      setOpen(false);
      await load();
    } catch {
      message.error(editing ? t('tunnelUpdateFailed') : t('tunnelCreateFailed'));
    }
  };

  const toggle = async (tunnel: Tunnel, enabled: boolean) => {
    try {
      const response = await api.put<unknown, ApiEnvelope<Tunnel>>(`/admin/tunnels/${tunnel.id}`, { enabled });
      if (response.code !== 0) {
        message.error(response.message);
        return;
      }
      await load();
    } catch {
      message.error(t('tunnelUpdateFailed'));
    }
  };

  const removeTunnel = async (tunnel: Tunnel) => {
    try {
      const response = await api.delete<unknown, ApiEnvelope<null>>(`/admin/tunnels/${tunnel.id}`);
      if (response.code !== 0) {
        message.error(response.message);
        return;
      }
      message.success(t('tunnelDeleted'));
      await load();
    } catch {
      message.error(t('tunnelDeleteFailed'));
    }
  };

  const pathText = (tunnel: Tunnel) => tunnel.hops
    .map(hop => hop.group_name || groupMap.get(hop.device_group_id)?.name || `#${hop.device_group_id}`)
    .join(' → ');

  const portText = (tunnel: Tunnel) => tunnel.hops.slice(1)
    .map(hop => `${hop.group_name || `#${hop.device_group_id}`}:${hop.listen_port ?? '-'}`)
    .join(' · ');

  const actions = (tunnel: Tunnel) => (
    <Space size={4}>
      <Button type="text" size="small" icon={<EditOutlined />} onClick={() => beginEdit(tunnel)}>{t('edit')}</Button>
      <Popconfirm
        title={t('deleteTunnelConfirm')}
        description={tunnel.bound_rule_count > 0 ? t('tunnelDeleteInUseHint') : undefined}
        onConfirm={() => removeTunnel(tunnel)}
      >
        <Button type="text" size="small" danger icon={<DeleteOutlined />}>{t('delete')}</Button>
      </Popconfirm>
    </Space>
  );

  const columns = [
    { title: t('name'), dataIndex: 'name', key: 'name', width: 150 },
    {
      title: t('status'), key: 'enabled', width: 110,
      render: (_: unknown, tunnel: Tunnel) => (
        <Space>
          <Switch size="small" checked={tunnel.enabled} onChange={enabled => toggle(tunnel, enabled)} />
          <Tag color={tunnel.enabled ? 'green' : 'default'}>{t(tunnel.enabled ? 'enabled' : 'disabled')}</Tag>
        </Space>
      ),
    },
    {
      title: t('tunnelAccess'), key: 'shared', width: 130,
      render: (_: unknown, tunnel: Tunnel) => (
        <Tag color={tunnel.shared ? 'blue' : 'default'}>
          {t(tunnel.shared ? 'tunnelSharedWithUsers' : 'tunnelAdminOnly')}
        </Tag>
      ),
    },
    {
      title: t('tunnelPath'), key: 'path', width: 300,
      render: (_: unknown, tunnel: Tunnel) => <Text ellipsis={{ tooltip: pathText(tunnel) }}>{pathText(tunnel)}</Text>,
    },
    {
      title: t('sharedTunnelPorts'), key: 'ports', width: 300,
      render: (_: unknown, tunnel: Tunnel) => <Text className="rp-mono" ellipsis={{ tooltip: portText(tunnel) }}>{portText(tunnel)}</Text>,
    },
    { title: t('boundRuleCount'), dataIndex: 'bound_rule_count', key: 'rules', width: 110 },
    { title: t('action'), key: 'actions', fixed: 'right' as const, width: 150, render: (_: unknown, tunnel: Tunnel) => actions(tunnel) },
  ];

  return (
    <>
      <div className="rp-page-header">
        <h2 className="rp-page-title"><ApiOutlined /> {t('tunnelManagement')}</h2>
        <Space className="rp-page-actions">
          <Button icon={<ReloadOutlined />} onClick={load}>{t('refresh')}</Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={beginCreate}>{t('createTunnel')}</Button>
        </Space>
      </div>

      {mobile ? (
        <List
          loading={loading}
          dataSource={tunnels}
          locale={{ emptyText: t('noTunnels') }}
          renderItem={tunnel => (
            <List.Item>
              <Card size="small" style={{ width: '100%' }} title={tunnel.name} extra={actions(tunnel)}>
                <Space orientation="vertical" style={{ width: '100%' }}>
                  <Space>
                    <Switch size="small" checked={tunnel.enabled} onChange={enabled => toggle(tunnel, enabled)} />
                    <Tag color={tunnel.enabled ? 'green' : 'default'}>{t(tunnel.enabled ? 'enabled' : 'disabled')}</Tag>
                    <Tag color={tunnel.shared ? 'blue' : 'default'}>{t(tunnel.shared ? 'tunnelSharedWithUsers' : 'tunnelAdminOnly')}</Tag>
                    <Text type="secondary">{t('boundRuleCount')}: {tunnel.bound_rule_count}</Text>
                  </Space>
                  <Text>{pathText(tunnel)}</Text>
                  <Text className="rp-mono" type="secondary">{portText(tunnel)}</Text>
                </Space>
              </Card>
            </List.Item>
          )}
        />
      ) : (
        <Table rowKey="id" loading={loading} dataSource={tunnels} columns={columns} scroll={{ x: 1050 }} />
      )}

      <Modal
        title={editing ? t('editTunnel') : t('createTunnel')}
        open={open}
        onCancel={() => setOpen(false)}
        onOk={() => form.submit()}
        width={780}
        okText={t('save')}
        cancelText={t('cancel')}
        className="rp-tunnel-modal"
      >
        <Form form={form} layout="vertical" onFinish={submit} className="rp-tunnel-form">
          <Form.Item name="name" label={t('name')} rules={[{ required: true, whitespace: true }]} className="rp-tunnel-name-field">
            <Input maxLength={100} />
          </Form.Item>
          <div className="rp-tunnel-setting-bar">
            <div className="rp-tunnel-setting-item">
              <Text>{t('status')}</Text>
              <Form.Item name="enabled" valuePropName="checked" noStyle>
                <Switch checkedChildren={t('enabled')} unCheckedChildren={t('disabled')} />
              </Form.Item>
            </div>
            <div className="rp-tunnel-setting-item">
              <Space size={5}>
                <Text>{t('tunnelUserSharing')}</Text>
                <Tooltip title={t('tunnelUserSharingHint')}>
                  <QuestionCircleOutlined className="rp-tunnel-help-icon" />
                </Tooltip>
              </Space>
              <Form.Item name="shared" valuePropName="checked" noStyle>
                <Switch />
              </Form.Item>
            </div>
          </div>
          {editing?.shared && !watchedShared && editing.bound_rule_count > 0 && (
            <Alert
              type="warning"
              showIcon
              style={{ marginBottom: 16 }}
              title={t('tunnelUnshareWarning').replace('{count}', String(editing.bound_rule_count))}
            />
          )}
          {editing && editing.bound_rule_count > 0 && oldEntry && newEntry && oldEntry.id !== newEntry.id && (
            <Alert
              type="warning"
              showIcon
              style={{ marginBottom: 16 }}
              title={t('tunnelEntryChangeWarning')
                .replace('{count}', String(editing.bound_rule_count))
                .replace('{oldRate}', String(oldEntry.rate))
                .replace('{newRate}', String(newEntry.rate))}
            />
          )}
          <Form.List name="hops" rules={[{
            validator: async (_, hops: HopFormValue[]) => {
              if (!hops || hops.length < 2 || hops.length > 8) throw new Error(t('tunnelHopCountHint'));
            },
          }]}>
            {(fields, { add, remove }, { errors }) => (
              <div className="rp-tunnel-path-editor">
                <div className="rp-tunnel-path-heading">
                  <Space size={5}>
                    <Text strong><span className="rp-required-mark">*</span>{t('tunnelPath')}</Text>
                    <Tooltip title={t('tunnelHopCountHint')}>
                      <QuestionCircleOutlined className="rp-tunnel-help-icon" />
                    </Tooltip>
                  </Space>
                </div>
                <div className="rp-tunnel-hop-list">
                  {fields.map((field, index) => {
                    const { key: fieldKey, ...fieldProps } = field;
                    const portMode = watchedHops[index]?.port_mode ?? 'auto';
                    const options = (index === 0 ? entryGroups : relayGroups).map(group => ({
                      value: group.id,
                      label: `${group.name}${group.connect_host ? ` · ${group.connect_host}` : ''}`,
                      disabled: selectedGroupIds.includes(group.id) && watchedHops[index]?.device_group_id !== group.id,
                    }));
                    return (
                      <div key={fieldKey} className="rp-tunnel-hop-row">
                        <Tag className="rp-tunnel-hop-role">
                          {index === 0 ? t('hopEntry') : index === fields.length - 1 ? t('hopExit') : `${t('hopMid')} ${index}`}
                        </Tag>
                        <Form.Item
                          {...fieldProps}
                          name={[field.name, 'device_group_id']}
                          rules={[{ required: true, message: t('select') }]}
                          className="rp-tunnel-hop-group"
                        >
                          <Select options={options} showSearch optionFilterProp="label" placeholder={t('select')} />
                        </Form.Item>
                        {index > 0 && (
                          <div className="rp-tunnel-port-controls">
                            <Form.Item name={[field.name, 'port_mode']} className="rp-tunnel-port-mode">
                              <Select options={[
                                { value: 'auto', label: t('autoPort') },
                                { value: 'fixed', label: t('fixedPort') },
                              ]} />
                            </Form.Item>
                            {portMode === 'fixed' && (
                              <Form.Item
                                name={[field.name, 'listen_port']}
                                rules={[{ required: true, message: t('listenPortHint') }]}
                                className="rp-tunnel-fixed-port"
                              >
                                <InputNumber min={1} max={65535} placeholder={t('port')} style={{ width: '100%' }} />
                              </Form.Item>
                            )}
                          </div>
                        )}
                        {fields.length > 2 && (
                          <Button
                            type="text"
                            danger
                            icon={<DeleteOutlined />}
                            onClick={() => remove(field.name)}
                            className="rp-tunnel-remove-hop"
                          />
                        )}
                      </div>
                    );
                  })}
                  {fields.length < 8 && (
                    <Button type="dashed" block icon={<PlusOutlined />} onClick={() => add({ port_mode: 'auto' })} className="rp-tunnel-add-hop">
                      {t('addHop')}
                    </Button>
                  )}
                  <Form.ErrorList errors={errors} />
                </div>
              </div>
            )}
          </Form.List>
        </Form>
      </Modal>

    </>
  );
}
