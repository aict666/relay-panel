import { Table, Button, Modal, Form, Input, InputNumber, Select, Space, message, Popconfirm, Typography, Tag, Tooltip, Alert, Switch, Checkbox } from 'antd';
import { PlusOutlined, ReloadOutlined, CopyOutlined, EditOutlined, CloudServerOutlined, CodeOutlined, ApiOutlined } from '@ant-design/icons';
import { useCallback, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import api from '../api/client';
import type { ApiEnvelope, BlockedProtocol, DeviceGroup, NodeStatus, SharedGroupSummary } from '../api/types';
import { useI18n } from '../i18n/context';
import { copyText } from '../utils/clipboard';
import { useAuth } from '../auth/useAuth';
import { buildInstallCommand } from '../utils/installCommand';

const { Text } = Typography;

const INSTALL_SCRIPT_URL = 'https://raw.githubusercontent.com/aict666/relay-panel/main/scripts/relay-node-install.sh';

interface GroupFormValues {
  name?: string;
  group_type?: string;
  connect_host?: string;
  port_range?: string;
  rate?: number;
  hidden?: boolean;
  blocked_protocols?: BlockedProtocol[];
}

function selectedBlockedProtocols(
  ingressCapable: boolean,
  blockedProtocols: BlockedProtocol[] | undefined,
): BlockedProtocol[] {
  if (!ingressCapable) return [];
  return (['http', 'tls'] as const).filter(protocol => blockedProtocols?.includes(protocol));
}

function isLocalhost(): boolean {
  const h = window.location.hostname;
  return h === 'localhost' || h === '127.0.0.1' || h === '::1';
}

export default function Groups() {
  const { t } = useI18n();
  const { isAdmin, user } = useAuth();
  const authScope = `${isAdmin ? 'admin' : 'user'}:${user?.id ?? 'anonymous'}`;
  const [groups, setGroups] = useState<Array<DeviceGroup | SharedGroupSummary>>([]);
  const [nodes, setNodes] = useState<NodeStatus[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadFailed, setLoadFailed] = useState(false);
  const [saving, setSaving] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [cmdModalOpen, setCmdModalOpen] = useState(false);
  const [cmdModalContent, setCmdModalContent] = useState<{ title: ReactNode; body: ReactNode }>({ title: null, body: null });
  const [editing, setEditing] = useState<DeviceGroup | null>(null);
  const [createForm] = Form.useForm();
  const [editForm] = Form.useForm();
  const createGroupType = Form.useWatch('group_type', createForm);
  const editGroupType = Form.useWatch('group_type', editForm);
  const loadGenerationRef = useRef(0);
  const loadScopeRef = useRef<string | null>(null);
  const desiredScopeRef = useRef(authScope);
  const commandGenerationRef = useRef(0);
  useLayoutEffect(() => {
    desiredScopeRef.current = authScope;
  }, [authScope]);

  const load = useCallback(async () => {
    if (desiredScopeRef.current !== authScope) return false;
    const requestId = ++loadGenerationRef.current;
    ++commandGenerationRef.current;
    setCmdModalOpen(false);
    setCmdModalContent({ title: null, body: null });
    if (loadScopeRef.current !== authScope) {
      loadScopeRef.current = authScope;
      Modal.destroyAll();
      setGroups([]);
      setNodes([]);
      setCreateOpen(false);
      setEditOpen(false);
      setEditing(null);
    }
    setLoading(true);
    setLoadFailed(false);
    try {
      if (isAdmin) {
        // The node catalog drives expandable rows. Treat failures as load
        // failures instead of presenting false empty lists that could mislead
        // an administrator.
        const [g, n] = await Promise.all([
          api.get<unknown, ApiEnvelope<DeviceGroup[]>>('/groups'),
          api.get<unknown, ApiEnvelope<NodeStatus[]>>('/nodes'),
        ]);
        if (requestId !== loadGenerationRef.current || desiredScopeRef.current !== authScope) return false;
        setGroups(g.data || []);
        setNodes(n.data || []);
      } else {
        // This route is kept only as a read-only view of the user's own legacy
        // groups. `/nodes/shared` describes admin-owned plan-authorized groups,
        // so joining it to these rows is both meaningless and made an unrelated
        // shared-node outage fail this page. Regular users use /nodes for the
        // separate shared-node view instead.
        const g = await api.get<unknown, ApiEnvelope<SharedGroupSummary[]>>('/groups/owned');
        if (requestId !== loadGenerationRef.current || desiredScopeRef.current !== authScope) return false;
        setGroups(g.data || []);
        setNodes([]);
      }
      setLoadFailed(false);
      return true;
    } catch {
      if (requestId === loadGenerationRef.current && desiredScopeRef.current === authScope) {
        setLoadFailed(true);
        message.error(t('loadFailed'));
      }
      return false;
    } finally {
      if (requestId === loadGenerationRef.current && desiredScopeRef.current === authScope) setLoading(false);
    }
  }, [authScope, isAdmin, t]);

  useEffect(() => { load(); }, [load]);
  const mutationsBlocked = loading || loadFailed || saving;

  // ── Node helpers ──
  const nodesByGroup = useCallback((groupId: number): NodeStatus[] => {
    return nodes.filter(n => n.group_id === groupId);
  }, [nodes]);

  const nodeCount = useCallback((groupId: number) => nodesByGroup(groupId).length, [nodesByGroup]);
  const onlineCount = useCallback((groupId: number) => nodesByGroup(groupId).filter(n => n.online).length, [nodesByGroup]);
  const blockedTlsCount = useCallback((groupId: number) => nodesByGroup(groupId)
    .filter(n => n.online)
    .reduce((sum, n) => sum + (n.blocked_protocol_connections?.tls ?? 0), 0), [nodesByGroup]);
  const blockedHttpCount = useCallback((groupId: number) => nodesByGroup(groupId)
    .filter(n => n.online)
    .reduce((sum, n) => sum + (n.blocked_protocol_connections?.http ?? 0), 0), [nodesByGroup]);

  const handleCreate = async (values: GroupFormValues) => {
    if (!isAdmin || loading || loadFailed || saving) return;
    setSaving(true);
    try {
      // v1.0.8: rate defaults to 1.0 on the server when omitted; send it
      // explicitly so the value the admin picked is what gets persisted.
      const ingressCapable = values.group_type === 'in' || values.group_type === 'both';
      const payload = {
        ...values,
        rate: values.rate ?? 1.0,
        hidden: values.hidden ?? false,
        blocked_protocols: selectedBlockedProtocols(ingressCapable, values.blocked_protocols),
      };
      const res = await api.post<unknown, ApiEnvelope<DeviceGroup>>('/groups', payload);
      if (res.code !== 0) { message.error(res.message); return; }
      message.success(t('groupCreated'));
      setCreateOpen(false);
      createForm.resetFields();
      await load();
    } catch { message.error(t('failedCreateGroup')); }
    finally { setSaving(false); }
  };

  const handleEdit = (g: DeviceGroup) => {
    if (!isAdmin || loading || loadFailed || saving) return;
    setEditing(g);
    editForm.setFieldsValue({
      name: g.name,
      group_type: g.group_type,
      connect_host: g.connect_host,
      port_range: g.port_range,
      rate: g.rate,
      hidden: !!g.hidden,
      blocked_protocols: g.blocked_protocols ?? [],
    });
    setEditOpen(true);
  };

  const handleUpdate = async (values: GroupFormValues) => {
    if (!isAdmin || !editing) return;
    if (loading || loadFailed || saving) return;
    const payload: Record<string, unknown> = {};
    if (values.name !== undefined && values.name !== editing.name) payload.name = values.name;
    if (values.group_type !== undefined && values.group_type !== editing.group_type) payload.group_type = values.group_type;
    if (values.connect_host !== undefined && values.connect_host !== editing.connect_host) payload.connect_host = values.connect_host;
    if (values.port_range !== undefined && values.port_range !== editing.port_range) payload.port_range = values.port_range;
    // v1.0.8: only send rate when it actually changed (avoid no-op 400s and
    // keep the diff-based payload pattern used for the other fields).
    if (values.rate !== undefined && values.rate !== editing.rate) payload.rate = values.rate;
    // v1.0.7: only send hidden when it actually changed.
    if (values.hidden !== undefined && values.hidden !== !!editing.hidden) payload.hidden = values.hidden;
    const effectiveType = values.group_type ?? editing.group_type;
    const nextBlockedProtocols = selectedBlockedProtocols(
      effectiveType === 'in' || effectiveType === 'both',
      values.blocked_protocols,
    );
    const previousBlockedProtocols = [...(editing.blocked_protocols ?? [])].sort();
    if (nextBlockedProtocols.join(',') !== previousBlockedProtocols.join(',')) {
      payload.blocked_protocols = nextBlockedProtocols;
    }
    if (Object.keys(payload).length === 0) { setEditOpen(false); return; }
    setSaving(true);
    try {
      const res = await api.put<unknown, ApiEnvelope<null>>(`/groups/${editing.id}`, payload);
      if (res.code !== 0) { message.error(res.message); return; }
      message.success(t('groupUpdated'));
      setEditOpen(false);
      await load();
    } catch { message.error(t('failedUpdateGroup')); }
    finally { setSaving(false); }
  };

  const handleDelete = async (id: number) => {
    if (!isAdmin || loading || loadFailed || saving) return;
    setSaving(true);
    try {
      const res = await api.delete<unknown, ApiEnvelope<null>>(`/groups/${id}`);
      if (res.code !== 0) {
        message.error(res.code === 409 ? (res.message || t('groupInUse')) : (res.message || t('failedDeleteGroup')));
        return;
      }
      message.success(t('groupDeleted'));
      await load();
    } catch {
      message.error(t('failedDeleteGroup'));
    } finally {
      setSaving(false);
    }
  };

  const doCopy = async (text: string, successMsg: string) => {
    if (!text || text.length < 20) { message.error(t('copyFailed')); return; }
    const ok = await copyText(text);
    if (ok) {
      message.success(successMsg);
    } else {
      message.error(t('copyFailed'));
    }
  };

  const panelUrlRef = async (): Promise<string> => {
    try {
      const resp = await api.get<unknown, { public_panel_url?: string }>("/system/version");
      if (resp.public_panel_url) return resp.public_panel_url;
    } catch { /* ignore */ }
    return window.location.origin;
  };

  const showInstallCommand = async (g: DeviceGroup) => {
    if (loading || loadFailed) return;
    const requestId = ++commandGenerationRef.current;
    const requestScope = authScope;
    const panelUrl = await panelUrlRef();
    if (requestId !== commandGenerationRef.current || desiredScopeRef.current !== requestScope) return;
    const cmd = buildInstallCommand(INSTALL_SCRIPT_URL, g.token, panelUrl);
    setCmdModalContent({
      title: <span>{t('installCommandTitle')}</span>,
      body: (
        <>
          {(isLocalhost() || panelUrl.includes("127.0.0.1") || panelUrl.includes("localhost") || panelUrl.includes("0.0.0.0")) && (
            <Alert type="warning" showIcon style={{ marginBottom: 12 }} title={t('localhostWarning')} />
          )}
          <Input.TextArea value={cmd} readOnly autoSize={{ minRows: 3, maxRows: 5 }} style={{ fontFamily: 'var(--rp-font-mono)', fontSize: 12 }} />
          <div style={{ textAlign: 'right', marginTop: 8 }}>
            <Button type="primary" icon={<CopyOutlined />} onClick={() => doCopy(cmd, t('installCommandCopied'))}>
              {t('copyInstallCommand')}
            </Button>
          </div>
        </>
      ),
    });
    setCmdModalOpen(true);
  };

  const closeCommand = () => {
    ++commandGenerationRef.current;
    setCmdModalOpen(false);
    setCmdModalContent({ title: null, body: null });
  };

  const typeColor = (gt: string) => {
    switch (gt) {
      case 'in': return 'green';
      case 'out': return 'cyan';
      case 'both': return 'purple';
      case 'monitor': return 'default';
      default: return 'default';
    }
  };

  // Chain intermediate/exit nodes use type `out` (egress/mid-hop).
  const groupTypeOptions = [
    { value: 'in', label: t('inboundListener') },
    { value: 'out', label: t('outboundEgress') },
    { value: 'both', label: t('inboundOutbound') },
    { value: 'monitor', label: t('typeMonitor') },
  ];

  const columns = [
    { title: t('id'), dataIndex: 'id', key: 'id', width: 60 },
    { title: t('name'), dataIndex: 'name', key: 'name' },
    {
      title: t('type'), dataIndex: 'group_type', key: 'group_type',
      render: (gt: string) => <Tag color={typeColor(gt)}>{gt.toUpperCase()}</Tag>,
    },
    {
      title: t('nodes'), key: 'nodes', width: 100,
      render: (_: unknown, g: DeviceGroup | SharedGroupSummary) => {
        const total = nodeCount(g.id);
        const online = onlineCount(g.id);
        return <span>{total > 0 ? `${online}/${total}` : '-'}</span>;
      },
    },
    {
      title: t('nodeToken'), dataIndex: 'token', key: 'token',
      render: (tk: string, g: DeviceGroup) => (
        <Space>
          <Text code style={{ maxWidth: 180 }} ellipsis>{tk}</Text>
          <Tooltip title={t('copyInstallCommand')}>
            <Button size="small" type="text" icon={<CodeOutlined />} aria-label={t('copyInstallCommand')} disabled={loading || loadFailed} onClick={() => showInstallCommand(g)} />
          </Tooltip>
        </Space>
      ),
    },
    { title: t('connectHost'), dataIndex: 'connect_host', key: 'connect_host', render: (v: string) => <span className="rp-mono">{v}</span> },
    { title: t('portRange'), dataIndex: 'port_range', key: 'port_range', render: (v: string) => <span className="rp-mono">{v}</span> },
    {
      title: t('protocolBlocking'), dataIndex: 'blocked_protocols', key: 'blocked_protocols', width: 120,
      render: (protocols?: string[]) => protocols?.length ? (
        <Space size={4} wrap>
          {protocols.includes('http') && <Tag color="orange">{t('httpBlocked')}</Tag>}
          {protocols.includes('tls') && <Tag color="red">{t('tlsBlocked')}</Tag>}
        </Space>
      ) : <span style={{ color: 'var(--rp-text-tertiary)' }}>-</span>,
    },
    {
      title: <Tooltip title={t('blockedSinceNodeStart')}>{t('blockedHttpConnections')}</Tooltip>,
      key: 'blocked_http_connections', width: 100,
      render: (_: unknown, g: DeviceGroup | SharedGroupSummary) => {
        const count = blockedHttpCount(g.id);
        return count > 0 ? count.toLocaleString() : <span style={{ color: 'var(--rp-text-tertiary)' }}>0</span>;
      },
    },
    {
      title: <Tooltip title={t('blockedSinceNodeStart')}>{t('blockedTlsConnections')}</Tooltip>,
      key: 'blocked_tls_connections', width: 100,
      render: (_: unknown, g: DeviceGroup | SharedGroupSummary) => {
        const count = blockedTlsCount(g.id);
        return count > 0 ? count.toLocaleString() : <span style={{ color: 'var(--rp-text-tertiary)' }}>0</span>;
      },
    },
    {
      // v1.0.8: billing rate. Only show a tag when it differs from 1.0 — a 1x
      // column on every row is noise. The tag color reflects the multiplier
      // direction (gold = premium line, no tag = bill-as-used).
      title: t('rate'), dataIndex: 'rate', key: 'rate', width: 80,
      render: (rate: number) => {
        const r = typeof rate === 'number' ? rate : 1.0;
        if (Math.abs(r - 1.0) < 1e-9) return <span style={{ color: 'var(--rp-text-tertiary)' }}>1x</span>;
        return <Tag color="gold">{r}x</Tag>;
      },
    },
    {
      // v1.0.7: hidden flag — only tag when hidden, to keep the column quiet.
      title: t('groupHidden'), dataIndex: 'hidden', key: 'hidden', width: 80,
      render: (hidden: boolean) =>
        hidden ? <Tag>{t('yes')}</Tag> : <span style={{ color: 'var(--rp-text-tertiary)' }}>-</span>,
    },
    {
      title: t('action'), key: 'action', width: 120, fixed: 'right' as const,
      render: (_: unknown, g: DeviceGroup | SharedGroupSummary) => isAdmin && 'token' in g ? (
        <Space>
          <Button size="small" type="text" icon={<EditOutlined />} disabled={mutationsBlocked} onClick={() => handleEdit(g)}>{t('edit')}</Button>
          <Popconfirm title={t('deleteGroupConfirm')} onConfirm={() => handleDelete(g.id)}>
            <Button danger size="small" type="text" disabled={mutationsBlocked}>{t('delete')}</Button>
          </Popconfirm>
        </Space>
      ) : null,
    },
  ];
  const regularColumnKeys = new Set(['id', 'name', 'group_type', 'connect_host', 'blocked_protocols']);
  const visibleColumns = isAdmin ? columns : columns.filter(column => regularColumnKeys.has(column.key));

  const expandedRowRender = (g: DeviceGroup | SharedGroupSummary) => {
    if (!('token' in g)) return null;
    const groupNodes = nodesByGroup(g.id);
    if (groupNodes.length === 0) {
      return (
        <div style={{ padding: '8px 0', color: 'var(--rp-text-tertiary)', fontSize: 13 }}>
          {t('noNodesInGroup')}
          <Button size="small" type="link" icon={<ApiOutlined />} disabled={loading || loadFailed} style={{ marginLeft: 12 }} onClick={() => showInstallCommand(g)}>
            {t('addNode')}
          </Button>
        </div>
      );
    }
    return (
      <div style={{ padding: 4 }}>
        <div style={{ marginBottom: 8, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Text type="secondary" style={{ fontSize: 12 }}>{t('nodesInGroup')} ({groupNodes.length})</Text>
          <Button size="small" icon={<ApiOutlined />} disabled={loading || loadFailed} onClick={() => showInstallCommand(g)}>{t('addNode')}</Button>
        </div>
        <Table
          className="rp-responsive-table"
          dataSource={groupNodes}
          rowKey={(n: NodeStatus) => n.node_id ?? `${n.public_ipv4 ?? n.public_ip}-${n.last_seen}`}
          pagination={false}
          size="small"
          scroll={{ x: 'max-content' }}
          columns={[
            { title: 'ID', dataIndex: 'node_id', key: 'node_id', width: 120, render: (v: string | undefined) => v ? <Text code style={{ fontSize: 11 }}>{v.slice(0, 8)}...{v.slice(-4)}</Text> : '-' },
            { title: t('status'), dataIndex: 'online', key: 'online', width: 80, render: (v: boolean) => <Tag color={v ? 'green' : 'default'}>{v ? t('online') : t('offline')}</Tag> },
            { title: t('nodeVersion'), dataIndex: 'node_version', key: 'version', width: 90, render: (v: string | undefined) => v ? <span className="rp-mono" style={{ fontSize: 12 }}>{v}</span> : '-' },
            { title: t('blockedHttpConnections'), key: 'blocked_http_connections', width: 100, render: (_: unknown, n: NodeStatus) => (n.blocked_protocol_connections?.http ?? 0).toLocaleString() },
            { title: t('blockedTlsConnections'), key: 'blocked_tls_connections', width: 100, render: (_: unknown, n: NodeStatus) => (n.blocked_protocol_connections?.tls ?? 0).toLocaleString() },
            { title: t('lastSeen'), dataIndex: 'last_seen', key: 'last_seen', width: 120, render: (v: string | undefined) => v ? <span style={{ fontSize: 12 }}>{v}</span> : '-' },
          ]}
        />
      </div>
    );
  };

  return (
    <>
      <div className="rp-page-header">
        <h2 className="rp-page-title"><CloudServerOutlined /> {t('deviceGroups')}</h2>
        <Space className="rp-page-actions" wrap>
          <Button icon={<ReloadOutlined />} loading={loading} disabled={saving || createOpen || editOpen || cmdModalOpen} onClick={load}>{t('refresh')}</Button>
          {isAdmin && <Button type="primary" icon={<PlusOutlined />} disabled={mutationsBlocked} onClick={() => setCreateOpen(true)}>{t('addGroup')}</Button>}
        </Space>
      </div>

      {loadFailed && (
        <Alert type="error" showIcon style={{ marginBottom: 12 }} title={t('loadFailed')} />
      )}
      <Table
        className="rp-responsive-table"
        dataSource={groups}
        columns={visibleColumns}
        rowKey="id"
        loading={loading}
        pagination={{ pageSize: 20 }}
        scroll={{ x: 'max-content' }}
        expandable={isAdmin ? {
          expandedRowRender,
          rowExpandable: (group) => 'token' in group,
        } : undefined}
      />

      <Modal title={t('addGroup')} open={createOpen} onCancel={() => { if (!saving) setCreateOpen(false); }} onOk={() => createForm.submit()} confirmLoading={saving} okButtonProps={{ disabled: loading || loadFailed }} okText={t('create')} cancelText={t('cancel')}>
        <Form form={createForm} onFinish={handleCreate} layout="vertical" disabled={saving || loading || loadFailed}>
          <Form.Item name="name" label={t('name')} rules={[{ required: true, whitespace: true }]}><Input placeholder="tokyo-node-1" /></Form.Item>
          <Form.Item name="group_type" label={t('type')} rules={[{ required: true }]} initialValue="in">
            <Select options={groupTypeOptions} onChange={(value) => {
              if (value !== 'in' && value !== 'both') {
                createForm.setFieldValue('blocked_protocols', []);
              }
            }} />
          </Form.Item>
          <Form.Item name="connect_host" label={t('connectHost')} rules={[{ required: true }]}><Input placeholder="1.2.3.4 or node.example.com" /></Form.Item>
          <Form.Item name="port_range" label={t('portRange')} rules={[{ required: true }]} initialValue="10000-65535"><Input placeholder="10000-65535" /></Form.Item>
          {/* v1.0.8: billing rate. Users are charged real bytes × rate; the
              rule/user byte counters keep real bytes. 1.0 = bill as used. */}
          <Form.Item name="rate" label={t('rate')} initialValue={1.0} rules={[{ required: true }]}>
            <InputNumber min={0.1} max={100} step={0.1} style={{ width: '100%' }} />
          </Form.Item>
          {/* v1.0.7: hide this group from regular users' node-status / available
              lines. Admins always see it. */}
          <Form.Item name="hidden" label={t('groupHidden')} valuePropName="checked" initialValue={false}>
            <Switch />
          </Form.Item>
          <Form.Item name="blocked_protocols" label={t('protocolBlocking')} initialValue={[]}>
            <Checkbox.Group
              disabled={createGroupType !== 'in' && createGroupType !== 'both'}
              options={[{ label: 'HTTP', value: 'http' }, { label: 'TLS', value: 'tls' }]}
            />
          </Form.Item>
        </Form>
      </Modal>

      <Modal title={t('editGroup')} open={editOpen} onCancel={() => { if (!saving) setEditOpen(false); }} onOk={() => editForm.submit()} confirmLoading={saving} okButtonProps={{ disabled: loading || loadFailed }} okText={t('save')} cancelText={t('cancel')}>
        <Form form={editForm} onFinish={handleUpdate} layout="vertical" disabled={saving || loading || loadFailed}>
          <Form.Item name="name" label={t('name')} rules={[{ required: true, whitespace: true }]}><Input /></Form.Item>
          <Form.Item name="group_type" label={t('type')}><Select options={groupTypeOptions} onChange={(value) => {
            if (value !== 'in' && value !== 'both') {
              editForm.setFieldValue('blocked_protocols', []);
            }
          }} /></Form.Item>
          <Form.Item name="connect_host" label={t('connectHost')}><Input /></Form.Item>
          <Form.Item name="port_range" label={t('portRange')}><Input /></Form.Item>
          <Form.Item name="rate" label={t('rate')}>
            <InputNumber min={0.1} max={100} step={0.1} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="hidden" label={t('groupHidden')} valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item name="blocked_protocols" label={t('protocolBlocking')}>
            <Checkbox.Group
              disabled={editGroupType !== 'in' && editGroupType !== 'both'}
              options={[{ label: 'HTTP', value: 'http' }, { label: 'TLS', value: 'tls' }]}
            />
          </Form.Item>
        </Form>
      </Modal>

      <Modal title={cmdModalContent.title} open={cmdModalOpen} onCancel={closeCommand} footer={null} width={580}>
        {cmdModalContent.body}
      </Modal>
    </>
  );
}
