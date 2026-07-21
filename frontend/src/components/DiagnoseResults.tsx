import { Space, Table, Tag, Tooltip, Typography } from 'antd';
import type { DiagnoseTargetResult, NodeDiagnoseStatus } from '../api/types';

const { Text } = Typography;

interface DiagnoseNodeListProps {
  nodes: NodeDiagnoseStatus[];
  t: (key: string) => string;
  isAdmin: boolean;
  tunnelName?: string | null;
}

/** Replace the relay-node's stable wire id with panel-owned display metadata. */
function diagnoseTargetLabel(address: string, tunnelName?: string | null): string {
  if (!tunnelName) return address;
  return address.replace(/^tunnel:\d+(?=\s*\/)/, () => `tunnel:${tunnelName}`);
}

export function DiagnoseNodeList({ nodes, t, isAdmin, tunnelName }: DiagnoseNodeListProps) {
  return (
    <Space orientation="vertical" style={{ width: '100%' }}>
      {nodes.map((node, index) => (
        <DiagnoseNodeRow
          key={`${node.node_id}-${index}`}
          node={node}
          t={t}
          isAdmin={isAdmin}
          tunnelName={tunnelName}
        />
      ))}
    </Space>
  );
}

/** The visible node label uses operational group/IP data; raw node ids remain
 * available to administrators only as a troubleshooting tooltip. */
function DiagnoseNodeRow({
  node,
  t,
  isAdmin,
  tunnelName,
}: {
  node: NodeDiagnoseStatus;
  t: (key: string) => string;
  isAdmin: boolean;
  tunnelName?: string | null;
}) {
  const label = `${node.group_name || '-'} · ${node.public_ip || t('diagnoseIpMissing')}`;
  const labelText = <Text strong>{label}</Text>;
  const labelWithId = isAdmin
    ? <Tooltip title={t('diagnoseNodeIdLabel') + node.node_id}>{labelText}</Tooltip>
    : labelText;

  return (
    <div>
      <Space wrap align="center">
        {labelWithId}
        {node.status === 'result' && (
          <>
            <Tag color={node.listener_running ? 'green' : 'red'}>
              {node.listener_running ? t('diagnoseListenerRunning') : t('diagnoseListenerStopped')}
            </Tag>
            {node.listen_port ? <Text type="secondary">:{node.listen_port}</Text> : null}
            {node.protocol ? <Tag>{node.protocol}</Tag> : null}
            {node.transport ? <Tag>{node.transport}</Tag> : null}
          </>
        )}
        {node.status === 'unsupported' && (
          <Text type="warning">{t('diagnoseUnsupportedPrefix')}{node.node_version}{t('diagnoseUnsupportedSuffix')}</Text>
        )}
        {node.status === 'control_channel_offline' && (
          <Text type="secondary">{t('diagnoseOffline')}</Text>
        )}
        {node.status === 'timeout' && (
          <Tag color="orange">{t('diagnoseTimeout')}</Tag>
        )}
      </Space>
      {node.status === 'result' && node.results.length > 0 && (
        <Table<DiagnoseTargetResult>
          className="rp-responsive-table"
          size="small"
          pagination={false}
          style={{ marginTop: 8 }}
          scroll={{ x: 'max-content' }}
          dataSource={node.results}
          rowKey="address"
          columns={[
            {
              title: t('diagnoseTarget'),
              dataIndex: 'address',
              key: 'address',
              render: (value: string) => (
                <span className="rp-mono">{diagnoseTargetLabel(value, tunnelName)}</span>
              ),
            },
            {
              title: t('diagnoseOutcome'),
              key: 'outcome',
              render: (_: unknown, result: DiagnoseTargetResult) => (
                <ProbeOutcomeTag outcome={result.outcome} t={t} />
              ),
            },
          ]}
        />
      )}
    </div>
  );
}

function ProbeOutcomeTag({
  outcome,
  t,
}: {
  outcome: DiagnoseTargetResult['outcome'];
  t: (key: string) => string;
}) {
  if (outcome === 'timeout') return <Tag color="orange">{t('diagnoseOutcomeTimeout')}</Tag>;
  if ('reachable' in outcome) return <Tag color="green">{t('diagnoseOutcomeReachable')} {outcome.reachable.elapsed_ms}ms</Tag>;
  if ('failed' in outcome) return <Tag color="red">{t('diagnoseOutcomeFailed')}: {outcome.failed.error}</Tag>;
  return <Tag>?</Tag>;
}
