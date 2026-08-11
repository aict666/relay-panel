 
import { Table, Tag, Typography, Button, Tooltip, Popconfirm } from 'antd';
import { CloudDownloadOutlined, CheckCircleOutlined, CloudServerOutlined, DeleteOutlined } from '@ant-design/icons';
import type { Tfn } from './types';
import type { NodeDisplayRow } from '../../api/types';
import { NodeResourceBar, NodeDiskBar } from './NodeResourceBar';
import { formatBps, formatBytes, formatUptime, formatPercent } from '../../utils/format';
import { versionRelation, versionTagColor } from '../../utils/version';
import { ConnectionsCell, NetworkCell, statusTag } from './shared';
import { resolveNodeUpgrade } from './upgrade';
import { nodeDesktopColumnWidths } from './tableLayout';

interface Props {
  rows: NodeDisplayRow[];
  panelProtocol: number;
  /** v1.2: the latest NODE release (bare, e.g. "1.1.0"). Nodes compare their
   *  own version against this — NOT the panel version. Empty when unknown. */
  latestNodeVersion: string;
  /** v1.2: the node-version lookup failed; show an unknown state. */
  nodeVersionCheckFailed: boolean;
  t: Tfn;
  openDetail: (row: NodeDisplayRow) => void;
  /** v1.0.10: admin-only. When set, a "节点更新" column shows a per-node upgrade
   *  icon (active when the node is behind the latest node release). Absent for
   *  the regular-user view. */
  onUpgrade?: (row: NodeDisplayRow) => void;
  /** Admin-only manual cleanup. Only rendered for real offline rows. */
  onDelete?: (row: NodeDisplayRow) => Promise<void> | void;
}

/** Desktop table for one group's nodes. Both admin and user share the same
 *  columns — the permission difference is in the data source (admin reads
 *  /nodes, user reads /nodes/shared) and the detail drawer. */
export function NodeDesktopTable({ rows, panelProtocol, latestNodeVersion, nodeVersionCheckFailed, t, openDetail, onUpgrade, onDelete }: Props) {
  const labels = { d: t('uptimeDay'), h: t('uptimeHour'), m: t('uptimeMinute'), s: t('uptimeSecond') };

  const columns = [
    {
      // v1.3.16: was an inline copy of statusTag's logic; now shares it with the
      // mobile list so the control-channel warning can't appear on one view and
      // not the other.
      title: t('status'), key: 'status', width: nodeDesktopColumnWidths.status, fixed: 'left' as const,
      render: (_: unknown, r: NodeDisplayRow) => statusTag(r, t, panelProtocol),
    },
    // v1.0.10: node version moved forward, with the upgrade action right after it.
    // v1.2: compared against the latest NODE release (latestNodeVersion), not
    // the panel version.
    {
      title: t('nodeVersion'), dataIndex: 'node_version', key: 'node_version', width: nodeDesktopColumnWidths.nodeVersion,
      render: (v: string | null) => {
        if (!v) return <Typography.Text type="secondary">-</Typography.Text>;
        // v1.2: if the node-version check failed, we can't vouch for any
        // "behind/latest" colouring — show the bare version with no arrow.
        if (nodeVersionCheckFailed) return <Tag>{`v${v}`}</Tag>;
        const rel = versionRelation(v, latestNodeVersion);
        const label = rel === 'behind' ? `v${v} ↑` : `v${v}`;
        return <Tag color={versionTagColor(rel)}>{label}</Tag>;
      },
    },
    // v1.0.10: admin-only per-node upgrade icon. v1.2 (PR4+PR5 reconciled): the
    // eligibility ladder is shared with the mobile list via resolveNodeUpgrade
    // (PR4) AND compared against the latest NODE release with a failed-check
    // neutral state (PR5). Protocol-incompatible and a failed lookup both take
    // priority over version status.
    ...(onUpgrade ? [{
      title: t('nodeUpgrade'), key: 'upgrade', width: nodeDesktopColumnWidths.nodeUpgrade,
      render: (_: unknown, r: NodeDisplayRow) => {
        const { state } = resolveNodeUpgrade(r, latestNodeVersion, panelProtocol, nodeVersionCheckFailed);
        switch (state) {
          case 'none':
          case 'unknown':
            return <Typography.Text type="secondary">-</Typography.Text>;
          case 'checkFailed':
            return (
              <Tooltip title={t('nodeVersionCheckFailed')}>
                <Typography.Text type="secondary" aria-label={t('nodeUpgrade')}>-</Typography.Text>
              </Tooltip>
            );
          case 'latest':
            return <Tooltip title={t('nodeUpgradeLatest')}><CheckCircleOutlined style={{ color: '#52c41a' }} /></Tooltip>;
          case 'ahead':
            return <Tooltip title={t('nodeVersionAhead')}><CheckCircleOutlined style={{ color: '#52c41a' }} /></Tooltip>;
          case 'docker':
            return <Tooltip title={t('nodeUpgradeDocker')}><CloudServerOutlined style={{ color: '#faad14' }} /></Tooltip>;
          case 'manual':
            return <Tooltip title={t('nodeUpgradeManual')}><CloudDownloadOutlined style={{ color: '#bfbfbf' }} /></Tooltip>;
          case 'protocolIncompatible':
            return <Tag color="red">{t('protocolIncompatible')}</Tag>;
          case 'upgradeable':
            return (
              <Tooltip title={t('nodeUpgradeTip').replace('{v}', latestNodeVersion)}>
                <Button
                  size="small"
                  type="link"
                  icon={<CloudDownloadOutlined />}
                  aria-label={t('nodeUpgrade')}
                  onClick={(e) => {
                    e.stopPropagation();
                    onUpgrade(r);
                  }}
                />
              </Tooltip>
            );
          case 'offline':
          default:
            return <Tooltip title={t('offline')}><CloudDownloadOutlined style={{ color: '#bfbfbf' }} /></Tooltip>;
        }
      },
    }] : []),
    {
      title: t('network'), key: 'network', width: 300,
      render: (_: unknown, r: NodeDisplayRow) => <NetworkCell row={r} t={t} />,
    },
    {
      title: <Tooltip title={t('connectionsHint')}>{t('connections')}</Tooltip>,
      dataIndex: 'connections', key: 'connections', width: 88,
      render: (_: unknown, r: NodeDisplayRow) => <ConnectionsCell row={r} t={t} />,
    },
    {
      title: 'CPU', key: 'cpu', width: nodeDesktopColumnWidths.cpu,
      render: (_: unknown, r: NodeDisplayRow) => <NodeResourceBar value={r.cpu} tooltip={`CPU: ${formatPercent(r.cpu)}`} />,
    },
    {
      title: t('mem'), key: 'mem', width: nodeDesktopColumnWidths.mem,
      render: (_: unknown, r: NodeDisplayRow) => <NodeResourceBar value={r.mem} tooltip={`${t('mem')}: ${formatPercent(r.mem)}`} />,
    },
    {
      title: t('disk'), key: 'disk', width: nodeDesktopColumnWidths.disk,
      render: (_: unknown, r: NodeDisplayRow) => <NodeDiskBar usagePercent={r.disk_usage_percent} used={r.disk_used} total={r.disk_total} mount={r.disk_mount} t={t} />,
    },
    {
      title: `${t('uploadRate')}/${t('downloadRate')}`, key: 'rate', width: nodeDesktopColumnWidths.rate,
      render: (_: unknown, r: NodeDisplayRow) => (
        <span className="rp-mono rp-node-throughput">{formatBps(r.upload_bps)} / {formatBps(r.download_bps)}</span>
      ),
    },
    {
      title: `${t('totalUpload')}/${t('totalDownload')}`, key: 'traffic', width: nodeDesktopColumnWidths.traffic,
      render: (_: unknown, r: NodeDisplayRow) => (
        <span className="rp-mono rp-node-throughput">{formatBytes(r.boot_upload_bytes)} / {formatBytes(r.boot_download_bytes)}</span>
      ),
    },
    {
      title: t('systemUptime'), key: 'uptime', width: 90,
      render: (_: unknown, r: NodeDisplayRow) => <span className="rp-mono">{formatUptime(r.uptime, labels)}</span>,
    },
    {
      title: t('resourceDetails'), key: 'detail', width: 70, fixed: 'right' as const,
      render: (_: unknown, r: NodeDisplayRow) => (
        <Button
          size="small"
          type="link"
          onClick={(e) => {
            e.stopPropagation();
            openDetail(r);
          }}
        >
          {t('resourceDetails')}
        </Button>
      ),
    },
    ...(onDelete ? [{
      title: t('action'), key: 'delete', width: 70, fixed: 'right' as const,
      render: (_: unknown, r: NodeDisplayRow) => (!r.online ? (
        <span onClick={(event) => event.stopPropagation()}>
          <Popconfirm title={t('nodeStatusDeleteConfirm')} onConfirm={() => onDelete(r)}>
            <Button
              danger
              size="small"
              type="text"
              icon={<DeleteOutlined />}
              aria-label={t('nodeStatusDelete')}
            />
          </Popconfirm>
        </span>
      ) : null),
    }] : []),
  ];

  return (
    <Table
      className="rp-responsive-table rp-node-table"
      dataSource={rows}
      columns={columns}
      rowKey={(r) => `${r.group_id}:${r.node_id || 'legacy'}`}
      pagination={false}
      size="small"
      scroll={{ x: 'max-content' }}
      rowClassName={(r) => (!r.online ? 'rp-node-offline' : '')}
      onRow={(r) => ({
        onClick: () => {
          if (r.node_id) openDetail(r);
        },
        title: r.node_id ? t('clickRowForDetails') : undefined,
        style: r.node_id ? { cursor: 'pointer' } : undefined,
      })}
    />
  );
}
