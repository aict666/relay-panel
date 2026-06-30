 
import { Table, Tag, Typography, Button } from 'antd';
import type { Tfn } from './types';
import type { NodeDisplayRow } from '../../api/types';
import { NodeResourceBar, NodeDiskBar } from './NodeResourceBar';
import { formatBps, formatBytes, formatUptime, formatPercent } from '../../utils/format';
import { versionRelation, versionTagColor } from '../../utils/version';
import { NetworkCell } from './shared';

interface Props {
  rows: NodeDisplayRow[];
  panelProtocol: number;
  currentVersion: string;
  t: Tfn;
  openDetail: (row: NodeDisplayRow) => void;
}

/** Desktop table for one group's nodes. Both admin and user share the same
 *  columns — the permission difference is in the data source (admin reads
 *  /nodes, user reads /nodes/shared) and the detail drawer. */
export function NodeDesktopTable({ rows, panelProtocol, currentVersion, t, openDetail }: Props) {
  const labels = { d: t('uptimeDay'), h: t('uptimeHour'), m: t('uptimeMinute'), s: t('uptimeSecond') };

  const columns = [
    {
      title: t('status'), key: 'status', width: 84, fixed: 'left' as const,
      render: (_: unknown, r: NodeDisplayRow) => {
        const v = r.config_protocol_version;
        if (v != null && panelProtocol > 0 && v !== panelProtocol) {
          return <Tag color="red">{t('protocolIncompatible')}</Tag>;
        }
        return r.online ? <Tag color="green">{t('online')}</Tag> : <Tag>{t('offline')}</Tag>;
      },
    },
    {
      title: t('network'), key: 'network', width: 300,
      render: (_: unknown, r: NodeDisplayRow) => <NetworkCell row={r} t={t} />,
    },
    {
      title: t('nodeVersion'), dataIndex: 'node_version', key: 'node_version', width: 100,
      render: (v: string | null) => {
        if (!v) return <Typography.Text type="secondary">-</Typography.Text>;
        const rel = versionRelation(v, currentVersion);
        const label = rel === 'behind' ? `v${v} ↑` : `v${v}`;
        return <Tag color={versionTagColor(rel)}>{label}</Tag>;
      },
    },
    {
      title: t('connections'), dataIndex: 'connections', key: 'connections', width: 70,
      render: (v: number) => <span className="rp-mono">{v || 0}</span>,
    },
    {
      title: 'CPU', key: 'cpu', width: 84,
      render: (_: unknown, r: NodeDisplayRow) => <NodeResourceBar value={r.cpu} tooltip={`CPU: ${formatPercent(r.cpu)}`} />,
    },
    {
      title: t('mem'), key: 'mem', width: 100,
      render: (_: unknown, r: NodeDisplayRow) => <NodeResourceBar value={r.mem} tooltip={`${t('mem')}: ${formatPercent(r.mem)}`} />,
    },
    {
      title: t('disk'), key: 'disk', width: 100,
      render: (_: unknown, r: NodeDisplayRow) => <NodeDiskBar usagePercent={r.disk_usage_percent} used={r.disk_used} total={r.disk_total} mount={r.disk_mount} t={t} />,
    },
    {
      title: `${t('uploadRate')}/${t('downloadRate')}`, key: 'rate', width: 140,
      render: (_: unknown, r: NodeDisplayRow) => (
        <span className="rp-mono">{formatBps(r.upload_bps)} / {formatBps(r.download_bps)}</span>
      ),
    },
    {
      title: `${t('totalUpload')}/${t('totalDownload')}`, key: 'traffic', width: 150,
      render: (_: unknown, r: NodeDisplayRow) => (
        <span className="rp-mono">{formatBytes(r.boot_upload_bytes)} / {formatBytes(r.boot_download_bytes)}</span>
      ),
    },
    {
      title: t('systemUptime'), key: 'uptime', width: 90,
      render: (_: unknown, r: NodeDisplayRow) => <span className="rp-mono">{formatUptime(r.uptime, labels)}</span>,
    },
    {
      title: t('resourceDetails'), key: 'detail', width: 70, fixed: 'right' as const,
      render: (_: unknown, r: NodeDisplayRow) => (
        <Button size="small" type="link" onClick={() => openDetail(r)}>{t('resourceDetails')}</Button>
      ),
    },
  ];

  return (
    <Table
      dataSource={rows}
      columns={columns}
      rowKey={(r) => `${r.group_id}:${r.node_id || 'legacy'}`}
      pagination={false}
      size="small"
      scroll={{ x: 'max-content' }}
    />
  );
}
