 
import { Alert, Drawer, Descriptions, Tag, Button, Popconfirm, message, Space, Typography } from 'antd';
import { DeleteOutlined } from '@ant-design/icons';
import { formatPercent, formatBytes, formatBps, formatUptime } from '../../utils/format';
import { useI18n } from '../../i18n/context';
import { CountryFlag } from './CountryFlag';
import { hasConnectionCountAnomaly } from './shared';
import type { ApiEnvelope, NodeDisplayRow } from '../../api/types';
import api from '../../api/client';

interface Props {
  row: NodeDisplayRow | null;
  open: boolean;
  onClose: () => void;
  isAdmin: boolean;
  panelProtocol: number;
  onDeleted?: () => void;
}

/** Full-metric detail drawer for one node. Admin sees extra fields (node_id,
 *  config protocol, interface, disk mount, process uptime, listener errors, a
 *  delete-status action). Regular users see only safe metrics — no node_id,
 *  no token, no config protocol, no listener errors, no management actions. */
export function NodeDetailDrawer({ row, open, onClose, isAdmin, panelProtocol, onDeleted }: Props) {
  const { t } = useI18n();
  const labels = { d: t('uptimeDay'), h: t('uptimeHour'), m: t('uptimeMinute'), s: t('uptimeSecond') };

  const handleDelete = async () => {
    if (!row) return;
    const gid = row.group_id;
    const nid = row.node_id;
    const url = nid
      ? `/nodes/${gid}?node_id=${encodeURIComponent(nid)}`
      : `/nodes/${gid}`;
    try {
      const res = await api.delete<unknown, ApiEnvelope<null>>(url);
      if (res.code !== 0) {
        message.error(res.message || t('nodeStatusDeleteFailed'));
        return;
      }
      message.success(t('nodeStatusDeleted'));
      onDeleted?.();
      onClose();
    } catch {
      message.error(t('nodeStatusDeleteFailed'));
    }
  };

  const v4 = row?.public_ipv4 ?? row?.public_ip;
  const v6 = row?.public_ipv6;
  const reportIp = row?.report_ip;

  return (
    <Drawer title={row?.group_name || t('resourceDetails')} open={open} onClose={onClose} size={440}>
      {row && (
        <>
        <Descriptions column={1} size="small" bordered>
          <Descriptions.Item label={t('status')}>
            {row.online ? <Tag color="green">{t('online')}</Tag> : <Tag>{t('offline')}</Tag>}
          </Descriptions.Item>

          {/* Prefer the address observed on the actual status-report path.
           * Legacy rows have no report_ip and fall back to self-detection. */}
          {reportIp && (
            <Descriptions.Item label={t('reportPathIp')}>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                <CountryFlag code={row.report_ip_country_code} />
                <span className="rp-mono">{reportIp}</span>
              </span>
            </Descriptions.Item>
          )}
          {!reportIp && v4 && (
            <Descriptions.Item label="IPv4">
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                <CountryFlag code={row.ipv4_country_code} />
                <span className="rp-mono">{v4}</span>
              </span>
            </Descriptions.Item>
          )}
          {!reportIp && v6 && (
            <Descriptions.Item label="IPv6">
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                <CountryFlag code={row.ipv6_country_code} />
                <span className="rp-mono">{v6}</span>
              </span>
            </Descriptions.Item>
          )}

          <Descriptions.Item label={t('nodeVersion')}>{row.node_version || '-'}</Descriptions.Item>
          <Descriptions.Item label={t('connections')}>
            {(row.connections || 0).toLocaleString()}
            {hasConnectionCountAnomaly(row) ? (
              <span style={{ marginLeft: 8, color: 'var(--rp-warning, #d97706)', fontSize: 12 }}>
                {t('connectionsAnomalyHint')}
              </span>
            ) : null}
          </Descriptions.Item>
          <Descriptions.Item label={t('capacityScore')}>
            {row.capacity_score == null ? '-' : (
              <Tag color={row.capacity_score >= 50 ? 'green' : row.capacity_score >= 20 ? 'orange' : 'red'}>
                {row.capacity_score.toFixed(1)} / 100
              </Tag>
            )}
          </Descriptions.Item>
          <Descriptions.Item label={t('predictedSpareConnections')}>
            {row.predicted_spare_connections ?? '-'}
          </Descriptions.Item>
          <Descriptions.Item label={t('anomalyStatus')}>
            {row.anomaly_detected == null
              ? '-'
              : row.anomaly_detected
                ? <Tag color="red">{t('anomalyDetected')}</Tag>
                : <Tag color="green">{t('normal')}</Tag>}
          </Descriptions.Item>
          <Descriptions.Item label="CPU">{formatPercent(row.cpu)}</Descriptions.Item>
          <Descriptions.Item label={t('mem')}>{formatPercent(row.mem)}</Descriptions.Item>
          <Descriptions.Item label={t('disk')}>
            {row.disk_usage_percent == null && row.disk_used == null
              ? '-'
              : `${formatPercent(row.disk_usage_percent)} (${formatBytes(row.disk_used)}/${formatBytes(row.disk_total)})`}
          </Descriptions.Item>
          <Descriptions.Item label={`${t('uploadRate')}/${t('downloadRate')}`}>
            {formatBps(row.upload_bps)} / {formatBps(row.download_bps)}
          </Descriptions.Item>
          <Descriptions.Item label={`${t('totalUpload')}/${t('totalDownload')}`}>
            {formatBytes(row.boot_upload_bytes)} / {formatBytes(row.boot_download_bytes)}
          </Descriptions.Item>
          <Descriptions.Item label={t('systemUptime')}>{formatUptime(row.uptime, labels)}</Descriptions.Item>
          <Descriptions.Item label={t('lastSeen')}>{row.last_seen || '-'}</Descriptions.Item>

          {/* Admin-only fields */}
          {isAdmin && (
            <>
              <Descriptions.Item label="node_id">{row.node_id || '-'}</Descriptions.Item>
              {/* v1.3.16: the control plane, stated outright. Unlike the status
                  column this shows even for a fully-offline node — when you've
                  opened the drawer you're troubleshooting, and "did the socket
                  ever come up" is the first question. The connection census is
                  group-level context: unidentified sockets cannot be attributed
                  to this row because they have no node_id. */}
              <Descriptions.Item label={t('controlChannel')}>
                {row.control_channel_online == null ? '-' : row.control_channel_online ? (
                  <Tag color="green">{t('online')}</Tag>
                ) : (
                  <Space size={4} wrap>
                    <Tag color={row.online ? 'orange' : undefined}>{t('offline')}</Tag>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      {t('controlChannelConns')
                        .replace('{total}', String(row.ws_conn_total ?? 0))
                        .replace('{unidentified}', String(row.ws_conn_unidentified ?? 0))}
                    </Typography.Text>
                  </Space>
                )}
              </Descriptions.Item>
              <Descriptions.Item label={t('configProtocolVersion')}>
                {(() => {
                  const v = row.config_protocol_version;
                  if (v == null) return '-';
                  if (panelProtocol > 0 && v !== panelProtocol) return <Tag color="red">v{v}</Tag>;
                  return <Tag color="green">v{v}</Tag>;
                })()}
              </Descriptions.Item>
              <Descriptions.Item label={t('networkInterface')}>{row.network_interface || '-'}</Descriptions.Item>
              {reportIp && v4 && (
                <Descriptions.Item label={t('detectedIpv4')}>
                  <span className="rp-mono">{v4}</span>
                </Descriptions.Item>
              )}
              {reportIp && v6 && (
                <Descriptions.Item label={t('detectedIpv6')}>
                  <span className="rp-mono">{v6}</span>
                </Descriptions.Item>
              )}
              <Descriptions.Item label={t('diskMount')}>{row.disk_mount || '-'}</Descriptions.Item>
              {row.process_uptime != null && (
                <Descriptions.Item label={t('processUptime')}>{formatUptime(row.process_uptime, labels)}</Descriptions.Item>
              )}
              <Descriptions.Item label={t('listeners')}>
                {(() => {
                  const errs = row.listener_errors;
                  if (!errs || errs.length === 0) return <Tag color="green">{t('ok')}</Tag>;
                  return <Tag color="red">{errs.length} {t('failed')}</Tag>;
                })()}
              </Descriptions.Item>
            </>
          )}
        </Descriptions>

        {isAdmin && row.listener_errors && row.listener_errors.length > 0 && (
          <Space orientation="vertical" style={{ width: '100%', marginTop: 12 }}>
            {row.listener_errors.map((listenerError, index) => (
              <Alert
                key={`${listenerError.port}-${listenerError.protocol}-${index}`}
                type="error"
                showIcon
                title={
                  <Space wrap>
                    <span className="rp-mono">{listenerError.protocol}:{listenerError.port}</span>
                    {listenerError.tunnel_id != null && <Tag color="geekblue">Tunnel #{listenerError.tunnel_id}</Tag>}
                    {listenerError.rule_id != null && <Tag>Rule #{listenerError.rule_id}</Tag>}
                  </Space>
                }
                description={listenerError.error}
              />
            ))}
          </Space>
        )}
        </>
      )}
      {isAdmin && row && !row.online && (
        <div style={{ marginTop: 16 }}>
          <Popconfirm title={t('nodeStatusDeleteConfirm')} onConfirm={handleDelete}>
            <Button danger icon={<DeleteOutlined />}>{t('nodeStatusDelete')}</Button>
          </Popconfirm>
        </div>
      )}
    </Drawer>
  );
}
