/* eslint-disable react-refresh/only-export-components */
import { Tag, Tooltip, Typography } from 'antd';
import { WarningOutlined } from '@ant-design/icons';
import type { Tfn } from './types';
import type { NodeDisplayRow } from '../../api/types';
import { CountryFlag } from './CountryFlag';
import { controlChannelTipKey, resolveControlChannel } from './controlChannel';

const { Text } = Typography;

/**
 * Sustained NIC rate with zero reported sessions usually means the node is
 * forwarding via a path that doesn't track connections (historically: shared
 * tunnels) or the node binary is too old. 10 KB/s total is above idle chatter.
 */
export const CONNECTION_ANOMALY_BPS = 10_000;

/** True when an online node reports 0 connections but non-trivial NIC traffic. */
export function hasConnectionCountAnomaly(row: Pick<NodeDisplayRow, 'online' | 'connections' | 'upload_bps' | 'download_bps'>): boolean {
  if (!row.online) return false;
  if ((row.connections ?? 0) > 0) return false;
  const rate = (row.upload_bps ?? 0) + (row.download_bps ?? 0);
  return rate >= CONNECTION_ANOMALY_BPS;
}

/** Network cell. New status rows show the IP observed on the actual report
 *  path. Old rows fall back to the node's legacy self-detected IPv4/IPv6. */
export function NetworkCell({ row }: { row: NodeDisplayRow; t: Tfn }) {
  const reportIp = row.report_ip;
  const v4 = row.public_ipv4 ?? row.public_ip;
  const v6 = row.public_ipv6;
  if (!reportIp && !v4 && !v6) return <Text type="secondary">-</Text>;
  const line = (ip: string, code: string | null | undefined) => (
    <div key={ip} style={{ fontSize: 12, lineHeight: '18px', display: 'flex', alignItems: 'center', gap: 6 }}>
      <CountryFlag code={code} />
      {/* nowrap on desktop (table cell), wrapping on phones — a full IPv6
          address is wider than a 375px card. See styles/theme.css. */}
      <span className="rp-mono rp-net-ip">{ip}</span>
    </div>
  );
  return (
    <>
      {reportIp ? line(reportIp, row.report_ip_country_code) : (
        <>
          {v4 ? line(v4, row.ipv4_country_code) : null}
          {v6 ? line(v6, row.ipv6_country_code) : null}
        </>
      )}
    </>
  );
}

/** v1.3.16: amber warning next to a reporting node's primary status tag when
 *  its CONTROL channel is down.
 *  Renders nothing in the states that carry no information (see
 *  resolveControlChannel), so a healthy or fully-offline node is unchanged. */
export function ControlChannelWarning({ row, t }: { row: NodeDisplayRow; t: Tfn }) {
  const tipKey = controlChannelTipKey(resolveControlChannel(row));
  if (!tipKey) return null;
  return (
    <Tooltip title={t(tipKey)}>
      <WarningOutlined
        style={{ color: 'var(--rp-warning, #d97706)', fontSize: 12 }}
        aria-label={t(tipKey)}
      />
    </Tooltip>
  );
}

/** Status tag with protocol-mismatch detection.
 *
 *  v1.3.16: an online node can still have a dead control channel, which used to
 *  be invisible here — the board said 在线 while diagnosis said the opposite.
 *  The tag keeps meaning exactly what it always meant (the node is reporting);
 *  the control plane gets its own adjacent marker rather than being folded into
 *  the same green/grey signal. */
export function statusTag(r: NodeDisplayRow, t: Tfn, panelProtocol: number) {
  const v = r.config_protocol_version;
  const protocolIncompatible = v != null && panelProtocol > 0 && v !== panelProtocol;
  const primaryTag = protocolIncompatible ? (
    <Tag color="red" style={{ marginInlineEnd: 0 }}>{t('protocolIncompatible')}</Tag>
  ) : r.online ? (
    <Tag color="green" style={{ marginInlineEnd: 0 }}>{t('online')}</Tag>
  ) : (
    <Tag style={{ marginInlineEnd: 0 }}>{t('offline')}</Tag>
  );
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
      {primaryTag}
      <ControlChannelWarning row={r} t={t} />
    </span>
  );
}

/** Active session count with a soft warning when NIC rates suggest undercount. */
export function ConnectionsCell({ row, t }: { row: NodeDisplayRow; t: Tfn }) {
  const value = row.connections ?? 0;
  const anomaly = hasConnectionCountAnomaly(row);
  const tip = anomaly ? t('connectionsAnomalyHint') : t('connectionsHint');
  return (
    <Tooltip title={tip}>
      <span className="rp-mono" style={anomaly ? { color: 'var(--rp-warning, #d97706)' } : undefined}>
        {value}
        {anomaly ? (
          <WarningOutlined
            style={{ marginLeft: 4, fontSize: 12 }}
            aria-label={t('connectionsAnomalyHint')}
          />
        ) : null}
      </span>
    </Tooltip>
  );
}
