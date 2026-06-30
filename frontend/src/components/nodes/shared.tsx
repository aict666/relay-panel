/* eslint-disable react-refresh/only-export-components */
import { Tag, Typography } from 'antd';
import type { Tfn } from './types';
import type { NodeDisplayRow } from '../../api/types';
import { CountryFlag } from './CountryFlag';

const { Text } = Typography;

/** Dual-stack network cell — IPv4 line + IPv6 line. Each line shows the
 *  CountryFlag pill (SVG, no Emoji) followed by the IP. No country name and
 *  no regionUnknown text: unknown regions render "--". */
export function NetworkCell({ row }: { row: NodeDisplayRow; t: Tfn }) {
  const v4 = row.public_ipv4 ?? row.public_ip;
  const v6 = row.public_ipv6;
  if (!v4 && !v6) return <Text type="secondary">-</Text>;
  const line = (ip: string, code: string | null | undefined) => (
    <div key={ip} style={{ fontSize: 12, lineHeight: '18px', display: 'flex', alignItems: 'center', gap: 6 }}>
      <CountryFlag code={code} />
      <span className="rp-mono" style={{ whiteSpace: 'nowrap' }}>{ip}</span>
    </div>
  );
  return (
    <>
      {v4 ? line(v4, row.ipv4_country_code) : null}
      {v6 ? line(v6, row.ipv6_country_code) : null}
    </>
  );
}

/** Status tag with protocol-mismatch detection. */
export function statusTag(r: NodeDisplayRow, t: Tfn, panelProtocol: number) {
  const v = r.config_protocol_version;
  if (v != null && panelProtocol > 0 && v !== panelProtocol) {
    return <Tag color="red">{t('protocolIncompatible')}</Tag>;
  }
  return r.online ? <Tag color="green">{t('online')}</Tag> : <Tag>{t('offline')}</Tag>;
}
