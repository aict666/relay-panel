import { Area, Bar, Line, Pie } from '@ant-design/charts';
import { QuestionCircleOutlined } from '@ant-design/icons';
import { Alert, Button, Card, Col, Empty, Row, Segmented, Space, Spin, Tag, Tooltip, Typography } from 'antd';
import { useMemo } from 'react';
import type {
  DashboardHistory,
  DashboardHistoryRange,
  DeviceGroup,
  ForwardRule,
} from '../../api/types';
import { useI18n } from '../../i18n/context';
import { formatBps, formatBytes } from '../../utils/format';
import type { NodeGroupSummary } from '../nodes/aggregate';
import {
  buildGroupHealth,
  buildGroupRateRanking,
  buildRuleTrafficRanking,
  insertHistoryGaps,
  type GroupHealthKey,
} from './data';

const { Text } = Typography;

interface DashboardChartsProps {
  history: DashboardHistory | null;
  historyRange: DashboardHistoryRange;
  historyLoading: boolean;
  historyError: boolean;
  liveDataError: boolean;
  deviceGroups: DeviceGroup[];
  nodeGroups: NodeGroupSummary[];
  rules: ForwardRule[];
  onHistoryRangeChange: (range: DashboardHistoryRange) => void;
  onNavigate: (path: string) => void;
}

function ChartTitle({ title, hint }: { title: string; hint: string }) {
  return (
    <Space size={6}>
      <span>{title}</span>
      <Tooltip title={hint}>
        <QuestionCircleOutlined className="rp-dashboard-chart-help" />
      </Tooltip>
    </Space>
  );
}

export default function DashboardCharts({
  history,
  historyRange,
  historyLoading,
  historyError,
  liveDataError,
  deviceGroups,
  nodeGroups,
  rules,
  onHistoryRangeChange,
  onNavigate,
}: DashboardChartsProps) {
  const { t, lang } = useI18n();
  const historyPoints = useMemo(
    () => insertHistoryGaps(history?.points ?? [], history?.bucket_seconds ?? 0),
    [history],
  );
  const health = useMemo(() => buildGroupHealth(deviceGroups, nodeGroups), [deviceGroups, nodeGroups]);
  const groupRanking = useMemo(() => buildGroupRateRanking(nodeGroups), [nodeGroups]);
  const ruleRanking = useMemo(() => buildRuleTrafficRanking(rules), [rules]);

  const formatTime = (value: unknown) => {
    const date = new Date(Number(value));
    if (Number.isNaN(date.getTime())) return '-';
    return new Intl.DateTimeFormat(lang, {
      month: historyRange === '7d' || historyRange === '30d' ? '2-digit' : undefined,
      day: historyRange === '7d' || historyRange === '30d' ? '2-digit' : undefined,
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    }).format(date);
  };

  const uploadLabel = t('dashboardUpload');
  const downloadLabel = t('dashboardDownload');
  const bandwidthData = historyPoints.flatMap((point) => [
    { time: Date.parse(point.timestamp), value: point.upload_bps_avg, direction: uploadLabel },
    { time: Date.parse(point.timestamp), value: point.download_bps_avg, direction: downloadLabel },
  ]);
  const connectionData = historyPoints.map((point) => ({
    time: Date.parse(point.timestamp),
    value: point.connections_max,
  }));

  const healthLabels: Record<GroupHealthKey, string> = {
    online: t('groupStatusOnline'),
    partial: t('dashboardHealthPartial'),
    offline: t('groupStatusOffline'),
    unreported: t('dashboardHealthUnreported'),
  };
  const healthData = health.map((item) => ({
    status: healthLabels[item.status],
    count: item.count,
  }));
  const healthDomain = (['online', 'partial', 'offline', 'unreported'] as GroupHealthKey[])
    .map((key) => healthLabels[key]);

  const groupBarData = groupRanking.flatMap((item) => [
    { group: item.groupName, value: item.uploadBps, direction: uploadLabel },
    { group: item.groupName, value: item.downloadBps, direction: downloadLabel },
  ]);
  const ruleBarData = ruleRanking.map((item) => ({
    rule: item.ruleName,
    value: item.trafficUsed,
    kind: t('traffic'),
  }));

  const historyContent = () => {
    if (historyLoading && !history) {
      return <div className="rp-dashboard-chart-empty"><Spin /></div>;
    }
    if (historyError && !history) {
      return (
        <div className="rp-dashboard-chart-empty">
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('dashboardHistoryFailed')} />
        </div>
      );
    }
    if (historyPoints.length === 0) {
      return (
        <div className="rp-dashboard-chart-empty">
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('dashboardHistoryCollecting')} />
        </div>
      );
    }
    return (
      <div role="img" aria-label={t('dashboardNetworkTrend')} className="rp-dashboard-history-chart">
        <Area
          data={bandwidthData}
          xField="time"
          yField="value"
          colorField="direction"
          height={220}
          scale={{
            x: { type: 'time' },
            color: { domain: [uploadLabel, downloadLabel], range: ['#159f91', '#2f7edb'] },
          }}
          axis={{
            x: { labelFormatter: formatTime, title: false },
            y: { labelFormatter: (value: unknown) => formatBps(Number(value)), title: false },
          }}
          legend={{ color: { position: 'top' } }}
          tooltip={{ items: [{ channel: 'y', valueFormatter: (value: unknown) => formatBps(Number(value)) }] }}
          style={{ fillOpacity: 0.18, lineWidth: 2 }}
        />
        <div className="rp-dashboard-connection-label">{t('dashboardConnectionsPeak')}</div>
        <Line
          data={connectionData}
          xField="time"
          yField="value"
          height={110}
          scale={{ x: { type: 'time' } }}
          axis={{
            x: { labelFormatter: formatTime, title: false },
            y: { labelFormatter: (value: unknown) => String(Math.round(Number(value))), title: false },
          }}
          tooltip={{ items: [{ channel: 'y', valueFormatter: (value: unknown) => String(Math.round(Number(value))) }] }}
          style={{ stroke: '#7c6bc4', lineWidth: 2 }}
        />
      </div>
    );
  };

  return (
    <div className="rp-dashboard-charts">
      {liveDataError && (
        <Alert
          className="rp-dashboard-live-error"
          type="warning"
          showIcon
          title={t('dashboardLiveFailed')}
        />
      )}
      <Row gutter={[16, 16]} align="stretch">
        <Col xs={24} xl={16} className="rp-dashboard-chart-col">
          <Card
            className="rp-dashboard-chart-card"
            title={<ChartTitle title={t('dashboardNetworkTrend')} hint={t('dashboardNetworkTrendHint')} />}
            extra={(
              <Space size={8} wrap>
                {historyError && history && <Tag color="warning">{t('dashboardHistoryFailed')}</Tag>}
                <Segmented<DashboardHistoryRange>
                  size="small"
                  value={historyRange}
                  options={['1h', '24h', '7d', '30d']}
                  onChange={onHistoryRangeChange}
                />
              </Space>
            )}
          >
            {historyContent()}
            <Text type="secondary" className="rp-dashboard-refresh-note">
              {t('dashboardHistoryRefresh')}
            </Text>
          </Card>
        </Col>
        <Col xs={24} xl={8} className="rp-dashboard-chart-col">
          <Card className="rp-dashboard-chart-card" title={t('dashboardGroupHealth')}>
            {healthData.length === 0 ? (
              <div className="rp-dashboard-chart-empty">
                <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('dashboardNoGroups')} />
              </div>
            ) : (
              <div role="img" aria-label={t('dashboardGroupHealth')} className="rp-dashboard-health-chart">
                <Pie
                  data={healthData}
                  angleField="count"
                  colorField="status"
                  innerRadius={0.64}
                  radius={0.86}
                  height={330}
                  scale={{
                    color: {
                      domain: healthDomain,
                      range: ['#22a06b', '#d99b24', '#d84a4a', '#a8b0bc'],
                    },
                  }}
                  legend={{ color: { position: 'bottom', layout: { justifyContent: 'center' } } }}
                  label={false}
                />
                <div className="rp-dashboard-health-total">
                  <strong>{deviceGroups.length}</strong>
                  <span>{t('deviceGroups')}</span>
                </div>
              </div>
            )}
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} align="stretch">
        <Col xs={24} xl={12} className="rp-dashboard-chart-col">
          <Card
            className="rp-dashboard-chart-card"
            title={<ChartTitle title={t('dashboardGroupRateTop')} hint={t('dashboardGroupRateHint')} />}
            extra={<Button type="link" size="small" onClick={() => onNavigate('/nodes')}>{t('dashboardViewAll')}</Button>}
          >
            {groupBarData.length === 0 ? (
              <div className="rp-dashboard-chart-empty rp-dashboard-chart-empty-short">
                <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('dashboardNoLiveTraffic')} />
              </div>
            ) : (
              <div role="img" aria-label={t('dashboardGroupRateTop')}>
                <Bar
                  data={groupBarData}
                  xField="group"
                  yField="value"
                  colorField="direction"
                  group
                  height={Math.max(250, groupRanking.length * 36)}
                  scale={{
                    x: { domain: groupRanking.map((item) => item.groupName).reverse() },
                    y: { tickCount: 4 },
                    color: { domain: [uploadLabel, downloadLabel], range: ['#159f91', '#2f7edb'] },
                  }}
                  axis={{
                    x: { title: false },
                    y: {
                      labelAutoRotate: false,
                      labelFormatter: (value: unknown) => formatBps(Number(value)),
                      title: false,
                    },
                  }}
                  legend={{ color: { position: 'top' } }}
                  tooltip={{ items: [{ channel: 'y', valueFormatter: (value: unknown) => formatBps(Number(value)) }] }}
                />
              </div>
            )}
          </Card>
        </Col>
        <Col xs={24} xl={12} className="rp-dashboard-chart-col">
          <Card
            className="rp-dashboard-chart-card"
            title={<ChartTitle title={t('dashboardRuleTrafficTop')} hint={t('dashboardRuleTrafficHint')} />}
            extra={<Button type="link" size="small" onClick={() => onNavigate('/rules')}>{t('dashboardViewAll')}</Button>}
          >
            <Text type="secondary" className="rp-dashboard-chart-subtitle">
              {t('dashboardRuleTrafficSinceReset')}
            </Text>
            {ruleBarData.length === 0 ? (
              <div className="rp-dashboard-chart-empty rp-dashboard-chart-empty-short">
                <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('dashboardNoRuleTraffic')} />
              </div>
            ) : (
              <div role="img" aria-label={t('dashboardRuleTrafficTop')}>
                <Bar
                  data={ruleBarData}
                  xField="rule"
                  yField="value"
                  colorField="kind"
                  height={Math.max(250, ruleRanking.length * 44)}
                  scale={{
                    x: { domain: ruleRanking.map((item) => item.ruleName).reverse() },
                    y: { tickCount: 4 },
                    color: { range: ['#159f91'] },
                  }}
                  axis={{
                    x: { title: false },
                    y: {
                      labelAutoRotate: false,
                      labelFormatter: (value: unknown) => formatBytes(Number(value)),
                      title: false,
                    },
                  }}
                  legend={false}
                  tooltip={{ items: [{ channel: 'y', valueFormatter: (value: unknown) => formatBytes(Number(value)) }] }}
                />
              </div>
            )}
          </Card>
        </Col>
      </Row>
    </div>
  );
}
