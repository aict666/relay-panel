import { Card, Col, Row, Tag, Typography, Alert, Modal, Button, Space, Tooltip } from 'antd';
import {
  CloudServerOutlined, ApiOutlined, UserOutlined, DashboardOutlined, ReloadOutlined,
} from '@ant-design/icons';
import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api/client';
import type {
  ApiEnvelope,
  User,
  ForwardRule,
  DeviceGroup,
} from '../api/types';
import { useI18n } from '../i18n/context';
import TrafficChart from '../components/TrafficChart';
import NodeMetricsChart from '../components/NodeMetricsChart';

const { Text } = Typography;

interface VersionInfo {
  current_version: string;
  latest_version: string;
  has_update: boolean;
  is_outdated: boolean;
  release_url: string;
  release_notes: string;
  published_at: string;
  /** True if the GitHub release check itself failed (network / parse / non-2xx).
   *  In this case latest_version is unreliable; surface a "check failed" hint
   *  instead of letting the user think they are up to date. */
  check_failed: boolean;
  /** Short human-readable error from the last failed check. Empty on success. */
  error_message: string;
}

const IGNORED_KEY = 'relaypanel_ignored_version';
// The "Update Now" button points here. README.md is the user-facing entry
// doc with the one-line install + a dedicated upgrade section, so it's a better
// landing page than the (more ops-focused) docs/DEPLOYMENT.md.
const DEPLOY_DOC_URL = 'https://github.com/aict666/relay-panel/blob/main/README.md#-更新';

export default function Dashboard() {
  const { t } = useI18n();
  const navigate = useNavigate();
  const [stats, setStats] = useState({ users: 0, rules: 0, groups: 0 });
  const [rules, setRules] = useState<ForwardRule[]>([]);
  const [versionInfo, setVersionInfo] = useState<VersionInfo | null>(null);
  const [showChangelog, setShowChangelog] = useState(false);
  const [versionRefreshing, setVersionRefreshing] = useState(false);
  const loadInFlightRef = useRef(false);
  const versionRequestRef = useRef(0);
  const backgroundVersionInFlightRef = useRef(false);
  const manualVersionInFlightRef = useRef(false);

  const load = async () => {
    if (loadInFlightRef.current) return;
    loadInFlightRef.current = true;
    try {
      try {
        const [users, rules, groups] = await Promise.all([
          api.get<unknown, ApiEnvelope<User[]>>('/admin/users'),
          api.get<unknown, ApiEnvelope<ForwardRule[]>>('/rules'),
          api.get<unknown, ApiEnvelope<DeviceGroup[]>>('/groups'),
        ]);
        setStats({
          users: users.data?.length || 0,
          rules: rules.data?.length || 0,
          groups: groups.data?.length || 0,
        });
        setRules(rules.data || []);
      } catch { /* Keep the previous KPI values and retry on the next poll. */ }
    } finally {
      loadInFlightRef.current = false;
    }
  };

  const checkVersion = async (forceRefresh = false) => {
    if (forceRefresh) {
      if (manualVersionInFlightRef.current) return;
      manualVersionInFlightRef.current = true;
      setVersionRefreshing(true);
    } else {
      // Do not let a scheduled cached check start after (and supersede) a
      // manual force-refresh. Background checks also never need to overlap.
      if (manualVersionInFlightRef.current || backgroundVersionInFlightRef.current) return;
      backgroundVersionInFlightRef.current = true;
    }
    const requestId = ++versionRequestRef.current;
    try {
      // ?refresh=true bypasses the 30-minute server-side cache so the manual
      // "check update" button always queries GitHub live. Backend accepts
      // true/false/1/0; frontend standardizes on "true".
      const url = forceRefresh ? '/system/version?refresh=true' : '/system/version';
      const res = await api.get<unknown, VersionInfo>(url);
      if (requestId === versionRequestRef.current) setVersionInfo(res);
    } catch (err: unknown) {
      // axios errors expose the response on err.response (AxiosError); other
      // throws just have a message. Read whatever is available and surface it
      // so the user can diagnose (was hardcoded "Network error" which always
      // showed even when the panel reached GitHub but a different layer
      // failed).
      const e = err as {
        response?: { data?: { error_message?: string; message?: string } };
        message?: string;
      };
      const serverMsg =
        e?.response?.data?.error_message ||
        e?.response?.data?.message ||
        e?.message;
      if (requestId === versionRequestRef.current) {
        setVersionInfo((previous) => ({
          current_version: previous?.current_version || '',
          latest_version: previous?.latest_version || '',
          has_update: false,
          is_outdated: false,
          release_url: '',
          release_notes: '',
          published_at: '',
          check_failed: true,
          error_message: serverMsg || 'Unknown error',
        }));
      }
    } finally {
      if (forceRefresh) {
        manualVersionInFlightRef.current = false;
        setVersionRefreshing(false);
      } else {
        backgroundVersionInFlightRef.current = false;
      }
    }
  };

  useEffect(() => {
    load();
    checkVersion();
    const ti = setInterval(load, 10000);
    const tv = setInterval(checkVersion, 1800000); // 30 min
    return () => { clearInterval(ti); clearInterval(tv); };
  }, []);

  // KPI tiles. Each is a shortcut to the page that owns the number, so the
  // dashboard doubles as navigation instead of being a read-only wall.
  const kpis = [
    { label: t('users'), value: stats.users, icon: <UserOutlined />, to: '/users', tone: '' },
    { label: t('forwardRules'), value: stats.rules, icon: <ApiOutlined />, to: '/rules', tone: 'rp-stat-icon-cyan' },
    { label: t('deviceGroups'), value: stats.groups, icon: <CloudServerOutlined />, to: '/groups', tone: 'rp-stat-icon-emerald' },
  ];

  // Version banner logic
  const ignoredVersion = localStorage.getItem(IGNORED_KEY);
  const showUpdateBanner = versionInfo?.has_update
    && versionInfo.latest_version !== ignoredVersion;

  const handleIgnore = () => {
    if (versionInfo) {
      localStorage.setItem(IGNORED_KEY, versionInfo.latest_version);
      setVersionInfo({ ...versionInfo, has_update: false });
    }
  };

  const bannerMsg = versionInfo?.is_outdated
    ? t('versionOutdated').replace('{version}', versionInfo.latest_version)
    : t('newVersionFound').replace('{version}', versionInfo?.latest_version || '');

  return (
    <>
      {versionInfo?.check_failed && (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
          title={t('updateCheckFailed')}
          description={versionInfo.error_message || t('versionCheckFailed')}
        />
      )}
      {showUpdateBanner && (
        <Alert
          type={versionInfo?.is_outdated ? 'error' : 'info'}
          showIcon
          style={{ marginBottom: 16 }}
          title={bannerMsg}
          action={
            <Space>
              <Button size="small" onClick={handleIgnore}>{t('ignoreVersion')}</Button>
              <Button size="small" onClick={() => setShowChangelog(true)}>{t('viewChangelog')}</Button>
              <Button size="small" type="primary" href={DEPLOY_DOC_URL} target="_blank">{t('updateNow')}</Button>
            </Space>
          }
        />
      )}
      {/* v1.2.4: the "you are up to date" state no longer gets a full-width
          success banner — it's the normal case, so it reads as a quiet tag next
          to the version in the page header. Only failures and available
          updates still warrant a banner. */}
      <div className="rp-page-header">
        <h2 className="rp-page-title">
          <DashboardOutlined /> {t('dashboard')}
          {versionInfo && (
            <Space size={8} style={{ marginLeft: 12, fontSize: 13, fontWeight: 'normal' }}>
              <Text type="secondary">
                <span className="rp-mono">v{versionInfo.current_version}</span>
              </Text>
              {versionInfo.has_update ? (
                <Tag color="gold">
                  {t('latestVersion')}: {versionInfo.latest_version}
                </Tag>
              ) : !versionInfo.check_failed ? (
                <Tag color="green">{t('upToDate')}</Tag>
              ) : null}
            </Space>
          )}
        </h2>
        <Tooltip title={t('checkUpdate')}>
          <Button
            icon={<ReloadOutlined />}
            loading={versionRefreshing}
            onClick={() => checkVersion(true)}
          >
            {t('checkUpdate')}
          </Button>
        </Tooltip>
      </div>
      <Row gutter={[16, 16]} style={{ marginBottom: 20 }}>
        {kpis.map((k) => (
          <Col xs={24} sm={12} lg={8} key={k.to}>
            <Card
              className="rp-stat-card rp-stat-card-link"
              style={{ cursor: 'pointer' }}
              role="link"
              tabIndex={0}
              aria-label={`${k.label}: ${k.value}`}
              onClick={() => navigate(k.to)}
              onKeyDown={(event) => {
                if (event.key === 'Enter' || event.key === ' ') {
                  event.preventDefault();
                  navigate(k.to);
                }
              }}
            >
              <div className="rp-stat">
                <div className="rp-stat-text">
                  <span className="rp-stat-label">{k.label}</span>
                  <span className="rp-stat-value">{k.value}</span>
                </div>
                <span className={`rp-stat-icon ${k.tone}`}>{k.icon}</span>
              </div>
            </Card>
          </Col>
        ))}
      </Row>

      <TrafficChart rules={rules.map((rule) => ({ id: rule.id, name: rule.name }))} />
      <NodeMetricsChart />

      <Modal
        title={t('changelogTitle') + ' — ' + (versionInfo?.latest_version || '')}
        open={showChangelog}
        onCancel={() => setShowChangelog(false)}
        footer={[
          <Button key="github" href={versionInfo?.release_url} target="_blank">{t('openReleasePage')}</Button>,
          <Button key="close" type="primary" onClick={() => setShowChangelog(false)}>{t('cancel')}</Button>,
        ]}
      >
        <Text type="secondary" style={{ fontSize: 12 }}>
          {t('currentVersion')}: {versionInfo?.current_version} · {versionInfo?.published_at}
        </Text>
        <pre style={{ whiteSpace: 'pre-wrap', fontSize: 13, marginTop: 12 }}>
          {versionInfo?.release_notes || 'No release notes.'}
        </pre>
      </Modal>
    </>
  );
}
