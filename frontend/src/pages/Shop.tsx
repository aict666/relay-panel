import { Card, Row, Col, Button, Spin, Tag, Modal, Table, Typography, message, Result, Alert, Space, Form, Input, Checkbox } from 'antd';
import { ShoppingOutlined, ReloadOutlined, WalletOutlined } from '@ant-design/icons';
import { useCallback, useEffect, useRef, useState } from 'react';
import api from '../api/client';
import type { ApiEnvelope, Plan, Order, UserSelf } from '../api/types';
import { useI18n } from '../i18n/context';
import { formatBytes } from '../utils/format';

const { Text } = Typography;

/**
 * v1.0.8: self-service shop. Lists purchasable (non-hidden) plans as cards,
 * with a confirm modal before buying. Buying charges balance, stacks traffic
 * onto the current quota (per the "流量叠加到当前额度" note), and records an
 * order. The order-history table shows past purchases (snapshotted plan_name +
 * price). A suspended user can still buy (buying does NOT auto-unsuspend).
 */
export default function Shop() {
  const { t } = useI18n();
  const [plans, setPlans] = useState<Plan[]>([]);
  const [orders, setOrders] = useState<Order[]>([]);
  const [me, setMe] = useState<UserSelf | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadFailed, setLoadFailed] = useState(false);
  const [buying, setBuying] = useState<Plan | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [autoRenew, setAutoRenew] = useState(false);
  const [redeemOpen, setRedeemOpen] = useState(false);
  const [redeeming, setRedeeming] = useState(false);
  const [redeemForm] = Form.useForm();
  const loadGenerationRef = useRef(0);

  const load = useCallback(async () => {
    const requestId = ++loadGenerationRef.current;
    setLoading(true);
    setLoadFailed(false);
    try {
      const [plansRes, ordersRes, meRes] = await Promise.all([
        api.get<unknown, ApiEnvelope<Plan[]>>('/plans'),
        api.get<unknown, ApiEnvelope<Order[]>>('/user/orders'),
        api.get<unknown, ApiEnvelope<UserSelf>>('/user/me'),
      ]);
      if (requestId !== loadGenerationRef.current) return false;
      const nextPlans = plansRes.data || [];
      setPlans(nextPlans);
      setOrders(ordersRes.data || []);
      setMe(meRes.data || null);
      // A refresh may change or remove the plan while its confirmation dialog
      // is open. Reconcile the dialog to the authoritative catalog so it never
      // displays an old price for a purchase that the server will charge at the
      // new price.
      setBuying(current => current
        ? (nextPlans.find(plan => plan.id === current.id) ?? null)
        : null);
      return true;
    } catch {
      if (requestId === loadGenerationRef.current) {
        setBuying(null);
        setLoadFailed(true);
      }
      return false;
    } finally {
      if (requestId === loadGenerationRef.current) setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleBuy = async () => {
    if (!buying || loading || loadFailed || submitting) return;
    setSubmitting(true);
    try {
      const res = await api.post<unknown, ApiEnvelope<null>>('/user/buy-plan', {
        plan_id: buying.id,
        expected_price: buying.price,
        expected_revision: buying.purchase_revision,
        ...(buying.plan_type === 'monthly' ? { auto_renew: autoRenew } : {}),
      });
      if (res.code !== 0) {
        message.error(res.message);
        if (res.code === 409) await load();
        return;
      }
      message.success(t('purchaseSuccess'));
      setBuying(null);
      // Keep purchase controls locked until the new balance and order history
      // arrive. Otherwise the retained card data exposes a second purchase
      // window that still uses the pre-purchase balance.
      await load();
    } catch {
      message.error(t('purchaseFailed'));
    } finally {
      setSubmitting(false);
    }
  };

  const handleRedeem = async (values: { code: string }) => {
    if (loading || loadFailed || submitting || redeeming) return;
    setRedeeming(true);
    try {
      const res = await api.post<unknown, ApiEnvelope<{ amount: string; balance: string }>>(
        '/user/redeem',
        { code: values.code },
      );
      if (res.code !== 0 || !res.data) {
        message.error(res.message || t('redeemFailed'));
        return;
      }
      message.success(
        t('redeemSuccess')
          .replace('{amount}', res.data.amount)
          .replace('{balance}', res.data.balance),
      );
      setRedeemOpen(false);
      redeemForm.resetFields();
      await load();
    } catch {
      message.error(t('redeemFailed'));
    } finally {
      setRedeeming(false);
    }
  };

  if (loading && !me && plans.length === 0 && orders.length === 0) {
    return <div style={{ textAlign: 'center', padding: 48 }}><Spin /></div>;
  }

  if (loadFailed) {
    return (
      <Result
        status="warning"
        title={t('shopLoadFailed')}
        extra={<Button type="primary" onClick={load}>{t('refresh')}</Button>}
      />
    );
  }

  const orderColumns = [
    { title: t('orderId'), dataIndex: 'id', key: 'id', width: 70 },
    { title: t('planName'), dataIndex: 'plan_name', key: 'plan_name' },
    { title: t('planPrice'), dataIndex: 'price', key: 'price', render: (v: string) => <span className="rp-mono">{v}</span> },
    { title: t('purchaseTime'), dataIndex: 'created_at', key: 'created_at', render: (v: string) => <span className="rp-mono">{v}</span> },
  ];

  const canAfford = (plan: Plan): boolean => {
    if (!me) return false;
    const balance = Number(me.balance);
    const price = Number(plan.price);
    return Number.isFinite(balance) && Number.isFinite(price) && balance >= price;
  };

  return (
    <>
      <div className="rp-page-header">
        <h2 className="rp-page-title"><ShoppingOutlined /> {t('shop')}</h2>
        <Button icon={<ReloadOutlined />} loading={loading} onClick={load}>{t('refresh')}</Button>
      </div>

      {/* v1.0.8: suspended banner — buying is still allowed (does not auto-clear). */}
      {me?.suspended && (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
          title={t('accountSuspended')}
          description={t('shopSuspendedHint')}
        />
      )}

      {/* Current balance. Purchase effects are shown in confirmation. */}
      {me && (
        <Card size="small" style={{ marginBottom: 16 }}>
          <Space wrap>
            <Text strong>{t('accountBalance')}:</Text>
            <span className="rp-mono">{me.balance}</span>
            <Button
              size="small"
              type="primary"
              ghost
              icon={<WalletOutlined />}
              disabled={loading || submitting || redeeming}
              onClick={() => {
                redeemForm.resetFields();
                setRedeemOpen(true);
              }}
            >
              {t('redeem')}
            </Button>
          </Space>
        </Card>
      )}

      <Row gutter={[16, 16]}>
        {plans.length === 0 && (
          <Col span={24}>
            <Card><Text type="secondary">{t('noPlansAvailable')}</Text></Card>
          </Col>
        )}
        {plans.map((p) => (
          <Col xs={24} sm={12} md={8} key={p.id}>
            <Card
              title={<Space><Text strong>{p.name}</Text>{p.plan_type === 'time' && <Tag color="purple">{t('planTypeTime')}</Tag>}{p.plan_type === 'monthly' && <Tag color="magenta">{t('planTypeMonthly')}</Tag>}</Space>}
              extra={p.description ? <Text type="secondary" style={{ fontSize: 12 }}>{p.description}</Text> : null}
            >
              {/* The price used to be a <Title> wrapping .rp-mono, whose 12px
                  font-size won — it rendered smaller than the body text. */}
              <div className="rp-plan-price">{p.price}</div>
              <div className="rp-plan-features">
                <div>{t('planTraffic')}: {p.traffic > 0 ? formatBytes(p.traffic) : t('unlimited')}</div>
                <div>{t('planMaxRules')}: {p.max_rules}</div>
                {p.duration_days > 0 && <div>{t('planDuration')}: {p.duration_days} {t('days')}</div>}
                {/* v1.0.9: device groups this plan grants on purchase. Names are
                    resolved server-side (device_group_names) — the buyer isn't
                    authorized for these groups yet, so the client can't resolve
                    the ids itself. */}
                {/* v1.0.10: always render this row (show "无" when a plan grants
                    no lines) so plan cards stay vertically aligned. */}
                {p.grant_all_groups ? (
                  <div>{t('planGrantGroups')}: <Tag color="gold">{t('planGrantAll')}</Tag></div>
                ) : (p.device_group_names && p.device_group_names.length > 0) ? (
                  <div>{t('planGrantGroups')}: {p.device_group_names.join(', ')}</div>
                ) : (
                  <div>{t('planGrantGroups')}: <Text type="secondary">{t('planGrantNone')}</Text></div>
                )}
                {p.reset_traffic && <div><Tag color="green">{t('planResetTraffic')}</Tag></div>}
              </div>
              <Button type="primary" block disabled={loading || submitting || !canAfford(p)} title={!canAfford(p) ? t('insufficientBalance') : undefined} style={{ marginTop: 16 }} onClick={() => { setAutoRenew(p.plan_type === 'monthly' && p.id === me?.plan_id && !!me.plan_auto_renew); setBuying(p); }}>
                {t('buyNow')}
              </Button>
              {!canAfford(p) && <Text type="danger" style={{ display: 'block', marginTop: 6, fontSize: 12 }}>{t('insufficientBalance')}</Text>}
            </Card>
          </Col>
        ))}
      </Row>

      {/* Order history. */}
      <Card title={t('orderHistory')} style={{ marginTop: 24 }}>
        <Table
          className="rp-responsive-table"
          dataSource={orders}
          columns={orderColumns}
          rowKey="id"
          pagination={{ pageSize: 10 }}
          size="small"
          scroll={{ x: 'max-content' }}
          locale={{ emptyText: t('noOrders') }}
        />
      </Card>

      {/* Purchase confirm. */}
      <Modal
        open={!!buying}
        onCancel={() => { if (!submitting) setBuying(null); }}
        onOk={handleBuy}
        okText={t('confirmPurchase')}
        cancelText={t('cancel')}
        confirmLoading={submitting}
        okButtonProps={{ disabled: loading || loadFailed || (!!buying && !canAfford(buying)) }}
        title={t('purchaseConfirmTitle')}
      >
        {buying && (
          <div>
            <p>{t('planName')}: <Text strong>{buying.name}</Text></p>
            <p>{t('planPrice')}: <span className="rp-mono">{buying.price}</span></p>
            {me && <p>{t('accountBalance')}: <span className="rp-mono">{me.balance}</span></p>}
            {!canAfford(buying) && (
              <Alert type="error" showIcon style={{ marginTop: 8 }} title={t('insufficientBalance')} />
            )}
            {/* v1.0.9: buying a DIFFERENT plan is a switch — the current plan's
                remaining traffic and expiry are wiped. Warn explicitly. Buying
                the SAME plan (or having none) just renews/stacks. */}
            {buying.plan_type === 'monthly' ? (
              <>
                <Alert type="info" showIcon style={{ marginTop: 8 }} title={t('monthlyPurchaseHint')} />
                <Checkbox checked={autoRenew} onChange={(event) => setAutoRenew(event.target.checked)} style={{ marginTop: 12 }}>
                  {t('enableAutoRenew')}
                </Checkbox>
                <div><Text type="secondary">{t('autoRenewChargeHint')}</Text></div>
              </>
            ) : me?.plan_id != null && buying.id !== me.plan_id ? (
              <Alert type="warning" showIcon style={{ marginTop: 8 }} title={t('shopSwitchPlanWarning')} />
            ) : (
              <Alert type="info" showIcon style={{ marginTop: 8 }} title={t('shopTrafficStacksHint')} />
            )}
          </div>
        )}
      </Modal>

      <Modal
        title={t('redeem')}
        open={redeemOpen}
        onCancel={() => {
          if (!redeeming) setRedeemOpen(false);
        }}
        onOk={() => redeemForm.submit()}
        okText={t('redeemConfirm')}
        cancelText={t('cancel')}
        confirmLoading={redeeming}
        okButtonProps={{ disabled: loading || loadFailed || submitting }}
      >
        <Form form={redeemForm} onFinish={handleRedeem} layout="vertical" disabled={redeeming}>
          <Form.Item
            name="code"
            label={t('redeemCode')}
            extra={t('redeemCodeHint')}
            rules={[{ required: true, message: t('redeemCodeRequired') }]}
          >
            <Input placeholder="XXXX-XXXX-XXXX-XXXX" autoComplete="off" />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
}
