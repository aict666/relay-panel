import { useState } from 'react';
import { Alert, Button, Card, Space, Table } from 'antd';
import api from '../api/client';
import type { ApiEnvelope } from '../api/types';
import { useI18n } from '../i18n/context';
import BillingKind from './BillingKind';

interface Entry {
  id: string;
  kind: string;
  amount_cents: number;
  balance_after: string;
  reference_id: string;
  created_at: string;
}

/** Load on demand; pagination is server-side and errors never look like an empty ledger. */
export default function BalanceHistory({ userId }: { userId?: number }) {
  const { t } = useI18n();
  const [rows, setRows] = useState<Entry[]>([]);
  const [offset, setOffset] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const load = async (next: number) => {
    setBusy(true);
    setError(false);
    try {
      const endpoint = userId == null ? '/user/balance-ledger' : `/admin/users/${userId}/balance-ledger`;
      const res = await api.get<unknown, ApiEnvelope<Entry[]>>(endpoint, { params: { limit: 50, offset: next } });
      if (res.code !== 0 || !Array.isArray(res.data)) { setError(true); return; }
      setRows(res.data);
      setOffset(next);
    } catch { setError(true); }
    finally { setBusy(false); }
  };
  return <Card title={t('balanceHistory')} style={{ marginTop: 24 }} extra={
    <Button loading={busy} onClick={() => void load(offset ?? 0)}>{offset === null ? t('loadBalanceHistory') : t('refresh')}</Button>
  }>
    {error && <Alert type="error" showIcon title={t('loadFailed')} />}
    {offset !== null && <>
      <Table<Entry> rowKey="id" dataSource={rows} loading={busy} pagination={false} size="small" scroll={{ x: 'max-content' }} columns={[
        { title: t('billingKind'), dataIndex: 'kind', render: (kind: string) => <BillingKind kind={kind} /> },
        { title: t('balanceMovement'), dataIndex: 'amount_cents', render: (n: number) => `${n > 0 ? '+' : ''}${(n / 100).toFixed(2)}` },
        { title: t('balanceAfter'), dataIndex: 'balance_after' },
        { title: t('billingReference'), dataIndex: 'reference_id' },
        { title: 'UTC', dataIndex: 'created_at' },
      ]} />
      <Space style={{ marginTop: 12 }}>
        <Button disabled={busy || offset === 0} onClick={() => void load(Math.max(0, offset - 50))}>←</Button>
        <Button disabled={busy || rows.length < 50} onClick={() => void load(offset + 50)}>→</Button>
      </Space>
    </>}
  </Card>;
}
