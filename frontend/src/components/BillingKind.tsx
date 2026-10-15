import { useI18n } from '../i18n/context';

/** Keep unknown future kinds visible, but never expose raw internal names for known movements. */
export default function BillingKind({ kind }: { kind?: string }) {
  const { t } = useI18n();
  const labels: Record<string, string> = {
    opening: t('billingOpening'), purchase: t('billingPurchase'), prepayment: t('billingPrepayment'),
    auto_renew: t('billingAutoRenew'), redeem: t('billingRedeem'),
    adjustment: t('billingAdjustment'), admin_adjustment: t('billingAdjustment'), legacy: t('billingLegacy'),
  };
  return <>{kind ? labels[kind] ?? kind : t('billingLegacy')}</>;
}
