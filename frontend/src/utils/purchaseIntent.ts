import type { Plan } from '../api/types';

export interface PurchaseBody {
  request_id: string;
  plan_id: number;
  expected_current_plan_id: number;
  expected_price: string;
  expected_revision?: string;
  auto_renew?: boolean;
}

export interface PurchaseIntent {
  body: PurchaseBody;
  plan: Plan;
}

const key = (scope: string) => `relay:pending-purchase:${scope}`;

// Per-tab storage survives navigation/reload without merging independently
// confirmed purchases in different tabs. No tokens or credentials are stored.
export function readPurchaseIntent(scope: string): PurchaseIntent | null {
  const raw = sessionStorage.getItem(key(scope));
  if (!raw) return null;
  const intent = JSON.parse(raw) as PurchaseIntent;
  if (!intent.body?.request_id || !intent.plan || intent.body.plan_id !== intent.plan.id) {
    throw new Error('Invalid pending purchase');
  }
  return intent;
}

export function purchaseIntent(scope: string, plan: Plan, currentPlanId: number | null, autoRenew: boolean): PurchaseIntent {
  const pending = readPurchaseIntent(scope);
  if (pending) return pending; // Never mutate the bytes of an uncertain retry.
  const random = crypto.getRandomValues(new Uint8Array(16));
  const intent: PurchaseIntent = {
    plan,
    body: {
      request_id: Array.from(random, byte => byte.toString(16).padStart(2, '0')).join(''),
      plan_id: plan.id,
      expected_current_plan_id: currentPlanId ?? 0,
      expected_price: plan.price,
      expected_revision: plan.purchase_revision,
      ...(plan.plan_type === 'monthly' ? { auto_renew: autoRenew } : {}),
    },
  };
  // Fail closed if storage is unavailable, before sending a financial action.
  sessionStorage.setItem(key(scope), JSON.stringify(intent));
  return intent;
}

export function clearPurchaseIntent(scope: string) {
  sessionStorage.removeItem(key(scope));
}
